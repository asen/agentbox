"""The group anchor: the leader of one command's process group, started by the
guest helper's session (execution.py) only, never by the host.

The helper starts it in a new session, so its pid is the group's id, with a
fixed environment and the private working directory, and with
`[--env=CFG] [--stdin=IN] OUT ERR GRACE_MS ARGV...` as arguments: the
descriptors it inherited for the command's stdout and stderr (and config and
input below). It runs ARGV directly (no shell) in its own group, the command's
stdout and stderr on OUT and ERR, and stays the group's leader until the
group's final SIGKILL, which it sends itself, to the group and itself at once.
Every group signal comes from this live process, so the group id it names is
always its own.

Control in (descriptor 0), from the helper: any byte, or its end, as when the
helper is lost, stops the command: SIGTERM to the group now, SIGKILL GRACE_MS
later. Nothing renews that deadline. Control out (descriptor 1), to the
helper: fixed lines only, `e<code>` (the command exited), `s` (killed by a
signal) or `f` (failed to start), then `k` just before the final SIGKILL. When
the command ends on its own, the SIGKILL follows at once: whatever is left in
its group is abandoned. Terminating signals get a no-op handler here (never
SIG_IGN, which the command would inherit), so the command's group signals do
not end its anchor first while the command still gets them. Run as anything
but its group's leader, it exits at once and signals nothing.

With `--env=CFG`, the helper's explicit selection arrives on descriptor CFG,
its config pipe, written once and closed: the frame's `env` object, strictly
validated again (protocol.py). Only once it has ended and the pipe is closed
is the command spawned, with this process's fixed environment plus the
selection; this process's own environment, arguments and other descriptors
are unchanged, and nothing here writes the values anywhere. An invalid,
oversized or failed config reports `f` and ends the group; a stop meanwhile
starts nothing. Descriptor 0 stays the stop channel throughout.

With `--session`, ARGV is the installation's session wrapper and the
command behind it. The wrapper gets one more first argument,
`--status=FD`, the write end of a pipe of this process's (close-on-exec in
the wrapper): `r` just before it execs the command, `f` if that exec fails.
Ends with `r` alone: the command's own status, reported as ever; `f`, or no
`r` and an exit: `f`, the command never started; a signal: `s`. Only the
first 64 bytes count, and once the wrapper ended its pipe gets at most
STATUS_WAIT more.

With `--stdin=IN`, descriptor IN is the command's task input pipe from the
helper: the command gets it as its descriptor 0, and this process closes its
own copy right after the spawn and never reads or writes it. Without the flag
the command's input is the null device. No input byte is ever in this
process's arguments or environment.
"""

if __name__ == "__main__":
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import asyncio
import os
import re
import signal
import subprocess
import sys

from guest.src.pipes import FdReader, close_quietly
from guest.src.protocol import MAX_FRAME_BYTES, decode_env_config

ENV_FLAG = "--env="
STDIN_FLAG = "--stdin="
SESSION_FLAG = "--session"
STATUS_ARG = "--status=%d"
STATUS_BYTES = 64
# After the wrapper ended, how long a leaked holder may keep its status pipe.
STATUS_WAIT = 1.0
MAX_GRACE_MS = 60_000

IGNORED = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2,
           signal.SIGALRM, signal.SIGVTALRM, signal.SIGPROF, signal.SIGXCPU, signal.SIGXFSZ)

_DECIMAL = re.compile(r"0|[1-9][0-9]{0,8}")


def _report(line):
    """Writes a control line; the helper may be gone, which changes nothing."""
    try:
        os.write(1, (line + "\n").encode("ascii"))
    except OSError:
        pass


def _finish():
    """The final SIGKILL, to the whole group with this process in it."""
    _report("k")
    try:
        os.killpg(os.getpid(), signal.SIGKILL)
    finally:
        # Unreachable: the signal above ends this process too.
        os._exit(1)


def _ignore(_number, _frame):
    pass


def _number(text, low, high):
    if _DECIMAL.fullmatch(text) is None:
        return None
    value = int(text)
    return value if low <= value <= high else None


class Anchor:
    def __init__(self, loop, words):
        self.loop = loop
        self.config = self.task = None
        if words and words[0].startswith(ENV_FLAG):
            self.config = _number(words[0][len(ENV_FLAG):], 3, 1 << 20)
            words = words[1:]
            if self.config is None:
                _finish()
        if words and words[0].startswith(STDIN_FLAG):
            self.task = _number(words[0][len(STDIN_FLAG):], 3, 1 << 20)
            words = words[1:]
            if self.task is None:
                _finish()
        self.session = bool(words) and words[0] == SESSION_FLAG
        if self.session:
            words = words[1:]
        if len(words) < 4 + self.session:
            _finish()
        self.out = _number(words[0], 3, 1 << 20)
        self.err = _number(words[1], 3, 1 << 20)
        self.grace = _number(words[2], 0, MAX_GRACE_MS)
        self.program, self.args = words[3], words[4:]
        if self.out is None or self.err is None or self.grace is None:
            _finish()
        self.stopping = False
        self.ended = False
        self.told = b""

    def stop(self, _chunk=None):
        if self.stopping:
            return
        self.stopping = True
        try:
            os.killpg(os.getpid(), signal.SIGTERM)
        except OSError:
            # This process is in the group: it always exists.
            pass
        self.loop.call_later(self.grace / 1000, _finish)

    async def start(self, env):
        """The command, with the selection added to its environment only."""
        merged = None if env is None else dict(os.environ, **dict(env))
        status = (None, None)
        try:
            args, passed = self.args, ()
            if self.session:
                status = os.pipe2(os.O_CLOEXEC)
                args, passed = [STATUS_ARG % status[1], *self.args], (status[1],)
            command = await asyncio.create_subprocess_exec(
                self.program, *args, stdin=subprocess.DEVNULL if self.task is None else self.task,
                stdout=self.out, stderr=self.err, env=merged, pass_fds=passed)
        except Exception:
            command = None
        # Only the command and its descendants hold the output, and the input, now.
        close_quietly(self.out, self.err, self.task, status[1])
        if command is None:
            close_quietly(status[0])
            if self.ended:
                return
            self.ended = True
            _report("f")
            if not self.stopping:
                _finish()
            return
        reading = None if status[0] is None else self.loop.create_task(self.status(status[0]))
        code = await command.wait()
        started = True
        if reading is not None:
            try:
                await asyncio.wait_for(asyncio.shield(reading), STATUS_WAIT)
            except asyncio.TimeoutError:
                pass
            told = self.told
            started = b"f" not in told and (b"r" in told or code < 0)
        if self.ended:
            return
        self.ended = True
        _report("f" if not started else "e%d" % code if code >= 0 else "s")
        # A stop keeps its original deadline for the rest of the group.
        if not self.stopping:
            _finish()

    async def status(self, fd):
        """The wrapper's status pipe to its end (module documentation):
        `self.told`, its first STATUS_BYTES."""
        done = self.loop.create_future()

        def readable():
            try:
                chunk = os.read(fd, STATUS_BYTES)
            except BlockingIOError:
                return
            except OSError:
                chunk = b""
            if chunk:
                self.told = (self.told + chunk)[:STATUS_BYTES]
                return
            self.loop.remove_reader(fd)
            done.set_result(None)

        os.set_blocking(fd, False)
        self.loop.add_reader(fd, readable)
        try:
            await done
        finally:
            self.loop.remove_reader(fd)
            os.close(fd)

    def refuse(self):
        """Nothing started: the group ends now, a stop's deadline included."""
        if self.ended:
            return
        self.ended = True
        _report("f")
        _finish()

    def configured(self):
        """Reads the config pipe to its end, bounded, closes it, then starts."""
        chunks = []
        state = {"size": 0, "failed": False}

        def data(chunk):
            state["size"] += len(chunk)
            if state["size"] > MAX_FRAME_BYTES:
                state["failed"] = True
                reader.destroy()
                return
            chunks.append(chunk)

        def fail():
            state["failed"] = True

        def closed():
            env = None if state["failed"] else decode_env_config(b"".join(chunks))
            chunks.clear()
            if env is None or self.stopping:
                self.refuse()
                return
            self.loop.create_task(self.start(env))

        reader = FdReader(self.config, data, error=fail, close=closed)


async def _main(words):
    loop = asyncio.get_running_loop()
    # Any fault here ends the group rather than leaving it unanchored.
    loop.set_exception_handler(lambda _loop, _context: _finish())
    anchor = Anchor(loop, words)
    if anchor.config is not None:
        anchor.configured()
    else:
        loop.create_task(anchor.start(None))
    FdReader(0, anchor.stop, end=anchor.stop, error=anchor.stop, own=False)
    await loop.create_future()


def main(words):
    if os.getpgid(0) != os.getpid():
        os._exit(2)
    for number in IGNORED:
        signal.signal(number, _ignore)
    try:
        asyncio.run(_main(words))
    except BaseException:
        _finish()


if __name__ == "__main__":
    main(sys.argv[1:])
