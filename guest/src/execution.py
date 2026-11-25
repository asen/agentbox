"""One guest helper session over SSH stdio: the host hello, the matching guest
hello, one shell-free command with bounded output frames and one terminal
frame, then the end of the host's input.

Before its exec, the host may ask once, after the hello, for the copied-input
setup of this execution (`inputs_setup`, inputs.py): extract the archive it
uploaded into fresh work and refs directories. Only after that succeeds is
`inputs_ready` sent; until then any other frame is a protocol failure. A
failed setup gets the fixed `invalid_field` error and ends the session; the
loss of the host's input or output stops it (the tar child is killed and
reaped) and gets no reply. `inputs_ready` says nothing of a command.

The host is the only authority. This side validates every host frame with the
shared protocol rules, runs `argv` directly (never through a shell) in a fixed
private working directory with a fixed environment, and reports untrusted
output. Errors are fixed protocol codes only. In a supplied session the
installation's wrappers lead that environment's fixed PATH
(`command_environment`); nothing else of the jail's is inherited. When those
wrappers include a session wrapper, the command runs behind it
(`session_argv`).

The host hello's session, when it is a POST session nonce, is retained with
the session's working directory as the task's request context
(artifact_post_context.py): both go into the command's fixed environment
under reserved names, so no selection can replace them, and the POST clients
read them back. A hello of any other id leaves them out.

An exec's optional `env`, the host's explicit selection, is added to the
command's environment only: it goes to the anchor over a dedicated config
pipe, never its arguments or environment, and the anchor adds it to the
command's spawn alone (anchor.py). The helper and the anchor keep their fixed
environments. Nothing here stores, logs or reports the values; the command
may print or persist them.

An exec's `stdin: true` opts the command's standard input into the host's
`stdin` frames; without it the command's input is the null device, as always.
The anchor gets a fixed flag and a dedicated input pipe, never bytes in its
arguments or environment, and passes it to the command as its descriptor 0,
keeping none itself (anchor.py). Descriptor 0 of the anchor stays its stop
control. Credit is one frame at a time: `stdin_ready` with the next sequence,
first once the anchor spawned, then only once the previous chunk's write
completed, so at most one chunk waits here, while host frames, a cancel
included, are always read. `stdin_eof` ends the command's input only. An
early close of the command's input sends `stdin_closed` once; a stop, the
command's end or a loss destroys the pipe and suppresses every later
callback, with no reply. Frames already in flight then, with the expected
sequence, are dropped unwritten; anything else is a protocol failure. Input
never decides the command's outcome, and nothing here logs it.

The command runs in its own process group under a group anchor (anchor.py),
which leads the group until its final SIGKILL and sends every group signal
itself; this side never signals a group. A cancel, the loss of the host's
input (its end, error or close) or output, a protocol failure, or a failed
read of the command's output stops the command: SIGTERM to its group, SIGKILL
after the grace. When the command ends on its own, the rest of its group gets
SIGKILL at once. Each cleanup has one deadline, from its start: grace plus
REAP_MS. By then the anchor must have confirmed the group's SIGKILL, or the
cleanup is uncertain: the command's output is dropped and the outcome is
never a clean exit. When the session is abandoned, undelivered output is
dropped at the deadline and the last frames get no more than the rest of it,
whether or not the host reads them. Processes that leave the group, and
processes the SIGKILL cannot end (uninterruptible, or a stopped anchor), are
outside this cleanup; while the host keeps reading, the exit frame waits for
the end of the command's output, which such a process can hold open.
"""

import asyncio
import base64
import os
import re
import shutil
import signal
import stat
import subprocess
import time

from guest.src.artifact_post_context import context_environment, request_context
from guest.src.inputs import setup_inputs
from guest.src.pipes import FdReader, FdWriter, close_quietly, pipe
from guest.src.protocol import (
    MAX_OUTPUT_BYTES, MAX_SAFE_INTEGER, FrameSplitter, Refused, decode_host_frame, encode_env_config,
    encode_guest_frame,
)
from guest.src.runtime import python_argv
from guest.src.worker_profile import is_plain_absolute, within

GUEST_VERSION = "0.1.0"
# The provisioned user's home inside the guest.
GUEST_HOME = "/home/agentbox"
# The fixed private working directory of every command.
WORK_DIR = "/home/agentbox/work"
# The guest end of SSH's reverse forward to the host's CONNECT broker.
PROXY_URL = "http://127.0.0.1:18080"
# SIGTERM to SIGKILL for the command's process group.
KILL_GRACE_MS = 2000
# After the grace: the anchor's end, the rest of the output, the last frames.
REAP_MS = 1000

# Helper exit statuses.
EXIT_OK = 0
EXIT_PROTOCOL = 1
# The host's input or output was lost, or the last frames were not flushed.
EXIT_INPUT_LOST = 2
# The command's group was not confirmed ended.
EXIT_CLEANUP = 3
# The command's stdout or stderr could not be read to its end.
EXIT_OUTPUT_LOST = 4

# The anchor beside this module.
ANCHOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anchor.py")
# The anchor's control lines are a few bytes; anything longer is a fault.
MAX_CONTROL_BYTES = 64
# The anchor's flag naming its config pipe, which carries a selection.
ANCHOR_ENV_FLAG = "--env"
# The anchor's flag naming its task input pipe, the command's descriptor 0.
ANCHOR_STDIN_FLAG = "--stdin"
# The anchor's flag for a command behind the session wrapper: it reports
# the wrapper's own exec failure as a failed start (anchor.py).
ANCHOR_SESSION_FLAG = "--session"

# Bytes of frames waiting here before the command's streams pause.
OUTPUT_HIGH_WATER = 16384

# Every command's fixed system PATH.
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# An installation's session wrapper (acquisitions/contracts/handlers/v1 `jail.session`):
# when its `bin/` has one, every command runs behind it.
SESSION_WRAPPER = "agentbox-session"

_EXITED = re.compile(r"e(0|[1-9][0-9]{0,2})")


def command_environment(home, context=None, wrapper_bin=None):
    """The complete environment of a command, with the request context if
    any: nothing is inherited. A supplied installation's `wrapper_bin`
    precedes the fixed system PATH; HOME/.local/bin follows it. Wrappers and
    system commands therefore take precedence over user-installed commands.
    The wrapper prefix must be plain and absolute (worker_profile.py), so it
    holds no separator, or this raises ValueError."""
    if wrapper_bin is not None and not is_plain_absolute(wrapper_bin):
        raise ValueError("invalid PATH prefix")
    prefix = [] if wrapper_bin is None else [wrapper_bin]
    env = {
        "PATH": ":".join(prefix + [SYSTEM_PATH, os.path.join(home, ".local", "bin")]),
        "HOME": home,
        "LANG": "C.UTF-8",
        "TERM": "dumb",
        "HTTP_PROXY": PROXY_URL,
        "HTTPS_PROXY": PROXY_URL,
        "http_proxy": PROXY_URL,
        "https_proxy": PROXY_URL,
    }
    if context is not None:
        env.update(context_environment(context))
    return env


def session_argv(wrapper_bin, argv, env, cwd):
    """`argv` behind the installation's session wrapper, `[WRAPPER, *argv]`,
    when `wrapper_bin` has one and `argv[0]` resolves on the command's PATH
    (from `cwd` when it names a relative path); else `argv` itself, so a
    command that cannot be found fails as it would without the wrapper. The
    wrapper replaces itself with exactly `argv` (its pid, descriptors,
    terminal, group and exit status the command's). One that resolves but
    still cannot start (a missing script interpreter, say) is a failed start
    too: the anchor learns it from the wrapper's status pipe (`--session`),
    never from an exit status."""
    if wrapper_bin is None or not argv:
        return argv
    wrapper = os.path.join(wrapper_bin, SESSION_WRAPPER)
    if not os.path.isfile(wrapper) or not os.access(wrapper, os.X_OK):
        return argv
    program = argv[0]
    if "/" in program:
        program = os.path.join(cwd, program)
    if shutil.which(program, path=env["PATH"]) is None:
        return argv
    return [wrapper, *argv]


async def spawn_anchor(argv, control_in, control_out, pass_fds, cwd, env):
    """The anchor in a new session, its control pipes on descriptors 0 and 1;
    a process whose `wait()` is its exit status. Tests replace it."""
    return await asyncio.create_subprocess_exec(*argv, stdin=control_in, stdout=control_out, stderr=subprocess.DEVNULL,
                                                pass_fds=pass_fds, cwd=cwd, env=env, start_new_session=True)


def prepare_work_dir(path, home, mount=None):
    """Creates the private working directory `path`, strictly beneath
    `home` (the project location, or work). HOME and every directory down
    to it must be a real directory of this user, not group or other
    writable, the working directory itself private; a missing one is made
    0700, one at a time, never through a symlink. With `mount`, the root of
    the host mount holding `path` (worker_profile.py's mounted form), the
    directories from it down are the host's: each must exist, a real
    directory of this user, not other-writable (group bits allowed);
    nothing is made there. Anything else, a replaced ancestor included,
    refuses. These checks guard against mistakes, not this guest's own
    processes, which own HOME anyway."""
    below = os.path.relpath(path, home) if path.startswith(home + "/") else None
    if below is None or below.startswith("..") or os.path.join(home, below) != path:
        return False
    if mount is not None and (mount == home or not within(mount, home) or not within(path, mount)):
        return False
    at, uid = home, os.geteuid()
    mounted = False
    try:
        for part in [None] + below.split("/"):
            if part is not None:
                at = os.path.join(at, part)
                mounted = mount is not None and within(at, mount)
                if not mounted:
                    try:
                        os.mkdir(at, 0o700)
                    except FileExistsError:
                        pass
            info = os.lstat(at)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
                return False
            if info.st_mode & (0o002 if mounted else 0o022):
                return False
        return mounted or (info.st_mode & 0o077) == 0
    except OSError:
        return False


class SessionOptions:
    """`input_fd`, `output_fd`: the host's stream; `work_dir`: created private
    if missing, also the request context's working root; `home`; `wrapper_bin`:
    a supplied session's host-generated wrappers (`agentbox-request`, an
    enabled handler's shims; runtime/bootstrap.rs), first on the command's
    PATH; `abort`: an Abort whose abort is the loss of the host's input, such
    as on SIGTERM; `mount`: the root of the host mount holding `work_dir`, if
    any (worker_profile.py); `inputs_setup`: owned tests only, replaces the copied input
    setup (a coroutine of the execution id and `live`)."""

    def __init__(self, input_fd, output_fd, work_dir, home, wrapper_bin=None, kill_grace_ms=None, abort=None,
                 inputs_setup=None, mount=None):
        self.input_fd = input_fd
        self.output_fd = output_fd
        self.work_dir = work_dir
        self.mount = mount
        self.home = home
        self.wrapper_bin = wrapper_bin
        self.kill_grace_ms = KILL_GRACE_MS if kill_grace_ms is None else kill_grace_ms
        self.abort = abort
        self.inputs_setup = inputs_setup


async def run_session(options):
    """Runs one session to its end; returns the helper's exit status."""
    return await Session(options).run()


class Session:
    def __init__(self, options):
        self.options = options
        self.splitter = FrameSplitter()
        self.phase = "hello"
        # The host hello's nonce and the working directory, once valid.
        self.context = None
        self.exec_id = ""
        self.status = EXIT_OK
        self.future = None
        self.resolved = False
        self.loop = None
        # The one copied-input setup, and its work in flight.
        self.inputs_asked = False
        self.installing = None
        # Task input, one credit and one chunk at a time: `off`, `open`,
        # `ended` once its end arrived, `closed` once it closed early or was
        # destroyed.
        self.input = "off"
        self.input_pipe = None
        self.input_seq = 0
        self.credited = False
        # The command, through its anchor.
        self.anchor = None
        self.anchor_stdin = None
        self.control = None
        self.streams = []
        self.open = 0
        self.leader = None
        self.control_line = ""
        self.control_bytes = 0
        self.control_bad = False
        self.control_ended = False
        self.killing = False
        self.anchor_returncode = None
        self.anchor_failed = False
        self.anchor_released = False
        self.stop_sent = False
        # A stop asked for while the anchor was being started.
        self.stop_requested = False
        # Cleanup and delivery.
        self.cancelled = False
        self.abandoned = False
        self.output_lost = False
        self.uncertain = False
        self.dropped = False
        self.read_lost = False
        self.input_done = False
        self.paused = False
        self.deadline = None
        self.deadline_timer = None
        self.flush_timer = None
        self.reader = None
        self.output = None

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.future = self.loop.create_future()
        self.output = FdWriter(self.options.output_fd, drain=self._resume, gone=self._output_gone, own=False,
                               high_water=OUTPUT_HIGH_WATER)
        self.reader = FdReader(self.options.input_fd, self._receive, end=self._input_ended, error=self._input_lost,
                               own=False)
        if self.options.abort is not None:
            if self.options.abort.aborted:
                self.loop.call_soon(self._lose)
            else:
                self.options.abort.add_listener(self._lose)
        try:
            return await self.future
        finally:
            self.reader.destroy()
            if self.options.abort is not None:
                self.options.abort.remove_listener(self._lose)

    def _ended(self):
        return self.phase == "ended"

    def _receive(self, chunk):
        if self._ended():
            return
        try:
            frames = self.splitter.push(chunk)
        except Refused as error:
            self._fail(error.code)
            return
        for data in frames:
            if self._ended():
                return
            try:
                frame = decode_host_frame(data)
            except Refused as error:
                self._fail(error.code)
                return
            self._handle(frame)

    def _handle(self, frame):
        kind = frame["type"]
        if self.phase == "hello" and kind == "hello":
            self.phase = "exec"
            self.context = request_context(frame["session"], self.options.work_dir, self.options.mount)
            self._send({"v": 1, "type": "hello", "session": frame["session"], "guest_version": GUEST_VERSION})
            return
        if self.phase == "exec" and kind == "inputs_setup" and not self.inputs_asked:
            self.inputs_asked = True
            self.phase = "inputs"
            self.installing = self.loop.create_task(self._setup_inputs(frame["execution_id"]))
            return
        if self.phase == "exec" and kind == "exec":
            self.phase = "running"
            self.exec_id = frame["id"]
            if frame.get("stdin") is True:
                self.input = "open"
            self.loop.create_task(self._start(frame["argv"], frame.get("env") or ()))
            return
        if kind in ("stdin", "stdin_eof") and self._input_frame(frame):
            return
        if kind == "cancel" and frame["id"] == self.exec_id:
            # A cancel may cross the terminal frame on the wire.
            if self.phase == "running":
                self._stop(True)
            if self.phase in ("running", "finished"):
                return
        # Anything else, including a mismatched cancel, a second exec or setup,
        # anything during a setup.
        self._fail("invalid_field")

    async def _setup_inputs(self, execution_id):
        def live():
            return self.phase == "inputs" and not self.abandoned

        setup = self.options.inputs_setup
        try:
            if setup is not None:
                ok = await setup(execution_id, live)
            else:
                ok = await setup_inputs(self.options.home, execution_id, live)
        except Exception:
            ok = False
        # Rechecked here: a loss or failure meanwhile gets no late reply.
        if not live():
            return
        if not ok:
            self._fail("invalid_field")
            return
        self.phase = "exec"
        self._send({"v": 1, "type": "inputs_ready"})

    async def _start(self, argv, env):
        options = self.options
        program = argv[0] if argv else None
        if program is None or not prepare_work_dir(options.work_dir, options.home, options.mount):
            self._terminal("failed")
            return
        if self.phase != "running" or self.cancelled:
            self._terminal("cancelled")
            return
        grace = str(options.kill_grace_ms)
        selected = len(env) > 0
        stdin = self.input == "open"
        ctl_in = ctl_out = out = err = config = task = (None, None)
        try:
            ctl_in, ctl_out, out, err = pipe(), pipe(), pipe(), pipe()
            config = pipe() if selected else (None, None)
            task = pipe() if stdin else (None, None)
        except OSError:
            close_quietly(*ctl_in, *ctl_out, *out, *err, *config, *task)
            self._terminal("failed")
            return
        # A selection or the input opt-in adds only fixed flags and their
        # pipes, never values or bytes.
        flags = []
        if selected:
            flags.append("%s=%d" % (ANCHOR_ENV_FLAG, config[0]))
        if stdin:
            flags.append("%s=%d" % (ANCHOR_STDIN_FLAG, task[0]))
        passed = tuple(fd for fd in (out[1], err[1], config[0], task[0]) if fd is not None)
        try:
            fixed = command_environment(options.home, self.context, options.wrapper_bin)
            wrapped = session_argv(options.wrapper_bin, argv, fixed, options.work_dir)
            if wrapped is not argv:
                flags.append(ANCHOR_SESSION_FLAG)
                argv = wrapped
            # A new session: the anchor leads the command's group.
            anchor = await spawn_anchor(
                python_argv(ANCHOR, *flags, str(out[1]), str(err[1]), grace, *argv), ctl_in[0],
                ctl_out[1], passed, options.work_dir, fixed)
        except Exception:
            # Nothing started, so there is no group to end.
            close_quietly(*ctl_in, *ctl_out, *out, *err, *config, *task)
            self.anchor_failed = True
            if self.leader is None:
                self.leader = ("failed", None)
            self._settle_failed_start()
            return
        # Only the anchor holds the child ends now.
        close_quietly(ctl_in[0], ctl_out[1], out[1], err[1], config[0], task[0])
        self.anchor = anchor
        self.anchor_stdin = FdWriter(ctl_in[1])
        if stdin:
            self._open_input(task[1])
        if selected:
            # Written once and closed; a short or failed write fails the anchor.
            FdWriter(config[1]).end(encode_env_config(env))
        self.control = FdReader(ctl_out[0], self._control_data, close=self._control_closed)
        for fd, stream in ((out[0], "stdout"), (err[0], "stderr")):
            self.open += 1
            reader = FdReader(fd, lambda chunk, stream=stream: self._output_data(stream, chunk),
                              error=self._read_failed, close=self._stream_closed)
            self.streams.append(reader)
        if self.paused:
            for reader in self.streams:
                reader.pause()
        self.loop.create_task(self._watch_anchor(anchor))
        # The first credit, only once the command can be started.
        self._grant()
        # A stop or loss that came while the anchor was starting.
        if self.stop_requested:
            self._send_stop()

    async def _watch_anchor(self, anchor):
        returncode = await anchor.wait()
        self.anchor_returncode = returncode
        self._settle()

    def _settle_failed_start(self):
        self._release_streams()
        self._settle()

    def _stream_closed(self):
        self.open -= 1
        self._settle()

    def _control_closed(self):
        self.control_ended = True
        self._settle()

    def _open_input(self, fd):
        """Takes the anchor's input pipe; its failure or its reader's close is an early close."""
        holder = {}

        def closed():
            if self.input_pipe is holder.get("pipe"):
                self._close_input(True)

        writer = FdWriter(fd, gone=closed, watch=True)
        holder["pipe"] = writer
        self.input_pipe = writer

    def _grant(self):
        """Grants the one next credit, while the input is open and running."""
        if self.input != "open" or self.credited or self.phase != "running" or self.cancelled:
            return
        self.credited = True
        self._send({"v": 1, "type": "stdin_ready", "id": self.exec_id, "seq": self.input_seq})

    def _input_frame(self, frame):
        """A `stdin` or `stdin_eof` frame: only for this command, only on the
        one credit granted. Once input is closed or the command finished, one
        in flight on that credit is dropped unwritten. False refuses it."""
        live = self.phase in ("running", "finished")
        if not live or frame["id"] != self.exec_id or self.input in ("off", "ended"):
            return False
        if not self.credited or frame["seq"] != self.input_seq:
            return False
        self.credited = False
        if self.input == "closed" or self.phase != "running":
            return True
        writer = self.input_pipe
        if writer is None:
            # Not spawned yet: no credit was granted, so this is unreachable.
            return True
        if frame["type"] == "stdin_eof":
            self.input = "ended"
            writer.end()
            return True
        if self.input_seq >= MAX_SAFE_INTEGER:
            return False
        self.input_seq += 1

        def written(ok):
            # A failure is the pipe's `gone`; a destroyed pipe, a stop or the
            # command's end meanwhile: nothing.
            if ok and self.input_pipe is writer and self.input == "open":
                self._grant()

        writer.write(base64.b64decode(frame["data"]))
        writer.flushed(written)
        return True

    def _close_input(self, early):
        """Ends task input: reported once, as `stdin_closed`, only for an early
        close while running; otherwise silent. Later callbacks are suppressed."""
        writer = self.input_pipe
        self.input_pipe = None
        was_open = self.input == "open"
        if was_open:
            self.input = "closed"
        if writer is not None:
            writer.destroy()
        if early and was_open and self.phase == "running" and not self.cancelled:
            self._send({"v": 1, "type": "stdin_closed", "id": self.exec_id})

    def _control_data(self, chunk):
        """The anchor's fixed lines: the command's end, then its final SIGKILL."""
        self.control_bytes += len(chunk)
        if self.control_bytes > MAX_CONTROL_BYTES:
            self.control_bad = True
            self.control.destroy()
            return
        for byte in chunk:
            if byte != 0x0A:
                self.control_line += chr(byte)
                continue
            line, self.control_line = self.control_line, ""
            if line == "k" and not self.killing:
                self.killing = True
                continue
            exited = _EXITED.fullmatch(line)
            if exited is not None and int(exited.group(1)) <= 255:
                leader = ("exited", int(exited.group(1)))
            elif line == "s":
                leader = ("signaled", None)
            elif line == "f":
                leader = ("failed", None)
            else:
                leader = None
            if leader is None or self.leader is not None or self.killing:
                self.control_bad = True
                continue
            self.leader = leader
            # The command ended: the rest of its group's cleanup is bounded.
            self._cleanup_by()

    def _output_data(self, stream, chunk):
        if self.output_lost:
            # Undeliverable: read and dropped, so the command never blocks on it.
            self.dropped = True
            return
        for offset in range(0, len(chunk), MAX_OUTPUT_BYTES):
            data = base64.b64encode(chunk[offset:offset + MAX_OUTPUT_BYTES]).decode("ascii")
            self._send({"v": 1, "type": "output", "id": self.exec_id, "stream": stream, "data": data})

    def _settle(self):
        """Once the anchor and the command's output are done, the exit frame."""
        if self.phase != "running" or not (self.anchor is not None or self.anchor_failed) or not self._anchor_done():
            return
        confirmed = self.anchor_failed or (self.killing and not self.control_bad
                                           and self.anchor_returncode == -signal.SIGKILL)
        if not confirmed and not self.uncertain:
            # The group may live on without its anchor: never signalled from
            # here, and its output is not waited for.
            self.uncertain = True
            self._release_streams()
        if self.open > 0:
            return
        if self.uncertain and self.status == EXIT_OK:
            self.status = EXIT_CLEANUP
        if self.read_lost and self.status == EXIT_OK:
            self.status = EXIT_OUTPUT_LOST
        if self.cancelled:
            self._terminal("cancelled")
            return
        if self.uncertain or self.dropped or self.leader is None:
            self._terminal("failed")
            return
        self._terminal(*self.leader)

    def _anchor_done(self):
        return (self.anchor_failed or self.anchor_released
                or (self.anchor_returncode is not None and self.control_ended))

    def _terminal(self, outcome, code=None):
        if self.phase != "running":
            return
        # No input frame or credit follows the exit frame.
        self._close_input(False)
        self.phase = "finished"
        self._clear_deadline_timer()
        if outcome == "exited":
            self._send({"v": 1, "type": "exit", "id": self.exec_id, "outcome": outcome, "code": code or 0})
        else:
            self._send({"v": 1, "type": "exit", "id": self.exec_id, "outcome": outcome})
        if self.abandoned:
            self._end()

    def _send(self, frame):
        """Writes one frame; a full output pauses the command's streams."""
        try:
            data = encode_guest_frame(frame)
        except Refused as error:
            self._fail(error.code)
            return
        if self.output_lost or self.output.destroyed:
            return
        if not self.output.write(data + b"\n") and not self.paused and not self.output.destroyed:
            self.paused = True
            for reader in self.streams:
                reader.pause()

    def _resume(self):
        if not self.paused:
            return
        self.paused = False
        for reader in self.streams:
            reader.resume()

    def _stop(self, cancelled):
        """Asks the anchor to stop the command, once, within one deadline."""
        self.cancelled = self.cancelled or cancelled
        # A stop or loss destroys the command's input, unreported.
        self._close_input(False)
        self._cleanup_by()
        self.stop_requested = True
        if self.anchor is None:
            return
        self._send_stop()

    def _send_stop(self):
        if self.stop_sent or self.anchor_stdin is None:
            return
        self.stop_sent = True
        self.anchor_stdin.end(b"s")

    def _cleanup_by(self):
        """Starts the cleanup deadline, once: grace plus REAP_MS from now."""
        if self.deadline is None:
            seconds = (self.options.kill_grace_ms + REAP_MS) / 1000
            self.deadline = time.monotonic() + seconds
            if self.phase == "running":
                self.deadline_timer = self.loop.call_later(seconds, self._expire)
        return self.deadline

    def _clear_deadline_timer(self):
        if self.deadline_timer is not None:
            self.deadline_timer.cancel()
        self.deadline_timer = None

    def _expire(self):
        """The cleanup deadline passed with the command not yet reported."""
        self.deadline_timer = None
        if self.phase != "running":
            return
        if not self._anchor_done():
            self._release_anchor()
        if self.abandoned:
            self._release_streams()
        self._settle()

    def _release_anchor(self):
        """Stops waiting for an anchor that did not end in time."""
        if self.anchor is None or self.anchor_released:
            return
        self.anchor_released = True
        if self.anchor_stdin is not None:
            self.anchor_stdin.destroy()
        if self.control is not None:
            self.control.destroy()

    def _release_streams(self):
        """Drops whatever the command's streams still hold."""
        for reader in self.streams:
            if reader.destroyed or reader.ended:
                continue
            self.dropped = True
            reader.destroy()

    def _output_gone(self):
        """The host's output is gone: nothing more can be delivered."""
        if self.output_lost:
            return
        self.output_lost = True
        # The command's streams are read and dropped from here on.
        self._resume()
        if self._ended():
            self._finish(False)
            return
        self._lose()

    def _read_failed(self):
        """The command's output failed to read: required output is lost, so
        the outcome cannot be a clean exit, and the command is stopped within
        the cleanup deadline rather than left running."""
        self.read_lost = True
        self.dropped = True
        if self.phase == "running":
            self._stop(False)

    def _input_lost(self):
        if self.input_done:
            return
        self.input_done = True
        self._lose()

    def _input_ended(self):
        if self.input_done:
            return
        self.input_done = True
        try:
            self.splitter.end()
        except Refused as error:
            self._fail(error.code)
            return
        if self.phase == "finished":
            self._end()
            return
        self._lose()

    def _lose(self):
        """The host's input is gone before the terminal frame."""
        if self._ended():
            return
        if self.status == EXIT_OK:
            self.status = EXIT_INPUT_LOST
        self._abandon()

    def _fail(self, code):
        if self._ended():
            return
        if self.status == EXIT_OK:
            self.status = EXIT_PROTOCOL
        # After the terminal frame the guest writes nothing more.
        if self.phase != "finished":
            self._send({"v": 1, "type": "error", "code": code})
        self._abandon()

    def _abandon(self):
        """Ends the command first, if any, then the session."""
        self.abandoned = True
        if self.phase == "running":
            self._stop(True)
            # A cleanup that started earlier keeps its deadline, even a past one.
            if self.deadline is not None and time.monotonic() >= self.deadline:
                self._expire()
            # The exit frame follows, then the end.
            return
        self._end()

    def _end(self):
        """Flushes the frames written before, bounded: by the cleanup deadline
        when the session is abandoned, else by REAP_MS from the host's end."""
        if self._ended():
            return
        self.phase = "ended"
        self._clear_deadline_timer()
        self.reader.pause()
        if self.output_lost or self.output.destroyed:
            self._finish(False)
            return
        self.output.flushed(self._finish)
        bound = self._cleanup_by() - time.monotonic() if self.abandoned else REAP_MS / 1000
        self.flush_timer = self.loop.call_later(max(0.0, bound), self._finish, False)

    def _finish(self, flushed):
        """Resolves once; an unconfirmed flush is never a clean end."""
        if self.resolved:
            return
        self.resolved = True
        self._clear_deadline_timer()
        if self.flush_timer is not None:
            self.flush_timer.cancel()
        self.flush_timer = None
        if not flushed and self.status == EXIT_OK:
            self.status = EXIT_INPUT_LOST
        # Never before a setup in flight has stopped and reaped its tar.
        status = self.status
        installing = self.installing

        async def resolve():
            if installing is not None:
                try:
                    await installing
                except Exception:
                    pass
            if not self.future.done():
                self.future.set_result(status)

        self.loop.create_task(resolve())
