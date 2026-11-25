"""A pull's local integration (application.py `_pull`): stock `git pull` in
the working repository, its fetch served from the verified delivery by the
fixed remote helper `git-remote-agentbox`, never by a network transport.

  shim --> /usr/bin/git -c remote.R.vcs=agentbox pull [FLAG]     own group
             └─ git fetch --> git-remote-agentbox R URL          checks R, URL
                                └─ connect git-upload-pack --> git upload-pack SOURCE

Hardened like LocalGit: no system or global configuration, hooks, editors,
credentials, submodule recursion, autostash or automatic maintenance;
GIT_ALLOW_PROTOCOL admits only `agentbox`. Command-scoped configuration adds
only the effective user.name, user.email, pull.ff, pull.rebase and
branch.<current>.rebase: the repository's own value, else the jail user's
global one (`global_settings`). Identity from the environment only and
conditional global includes are not imported. Unsupported strategies refuse.

Git's own output streams through, bounded (output.py): an unread stdout or
stderr holds Git while it runs, and after it ended output gets STREAM_EOF_MS,
the rest dropped. Its exit status is the pull's. Accounting
is best effort: the direct child and its output pipes, observed; a normal
exit with both pipes at EOF claims no more than that. The group is signalled
only while its leader is unreaped (its id pinned), never after. An abnormal
end keeps staging."""

import asyncio
import os
import signal
import sys
import time

from acquisitions.git.jail.local import GIT, LOCAL_CONFIG, Failed, LocalGit, Records, fail
from acquisitions.git.jail.output import Sink

HELPER = "agentbox"
HELPER_COMMAND = "git-remote-" + HELPER
# The helper's binding, in the pull's own environment.
SOURCE_ENV = "AGENTBOX_GIT_PULL_SOURCE"
REMOTE_ENV = "AGENTBOX_GIT_PULL_REMOTE"
URL_ENV = "AGENTBOX_GIT_PULL_URL"
PYTHON_ENV = "AGENTBOX_GIT_PULL_PYTHON"
ENTRY_ENV = "AGENTBOX_GIT_PULL_ENTRY"
# The staged helper: fixed text, its paths from the environment above.
HELPER_SCRIPT = ('#!/bin/sh\nexec "$%s" -I -S -B -X utf8 "$%s" shim %s "$@"\n'
                 % (PYTHON_ENV, ENTRY_ENV, HELPER_COMMAND))
ENTRY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "git.py")

PULL_CONFIG = tuple(item for item in LOCAL_CONFIG if not item.startswith("protocol.file.")) + (
    "rebase.autoStash=false", "merge.autoStash=false",
)
# Imported keys; branch.<current>.rebase besides.
IDENTITY_KEYS = ("user.name", "user.email")
MAX_IDENTITY_BYTES = 1024
_GLOBAL_PATTERN = r"^(user\.(name|email)|pull\.(ff|rebase)|branch\..+\.rebase)$"
_TRUE = ("true", "yes", "on", "1")
_FALSE = ("false", "no", "off", "0", "")

# After the leader exited: how long both pipes may take to reach EOF and the
# output to be written; the unwritten rest is dropped.
STREAM_EOF_MS = 2000
# Unwritten output held per stream.
RELAY_BUFFER_BYTES = 262144
# After a stop: how long the leader may take to exit before the group is killed.
KILL_GRACE_MS = 1000


def _bool(value):
    folded = value.lower()
    if folded in _TRUE:
        return "true"
    if folded in _FALSE:
        return "false"
    return None


def effective_settings(local, global_values, branch):
    """[(key, value)] to add with command scope: each key's repository value,
    else the global one, validated. `local` maps keys to their values in
    order (application.py `_config`), `global_values` keys to the last
    value; `branch` is the current branch's short name. Raises Failed
    `git_pull_unsupported` for anything else than a plain identity or a
    boolean strategy (pull.ff also `only`)."""
    rebase = "branch.%s.rebase" % branch
    settings = []
    for key in IDENTITY_KEYS + ("pull.ff", "pull.rebase", rebase):
        values = local.get(key)
        value = values[-1] if values else global_values.get(key)
        if value is None:
            continue
        if key in IDENTITY_KEYS:
            if (len(value.encode("utf-8", "surrogatepass")) > MAX_IDENTITY_BYTES
                    or any(char in value for char in "\n\0<>")):
                fail("git_pull_unsupported")
        elif key == "pull.ff" and value == "only":
            pass
        else:
            value = _bool(value)
            if value is None:
                fail("git_pull_unsupported")
        settings.append((key, value))
    return settings


async def global_settings(stage, clock, environ):
    """The jail user's global values of the imported keys, includes followed
    but read outside any repository: {key: last value}. Nothing without an
    absolute HOME."""
    git = LocalGit(stage, clock)
    home = environ.get("HOME")
    if not isinstance(home, str) or not os.path.isabs(home):
        return {}
    git.env = dict(git.env, HOME=home)
    git.env.pop("XDG_CONFIG_HOME")
    git.env.pop("GIT_CONFIG_GLOBAL")
    for name in ("XDG_CONFIG_HOME", "GIT_CONFIG_GLOBAL"):
        if isinstance(environ.get(name), str) and environ[name] != "":
            git.env[name] = environ[name]
    found = {}

    def accept(data):
        text = data.decode("utf-8", "surrogateescape")
        split = text.find("\n")
        key = text if split < 0 else text[:split]
        found[key] = "true" if split < 0 else text[split + 1:]

    records = Records(0, 65536, accept)
    await git.run(["config", "--global", "--includes", "--null", "--get-regexp", _GLOBAL_PATTERN],
                  data=records.push, exits=(0, 1))
    records.finish()
    return found


def stage_helper(stage):
    """The helper in `stage/bin`, private, the pull's only PATH entry besides the system's."""
    directory = os.path.join(stage, "bin")
    os.mkdir(directory, 0o700)
    fd = os.open(os.path.join(directory, HELPER_COMMAND), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                 | os.O_CLOEXEC, 0o700)
    try:
        os.write(fd, HELPER_SCRIPT.encode())
    finally:
        os.close(fd)
    return directory


def pull_invocation(stage, work, remote, url, source, flag, settings):
    """(argv, env) of the pull."""
    env = _base_env(stage)
    env.update({
        "PATH": os.path.join(stage, "bin") + ":/usr/bin:/bin", "GIT_ALLOW_PROTOCOL": HELPER,
        "GIT_EDITOR": "false", "GIT_SEQUENCE_EDITOR": "false", "GIT_MERGE_AUTOEDIT": "no",
        SOURCE_ENV: source, REMOTE_ENV: remote, URL_ENV: url, PYTHON_ENV: sys.executable, ENTRY_ENV: ENTRY,
        "GIT_CONFIG_COUNT": str(len(settings)),
    })
    for index, (key, value) in enumerate(settings):
        env["GIT_CONFIG_KEY_%d" % index] = key
        env["GIT_CONFIG_VALUE_%d" % index] = value
    argv = [GIT, *(item for value in PULL_CONFIG for item in ("-c", value)),
            "-c", "remote.%s.vcs=%s" % (remote, HELPER), "-C", work, "pull", *([flag] if flag else [])]
    return argv, env


def _base_env(stage):
    home = os.path.join(stage, "home")
    return {
        "LC_ALL": "C", "HOME": home, "XDG_CONFIG_HOME": home, "TMPDIR": os.path.join(stage, "tmp"),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_PROTOCOL_FROM_USER": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1", "GIT_ATTR_NOSYSTEM": "1", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_PAGER": "",
    }


class _Relay:
    """One Git output pipe to one Sink (output.py), on the event loop. While
    Git runs, a full buffer stops reading it (Git waits); once its leader
    exited, reading continues to EOF and what exceeds the buffer is
    dropped. No thread and no blocking write."""

    def __init__(self, loop, source, target):
        self.loop = loop
        self.source = source
        self.sink = Sink(target)
        self.buffer = bytearray()
        self.eof = False
        self.draining = False
        self.reading = False
        self.waiting = False
        os.set_blocking(source, False)
        self._read()

    def _read(self):
        if not self.eof and not self.reading and (self.draining or len(self.buffer) < RELAY_BUFFER_BYTES):
            self.reading = True
            self.loop.add_reader(self.source, self._readable)

    def _readable(self):
        try:
            chunk = os.read(self.source, 65536)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            chunk = b""
        if not chunk:
            self.eof = True
            self._stop_reading()
            return
        self.buffer += chunk[:max(0, RELAY_BUFFER_BYTES - len(self.buffer))] if self.draining else chunk
        self._flush()
        if len(self.buffer) >= RELAY_BUFFER_BYTES and not self.draining:
            self._stop_reading()

    def _stop_reading(self):
        if self.reading:
            self.loop.remove_reader(self.source)
            self.reading = False

    def _flush(self):
        while self.buffer:
            count = self.sink.write(bytes(self.buffer[:65536]))
            if count == 0 and self.sink.fileno() is None:
                count = len(self.buffer)
            if count == 0:
                if not self.waiting:
                    self.waiting = True
                    self.loop.add_writer(self.sink.fileno(), self._writable)
                return
            del self.buffer[:count]
        self._read()

    def _writable(self):
        self.loop.remove_writer(self.sink.fileno())
        self.waiting = False
        self._flush()

    def drain(self):
        self.draining = True
        self._read()

    def close(self):
        """Ends the relay; anything unwritten is dropped."""
        self._stop_reading()
        if self.waiting:
            self.loop.remove_writer(self.sink.fileno())
            self.waiting = False
        self.sink.close()
        self.buffer.clear()
        os.close(self.source)


def _signal_group(pid, number):
    """Only while `pid`, the group's leader, is unreaped."""
    try:
        os.killpg(pid, number)
    except ProcessLookupError:
        pass


# Library tests only: the launcher.
_spawn = os.posix_spawn


async def run_pull(argv, env, clock, outputs=(1, 2)):
    """Git in its own process group, stdin /dev/null, its stdout and stderr
    relayed to `outputs` (_Relay: bounded, never blocking, even if nothing
    reads them). Its exit status after a normal end, both pipes at EOF;
    else Failed, the caller keeping its staging: the clock's code on
    cancellation or expiry, `git_cleanup_incomplete` when a signal ended it
    or its pipes stay open. Signals go to the group only before the leader
    is reaped. After the leader exited, output gets STREAM_EOF_MS."""
    loop = asyncio.get_running_loop()
    pipes = [os.pipe() for _ in outputs]
    try:
        pid = _spawn(argv[0], argv, env, setpgroup=0, setsigdef=(signal.SIGPIPE, signal.SIGXFSZ),
                     file_actions=[(os.POSIX_SPAWN_OPEN, 0, "/dev/null", os.O_RDONLY, 0),
                                   *((os.POSIX_SPAWN_DUP2, write, target)
                                     for (_, write), target in zip(pipes, (1, 2)))])
    except OSError:
        for read, write in pipes:
            os.close(read)
            os.close(write)
        fail("git_process_failed")
    for _, write in pipes:
        os.close(write)
    relays = []
    stop = None
    try:
        for (read, _), target in zip(pipes, outputs):
            relays.append(_Relay(loop, read, target))
        exited = asyncio.Event()
        watch = os.pidfd_open(pid)
        loop.add_reader(watch, exited.set)
        try:
            killed = False
            while not exited.is_set():
                if stop is None:
                    try:
                        clock.check()
                    except Failed as error:
                        stop = (error, time.monotonic())
                        _signal_group(pid, signal.SIGTERM)
                elif not killed and time.monotonic() >= stop[1] + KILL_GRACE_MS / 1000:
                    killed = True
                    _signal_group(pid, signal.SIGKILL)
                try:
                    await asyncio.wait_for(exited.wait(), 0.01)
                except asyncio.TimeoutError:
                    pass
        finally:
            loop.remove_reader(watch)
            os.close(watch)
        # Exited, not reaped: the group id is still this group's.
        info = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT)
        normal = stop is None and info.si_code == os.CLD_EXITED
        if not normal:
            _signal_group(pid, signal.SIGKILL)
        for relay in relays:
            relay.drain()
        until = time.monotonic() + STREAM_EOF_MS / 1000
        while (not all(relay.eof and not relay.buffer for relay in relays)) and time.monotonic() < until:
            await asyncio.sleep(0.005)
        if normal and not all(relay.eof for relay in relays):
            # A descendant holds the pipes: still this group, its leader unreaped.
            normal = False
            _signal_group(pid, signal.SIGKILL)
    except BaseException:
        # No pidfd, or this task cancelled: the group goes, then its leader is reaped.
        _signal_group(pid, signal.SIGKILL)
        os.waitid(os.P_PID, pid, os.WEXITED)
        raise
    finally:
        for relay in relays:
            relay.close()
        for read, _ in pipes[len(relays):]:
            os.close(read)
    os.waitid(os.P_PID, pid, os.WEXITED)
    if stop is not None:
        raise stop[0]
    if not normal:
        fail("git_cleanup_incomplete")
    return info.si_status

async def remote_helper_main(args):
    """`git-remote-agentbox REMOTE URL`, run by the pull's fetch: one
    `connect git-upload-pack` to the bound verified source, as often as Git
    asks within that pull. Anything else, or another remote or URL, refuses."""
    source = os.environ.get(SOURCE_ENV)
    if (not source or not os.path.isabs(source) or len(args) != 2
            or args != [os.environ.get(REMOTE_ENV), os.environ.get(URL_ENV)]):
        sys.stderr.write("%s: not this pull's remote\n" % HELPER_COMMAND)
        return 128
    while True:
        line = _line()
        if line == b"capabilities":
            os.write(1, b"connect\n\n")
        elif line == b"connect git-upload-pack":
            os.write(1, b"\n")
            env = dict(_base_env(os.path.dirname(source)), PATH="/usr/bin:/bin")
            if "GIT_PROTOCOL" in os.environ:
                env["GIT_PROTOCOL"] = os.environ["GIT_PROTOCOL"]
            os.execve(GIT, [GIT, *(item for value in LOCAL_CONFIG for item in ("-c", value)), "upload-pack",
                            "--strict", source], env)
        elif line == b"":
            return 0
        else:
            sys.stderr.write("%s: unsupported request\n" % HELPER_COMMAND)
            return 128


def _line():
    """One command line from Git, read bytewise: nothing beyond it is consumed."""
    data = bytearray()
    while len(data) <= 1024:
        byte = os.read(0, 1)
        if not byte or byte == b"\n":
            return bytes(data)
        data.extend(byte)
    return None
