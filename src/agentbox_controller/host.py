"""Host primitives: the captured environment, trusted tool lookup, the one
selectors loop and owned child processes.

```text
Loop      selectors: child pipes, own stdin/stdout, a signal wakeup pipe
Child     argv, exact env, `/` cwd, a new session (its own process group),
          optionally joined to a cgroup leaf before exec; reaped only after
          its group is killed (the leader held unreaped by WNOWAIT)
```

Single-threaded by design: a child joins its cgroup leaf in a fork-time
hook (`preexec_fn`), safe only without threads, which nothing here starts.
Errors are fixed codes (`HostError`), never tool output.
"""
import errno
import os
import resource
import selectors
import signal
import stat
import subprocess
import threading
import time

from .assets import provider_protocol

# The longest wait of the loop between rechecks of its stops.
SLICE = 0.05
# A command of several steps (`run AGENT`): one interrupt list for all its
# loops, sticky (`share_signals`); None: each loop its own.
SHARED = None
OWN_PREFIX = "AGENTBOX_"
TERMINATING = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


class HostError(Exception):
    """A fixed code; never a path, value or tool text."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def install_owner(st):
    """Installed code owned by this user or root. Accept the user's umask 0002."""
    uid = os.geteuid()
    return st.st_uid in (0, uid) and not st.st_mode & (0o002 if st.st_uid == uid else 0o022)


def filter_path(text):
    """The `:`-separated absolute, normalized, shell-inert entries, in order
    (the Rust host's `tools::filter_path`); None when none is."""
    kept = [entry for entry in (text or "").split(":") if provider_protocol.is_path(entry)]
    return ":".join(kept) if kept else None


_CAPTURED = None


def capture_host(environ=None):
    """This process's environment, captured once: every UTF-8 variable but
    PATH and AGENTBOX_*, then PATH filtered. The base of a provider's
    environment; never a guest's."""
    global _CAPTURED
    if _CAPTURED is None:
        source = os.environ if environ is None else environ
        env = [(k, v) for k, v in source.items()
               if k != "PATH" and not k.startswith(OWN_PREFIX)]
        path = filter_path(source.get("PATH"))
        if path is not None:
            env.append(("PATH", path))
        _CAPTURED = env
    return list(_CAPTURED)


def host_path():
    return dict(capture_host()).get("PATH")


def tool_env():
    """A host tool's whole environment: the captured PATH and LC_ALL=C."""
    env = {"LC_ALL": "C"}
    path = host_path()
    if path is not None:
        env["PATH"] = path
    return env


def find_tool(name):
    """`name` in the first captured PATH directory holding an executable
    regular file of that name, links followed, as its canonical path; as
    root only a root-owned file in root-owned, not group/world writable
    directories."""
    if not name or "/" in name or name in (".", ".."):
        raise HostError("tool_missing")
    for directory in (host_path() or "").split(":"):
        if not directory:
            continue
        try:
            real = os.path.realpath(os.path.join(directory, name))
            st = os.stat(real)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        if os.geteuid() == 0 and not _root_chain(real):
            raise HostError("tool_untrusted")
        return real
    raise HostError("tool_missing")


def _root_chain(path):
    while True:
        try:
            st = os.lstat(path)
        except OSError:
            return False
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False
        if path == "/":
            return True
        path = os.path.dirname(path)


class Loop:
    """The controller's one event loop. Callbacks run on readiness; `run`
    returns once `done()` holds or at `deadline`, whichever first. Signals
    are only counted (`signals`, by the handler), never raised as
    exceptions."""

    def __init__(self):
        self.selector = selectors.DefaultSelector()
        self.signals = SHARED if SHARED is not None else []
        self._previous = {}
        read, write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self._wake = (read, write)
        self.watch(read, selectors.EVENT_READ, self._drain_signals)

    def install_signals(self):
        # Counted in the handler itself (main thread, before any later
        # bytecode); the pipe only wakes `select`, so a byte unread at
        # `close` loses nothing.
        signals = self.signals
        signal.set_wakeup_fd(self._wake[1])
        for number in TERMINATING:
            self._previous[number] = signal.signal(number, lambda num, _frame: signals.append(num))

    def restore_signals(self):
        for number, previous in self._previous.items():
            signal.signal(number, previous)
        self._previous = {}
        signal.set_wakeup_fd(-1)

    def _drain_signals(self, _mask):
        """Wakeup bytes only: the handler already counted each signal."""
        while True:
            try:
                data = os.read(self._wake[0], 64)
            except BlockingIOError:
                return
            if not data:
                return

    def watch(self, fd, events, callback):
        try:
            self.selector.modify(fd, events, callback)
        except KeyError:
            self.selector.register(fd, events, callback)

    def unwatch(self, fd):
        try:
            self.selector.unregister(fd)
        except (KeyError, ValueError):
            pass

    def step(self, timeout):
        for key, mask in self.selector.select(max(0.0, timeout)):
            key.data(mask)

    def run(self, done, deadline=None, slice_=SLICE):
        """Until `done()` (True) or `deadline` (False)."""
        while not done():
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                return done()
            wait = slice_ if deadline is None else min(slice_, deadline - now)
            self.step(wait)
        return True

    def close(self):
        self.restore_signals()
        self.selector.close()
        for fd in self._wake:
            os.close(fd)


def share_signals():
    """From now on every loop counts into one fresh list, and so do
    terminating signals between loops: an interrupt stops the running step
    or the next one, and stays asked. Called again (a cleanup's start), a
    fresh list: only later interrupts count."""
    global SHARED
    SHARED = []
    for number in TERMINATING:
        signal.signal(number, lambda num, _frame: SHARED.append(num))
    return SHARED


def _child_hook(procs_fd, result_fd, fsize):
    """In the forked child, before exec: join the leaf by writing its own
    pid (a failure fails the spawn: nothing runs outside the leaf), put
    `result_fd` at descriptor 3, set the file-size limit."""
    def hook():
        if procs_fd is not None:
            os.write(procs_fd, f"{os.getpid()}\n".encode())
        if fsize is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        if result_fd is not None:
            os.dup2(result_fd, 3)
    return hook


class Child:
    """One owned child: a new session and process group led by it, `/` as
    its working directory, exactly `env`, no inherited descriptor but its
    pipes. `leaf` (a cgroup.procs descriptor) puts it in its leaf before
    exec. Killing is by its group while the leader is held unreaped, and
    by the caller's cgroup domain beyond that. `stdout_fd` gives it a file
    as stdout, `stdin_fd` one as stdin (a bridge's socket both), `result_fd`
    a descriptor as its 3, `fsize` RLIMIT_FSIZE. A stream given as
    "inherit" is this process's own. `session=False` (only an interactive
    agent's terminal SSH): in this process's group, killed by its pid
    alone, never by group."""

    def __init__(self, argv, env, leaf=None, stdin=True, stdout=True, stderr=True, stdout_fd=None,
                 result_fd=None, fsize=None, stdin_fd=None, session=True):
        if threading.active_count() != 1 and (leaf is not None or result_fd is not None or fsize is not None):
            raise HostError("threads_present")
        pipe = subprocess.PIPE
        self.session = session
        if not session and (leaf is not None or result_fd is not None or fsize is not None):
            raise HostError("spawn_failed")
        hook = None
        if leaf is not None or result_fd is not None or fsize is not None:
            hook = _child_hook(leaf, result_fd, fsize)
        def stream(value):
            return None if value == "inherit" else (pipe if value else subprocess.DEVNULL)

        out = stdout_fd if stdout_fd is not None else stream(stdout)
        try:
            # With `result_fd` nothing else is inherited either: every
            # descriptor here is close-on-exec but the one put at 3.
            self.popen = subprocess.Popen(
                list(argv), env=dict(env), cwd="/", close_fds=result_fd is None, start_new_session=session,
                stdin=stdin_fd if stdin_fd is not None else stream(stdin), stdout=out,
                stderr=stream(stderr),
                pass_fds=(), preexec_fn=hook)
        except (OSError, subprocess.SubprocessError):
            raise HostError("spawn_failed") from None
        self.pid = self.popen.pid
        self.code = None
        self.reaped = False
        for stream in (self.popen.stdin, self.popen.stdout, self.popen.stderr):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)

    def exited(self):
        """Whether the leader exited; it stays unreaped (WNOWAIT)."""
        if self.reaped:
            return True
        try:
            info = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True
        return info is not None

    def kill_group(self):
        """SIGKILL to its whole group, only while the leader is unreaped,
        so the group id cannot have been reused; a child in this process's
        own group: to its pid alone."""
        self.signal(signal.SIGKILL)

    def signal(self, number):
        """`number` to its group (its pid alone without a session of its
        own), only while unreaped."""
        if self.reaped:
            return
        try:
            if self.session:
                os.killpg(self.pid, number)
            else:
                os.kill(self.pid, number)
        except ProcessLookupError:
            pass

    def finish(self):
        """Once exited: its group killed, then reaped. Returns its status
        (negative: a signal)."""
        if not self.reaped:
            self.kill_group()
            self.code = self.popen.wait()
            self.reaped = True
            for stream in (self.popen.stdin, self.popen.stdout, self.popen.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
        return self.code

    def stop(self):
        """Ends it now: its group killed, the leader reaped."""
        self.kill_group()
        return self.finish()


def write_some(fd, data):
    """Nonblocking write: bytes written, 0 when it would block, None when
    the reader is gone."""
    try:
        return os.write(fd, data)
    except BlockingIOError:
        return 0
    except OSError as error:
        if error.errno in (errno.EPIPE, errno.EBADF, errno.EINVAL):
            return None
        raise


def read_some(fd, size=65536):
    """Nonblocking read: bytes, b"" at EOF, None when it would block."""
    try:
        return os.read(fd, size)
    except BlockingIOError:
        return None
    except OSError:
        return b""


class Drain:
    """A child's diagnostic stream: at most `limit` bytes kept, the rest
    read and counted; never parsed."""

    def __init__(self, loop, fd, limit=65536):
        self.loop, self.fd, self.limit = loop, fd, limit
        self.kept = bytearray()
        self.dropped = 0
        self.ended = False
        loop.watch(fd, selectors.EVENT_READ, self._read)

    def _read(self, _mask):
        data = read_some(self.fd)
        if data is None:
            return
        if not data:
            self.ended = True
            self.loop.unwatch(self.fd)
            return
        room = self.limit - len(self.kept)
        self.kept += data[:max(0, room)]
        self.dropped += max(0, len(data) - max(0, room))

    def close(self):
        if not self.ended:
            self.loop.unwatch(self.fd)
            self.ended = True
