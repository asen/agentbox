"""Host tools of the broker: lookup in the
captured host PATH, and bounded invocations driven by the broker's loop.

A tool runs by `posix_spawn` (no Python code between fork and exec, so
the broker's lookup threads cannot deadlock it): its own process group,
cwd `/` (the broker's own), stdin and stderr `/dev/null`, stdout a private
pipe, at most one forwarded descriptor as its fd 3, default SIGPIPE and
SIGXFSZ, nothing else inherited (every other descriptor of the broker is
close-on-exec). Its leader is held unreaped (WNOWAIT) while its group is
killed, so the group id cannot be reused meanwhile. Errors are fixed codes.
"""
import errno
import fcntl
import hashlib
import os
import signal
import stat

OWN_PREFIX = "AGENTBOX_"
MAX_PATH_BYTES = 4096
_CAPTURED = None


class ToolError(Exception):
    """`tool_missing`, `tool_untrusted`, `tool_start_failed`,
    `tool_timeout`, `tool_output_too_large` or `tool_cancelled`."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def is_path(text):
    from .transport import is_path as check
    return check(text)


def filter_path(text):
    kept = [entry for entry in (text or "").split(":") if is_path(entry)]
    return ":".join(kept) if kept else None


def capture_host(environ=None):
    """This process's environment, captured once: every variable but PATH
    and AGENTBOX_*, then the filtered PATH, if any."""
    global _CAPTURED
    if _CAPTURED is None:
        source = os.environ if environ is None else environ
        env = [(name, value) for name, value in source.items()
               if name != "PATH" and not name.startswith(OWN_PREFIX)]
        path = filter_path(source.get("PATH"))
        if path is not None:
            env.append(("PATH", path))
        _CAPTURED = env
    return list(_CAPTURED)


def host_path():
    return dict(capture_host()).get("PATH")


def tool_env():
    """A host tool's whole environment: the captured PATH, LC_ALL=C."""
    path = host_path()
    return ([("PATH", path)] if path is not None else []) + [("LC_ALL", "C")]


def _root_owned(st):
    return st.st_uid == 0 and not st.st_mode & 0o022


def _root_chain(path):
    while True:
        try:
            if not _root_owned(os.lstat(path)):
                return False
        except OSError:
            return False
        if path == "/":
            return True
        path = os.path.dirname(path)


def find_trusted(name):
    """`name` in the first captured PATH directory with an executable
    regular file of that name, links followed, as its canonical path; as
    root, only through a root-owned chain."""
    if not name or "/" in name or name in (".", ".."):
        raise ToolError("tool_missing")
    for directory in (host_path() or "").split(":"):
        if not directory.startswith("/"):
            continue
        try:
            real = os.path.realpath(os.path.join(directory, name), strict=True)
            st = os.stat(real)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        if os.geteuid() == 0 and not _root_chain(real):
            raise ToolError("tool_untrusted")
        return real
    raise ToolError("tool_missing")


def resolve(name):
    """`find_trusted`, then the file checked and hashed through one
    descriptor; as root also not setuid, setgid or group/world writable.
    The canonical path."""
    path = find_trusted(name)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise ToolError("tool_untrusted") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise ToolError("tool_untrusted")
        if os.geteuid() == 0 and (st.st_mode & (stat.S_ISUID | stat.S_ISGID) or not _root_owned(st)
                                  or _capabilities(fd)):
            raise ToolError("tool_untrusted")
        digest, total = hashlib.sha256(), 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > st.st_size:
                raise ToolError("tool_untrusted")
            digest.update(chunk)
        if total != st.st_size:
            raise ToolError("tool_untrusted")
    except OSError:
        raise ToolError("tool_untrusted") from None
    finally:
        os.close(fd)
    return path


def _capabilities(fd):
    try:
        os.getxattr(fd, "security.capability")
        return True
    except OSError as error:
        return error.errno not in (errno.ENODATA, errno.ENOTSUP)


class Run:
    """One bounded tool invocation, driven by the loop: `fileno()` its
    stdout to watch, `readable()` on readiness, `poll(now)` until it
    returns a result: ("ok", code_or_None, stdout) or ("error", code)."""

    def __init__(self, program, args, env, deadline, max_output, forwarded=None):
        self.deadline, self.max_output = deadline, max_output
        self.stdout = bytearray()
        self.eof = False
        self.code = None
        self.reaped = False
        self.result = None
        read, write = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        null = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
        copy = None
        try:
            actions = [(os.POSIX_SPAWN_DUP2, null, 0), (os.POSIX_SPAWN_DUP2, write, 1),
                       (os.POSIX_SPAWN_DUP2, null, 2)]
            if forwarded is not None:
                # A close-on-exec copy above 3, so its dup2 to 3 always
                # clears the flag in the child alone.
                copy = fcntl.fcntl(forwarded, fcntl.F_DUPFD_CLOEXEC, 10)
                actions.append((os.POSIX_SPAWN_DUP2, copy, 3))
            self.pid = os.posix_spawn(program, [program] + list(args), dict(env), file_actions=actions,
                                      setpgroup=0, setsigdef=(signal.SIGPIPE, signal.SIGXFSZ),
                                      setsigmask=())
        except OSError:
            os.close(read)
            raise ToolError("tool_start_failed") from None
        finally:
            os.close(write)
            os.close(null)
            if copy is not None:
                os.close(copy)
        self.read_fd = read

    def fileno(self):
        return self.read_fd

    def readable(self):
        """Drains stdout without blocking; over the cap kills the group."""
        while not self.eof and self.result is None and self.read_fd >= 0:
            try:
                chunk = os.read(self.read_fd, 65536)
            except BlockingIOError:
                return
            except OSError:
                chunk = b""
            if not chunk:
                self.eof = True
                return
            self.stdout += chunk
            if len(self.stdout) > self.max_output:
                self._end(("error", "tool_output_too_large"))
                return

    def _exited(self):
        try:
            info = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return True
        return info is not None

    def _kill_and_reap(self):
        if self.reaped:
            return
        try:
            os.killpg(self.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            _, status = os.waitpid(self.pid, 0)
            self.code = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass
        self.reaped = True

    def _end(self, result):
        if self.result is None:
            self.result = result
            self._kill_and_reap()
        return self.result

    def close(self):
        """Its stdout's end, once its owner stopped watching it."""
        if self.read_fd >= 0:
            os.close(self.read_fd)
            self.read_fd = -1

    def cancel(self):
        return self._end(("error", "tool_cancelled"))

    def poll(self, now):
        """Its result once known, else None."""
        if self.result is not None:
            return self.result
        self.readable()
        if self.result is not None:
            return self.result
        if self.code is None and self._exited():
            self._kill_and_reap()
        if self.reaped and self.eof:
            exited = self.code if self.code is not None and self.code >= 0 else None
            return self._end(("ok", exited, bytes(self.stdout)))
        if now >= self.deadline:
            return self._end(("error", "tool_timeout"))
        return None
