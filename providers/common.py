"""Host primitives shared by agentbox.provider v1 providers (stdlib only).

Single-threaded by design: child processes are started with a fork-time
hook (`spawn`) that joins their custody child before `exec`, which is only
safe without threads. Providers never start threads.

  Session   the control channel: one request, `cancel`, the owner's `stop`,
            EOF and signals (an unreported cancel); anchored deadlines
  Custody   the host's custody domain (AGENTBOX_CUSTODY) and the children a
            provider creates in it: limits written and read back before a
            process is released, exact kill and reap by that child. A
            domain is temporary containment, never a resource's identity:
            children recorded with another domain are gone by the host's
            precondition for standalone cleanup (`foreign`), never touched
  Dir       a private state directory used through its descriptor: atomic
            records, locks, no link following
  spawn, run_tool, host_dirs, trusted_executable, copy_hashed, BoundedSink
  subreaper, settle_children  a provider process as the reaper of what its
            children detach: owned children collected by their own Popen,
            adopted ones reaped by exact pid

Errors are fixed codes (`Failure`), never file, frame or tool content.
"""
import errno
import fcntl
import hashlib
import json
import os
import re
import resource
import selectors
import signal
import stat
import subprocess
import time

import protocol

CGROUP_ROOT = "/sys/fs/cgroup"
CUSTODY_ENV = "AGENTBOX_CUSTODY"
CONTROLLERS = ("cpu", "memory", "pids")
MAX_RECORD_BYTES = 65536
MAX_PROC_CGROUP_BYTES = 4096
MAX_CGROUP_PATH_BYTES = 4096
MAX_CGROUP_NAME_BYTES = 255
CHUNK = 1 << 20
CLEAR_DEPTH = 256
SETTLE_POLL = 0.02
# Every tool gets this much of its operation's remaining time to be killed
# and reaped through its custody child.
KILL_RESERVE = 10.0
RENAME_NOREPLACE = 1
IMAGES_LOCK = "images.lock"
CACHE_RESIDUE = 4
CACHE_LEFTOVERS = (".staging-", ".quarantine-")


class Failure(Exception):
    """A `failed` answer: fixed code, settlement and durability."""

    def __init__(self, code, settlement="settled", durability="unchanged"):
        if code not in protocol.FAILURE_CODES or settlement not in protocol.SETTLEMENT \
                or durability not in protocol.DURABILITY:
            raise ValueError("failure")
        super().__init__(code)
        self.code, self.settlement, self.durability = code, settlement, durability


class Unsettled(Failure):
    """A custody child that could not be confirmed gone: its members may
    still run and write. Its record entry stays as a debt; nothing it can
    touch is removed until a later settlement of that exact child."""

    def __init__(self, durability="unchanged"):
        super().__init__("failed", "unsettled", durability)


class Interrupted(Exception):
    """The in-flight request must stop: `cancelled`, `timeout` or `lost`
    (EOF, a signal or a refused host frame: an unreported cancel)."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason

    @property
    def code(self):
        return "timeout" if self.reason == "timeout" else "cancelled"


def diagnostic(text):
    """One fixed line on stderr; never secrets, never frame or guest bytes."""
    try:
        os.write(2, f"agentbox-provider: {text}\n".encode("ascii", "replace")[:512])
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Control session.

class Session:
    """Control frames on `rfd`/`wfd`. A request (the invocation's first, or
    the owner's `stop`) becomes the in-flight operation as it is parsed, its
    deadline anchored at receipt, so a `cancel` read in the same chunk
    applies to it. Nothing ever extends a deadline."""

    def __init__(self, rfd=0, wfd=1, clock=time.monotonic):
        self.rfd, self.wfd, self.clock = rfd, wfd, clock
        self.buffer = b""
        self.eof = False
        self.signalled = False
        self.refused = None
        self.stops = []
        self.received = False
        self.waiting = False
        self.operation = None
        self.cancelled = False
        self.deadline = None
        self.wake_r, self.wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        os.set_blocking(rfd, False)

    def install_signals(self):
        """SIGTERM, SIGINT and SIGHUP end the session like EOF."""
        def handler(_signum, _frame):
            self.signalled = True
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, handler)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        signal.set_wakeup_fd(self.wake_w, warn_on_full_buffer=False)

    @property
    def lost(self):
        return self.eof or self.signalled or self.refused is not None

    def begin(self, operation, timeout_ms):
        """Makes `operation` in flight; for the one already accepted from
        the input it keeps its deadline and any queued cancel."""
        if operation == self.operation:
            return
        self.operation = operation
        self.cancelled = False
        self.deadline = self.clock() + timeout_ms / 1000.0

    def await_stop(self):
        """The owner answered `started`: nothing is in flight until `stop`."""
        self.operation = None
        self.cancelled = False
        self.deadline = None
        self.waiting = True

    def remaining(self):
        return max(0.0, self.deadline - self.clock()) if self.deadline is not None else None

    def cleanup_deadline(self):
        """The in-flight operation's one absolute cleanup bound: its
        anchored deadline plus KILL_RESERVE (with none in flight,
        KILL_RESERVE from now). Read once where cleanup begins; never
        renewed by a later step."""
        return (self.deadline if self.deadline is not None else self.clock()) + KILL_RESERVE

    def _lines(self):
        while True:
            index = self.buffer.find(b"\n")
            if index < 0:
                if len(self.buffer) > protocol.MAX_FRAME_BYTES:
                    self.refused = "frame_too_large"
                    self.buffer = b""
                return
            line, self.buffer = self.buffer[:index], self.buffer[index + 1:]
            yield line

    def pump(self):
        """Reads what is available; returns the invocation's request when
        it arrives. Later frames: `cancel` of the in-flight request (once),
        or a `stop` kept for the owner; anything else is refused, which ends
        the session like EOF."""
        first = None
        while not self.eof:
            try:
                data = os.read(self.rfd, 65536)
            except BlockingIOError:
                break
            except OSError:
                data = b""
            if not data:
                self.eof = True
                if self.buffer:
                    self.refused = "truncated_frame"
                break
            self.buffer += data
            for line in self._lines():
                try:
                    frame = protocol.decode_request(line)
                except protocol.ProtocolError as error:
                    self.refused = error.code
                    continue
                if not self.received and frame["type"] != "cancel":
                    self.received = True
                    self.begin(frame["operation"], frame["timeout_ms"])
                    first = frame
                elif frame["type"] == "cancel" and self.operation is not None \
                        and frame["operation"] == self.operation and not self.cancelled:
                    self.cancelled = True
                elif frame["type"] == "stop" and self.waiting:
                    self.waiting = False
                    self.begin(frame["operation"], frame["timeout_ms"])
                    self.stops.append(frame)
                else:
                    self.refused = "unexpected_frame"
        try:
            os.read(self.wake_r, 512)
        except OSError:
            pass
        return first

    def wait(self, fds=(), timeout=None):
        """Waits for input, a signal, or one of `fds`; returns the ready
        subset of `fds` after pumping the control input."""
        selector = selectors.DefaultSelector()
        try:
            if not self.eof:
                selector.register(self.rfd, selectors.EVENT_READ)
            selector.register(self.wake_r, selectors.EVENT_READ)
            for fd in fds:
                selector.register(fd, selectors.EVENT_READ)
            events = selector.select(timeout)
        finally:
            selector.close()
        self.pump()
        return [key.fd for key, _ in events if key.fd in fds]

    def first(self):
        """The invocation's one request; None at EOF or after a refusal."""
        while True:
            frame = self.pump()
            if frame is not None:
                return frame
            if self.lost:
                return None
            self.wait()

    def check(self):
        """Raises Interrupted when the in-flight request must stop."""
        self.pump()
        if self.lost:
            raise Interrupted("lost")
        if self.cancelled:
            raise Interrupted("cancelled")
        if self.deadline is not None and self.clock() >= self.deadline:
            raise Interrupted("timeout")

    def send(self, frame):
        if self.lost:
            return False
        data = protocol.encode(frame) + b"\n"
        try:
            while data:
                try:
                    data = data[os.write(self.wfd, data):]
                except BlockingIOError:
                    time.sleep(SETTLE_POLL)
        except OSError:
            self.eof = True
            return False
        return True


# ---------------------------------------------------------------------------
# Private state directories.

def _private(st, mode=None):
    return st.st_uid == os.geteuid() and (mode is None or stat.S_IMODE(st.st_mode) == mode)


class Dir:
    """A directory used only through its descriptor; entries are opened
    without following links."""

    def __init__(self, fd, path):
        self.fd, self.path = fd, path

    @classmethod
    def root(cls, path):
        """The provider's private state root: ours, mode 0700."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise Failure("prerequisite") from None
        st = os.fstat(fd)
        if not _private(st) or stat.S_IMODE(st.st_mode) & 0o077:
            os.close(fd)
            raise Failure("prerequisite")
        return cls(fd, path)

    def join(self, name):
        return self.path + "/" + name

    def sub(self, name, create=False, modes=(0o700,)):
        """A private subdirectory, made 0700 if `create` and absent."""
        if create:
            try:
                os.mkdir(name, 0o700, dir_fd=self.fd)
            except FileExistsError:
                pass
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return None
        st = os.fstat(fd)
        if not _private(st) or stat.S_IMODE(st.st_mode) not in modes:
            os.close(fd)
            raise Failure("failed", "unknown", "unchanged")
        return Dir(fd, self.join(name))

    def mkdir(self, name):
        """A new private subdirectory; False if the name exists."""
        try:
            os.mkdir(name, 0o700, dir_fd=self.fd)
        except FileExistsError:
            return False
        self.fsync()
        return True

    def exists(self, name):
        try:
            os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True

    def names(self, limit=4096):
        out = []
        with os.scandir(self.fd) as entries:
            for entry in entries:
                out.append(entry.name)
                if len(out) > limit:
                    raise Failure("failed", "unknown", "unchanged")
        return sorted(out)

    def open_file(self, name, flags=os.O_RDONLY, mode=None):
        """A regular single-link file of ours (exactly `mode` if given)."""
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.fd)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not _private(st, mode):
            os.close(fd)
            raise Failure("failed", "unknown", "unchanged")
        os.set_blocking(fd, True)
        return fd

    def create(self, name, mode=0o600):
        return os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                       dir_fd=self.fd)

    def read_json(self, name, limit=MAX_RECORD_BYTES):
        """A record, or None if absent; an unreadable one is refused."""
        try:
            fd = self.open_file(name)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(limit + 1)
        try:
            value = json.loads(data) if len(data) <= limit else None
        except ValueError:
            value = None
        if not isinstance(value, dict):
            raise Failure("failed", "unknown", "unchanged")
        return value

    def write_json(self, name, value, mode=0o600):
        """Replaces `name` atomically and durably."""
        data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if len(data) > MAX_RECORD_BYTES:
            raise ValueError("record")
        temp = "." + name + ".tmp"
        self.unlink(temp)
        fd = self.create(temp, mode)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp, name, src_dir_fd=self.fd, dst_dir_fd=self.fd)
        self.fsync()

    def unlink(self, name):
        try:
            os.unlink(name, dir_fd=self.fd)
        except FileNotFoundError:
            return False
        return True

    def rmdir(self, name):
        try:
            os.rmdir(name, dir_fd=self.fd)
        except FileNotFoundError:
            return False
        return True

    def rename(self, old, new):
        os.rename(old, new, src_dir_fd=self.fd, dst_dir_fd=self.fd)

    def fsync(self):
        os.fsync(self.fd)

    def lock(self, name, exclusive=True, block=False, deadline=None):
        """An flock on `name` (created 0600) or None if held elsewhere.
        The descriptor is close-on-exec: no child ever holds it."""
        try:
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
        except OSError:
            raise Failure("failed", "unknown", "unchanged") from None
        operation = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB
        while True:
            try:
                fcntl.flock(fd, operation)
                return fd
            except BlockingIOError:
                if not block or (deadline is not None and time.monotonic() >= deadline):
                    os.close(fd)
                    return None
                time.sleep(SETTLE_POLL)

    def held(self, name):
        """Whether another holds an flock on `name`; False if it is free or
        absent. A probe: never creates the file."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            return False
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True
        finally:
            os.close(fd)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def fingerprint(st):
    """A file's identity and last change, for 'unchanged since' checks."""
    return [st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_uid]


def copy_hashed(source, target, length, check):
    """Copies `length` bytes from fd `source` to fd `target` (zero blocks
    left sparse), calling `check` per chunk; returns the SHA-256 of the
    bytes read. A short or long source is refused."""
    digest = hashlib.sha256()
    os.lseek(source, 0, os.SEEK_SET)
    os.lseek(target, 0, os.SEEK_SET)
    remaining, zero = length, bytes(CHUNK)
    while remaining:
        check()
        data = os.read(source, min(CHUNK, remaining))
        if not data:
            raise Failure("failed")
        digest.update(data)
        if data == zero[:len(data)]:
            os.lseek(target, len(data), os.SEEK_CUR)
        else:
            view = memoryview(data)
            while view:
                view = view[os.write(target, view):]
        remaining -= len(data)
    if os.read(source, 1):
        raise Failure("failed")
    os.ftruncate(target, length)
    return digest.hexdigest()


def hash_fd(fd, check, length=None):
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    total = 0
    while True:
        check()
        data = os.read(fd, CHUNK)
        if not data:
            break
        total += len(data)
        digest.update(data)
    if length is not None and total != length:
        raise Failure("failed")
    return digest.hexdigest()


def read_prefix(fd, limit):
    os.lseek(fd, 0, os.SEEK_SET)
    out = b""
    while len(out) < limit:
        data = os.read(fd, limit - len(out))
        if not data:
            break
        out += data
    return out


# ---------------------------------------------------------------------------
# Trusted installed executables and operator-selected host files.

def _trusted_dir(st):
    """Root's, or ours; never writable by others unless root's and sticky;
    group-writable only for our own primary group."""
    if st.st_uid not in (0, os.geteuid()):
        return False
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o002 and not (st.st_uid == 0 and mode & stat.S_ISVTX):
        return False
    return not (mode & 0o020 and st.st_gid not in (0, os.getegid()))


def trusted_path(path, kind, root_only=False):
    """`path` resolved without links: every ancestor a trusted directory,
    the entry itself `kind` ('file', 'dir' or 'exec'), owned by root (or us
    unless `root_only`), not writable by others. Returns its lstat."""
    if not protocol.is_path(path):
        raise Failure("prerequisite")
    parts = path.strip("/").split("/")
    current = "/"
    for part in parts[:-1]:
        current = os.path.join(current, part)
        st = os.lstat(current)
        if not stat.S_ISDIR(st.st_mode) or not _trusted_dir(st) or (root_only and st.st_uid != 0):
            raise Failure("prerequisite")
    try:
        st = os.lstat(path)
    except OSError:
        raise Failure("prerequisite") from None
    owners = (0,) if root_only else (0, os.geteuid())
    mode = stat.S_IMODE(st.st_mode)
    ok = st.st_uid in owners and not mode & 0o002 \
        and not (mode & 0o020 and st.st_gid not in (0, os.getegid()))
    if kind == "dir":
        ok = ok and stat.S_ISDIR(st.st_mode)
    else:
        ok = ok and stat.S_ISREG(st.st_mode) and not mode & (stat.S_ISUID | stat.S_ISGID)
        if kind == "exec":
            ok = ok and mode & 0o111 and not mode & 0o022
    if not ok:
        raise Failure("prerequisite")
    return st


def host_dirs(environ):
    """The host PATH the host gave this invocation (tools.rs `host_path`):
    its absolute, normalized, shell-inert entries (`protocol.is_path`), in
    order; empty, relative, spaced, quoted and other entries are ignored,
    never the working directory. Empty when none remains: no fallback."""
    return [entry for entry in environ.get("PATH", "").split(":") if protocol.is_path(entry)]


def host_search(environ):
    """`host_dirs` rejoined, for a tool's own lookups (Packer, the engine);
    None when empty, never an empty PATH."""
    return ":".join(host_dirs(environ)) or None


def tool_env(environ):
    """The whole environment of a tool a provider runs itself: PATH the
    usable host one (`host_search`; none when empty), so a wrapper found
    there finds its own `#!/usr/bin/env` interpreter as it would for the
    user, and LC_ALL=C. Nothing else of the host's."""
    search = host_search(environ)
    return dict({} if search is None else {"PATH": search}, LC_ALL="C")


def trusted_executable(name, environ, fallback=()):
    """An installed program by name: the first executable regular file in
    `host_dirs(environ)`, then in the backend's explicit `fallback`
    directories, links followed; other entries are passed over, as execvp
    does (tools.rs `find_trusted`). Never cwd or a host/guest-supplied
    path. Its real path must be shell-inert; as root it must also pass
    `root_executable`."""
    for directory in host_dirs(environ) + list(fallback):
        path = os.path.realpath(directory + "/" + name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            continue
        if not protocol.is_path(path):
            raise Failure("prerequisite")
        if os.geteuid() == 0 and not root_executable(path):
            raise Failure("prerequisite")
        return path
    raise Failure("prerequisite")


def root_executable(path, lstat=os.lstat, capable=None):
    """Root's rule for a host tool (tools.rs `find_trusted` and `resolve`
    as root): real `path` an executable regular file, not set-id or
    file-capable, it and every directory above it to `/` root-owned and
    neither group nor world writable (no sticky or own-group exception:
    stricter than `trusted_path`, which stays the operator-file rule).
    `lstat` and `capable` are seams for tests."""
    capable = _file_capable if capable is None else capable
    try:
        st = lstat(path)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 \
                or st.st_mode & (stat.S_ISUID | stat.S_ISGID) or capable(path):
            return False
        current = path
        while True:
            st = lstat(current)
            if st.st_uid != 0 or stat.S_IMODE(st.st_mode) & 0o022:
                return False
            if current == "/":
                return True
            current = os.path.dirname(current)
            if not stat.S_ISDIR(lstat(current).st_mode):
                return False
    except OSError:
        return False


def _file_capable(path):
    try:
        os.getxattr(path, "security.capability", follow_symlinks=False)
    except OSError as error:
        return error.errno not in (errno.ENODATA, errno.ENOTSUP)
    return True


# ---------------------------------------------------------------------------
# Custody.

def is_cgroup_path(path, root=CGROUP_ROOT):
    """A normalized kernel cgroup v2 directory path strictly under `root`:
    `/`-separated names of printable non-space ASCII (systemd's `@`, `\\`,
    `:` included), none empty, `.` or `..`, each at most
    MAX_CGROUP_NAME_BYTES, the whole at most MAX_CGROUP_PATH_BYTES. Not the
    shell-inert contract path grammar (`protocol.is_path`): a cgroup path is
    host-selected, travels only in the fixed environment or a kernel file,
    and never reaches argv, a shell or a control frame."""
    if not isinstance(path, str) or len(path.encode()) > MAX_CGROUP_PATH_BYTES:
        return False
    prefix = root + "/"
    if not path.startswith(prefix):
        return False
    names = path[len(prefix):].split("/")
    return all(0 < len(name.encode()) <= MAX_CGROUP_NAME_BYTES and name not in (".", "..")
               and all("!" <= c <= "~" for c in name) for name in names)


class Custody:
    """The custody domain D this invocation was started in. The host's
    generic supervisor creates and holds D (a cgroup v2 directory delegated
    to this user, `cpu memory pids` enabled in its cgroup.subtree_control,
    no processes of its own) and starts every invocation for D's instance or
    resource directly in a fresh leaf beneath it, naming D in
    AGENTBOX_CUSTODY. A provider creates further children of D for what it
    starts; every process joins its child before it runs (`spawn`)."""

    def __init__(self, path, fd):
        self.path, self.fd = path, fd
        st = os.fstat(fd)
        self.identity = [st.st_dev, st.st_ino]

    def same(self, record):
        """Whether `record` ({path, identity}) names this very domain."""
        return isinstance(record, dict) and record.get("path") == self.path \
            and record.get("identity") == self.identity

    def record(self):
        return {"path": self.path, "identity": self.identity}

    @classmethod
    def from_environment(cls, environ, proc_cgroup="/proc/self/cgroup", root=CGROUP_ROOT):
        path = environ.get(CUSTODY_ENV)
        if not is_cgroup_path(path, root):
            raise Failure("prerequisite")
        try:
            with open(proc_cgroup, "rb") as stream:
                text = stream.read(MAX_PROC_CGROUP_BYTES + 1).decode("ascii")
        except (OSError, UnicodeDecodeError):
            raise Failure("prerequisite") from None
        lines = text.split("\n")
        if len(text) > MAX_PROC_CGROUP_BYTES or lines[-1] != "" or len(lines) != 2 \
                or not lines[0].startswith("0::/"):
            raise Failure("prerequisite")
        own = root + lines[0][3:]
        if not is_cgroup_path(own, root) or os.path.dirname(own) != path:
            raise Failure("prerequisite")
        try:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise Failure("prerequisite") from None
        custody = cls(path, fd)
        try:
            custody._verify(os.path.basename(own))
        except (Failure, OSError, ValueError):
            custody.close()
            raise Failure("prerequisite") from None
        return custody

    def _read(self, name, dir_fd=None):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd if dir_fd is None else dir_fd)
        try:
            return os.read(fd, 4096).decode("ascii")
        finally:
            os.close(fd)

    def _write(self, name, text, dir_fd):
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        try:
            os.write(fd, text.encode())
        finally:
            os.close(fd)

    def _verify(self, leaf):
        st = os.fstat(self.fd)
        if not _private(st):
            raise Failure("prerequisite")
        for name in ("cgroup.procs", "cgroup.subtree_control", "cgroup.kill"):
            if not _private(os.stat(name, dir_fd=self.fd, follow_symlinks=False)):
                raise Failure("prerequisite")
        if not set(CONTROLLERS) <= set(self._read("cgroup.subtree_control").split()):
            raise Failure("prerequisite")
        if self._read("cgroup.procs").strip():
            raise Failure("prerequisite")
        if not _private(os.stat(leaf, dir_fd=self.fd, follow_symlinks=False)):
            raise Failure("prerequisite")

    def _make(self, name):
        os.mkdir(name, 0o755, dir_fd=self.fd)

    def child(self, name, limits=None):
        """A new child of D, its `limits` ({file: value}) written and read
        back. Refuses an existing name."""
        try:
            self._make(name)
        except FileExistsError:
            raise Failure("busy", "unsettled", "unchanged") from None
        child = self.existing(name)
        try:
            for key, value in (limits or {}).items():
                self._write(key, value, child.fd)
                if self._read(key, child.fd).strip() != value:
                    raise Failure("prerequisite")
        except (Failure, OSError):
            # Nothing joined it yet: remove it, or leave it to its record.
            if not child.settle(time.monotonic() + KILL_RESERVE):
                raise Unsettled() from None
            raise Failure("prerequisite") from None
        return child

    def existing(self, name, identity=None):
        """The child `name` of this domain, pinned by descriptor; None only
        when the name is positively absent. With `identity` (recorded at
        creation) a different directory under that name is refused: the
        original's fate is then unknown. Any other observation error
        propagates as OSError."""
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        except FileNotFoundError:
            if identity is not None:
                self._not_renamed(identity)
            return None
        child = Child(self, name, fd)
        if not _private(os.fstat(fd)) or (identity is not None and child.identity != identity):
            child.close()
            raise Unsettled("uncertain")
        return child

    def _not_renamed(self, identity):
        """A cgroup can only be renamed within its parent: the original is
        gone only if no entry of D is still that directory."""
        with os.scandir(self.fd) as entries:
            for entry in entries:
                st = os.stat(entry.name, dir_fd=self.fd, follow_symlinks=False)
                if [st.st_dev, st.st_ino] == identity:
                    raise Unsettled("uncertain")

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    # Kernel effects of a child; tests replace these.

    def kill(self, child):
        self._write("cgroup.kill", "1", child.fd)

    def populated(self, child):
        for line in self._read("cgroup.events", child.fd).splitlines():
            key, _, value = line.partition(" ")
            if key == "populated":
                return value != "0"
        raise Failure("failed", "unknown", "unchanged")

    def remove(self, child):
        os.rmdir(child.name, dir_fd=self.fd)


class Child:
    """One custody child: what joins it, how it is killed and removed."""

    def __init__(self, custody, name, fd):
        self.custody, self.name, self.fd = custody, name, fd
        st = os.fstat(fd)
        self.identity = [st.st_dev, st.st_ino]

    @property
    def path(self):
        return self.custody.path + "/" + self.name

    def join_fd(self):
        return os.open("cgroup.procs", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)

    def kill(self):
        self.custody.kill(self)

    def populated(self):
        return self.custody.populated(self)

    def removed(self):
        """Positive evidence that this pinned directory itself was removed:
        its control files are gone beneath its own descriptor."""
        for name in ("cgroup.procs", "cgroup.events"):
            try:
                os.stat(name, dir_fd=self.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            except OSError:
                return False
            return False
        return True

    def settle(self, deadline):
        """Kills every member through the pinned directory, waits until it
        reads empty, then removes it by name only while the name is still
        this directory. True only on that removal or on positive evidence
        that this very directory was removed; any denied, failed or
        ambiguous observation is False."""
        try:
            self.kill()
            while self.populated():
                if time.monotonic() >= deadline:
                    return False
                time.sleep(SETTLE_POLL)
        except FileNotFoundError:
            return self.removed()
        except (OSError, Failure):
            return False
        try:
            st = os.stat(self.name, dir_fd=self.custody.fd, follow_symlinks=False)
        except FileNotFoundError:
            return self.removed()
        except OSError:
            return False
        if [st.st_dev, st.st_ino] != self.identity:
            return False
        try:
            self.custody.remove(self)
        except OSError:
            return False
        self.close()
        return True

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


# ---------------------------------------------------------------------------
# Processes.

class Process:
    """A started child: its Popen and pidfd (exact, never a PID guess).
    Construction never raises: a refused pidfd leaves `pidfd` -1 and the
    caller must settle the child it already has (`admitted` False).

    Every Process is `owned` until its own Popen has its status (Popen's
    `returncode`, set only by Popen's wait on that very pid): an unreaped
    child's pid cannot be reused, so `settle_children` collects one only
    through that Popen, never by pid (Popen would read a status taken from
    it as exit 0). Held strongly, a dropped
    unreaped Process is never handed to subprocess's own collector; it
    stays owned until reaped or this process exits. A forked copy of this
    process (a test fixture) clears `owned` first."""

    owned = []

    def __init__(self, popen, child):
        self.popen, self.child = popen, child
        self.status = None
        Process.owned.append(self)
        try:
            self.pidfd = os.pidfd_open(popen.pid)
        except OSError:
            self.pidfd = -1

    @property
    def admitted(self):
        return self.pidfd >= 0

    def poll(self):
        if self.status is None:
            try:
                self.status = self.popen.poll()
            except OSError:
                return None
        return self.status

    def reap(self, deadline):
        while self.poll() is None:
            if time.monotonic() >= deadline:
                return None
            time.sleep(SETTLE_POLL)
        return self.status

    def close(self):
        if self.pidfd >= 0:
            os.close(self.pidfd)
            self.pidfd = -1
        for stream in (self.popen.stdout, self.popen.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37


def subreaper():
    """Makes this process a child subreaper, read back: whatever a
    descendant detaches (double fork, setsid) is orphaned to it, never past
    it. Not inherited by children. Refused: `failed` `prerequisite`."""
    import ctypes
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        flag = ctypes.c_int(0)
        if libc.prctl(PR_SET_CHILD_SUBREAPER, ctypes.c_ulong(1), ctypes.c_ulong(0), ctypes.c_ulong(0),
                      ctypes.c_ulong(0)) != 0 \
                or libc.prctl(PR_GET_CHILD_SUBREAPER, ctypes.byref(flag), ctypes.c_ulong(0), ctypes.c_ulong(0),
                              ctypes.c_ulong(0)) != 0 \
                or flag.value != 1:
            raise Failure("prerequisite")
    except (OSError, AttributeError):
        raise Failure("prerequisite") from None


def children():
    """This process's children, from its one task's `children` list; None
    when unreadable, malformed or when a second thread exists (it could be
    another waiter)."""
    try:
        tasks = os.listdir("/proc/self/task")
        if len(tasks) != 1:
            return None
        with open(f"/proc/self/task/{tasks[0]}/children", "rb") as stream:
            text = stream.read(1 << 20)
        return [int(word) for word in text.split()]
    except (OSError, ValueError):
        return None


def _owned():
    """Every Process whose Popen has no status yet (the others dropped)."""
    Process.owned[:] = [p for p in Process.owned if p.popen.returncode is None]
    return list(Process.owned)


def settle_children(deadline, kill=False):
    """A subreaper's children, every one, until one complete inventory
    finds none: True only then. Each pass collects every owned `Process`
    through its own Popen (its wait on that very pid, so its status,
    nonzero included, stays its own; never signalled here) and reaps every
    other child, one it adopted, by exact pid (`waitid`); after any reap a
    fresh inventory, since a reaped child's own orphans arrive here. Live
    ones are waited for through pidfds opened while they are still
    unreaped children (their pids cannot be reused); with `kill` an
    adopted one first gets `SIGKILL` through its pidfd. An empty custody
    child is no evidence of this. False at `deadline` with one still live
    or owned, or on any unreadable inventory or failed wait: unconfirmed,
    left to the caller's parent and the host's custody. Never raises."""
    while True:
        pids = children()
        if pids is None:
            return False
        owned, live, adopted, reaped = _owned(), [], [], False
        for process in owned:
            if process.poll() is None:
                live.append(process.popen.pid)
            else:
                reaped = True
        mine = {process.popen.pid for process in owned}
        for pid in pids:
            if pid in mine:
                continue
            try:
                if os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG) is None:
                    adopted.append(pid)
                else:
                    reaped = True
            except OSError:
                return False
        if reaped:
            continue
        if not live and not adopted:
            return True
        if time.monotonic() >= deadline:
            return False
        fds, selector = [], None
        try:
            selector = selectors.DefaultSelector()
            for pid in live + adopted:
                fds.append(os.pidfd_open(pid))
                if kill and pid in adopted:
                    try:
                        signal.pidfd_send_signal(fds[-1], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                selector.register(fds[-1], selectors.EVENT_READ)
            selector.select(max(0.0, deadline - time.monotonic()))
        except OSError:
            return False
        finally:
            if selector is not None:
                selector.close()
            for fd in fds:
                os.close(fd)


def spawn(argv, env, child, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, pass_fds=(),
          rlimits=(), ignore_xfsz=False, cwd=None, stdin=subprocess.DEVNULL):
    """Starts `argv` with exactly `env`, `stdin` (/dev/null unless given)
    and no inherited descriptor but `pass_fds`. Between fork and exec the
    child joins `child` (its own pid into cgroup.procs), then takes
    `rlimits`; the program never runs outside its custody child or above
    its limits."""
    join = child.join_fd()

    def enter():
        os.write(join, b"%d\n" % os.getpid())
        for which, value in rlimits:
            resource.setrlimit(which, (value, value))
        if ignore_xfsz:
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)

    try:
        popen = subprocess.Popen(argv, env=env, stdin=stdin, stdout=stdout, stderr=stderr,
                                 pass_fds=tuple(pass_fds), close_fds=True, preexec_fn=enter, cwd=cwd)
    except (OSError, subprocess.SubprocessError):
        # Nothing started; the caller still settles `child` itself.
        raise Failure("prerequisite") from None
    finally:
        os.close(join)
    return Process(popen, child)


class BoundedSink:
    """Keeps at most `limit` bytes in a private file; counts the rest."""

    def __init__(self, directory, name, limit):
        self.fd = directory.create(name, 0o600) if directory is not None else -1
        self.limit, self.kept, self.dropped = limit, 0, 0

    def write(self, data):
        room = max(0, self.limit - self.kept)
        if room and self.fd >= 0:
            os.write(self.fd, data[:room])
        self.kept += min(room, len(data))
        self.dropped += max(0, len(data) - room)

    def close(self):
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1


def drain(fd, sink):
    """Reads what a non-blocking pipe holds; False at its end."""
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return True
        if not data:
            return False
        sink.write(data)


class Collect:
    def __init__(self, limit):
        self.data, self.limit, self.over = b"", limit, False

    def write(self, data):
        room = self.limit - len(self.data)
        self.data += data[:max(0, room)]
        self.over = self.over or len(data) > room


class Ledger:
    """Tool children in memory only (prepare's scratch has no handle):
    `outstanding` names every child not confirmed gone."""

    def __init__(self):
        self.outstanding = []

    def add(self, name):
        self.outstanding.append(name)

    def bind(self, name, identity):
        pass

    def drop(self, name):
        self.outstanding.remove(name)


class RecordLedger(Ledger):
    """The tool children of one handle's record (e.g. resource.json or
    instance.json): each written into the record, with this domain, before
    it exists, its identity once it does, removed once it is gone."""

    def __init__(self, directory, name, record, custody):
        self.directory, self.name, self.record, self.custody = directory, name, record, custody

    def save(self):
        self.directory.write_json(self.name, self.record)

    def add(self, child):
        tools = self.record.setdefault("tools", [])
        if tools and not self.custody.same(self.record.get("custody")):
            raise Unsettled("uncertain")
        self.record["custody"] = self.custody.record()
        tools.append({"name": child, "identity": None})
        self.save()

    def bind(self, child, identity):
        for entry in self.record["tools"]:
            if entry["name"] == child:
                entry["identity"] = identity
        self.save()

    def drop(self, child):
        self.record["tools"] = [e for e in self.record["tools"] if e["name"] != child]
        self.save()


def foreign(record, custody):
    """Whether `record`'s children were recorded with another domain than
    this invocation's. The host invokes a standalone lifecycle operation in
    a fresh domain only after it has itself killed and reaped every process
    of the earlier one (contract Custody): those children are then gone by
    that precondition. Nothing of them is signalled, removed or observed;
    the recorded names and identities are only dropped."""
    return not custody.same(record.get("custody"))


def settle_debts(record, custody):
    """Settles the record's tool children left unconfirmed (by name and
    recorded identity, in the very domain recorded with them; from another
    domain by the host's precondition, `foreign`). True when none is left;
    the caller saves the record."""
    tools = record.get("tools") or []
    if not tools:
        return True
    if foreign(record, custody):
        record["tools"] = []
        return True
    deadline = time.monotonic() + KILL_RESERVE
    for entry in list(tools):
        try:
            child = custody.existing(entry["name"], entry["identity"])
        except (Unsettled, OSError):
            return False
        if child is not None and not child.settle(deadline):
            child.close()
            return False
        tools.remove(entry)
    return True


class Budget:
    """A removal's bound: at most `entries` unlinks before `deadline`."""

    def __init__(self, entries, deadline):
        self.entries, self.deadline = entries, deadline

    def take(self):
        if self.entries <= 0 or time.monotonic() >= self.deadline:
            return False
        self.entries -= 1
        return True


def clear_tree(fd, dev, budget):
    """Unlinks everything beneath the directory `fd`, depth first, never
    following a link, leaving its device or changing a mode or owner; each
    opened directory the very entry it was opened as. True when empty;
    False when the budget ended or anything refused (unwritable or foreign
    contents stay, unconfirmed)."""
    try:
        return _clear(fd, dev, budget, 0)
    except OSError:
        return False


def _clear(fd, dev, budget, depth):
    if depth > CLEAR_DEPTH:
        return False
    while True:
        with os.scandir(fd) as entries:
            names = [entry.name for _, entry in zip(range(32), entries)]
        if not names:
            return True
        for name in names:
            if not budget.take():
                return False
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if st.st_dev != dev:
                return False
            if stat.S_ISDIR(st.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    if [opened.st_dev, opened.st_ino] != [st.st_dev, st.st_ino] \
                            or not _clear(child, dev, budget, depth + 1):
                        return False
                finally:
                    os.close(child)
                os.rmdir(name, dir_fd=fd)
            else:
                os.unlink(name, dir_fd=fd)


def named(parent, name, fd):
    """Whether `name` in `parent` is still the directory held by `fd`."""
    try:
        st, held = os.stat(name, dir_fd=parent.fd, follow_symlinks=False), os.fstat(fd)
    except OSError:
        return False
    return [st.st_dev, st.st_ino] == [held.st_dev, held.st_ino]


def remove_scratch(parent, name, fd):
    """Best-effort removal of a provider-made disposable directory (scratch,
    logs, staging) held by `fd`, once nothing can write it: walked only
    while `name` in `parent` is still that very directory (no link
    followed, no mode changed), then removed by name. True when it is gone,
    or when the held original is already empty (moved or removed
    elsewhere: housekeeping); False leaves whatever is there for a fixed
    warning: a changed, foreign or unwritable path is never deleted."""
    try:
        held = os.fstat(fd)
        if not named(parent, name, fd):
            return not os.listdir(fd)
        if not clear_tree(fd, held.st_dev, Budget(1 << 20, time.monotonic() + 60)) \
                or not named(parent, name, fd):
            return False
        os.rmdir(name, dir_fd=parent.fd)
        parent.fsync()
    except OSError:
        return False
    return True


def warning(text):
    """A fixed best-effort cleanup warning on stderr (never a path, frame
    or tool byte): disposable residue left, nothing settlement depends on."""
    diagnostic("warning: " + text)


class MemoryLedger(RecordLedger):
    """RecordLedger for an operation without a handle to recover by (a
    prepare): its tool children in `record`, nothing written. An
    unconfirmed one keeps the operation's scratch and its answer
    `unsettled`; the host's custody domain is the guard."""

    def __init__(self, record, custody):
        super().__init__(None, None, record, custody)

    def save(self):
        pass

    @property
    def outstanding(self):
        return [entry["name"] for entry in self.record.get("tools", [])] + \
            ([self.record["engine"]] if self.record.get("engine") else [])


def admit_space(directory, min_free, max_entries, prefixes=None):
    """Capacity admission before more disposable state is made under
    `directory`: at least `min_free` bytes free on its filesystem and at
    most `max_entries` entries (live plus leftover residue; with
    `prefixes` only names starting with one). Not a quota; a refusal is
    `prerequisite` with a fixed warning."""
    try:
        vfs = os.fstatvfs(directory.fd)
        with os.scandir(directory.fd) as entries:
            found = (e for e in entries if prefixes is None or e.name.startswith(prefixes))
            count = sum(1 for _ in zip(range(max_entries + 1), found))
    except OSError:
        raise Failure("prerequisite") from None
    if vfs.f_bavail * vfs.f_frsize < min_free or count > max_entries:
        warning("capacity admission refused (free space or residue)")
        raise Failure("prerequisite")


# ---------------------------------------------------------------------------
# Declared storage scopes (the host's run-limits.json `storage_scopes`).

SCOPES_ENV = "AGENTBOX_STORAGE_SCOPES"
MAX_U64 = 2 ** 64 - 1
MAX_SCOPES_FILE = 16 * 1024
MAX_SCOPES = 16
MAX_UNCAPPED = 16
MAX_PREFIX_BYTES = 1024
MEASURES = ("tree", "filesystem")


def _relative(outer, inner):
    """`inner` below or equal to `outer`, component-wise: the rest, else None."""
    if inner == outer:
        return ""
    if inner.startswith(outer + "/"):
        return inner[len(outer) + 1:]
    return None


def valid_scopes(scopes):
    """The host's rule (Rust run/scopes.rs `valid`), exactly: bounded,
    plain, distinct paths; uncapped prefixes plain, distinct, trees only;
    nested trees strict on both sides of their overlap."""
    if not isinstance(scopes, list) or len(scopes) > MAX_SCOPES:
        return False
    paths = set()
    for scope in scopes:
        if not isinstance(scope, dict) or not set(scope) <= {"path", "measure", "uncapped"} \
                or not {"path", "measure"} <= set(scope):
            return False
        uncapped = scope.get("uncapped", [])
        if not protocol.is_path(scope["path"]) or scope["measure"] not in MEASURES \
                or not isinstance(uncapped, list) or len(uncapped) > MAX_UNCAPPED \
                or not all(isinstance(p, str) and len(p.encode()) <= MAX_PREFIX_BYTES
                           and protocol.is_path("/" + p) for p in uncapped) \
                or len(set(uncapped)) != len(uncapped) \
                or (scope["measure"] != "tree" and uncapped) or scope["path"] in paths:
            return False
        paths.add(scope["path"])
    trees = [s for s in scopes if s["measure"] == "tree"]
    for outer in trees:
        for inner in trees:
            if outer is inner:
                continue
            rest = _relative(outer["path"], inner["path"])
            if rest is None:
                continue
            touches = any(_relative(p, rest) is not None or _relative(rest, p) is not None
                          for p in outer.get("uncapped", []))
            if touches or inner.get("uncapped"):
                return False
    return True


def _unique_keys(pairs):
    if len({key for key, _ in pairs}) != len(pairs):
        raise ValueError("duplicate key")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(name)


def _integer(text):
    # The host reads `-0` as a float.
    if text == "-0":
        raise ValueError(text)
    return int(text)


def parse_limits(data):
    """`run-limits.json` bytes: its declared scopes; anything else refuses.
    As the host parses them (Rust run.rs `parse_store_limits`): strict UTF-8
    (no BOM, no UTF-16), no duplicate key, no NaN or Infinity, no lone
    surrogate, the threshold a JSON integer (not a bool, float or `-0`)
    within u64."""
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_keys,
                           parse_constant=_no_constant, parse_int=_integer)
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except (ValueError, RecursionError):
        raise Failure("prerequisite") from None
    if not isinstance(value, dict) or not set(value) <= {"max_reserved_bytes", "storage_scopes"} \
            or not isinstance(value.get("max_reserved_bytes"), int) \
            or isinstance(value["max_reserved_bytes"], bool) \
            or not 0 <= value["max_reserved_bytes"] <= MAX_U64:
        raise Failure("prerequisite")
    scopes = value.get("storage_scopes", [])
    if not valid_scopes(scopes):
        raise Failure("prerequisite")
    return scopes


def legacy_store_roots(environ):
    """The old CLI's default store roots in the host environment it hands
    every provider: `XDG_DATA_HOME/agentbox` (an absolute plain path),
    `HOME/.local/share/agentbox`. Mount sources keep out of them whatever
    store asked (the controller's own check is this function too)."""
    roots = []
    xdg = environ.get("XDG_DATA_HOME")
    if xdg and protocol.is_path(xdg):
        roots.append(xdg + "/agentbox")
    home = environ.get("HOME")
    if home and protocol.is_path(home):
        roots.append(home + "/.local/share/agentbox")
    return roots


def storage_scopes(environ, required=False):
    """The operator's declared storage scopes, read from the one host limits
    file the host names in SCOPES_ENV (never cwd, PATH or another source):
    every ancestor a trusted directory opened without following links, the
    file ours, 0600, single-link, regular and bounded. Absent, nothing is
    declared; with `required` (a mount's protected set) an absent file
    refuses (`prerequisite`), judged by the open itself. Storage
    configuration only, never authority or attestation."""
    path = environ.get(SCOPES_ENV)
    if not isinstance(path, str) or not protocol.is_path(path):
        raise Failure("prerequisite")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.strip("/").split("/")[:-1]:
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except OSError:
                raise Failure("prerequisite") from None
            os.close(fd)
            fd = nfd
            if not _trusted_dir(os.fstat(fd)):
                raise Failure("prerequisite")
        try:
            ffd = os.open(os.path.basename(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                          dir_fd=fd)
        except FileNotFoundError:
            if required:
                raise Failure("prerequisite") from None
            return []
        except OSError:
            raise Failure("prerequisite") from None
    finally:
        os.close(fd)
    try:
        st = os.fstat(ffd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or not _private(st, 0o600) \
                or st.st_size > MAX_SCOPES_FILE:
            raise Failure("prerequisite")
        data = read_prefix(ffd, MAX_SCOPES_FILE + 1)
    finally:
        os.close(ffd)
    if len(data) > MAX_SCOPES_FILE:
        raise Failure("prerequisite")
    return parse_limits(data)


def _open_scope(path):
    """A declared scope's root, opened from / without following links; None
    if it cannot be."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.strip("/").split("/"):
            nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = nfd
    except OSError:
        os.close(fd)
        return None
    return fd


def covered(scopes, real, st):
    """The opened directory at `real` (its resolved path, `st` its fstat)
    within a declared scope by actual filesystem membership, as the host
    measures it (Rust run/scopes.rs `covers`): under a filesystem scope and
    on its device; or under a tree with every directory from the tree's
    root down to it on the root's device or a measured filesystem's, the
    last the very directory opened."""
    def root_dev(scope):
        fd = _open_scope(scope["path"])
        if fd is None:
            return None
        try:
            return os.fstat(fd).st_dev
        finally:
            os.close(fd)
    measured = {root_dev(scope) for scope in scopes if scope["measure"] == "filesystem"} - {None}
    for scope in scopes:
        rest = _relative(scope["path"], real)
        if rest is None:
            continue
        fd = _open_scope(scope["path"])
        if fd is None:
            continue
        try:
            dev = os.fstat(fd).st_dev
            allowed = {dev} if scope["measure"] == "filesystem" else measured | {dev}
            for part in rest.split("/") if rest else ():
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = nfd
                if os.fstat(fd).st_dev not in allowed:
                    break
            else:
                last = os.fstat(fd)
                if (last.st_dev, last.st_ino) == (st.st_dev, st.st_ino):
                    return True
        except OSError:
            pass
        finally:
            os.close(fd)
    return False


def require_scopes(environ, *dirs):
    """Before any NEW allocation: every opened directory a new entry is made
    in (the provider's STATE, its work, resources, checkpoints or instances
    directory, an external store root) lies in a declared scope by actual
    filesystem membership (`covered`); else `prerequisite` with a fixed
    warning. Never asked for disposal: stop, discard and recovery use
    recorded locations whatever is declared now."""
    scopes = storage_scopes(environ)
    for directory in dirs:
        try:
            real = os.readlink(f"/proc/self/fd/{directory.fd}")
            st = os.fstat(directory.fd)
        except OSError:
            raise Failure("prerequisite") from None
        if not covered(scopes, real, st):
            warning("storage scope undeclared: new allocation refused")
            raise Failure("prerequisite")


def allocation_dirs(environ, *pairs):
    """Each (`parent`, `name`)'s private subdirectory to allocate in, every
    `parent` already checked (require_scopes): all existing ones are checked
    first, and only then are the absent ones made in their parents."""
    found = []
    try:
        for parent, name in pairs:
            found.append(parent.sub(name))
        require_scopes(environ, *(d for d in found if d is not None))
        for index, (parent, name) in enumerate(pairs):
            if found[index] is None:
                found[index] = parent.sub(name, create=True)
    except BaseException:
        for directory in found:
            if directory is not None:
                directory.close()
        raise
    return found


_renameat2 = None


def rename_noreplace(directory, old, new):
    """renameat2(RENAME_NOREPLACE) within `directory`: never replaces
    `new`, not even an empty directory (EEXIST)."""
    global _renameat2
    import ctypes  # lazily: its import keeps a descriptor open
    if _renameat2 is None:
        try:
            _renameat2 = ctypes.CDLL(None, use_errno=True).renameat2
        except (OSError, AttributeError):
            raise Failure("prerequisite") from None
        _renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    if _renameat2(directory.fd, os.fsencode(old), directory.fd, os.fsencode(new), RENAME_NOREPLACE) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def remove_entry(parent, name, fd, expected, allowed):
    """Removes the provider-made directory `name` of `parent`, held by
    `fd` and recorded as `expected` ([dev, ino]), holding only `allowed`
    names: True only when that very directory is detached (its own fstat:
    same identity, nlink 0). Anything else (replaced, renamed, foreign
    entries, an error) is False and leaves the rest as it is."""
    try:
        st = os.fstat(fd)
        if [st.st_dev, st.st_ino] != expected or not named(parent, name, fd):
            return False
        os.fchmod(fd, 0o700)
        for entry in os.listdir(fd):
            if entry not in allowed:
                return False
            os.unlink(entry, dir_fd=fd)
        st = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
        if [st.st_dev, st.st_ino] != expected:
            return False
        os.rmdir(name, dir_fd=parent.fd)
        st = os.fstat(fd)
    except OSError:
        return False
    return [st.st_dev, st.st_ino] == expected and st.st_nlink == 0


def publish_entry(images, operation, image, fill, verify, allowed, claim):
    """Publishes an immutable cache entry: a fresh staging directory
    `.staging-OP` (pinned), `fill(entry)` (only this invocation writes
    it), 0500, then one no-replace rename to `image` and a cheap fsync of
    `images` (no crash promise). An existing `image` must pass `verify()`.
    One that fails is moved aside to `.quarantine-OP` only while
    `claim(image)` holds (a lock fd: no provider record may use it; a
    base in use is never touched or rebound), then the new entry is
    published; else the answer fails clearly. Staging or quarantine not
    removable as ours (`allowed` names only) is left with a fixed warning.
    Returns "published" or "cached"."""
    staging = ".staging-" + operation
    if not images.mkdir(staging):
        raise Failure("failed")
    entry = images.sub(staging)
    st = os.fstat(entry.fd)
    pinned = [st.st_dev, st.st_ino]
    outcome = None
    try:
        try:
            fill(entry)
            entry.fsync()
            os.fchmod(entry.fd, 0o500)
        except OSError:
            raise Failure("failed") from None
        if not _publish(images, staging, image):
            moved = _quarantine(images, image, ".quarantine-" + operation, verify, allowed, claim)
            if moved is None:
                return "cached"
            if not moved:
                warning("cache entry invalid: left untouched")
                raise Failure("failed")
            if not _publish(images, staging, image):
                verify()  # another invocation's entry won the name
                return "cached"
        outcome = "published"
        try:
            images.fsync()
        except OSError:
            warning("cache fsync failed")
        return outcome
    finally:
        if outcome is None and not remove_entry(images, staging, entry.fd, pinned, allowed):
            warning("cache staging residue left")
        entry.close()


def admit_cache(root):
    """The image cache's leftover staging and quarantine entries bounded
    before a build (admit_space, names counted, space checked by work)."""
    images = root.sub("images", create=True)
    try:
        admit_space(images, 0, CACHE_RESIDUE, CACHE_LEFTOVERS)
    finally:
        images.close()


def images_lock(root, exclusive):
    """STATE/images.lock: shared by a create from its image check to its
    record, exclusive while an invalid entry is moved aside. Shared waits
    briefly (`busy` after); exclusive never waits (None)."""
    if exclusive:
        return root.lock(IMAGES_LOCK)
    lock = root.lock(IMAGES_LOCK, exclusive=False, block=True, deadline=time.monotonic() + KILL_RESERVE)
    if lock is None:
        raise Failure("busy")
    return lock


def claim_unused(root, image, kinds):
    """images.lock held exclusively while no provider record of `kinds`
    ((directory, record name) pairs under `root`) uses `image`; else None."""
    lock = images_lock(root, exclusive=True)
    if lock is None:
        return None
    for directory, record in kinds:
        try:
            parent = root.sub(directory)
        except Failure:
            free = False
        else:
            free = unreferenced(parent, record, image)
            if parent is not None:
                parent.close()
        if not free:
            os.close(lock)
            return None
    return lock


_IMAGE = re.compile(r"[0-9a-f]{64}\Z")


def unreferenced(parent, record, image):
    """Whether no handle directory in `parent` (None: none exist) has a
    `record` that may use `image`: every record not `discarded` must name
    another valid image digest. Provider records only, never guest or
    user data; a missing, unreadable or malformed record is a possible
    use (False)."""
    if parent is None:
        return True
    try:
        for name in parent.names():
            entry = parent.sub(name, modes=(0o700, 0o500))
            if entry is None:
                continue
            try:
                value = entry.read_json(record)
            finally:
                entry.close()
            if value is not None and value.get("state") == "discarded":
                continue
            other = value.get("image") if value is not None else None
            if not isinstance(other, str) or not _IMAGE.match(other) or other == image:
                return False
    except (Failure, OSError):
        return False
    return True


def _publish(images, staging, image):
    """True when `staging` became `image`; False when `image` exists."""
    try:
        rename_noreplace(images, staging, image)
        return True
    except OSError as caught:
        if caught.errno not in (errno.EEXIST, errno.ENOTEMPTY):
            raise Failure("failed") from None
        return False


def _valid(verify):
    try:
        verify()
        return True
    except Failure as error:
        if isinstance(error, Unsettled):
            raise
        return False


def _quarantine(images, image, quarantine, verify, allowed, claim):
    """The existing entry `image`, pinned first: None when it verifies.
    An invalid one is moved aside only under `claim` and while the name is
    still the pinned directory (so the one verified: a replaced entry
    never returns under its name), by a no-replace rename; its removal is
    best effort. True when the name is free, False leaves it untouched."""
    try:
        fd = os.open(image, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=images.fd)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    lock = None
    try:
        st = os.fstat(fd)
        pinned = [st.st_dev, st.st_ino]
        if _valid(verify):
            return None
        if st.st_uid != os.geteuid():
            return False
        lock = claim(image)
        if lock is None or not named(images, image, fd):
            return False
        try:
            rename_noreplace(images, image, quarantine)
        except OSError:
            return False
        if not (named(images, quarantine, fd) and remove_entry(images, quarantine, fd, pinned, allowed)):
            warning("cache quarantine residue left")
        return True
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def _settled(child, process, deadline):
    """Kills and removes `child`, then reaps `process`: True only when both
    are confirmed. Never raises; output is not part of the answer."""
    try:
        settled = child.settle(deadline)
    except Exception:  # noqa: BLE001 - any doubt is unconfirmed
        settled = False
    if process is not None:
        settled = process.reap(max(deadline, time.monotonic() + SETTLE_POLL)) is not None and settled
    return settled


def _finish_streams(process, streams, settled):
    for fd, sink in streams.items():
        try:
            if settled:
                os.set_blocking(fd, True)
            drain(fd, sink)
        except OSError:
            pass
    process.close()


def run_tool(session, custody, name, argv, env, out_limit=1 << 20, log=None, cwd=None, ledger=None,
             durability="unchanged", err_sink=None):
    """Runs a tool in its own custody child until it exits; on cancel,
    loss or the deadline the child is killed and reaped before Interrupted
    propagates. Returns (exit status, stdout); with `log` both streams go
    to that bounded sink instead and stdout is empty; else stderr goes to
    `err_sink` (a Collect, say) when given, discarded otherwise.

    `ledger` persists the child's name before it exists and its identity
    once it does, and forgets it only after the child is confirmed gone.
    A child that cannot be confirmed gone raises Unsettled and stays in the
    ledger: a debt for a later settlement by that exact name."""
    ledger = ledger if ledger is not None else Ledger()
    ledger.add(name)
    try:
        child = custody.child(name)
    except Unsettled:
        raise
    except Failure:
        ledger.drop(name)
        raise
    ledger.bind(name, child.identity)
    process, streams, out = None, {}, None
    interrupted = error = None
    try:
        process = spawn(argv, env, child, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        out = log or Collect(out_limit)
        err = log or err_sink or BoundedSink(None, None, 0)
        streams = {process.popen.stdout.fileno(): out, process.popen.stderr.fileno(): err}
        for fd in streams:
            os.set_blocking(fd, False)
        if not process.admitted:
            raise Failure("failed")
        while process.poll() is None:
            try:
                session.check()
            except Interrupted as stop:
                interrupted = stop
                break
            for fd in session.wait(list(streams) + [process.pidfd], timeout=1.0):
                if fd in streams and not drain(fd, streams[fd]):
                    del streams[fd]
    except BaseException as caught:  # noqa: BLE001 - settled below, then re-raised
        error = caught
    # Whatever happened after the child existed: leftover members go with
    # the child, the leader is reaped by its own Popen, then the pipes end.
    settled = _settled(child, process, time.monotonic() + KILL_RESERVE)
    if process is not None:
        _finish_streams(process, streams, settled)
    if not settled:
        # Unconfirmed custody outranks the original error: the debt stays.
        raise Unsettled(durability) from error
    ledger.drop(name)
    if error is not None:
        raise error
    if interrupted is not None:
        raise interrupted
    status = process.status
    if log is not None:
        return status, b""
    if out.over:
        raise Failure("failed")
    return status, out.data
