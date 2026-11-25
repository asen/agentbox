"""The request context of one task: the execution's session nonce, from the
host's hello, and its working root, the session's own working directory
(execution.py). The helper session puts both into the task's fixed
environment under reserved names (protocol.py RESERVED_ENV, Rust
`environment::RESERVED`), so no explicit selection can replace them; a POST
client (artifact_post_client.py) reads them back and validates them.

    hello.session ----> AGENTBOX_REQUEST_SESSION  (32 lowercase hex digits)
    work_dir ---------> AGENTBOX_WORK_ROOT        (plain absolute path)
    launcher MOUNT ---> AGENTBOX_WORK_MOUNT       (only for a working directory
                                                  in a host mount: its root)

Every handler's uploads go to the one directory `.agentbox-requests` within
the working root, exactly the supplied target's `remote_dir`
(runtime/scp.rs), each named `<session>-<request>.artifact` from the host's
ids; the upload directory is always private. The working root must be a
private directory of this user, or, with a mount root (worker_profile.py's
mounted form), a directory of this user that is not other-writable: the
host directory's own mode. A client prepares it before it submits, reads the one file the host's
ids name there and, only once that handle's close is confirmed, removes it
while the name still holds the inode it read (`take_upload`); anything
uncertain stays, and a failed close or removal is the caller's sticky
incomplete cleanup. Every filesystem call goes through `files` (OS_FILES in
production). Every check is the guest's cooperative pathname check, not
containment: the guest user or root may change anything at any time. The
nonce correlates; it is no secret and grants nothing.
"""

import errno
import os
import stat

from guest.src.artifact_post_protocol import is_session
from guest.src.protocol import is_id
from guest.src.worker_profile import is_plain_absolute, within

SESSION_ENV = "AGENTBOX_REQUEST_SESSION"
WORK_ROOT_ENV = "AGENTBOX_WORK_ROOT"
MOUNT_ENV = "AGENTBOX_WORK_MOUNT"
# Every name; each is reserved in the helper's fixed environment.
CONTEXT_ENV = (SESSION_ENV, WORK_ROOT_ENV, MOUNT_ENV)

# The upload directory's name, within the working root.
UPLOAD_DIR_NAME = ".agentbox-requests"
# The fixed suffix of every upload's name.
UPLOAD_SUFFIX = ".artifact"


def upload_name(session, request):
    """`<session>-<request>.artifact` of the host-assigned ids; None otherwise."""
    return "%s-%s%s" % (session, request, UPLOAD_SUFFIX) if is_id(session) and is_id(request) else None


class _Handle:
    def __init__(self, fd):
        self.fd = fd

    def stat(self):
        return os.fstat(self.fd)

    def read(self, size, position):
        return os.pread(self.fd, size, position)

    def close(self):
        os.close(self.fd)


class OsFiles:
    """The filesystem calls of the upload directory; tests pass a double with
    the same methods."""

    def lstat(self, path):
        return os.lstat(path)

    def mkdir(self, path, mode):
        os.mkdir(path, mode)

    def open(self, path, flags):
        return _Handle(os.open(path, flags))

    def unlink(self, path):
        os.unlink(path)


OS_FILES = OsFiles()


class RequestContext:
    __slots__ = ("session", "work_root", "mount")

    def __init__(self, session, work_root, mount=None):
        self.session = session
        self.work_root = work_root
        self.mount = mount

    def __eq__(self, other):
        return isinstance(other, RequestContext) and \
            (self.session, self.work_root, self.mount) == (other.session, other.work_root, other.mount)

    def __repr__(self):
        return "RequestContext(%r, %r, %r)" % (self.session, self.work_root, self.mount)


def request_context(session, work_root, mount=None):
    """A context of exactly a session nonce, a plain absolute root and, if
    any, a plain absolute mount root equal to or above it; None otherwise."""
    if not is_session(session) or not is_plain_absolute(work_root):
        return None
    if mount is not None and not (is_plain_absolute(mount) and within(work_root, mount)):
        return None
    return RequestContext(session, work_root, mount)


def context_from_environment(env):
    """The context in `env`, read once; None when either name is missing or invalid."""
    mount = env.get(MOUNT_ENV)
    if MOUNT_ENV in env and mount is None:
        return None
    return request_context(env.get(SESSION_ENV), env.get(WORK_ROOT_ENV), mount)


def context_environment(context):
    """The two reserved variables of a context, for the task's fixed environment."""
    env = {SESSION_ENV: context.session, WORK_ROOT_ENV: context.work_root}
    if context.mount is not None:
        env[MOUNT_ENV] = context.mount
    return env


def upload_dir(context):
    """The upload directory: the working root and its fixed name."""
    return os.path.join(context.work_root, UPLOAD_DIR_NAME)


def _is_private(info, uid):
    return stat.S_ISDIR(info.st_mode) and info.st_uid == uid and (info.st_mode & 0o077) == 0


def _is_mounted(info, uid):
    return stat.S_ISDIR(info.st_mode) and info.st_uid == uid and (info.st_mode & 0o002) == 0


def prepare_upload_dir(context, files=OS_FILES):
    """Makes the upload directory (mode 0700) in the working root, which must
    already be a private directory of this user (in a host mount: a
    directory of this user, not other-writable). One already there is
    accepted: a directory, not a link, owned by this user, with no group or
    other access. The path, or None on anything else; nothing is removed."""
    uid = os.geteuid()
    path = upload_dir(context)
    try:
        root = _is_private if context.mount is None else _is_mounted
        if not root(files.lstat(context.work_root), uid):
            return None
        try:
            files.mkdir(path, 0o700)
        except OSError as error:
            if error.errno != errno.EEXIST:
                return None
        return path if _is_private(files.lstat(path), uid) else None
    except Exception:
        return None


# Never following a link, never blocking on a FIFO in its place.
READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC


class UploadRead:
    """The uploaded file's bytes, or why not: `code` `missing` (absent, not a
    regular file, unreadable), `mismatch` (another size, or more or fewer
    bytes) or `late` (`late()` held after a step). `closed` is False when the
    handle's close failed. `identity` is (st_dev, st_ino) once read."""

    __slots__ = ("ok", "data", "code", "identity", "closed")

    def __init__(self, ok, data=None, code=None, identity=None, closed=True):
        self.ok = ok
        self.data = data
        self.code = code
        self.identity = identity
        self.closed = closed


def read_upload(path, size, late, chunk=262144, files=OS_FILES):
    """Exactly `size` bytes of the regular file at `path`, read from one open
    handle whose read ends there; one byte more is read to detect growth.
    `late` is read after every step; its handle's close is always attempted."""
    try:
        handle = files.open(path, READ_FLAGS)
    except Exception:
        return UploadRead(False, code="late" if late() else "missing")
    identity = None
    try:
        result = None
        if late():
            result = UploadRead(False, code="late")
        else:
            info = handle.stat()
            if not stat.S_ISREG(info.st_mode):
                result = UploadRead(False, code="missing")
            else:
                identity = (info.st_dev, info.st_ino)
                if info.st_size != size:
                    result = UploadRead(False, code="mismatch", identity=identity)
        if result is None:
            body = bytearray()
            while len(body) < size + 1:
                if late():
                    result = UploadRead(False, code="late", identity=identity)
                    break
                data = handle.read(min(chunk, size + 1 - len(body)), len(body))
                if not data:
                    break
                body += data
        if result is None:
            if late():
                result = UploadRead(False, code="late", identity=identity)
            elif len(body) != size:
                result = UploadRead(False, code="mismatch", identity=identity)
            else:
                result = UploadRead(True, data=bytes(body), identity=identity)
    except Exception:
        result = UploadRead(False, code="missing", identity=identity)
    try:
        handle.close()
    except Exception:
        result.closed = False
    return result


def remove_upload(path, identity, files=OS_FILES):
    """Removes `path` only while it still names `identity`'s regular file; False when it stays."""
    try:
        info = files.lstat(path)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            return False
        files.unlink(path)
        return True
    except Exception:
        return False


class UploadTake:
    """One upload's read and removal. `removed` is True only once the inode
    read was unlinked after its handle's confirmed close; False when that
    removal failed or the name no longer held it; None when none was
    attempted: no inode was read, or the handle's close failed, which blocks
    both application and removal."""

    __slots__ = ("read", "removed")

    def __init__(self, read, removed=None):
        self.read = read
        self.removed = removed


def take_upload(path, size, late, chunk, files=OS_FILES):
    """`read_upload`, then, only after a confirmed close of a read inode, `remove_upload`."""
    read = read_upload(path, size, late, chunk, files)
    if not read.closed or read.identity is None:
        return UploadTake(read)
    return UploadTake(read, remove_upload(path, read.identity, files))
