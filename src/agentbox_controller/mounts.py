"""Host-directory mounts of a managed run (crates/agentbox/src/mounts.rs):
`--mount-ro SOURCE[=DEST]`, `--mount-rw SOURCE[=DEST]`, `--project DIR`,
fixed at creation and sent once with `create` (provider `host_mounts`). A
documented weakening of the jail contract: what a mount exposes is the
operator's choice.

```text
SOURCE   lexically absolute, kept as given: a symlink in it is resolved
         anew at every start (by the provider), never pinned
DEST     HOME-relative; default the workspace mapping: beneath the host
         HOME as there, else .agentbox-root/<absolute path>. Only an
         explicit DEST may be hidden (.pi), never a name starting .agentbox
         but .agentbox-root/<path>
--project a host directory at or beneath exactly one SOURCE: the working
         directory is that mount's DEST and the rest of the path, a
         project location (never hidden)
```

Refused before anything is recorded: more than 8, overlapping sources or
destinations (resolved targets too), a mount meeting the default `work`, a
source that is not an existing directory, one on a kernel
pseudo-filesystem, and one equal to, inside or containing a protected root
(this store, the legacy store's default roots, the provider's STATE and
assets, every declared storage scope; by resolved path and by the (dev,
ino) of each one's ancestors). Contents are never scanned. The provider
checks again at every start.
"""
import ctypes
import ctypes.util
import os

from .assets import provider_protocol
from .host import HostError
from .inputs import project, resolve

MAX_MOUNTS = provider_protocol.MAX_MOUNTS
MAX_PATH_BYTES = provider_protocol.MAX_MOUNT_PATH_BYTES
WORK = "work"
PSEUDO_ROOTS = ("/proc", "/sys", "/dev")
# statfs magic numbers of kernel pseudo-filesystems (mounts.rs).
PSEUDO_FILESYSTEMS = frozenset((
    0x9fa0, 0x62656572, 0x0027e0eb, 0x63677270, 0x64626720, 0x74726163, 0x73636673, 0x1cd1,
    0xcafe4a11, 0x62656570, 0x6165676c, 0xde5e81e4, 0x65735543, 0x19800202, 0x42494e4d,
    0x6e736673, 0xf97cff8c, 0x43415d53))


def valid(mounts):
    """A recorded mount list: empty, or the contract's `mounts_valid`."""
    return mounts == [] or provider_protocol.mounts_valid(mounts)


def parse(value, access):
    """One `SOURCE[=DEST]`, split at the first `=`."""
    source, sep, destination = value.partition("=")
    if not source or (sep and not destination):
        raise HostError("invalid_mount")
    return source, destination if sep else None, access


def select(args, project_dir, cwd, home):
    """(mounts, project location, project's host path): lexical only.
    `args`: [(source, destination or None, access)]."""
    if not args:
        if project_dir is not None:
            raise HostError("project_invalid")
        return [], None, None
    if len(args) > MAX_MOUNTS:
        raise HostError("mount_limit")
    mounts = []
    for source, destination, access in args:
        try:
            text = resolve(source, cwd)
        except HostError:
            raise HostError("mount_source_invalid") from None
        if not provider_protocol.is_path(text) or len(text.encode()) > MAX_PATH_BYTES:
            raise HostError("mount_source_invalid")
        if destination is None:
            if home is None:
                raise HostError("mount_host_home_invalid")
            try:
                destination = project(text, home)
            except HostError as error:
                raise HostError("mount_host_home_invalid" if error.code == "input_host_home_invalid"
                                else "mount_destination_unmapped") from None
        if not provider_protocol.is_mount_destination(destination) or len(destination.encode()) > MAX_PATH_BYTES:
            raise HostError("mount_destination_invalid")
        for other in mounts:
            if provider_protocol.overlap(other["source"], text):
                raise HostError("mount_source_overlap")
            if provider_protocol.overlap(other["destination"], destination):
                raise HostError("mount_destination_overlap")
        mounts.append({"source": text, "destination": destination, "access": access})
    location = host = None
    if project_dir is not None:
        try:
            host = resolve(project_dir, cwd)
        except HostError:
            raise HostError("project_invalid") from None
        found = locate(mounts, host)
        if found is None:
            raise HostError("project_invalid")
        location = found[0]
    elif any(provider_protocol.overlap(m["destination"], WORK) for m in mounts):
        raise HostError("mount_work_overlap")
    return mounts, location, host


def locate(mounts, directory):
    """(guest location, mount) of host directory `directory`: the one
    source equal to or containing it."""
    for mount in mounts:
        source = mount["source"]
        if directory == source or directory.startswith(source + "/"):
            location = mount["destination"] + directory[len(source):]
            if provider_protocol.is_project(location) and len(location.encode()) <= 1024:
                return location, mount
            return None
    return None


def mount_of(mounts, location):
    """The mount holding project location `location`, else None."""
    for mount in mounts:
        if location == mount["destination"] or location.startswith(mount["destination"] + "/"):
            return mount
    return None


def check_host(mounts, project_host, protected):
    """The host checks before anything is recorded."""
    guarded = [_Chain(root) for root in protected]
    targets = []
    for mount in mounts:
        target = resolve_source(mount["source"])
        chain = _Chain(target)
        if any(provider_protocol.overlap(root.path, target) or root.meets(chain) for root in guarded):
            raise HostError("mount_source_protected")
        if any(provider_protocol.overlap(other, target) for other, _ in targets):
            raise HostError("mount_source_overlap")
        targets.append((target, mount))
    if project_host is not None:
        found = locate(mounts, project_host)
        if found is None:
            raise HostError("project_invalid")
        mount = found[1]
        rest = project_host[len(mount["source"]):]
        target = next(t for t, m in targets if m is mount)
        try:
            resolved = os.path.realpath(project_host, strict=True)
        except OSError:
            raise HostError("project_unavailable") from None
        if resolved != target + rest or not os.path.isdir(resolved):
            raise HostError("project_unavailable")


def resolve_source(source):
    try:
        target = os.path.realpath(source, strict=True)
        fd = os.open(target, os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        raise HostError("mount_source_unavailable") from None
    try:
        import stat
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            raise HostError("mount_source_not_directory")
        if not provider_protocol.is_path(target) or any(provider_protocol.overlap(r, target) for r in PSEUDO_ROOTS) \
                or _pseudo(fd):
            raise HostError("mount_source_unsupported")
    finally:
        os.close(fd)
    return target


class _Statfs(ctypes.Structure):
    _fields_ = [("f_type", ctypes.c_long), ("rest", ctypes.c_byte * 120)]


_LIBC = None


def _pseudo(fd):
    """Whether open `fd` is on a pseudo-filesystem; unknown counts as one."""
    global _LIBC
    try:
        if _LIBC is None:
            _LIBC = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
        buf = _Statfs()
        if _LIBC.fstatfs(fd, ctypes.byref(buf)) != 0:
            return True
    except (OSError, AttributeError):
        return True
    return (buf.f_type & 0xffffffff) in PSEUDO_FILESYSTEMS


class _Chain:
    """A path resolved (else lexical) and the (dev, ino) of it and each
    ancestor: a bounded alias check, not a search."""

    def __init__(self, path):
        try:
            resolved = os.path.realpath(path, strict=True)
        except OSError:
            resolved = None
        ids = []
        at = resolved
        while at is not None:
            try:
                st = os.stat(at)
            except OSError:
                ids = []
                break
            ids.append((st.st_dev, st.st_ino))
            parent = os.path.dirname(at)
            at = None if parent == at else parent
        self.path = resolved or path
        self.ids = ids

    def meets(self, other):
        own = self.ids[0] if self.ids else None
        theirs = other.ids[0] if other.ids else None
        return (own is not None and own in other.ids[:-1]) or (theirs is not None and theirs in self.ids[:-1])
