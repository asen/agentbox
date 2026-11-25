"""Copied-input staging: the trusted host worker of `jail inputs`
(crates/agentbox/src/inputs.rs). Stdlib only, standalone: no import from
the asset tree. Host control code, not a sandboxed plugin; the operator's
selection is trusted, the selected bytes are only data, never run.

Agentbox runs it in a fresh leaf of a guard-held custody domain:

    INTERPRETER -I -S -B ASSETS/inputs/stage.py
      stdin   the request (one JSON object, at most MAX_REQUEST_BYTES)
      stdout  the run's fresh private spool (regular, empty), written once
              from offset 0; the kernel's RLIMIT_FSIZE is the byte limit
      fd 3    one result line (at most MAX_RESULT_BYTES), then EOF
      stderr  diagnostics only, bounded and sanitized by the host

    {"schema":"agentbox.inputs-request.v1",
     "store_hex":HEX,                    the data store's directory
     "copies":[{"source_hex":HEX,        absolute, lexically resolved
                "destination":"work",    guest-home-relative (host-checked)
                "kind":"directory"|"any"}, ...],
     "limits":{"archive_bytes":N,"entries":N,"depth":N,"path_bytes":N}}

    {"schema":"agentbox.inputs-result.v1","ok":true,"entries":N,
     "directories":N,"files":N,"links":N,"body_bytes":N,"archive_bytes":N}
    {"schema":"agentbox.inputs-result.v1","ok":false,"code":C}

Archive: GNU tar (`L`/`K` long-name records), deterministic for a given
tree: sorted byte names, mtime 0, owner 0, empty owner names; directories
0700, files 0600 or 0700 (owner executable), links 0777.

    plan                 "agentbox-inputs-v2\\n", then per copy, in order,
                         "d DEST\\n" | "f DEST\\n" | "l DEST\\n"
    slots/               one slot per copy, numbered from 0
    slots/N/...          a directory tree
    slots/N              a regular file, or a symlink (its own text)

Selection: every ancestor of a source is opened `O_PATH | O_NOFOLLOW`
from `/` and must be a directory, never a symlink. The leaf is opened the
same way and copied as it is: a directory tree, a regular file or a
symlink, whose text is copied and never followed. Below a directory root
every entry is opened relative to its parent's descriptor with
`O_PATH | O_NOFOLLOW` and classified from that descriptor; a directory is
reopened through it and a regular file through `/proc/self/fd`, so no
pathname check races a content open and no FIFO or device is ever opened.
Symlinks are copied as links whatever they name (inside, outside or
dangling); hard links are copied as independent files; `.git` directories
and pointer files are ordinary data; mount points are crossed. FIFOs,
sockets and devices refuse. The only identity check is the data store's
(`store_hex`): a source inside it, or a tree reaching it, refuses, so the
spool never archives itself. Best effort, not a snapshot: a file shorter
than its length at open, or an entry that vanishes or changes type, fails
the attempt.

Limits count everything copied, the roots included: `entries` objects,
`depth` levels below a root, `path_bytes` bytes of a source-relative path,
`archive_bytes` bytes of the whole archive (headers, padding, plan and end
blocks included). The walk is iterative, so depth costs no interpreter
recursion: one open listing descriptor per level (the soft descriptor limit
is raised for `depth`, within the hard limit) and its names.
"""

import errno
import json
import os
import resource
import stat
import sys
import tarfile

REQUEST_SCHEMA = "agentbox.inputs-request.v1"
RESULT_SCHEMA = "agentbox.inputs-result.v1"
PLAN_HEADER = b"agentbox-inputs-v2\n"
SLOTS = b"slots"
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESULT_BYTES = 4096
MAX_COPIES = 32
MAX_DESTINATION_BYTES = 1024
MAX_SOURCE_BYTES = 4096
RESULT_FD = 3
BLOCK = 512
CHUNK = 1 << 20
LIMITS = ("archive_bytes", "entries", "depth", "path_bytes")
MAX_LIMIT = 1 << 40

# Fixed failure codes, as inputs.rs `Error`.
CODES = frozenset(
    {
        "input_request_invalid",
        "input_output_invalid",
        "input_source_unavailable",
        "input_source_not_directory",
        "input_source_symlink_ancestor",
        "input_source_overlaps_store",
        "input_source_unreadable",
        "input_source_changed",
        "input_special_file",
        "input_entry_limit",
        "input_depth_limit",
        "input_path_limit",
        "input_archive_limit",
        "input_io_error",
    }
)


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        assert code in CODES
        self.code = code


def traversal_error(error):
    """An OSError met below a pinned root."""
    if error.errno in (errno.EACCES, errno.EPERM):
        return Refused("input_source_unreadable")
    if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP, errno.ESTALE):
        return Refused("input_source_changed")
    if error.errno == errno.EFBIG:
        return Refused("input_archive_limit")
    if error.errno == errno.ENAMETOOLONG:
        return Refused("input_path_limit")
    return Refused("input_io_error")


def identity(st):
    return (st.st_dev, st.st_ino)


# The request.


def read_request(fd):
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_REQUEST_BYTES:
            raise Refused("input_request_invalid")
        chunks.append(chunk)
    try:
        request = json.loads(b"".join(chunks))
    except ValueError:
        raise Refused("input_request_invalid")
    return check_request(request)


def plain_int(value, low, high):
    return type(value) is int and low <= value <= high


def unhex(text, limit):
    if not isinstance(text, str) or len(text) % 2 or len(text) > 2 * limit:
        raise Refused("input_request_invalid")
    try:
        return bytes.fromhex(text)
    except ValueError:
        raise Refused("input_request_invalid")


def plain_absolute(path):
    """`/` then nonempty components, none `.` or `..`, no NUL."""
    if not path.startswith(b"/") or path == b"/" or b"\0" in path:
        return False
    parts = path.split(b"/")[1:]
    return all(part not in (b"", b".", b"..") for part in parts)


def valid_destination(text):
    if not isinstance(text, str) or not text or "\n" in text or "\0" in text:
        return False
    if len(text.encode("utf-8", "surrogatepass")) > MAX_DESTINATION_BYTES:
        return False
    return all(part not in ("", ".", "..") for part in text.split("/"))


def check_request(request):
    keys = {"schema", "store_hex", "copies", "limits"}
    if not isinstance(request, dict) or set(request) != keys:
        raise Refused("input_request_invalid")
    if request["schema"] != REQUEST_SCHEMA:
        raise Refused("input_request_invalid")
    store = unhex(request["store_hex"], MAX_SOURCE_BYTES)
    if not plain_absolute(store) and store != b"/":
        raise Refused("input_request_invalid")
    limits = request["limits"]
    if not isinstance(limits, dict) or set(limits) != set(LIMITS):
        raise Refused("input_request_invalid")
    if not all(plain_int(limits[name], 1, MAX_LIMIT) for name in LIMITS):
        raise Refused("input_request_invalid")
    copies = request["copies"]
    if not isinstance(copies, list) or not 1 <= len(copies) <= MAX_COPIES:
        raise Refused("input_request_invalid")
    checked = []
    for copy in copies:
        if not isinstance(copy, dict) or set(copy) != {"source_hex", "destination", "kind"}:
            raise Refused("input_request_invalid")
        source = unhex(copy["source_hex"], MAX_SOURCE_BYTES)
        if not plain_absolute(source) or copy["kind"] not in ("directory", "any"):
            raise Refused("input_request_invalid")
        if not valid_destination(copy["destination"]):
            raise Refused("input_request_invalid")
        checked.append((source, copy["destination"], copy["kind"]))
    return store, checked, limits


# The output.


class Archive:
    """The spool on fd 1, written once from offset 0 within `limit`."""

    def __init__(self, fd, limit):
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size != 0 or os.lseek(fd, 0, os.SEEK_CUR) != 0:
            raise Refused("input_output_invalid")
        self.fd = fd
        self.limit = limit
        self.written = 0

    def write(self, data):
        if self.written + len(data) > self.limit:
            raise Refused("input_archive_limit")
        view = memoryview(data)
        while view:
            try:
                count = os.write(self.fd, view)
            except OSError as error:
                if error.errno == errno.EFBIG:
                    raise Refused("input_archive_limit")
                raise Refused("input_io_error")
            view = view[count:]
            self.written += count

    def header(self, name, kind, size=0, mode=0o600, link=b""):
        info = tarfile.TarInfo(name.decode("utf-8", "surrogateescape"))
        info.type = kind
        info.size = size
        info.mode = mode
        info.mtime = 0
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.linkname = link.decode("utf-8", "surrogateescape")
        self.write(info.tobuf(tarfile.GNU_FORMAT, "utf-8", "surrogateescape"))

    def pad(self, size):
        rest = size % BLOCK
        if rest:
            self.write(bytes(BLOCK - rest))

    def end(self):
        self.write(bytes(2 * BLOCK))


# Selection and traversal.


O_PATH = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
# Descriptors beside the walk's one listing per level: the standard
# streams, the result, the pinned root and parent, an entry and its file.
SPARE_FDS = 64


class Level:
    """One open directory of the walk: its listing descriptor, archive
    name, source-relative path, depth and its names still to visit."""

    __slots__ = ("fd", "name", "relative", "depth", "names", "next")

    def __init__(self, fd, name, relative, depth, names):
        self.fd = fd
        self.name = name
        self.relative = relative
        self.depth = depth
        self.names = names
        self.next = 0


def descriptors(depth):
    """Room for one open listing per level: the soft descriptor limit
    raised towards `depth + SPARE_FDS`, never above the hard limit. A
    hard limit too low fails a deep enough tree with `EMFILE`, a fixed
    `input_io_error`, never a traceback."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = depth + SPARE_FDS
    if hard != resource.RLIM_INFINITY:
        wanted = min(wanted, hard)
    if soft != resource.RLIM_INFINITY and soft < wanted:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))


class Walk:
    def __init__(self, archive, store, limits):
        self.archive = archive
        self.store = store
        self.limits = limits
        self.entries = 0
        self.directories = 0
        self.files = 0
        self.links = 0
        self.body_bytes = 0

    def count(self):
        self.entries += 1
        if self.entries > self.limits["entries"]:
            raise Refused("input_entry_limit")

    def pin(self, source):
        """The source's parent, every ancestor a plain directory outside
        the store, and the leaf's `O_PATH` descriptor and status."""
        parts = source.split(b"/")[1:]
        try:
            current = os.open(b"/", os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            raise Refused("input_source_unavailable")
        try:
            self.outside(os.fstat(current))
            for part in parts[:-1]:
                try:
                    step = os.open(part, O_PATH, dir_fd=current)
                except OSError as error:
                    raise self.root_error(error)
                os.close(current)
                current = step
                st = os.fstat(current)
                if stat.S_ISLNK(st.st_mode):
                    raise Refused("input_source_symlink_ancestor")
                if not stat.S_ISDIR(st.st_mode):
                    raise Refused("input_source_unavailable")
                self.outside(st)
            try:
                leaf = os.open(parts[-1], O_PATH, dir_fd=current)
            except OSError as error:
                raise self.root_error(error)
            return current, leaf, parts[-1]
        except BaseException:
            os.close(current)
            raise

    @staticmethod
    def root_error(error):
        if error.errno in (errno.EACCES, errno.EPERM):
            return Refused("input_source_unreadable")
        if error.errno == errno.ENAMETOOLONG:
            return Refused("input_path_limit")
        if error.errno in (errno.ENOENT, errno.ENOTDIR, errno.ELOOP):
            return Refused("input_source_unavailable")
        return Refused("input_io_error")

    def outside(self, st):
        if identity(st) == self.store:
            raise Refused("input_source_overlaps_store")

    def copy(self, index, source, kind):
        """One copy as slot `index`; returns its plan kind."""
        parent, leaf, name = self.pin(source)
        try:
            st = os.fstat(leaf)
            slot = SLOTS + b"/" + str(index).encode()
            if kind == "directory" and not stat.S_ISDIR(st.st_mode):
                raise Refused("input_source_not_directory")
            if stat.S_ISDIR(st.st_mode):
                self.directory(leaf, st, slot)
                return b"d"
            if stat.S_ISREG(st.st_mode):
                self.count()
                self.regular(leaf, st, slot)
                return b"f"
            if stat.S_ISLNK(st.st_mode):
                self.count()
                self.link(leaf, slot)
                return b"l"
            raise Refused("input_special_file")
        finally:
            os.close(leaf)
            os.close(parent)

    def directory(self, pinned, st, name):
        """A directory tree from its root's `O_PATH` descriptor, depth
        first in byte order, iteratively: an explicit stack of open listing
        descriptors, one per level, each closed once its level is done (or
        on any failure), every child opened relative to its parent's."""
        stack = [self.enter(pinned, st, name, b"", 0)]
        try:
            while stack:
                level = stack[-1]
                if level.next == len(level.names):
                    stack.pop()
                    os.close(level.fd)
                    continue
                child = level.names[level.next]
                level.next += 1
                path = level.relative + b"/" + child if level.relative else child
                if len(path) > self.limits["path_bytes"]:
                    raise Refused("input_path_limit")
                if level.depth + 1 > self.limits["depth"]:
                    raise Refused("input_depth_limit")
                try:
                    entry = os.open(child, O_PATH, dir_fd=level.fd)
                except OSError as error:
                    raise traversal_error(error)
                try:
                    st = os.fstat(entry)
                    member = level.name + b"/" + child
                    if stat.S_ISDIR(st.st_mode):
                        stack.append(self.enter(entry, st, member, path, level.depth + 1))
                    elif stat.S_ISREG(st.st_mode):
                        self.count()
                        self.regular(entry, st, member)
                    elif stat.S_ISLNK(st.st_mode):
                        self.count()
                        self.link(entry, member)
                    else:
                        raise Refused("input_special_file")
                finally:
                    os.close(entry)
        finally:
            for level in stack:
                os.close(level.fd)

    def enter(self, pinned, st, name, relative, depth):
        """One directory: its listing reopened through its own `O_PATH`
        descriptor (the same inode or nothing), its header, its sorted
        names; the open listing for its children, as a `Level`."""
        self.outside(st)
        self.count()
        try:
            listing = os.open(b".", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=pinned)
        except OSError as error:
            raise traversal_error(error)
        try:
            if identity(os.fstat(listing)) != identity(st):
                raise Refused("input_source_changed")
            self.archive.header(name, tarfile.DIRTYPE, mode=0o700)
            self.directories += 1
            try:
                names = sorted(os.fsencode(entry) for entry in os.listdir(listing))
            except OSError as error:
                raise traversal_error(error)
            if len(names) > self.limits["entries"] - self.entries:
                raise Refused("input_entry_limit")
            return Level(listing, name, relative, depth, names)
        except BaseException:
            os.close(listing)
            raise

    def regular(self, pinned, st, name):
        """A regular file reopened through its own descriptor, never by
        name: the same inode or nothing."""
        try:
            fd = os.open("/proc/self/fd/%d" % pinned, os.O_RDONLY | os.O_NOCTTY | os.O_CLOEXEC)
        except OSError as error:
            raise traversal_error(error)
        try:
            opened = os.fstat(fd)
            if identity(opened) != identity(st) or not stat.S_ISREG(opened.st_mode):
                raise Refused("input_source_changed")
            size = opened.st_size
            mode = 0o700 if opened.st_mode & stat.S_IXUSR else 0o600
            if self.archive.written + 2 * BLOCK + size > self.archive.limit:
                raise Refused("input_archive_limit")
            self.archive.header(name, tarfile.REGTYPE, size=size, mode=mode)
            left = size
            while left:
                try:
                    data = os.read(fd, min(CHUNK, left))
                except OSError as error:
                    raise traversal_error(error)
                if not data:
                    raise Refused("input_source_changed")
                self.archive.write(data)
                left -= len(data)
            self.archive.pad(size)
            self.files += 1
            self.body_bytes += size
        finally:
            os.close(fd)

    def link(self, pinned, name):
        """A symlink's own text, from its own descriptor; never followed."""
        try:
            target = os.readlink(b"", dir_fd=pinned)
        except OSError as error:
            raise traversal_error(error)
        self.archive.header(name, tarfile.SYMTYPE, mode=0o777, link=target)
        self.links += 1


def stage(request, out_fd):
    store_path, copies, limits = request
    try:
        store_fd = os.open(store_path, os.O_PATH | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise Refused("input_request_invalid")
    try:
        store = identity(os.fstat(store_fd))
    finally:
        os.close(store_fd)
    archive = Archive(out_fd, limits["archive_bytes"])
    descriptors(limits["depth"])
    walk = Walk(archive, store, limits)
    # The plan leads the archive: each leaf is classified first from its
    # own pinned descriptor; a leaf that changed kind by its copy refuses.
    kinds = []
    for source, _, kind in copies:
        parent, leaf, _ = walk.pin(source)
        try:
            st = os.fstat(leaf)
        finally:
            os.close(leaf)
            os.close(parent)
        if kind == "directory" and not stat.S_ISDIR(st.st_mode):
            raise Refused("input_source_not_directory")
        if stat.S_ISDIR(st.st_mode):
            kinds.append(b"d")
        elif stat.S_ISREG(st.st_mode):
            kinds.append(b"f")
        elif stat.S_ISLNK(st.st_mode):
            kinds.append(b"l")
        else:
            raise Refused("input_special_file")
    plan = PLAN_HEADER + b"".join(
        kind + b" " + destination.encode("utf-8") + b"\n"
        for kind, (_, destination, _) in zip(kinds, copies)
    )
    archive.header(b"plan", tarfile.REGTYPE, size=len(plan), mode=0o600)
    archive.write(plan)
    archive.pad(len(plan))
    archive.header(SLOTS, tarfile.DIRTYPE, mode=0o700)
    for index, (source, _, kind) in enumerate(copies):
        if walk.copy(index, source, kind) != kinds[index]:
            raise Refused("input_source_changed")
    archive.end()
    return {
        "entries": walk.entries,
        "directories": walk.directories,
        "files": walk.files,
        "links": walk.links,
        "body_bytes": walk.body_bytes,
        "archive_bytes": archive.written,
    }


def emit(result):
    line = json.dumps(dict(schema=RESULT_SCHEMA, **result), sort_keys=True).encode() + b"\n"
    assert len(line) <= MAX_RESULT_BYTES
    view = memoryview(line)
    while view:
        view = view[os.write(RESULT_FD, view):]


def main():
    try:
        if not stat.S_ISFIFO(os.fstat(RESULT_FD).st_mode):
            return 2
    except OSError:
        return 2
    try:
        result = stage(read_request(0), 1)
    except Refused as refused:
        emit({"ok": False, "code": refused.code})
        return 1
    emit(dict(ok=True, **result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
