"""Storage-growth admission (the Rust host's run.rs `admit_growth` and
run/scopes.rs, for the new-path store): before an execution begins, under
the store lock, the operator's `run-limits.json` (the providers' exact
validity rule, providers/common.py `parse_limits`), the provider's STATE in
a declared scope by filesystem membership (`common.covered`), every declared
scope measured, and the store's reservations plus that measurement at most
`max_reserved_bytes`.

```text
filesystem  allocated blocks of the opened root's filesystem, once per device
tree        allocated blocks of every inode beneath, streamed depth first
            (an open directory per level, never a whole listing held); a
            multiply-linked file once per (dev, ino) while the bounded memo
            lasts, then again (over, never under); no link followed, each
            directory reopened and checked to be the entry seen; inodes on a
            measured filesystem not charged again; another declared tree's
            root walked as itself
            strict (default): a permission gap, foreign mount, race, depth
            or entry budget refuses; uncapped prefixes: a gap or the spent
            budget prunes (a lower bound, counted as a warning)
```

Admission, not a quota: a moment's lower bound; nothing reserves what a
provider writes afterwards.
"""
import json
import os
import stat

from .assets import provider_common
from .config import read_private
from .host import HostError

LIMITS_FILE = "run-limits.json"
MAX_LIMITS_BYTES = 16 * 1024
MAX_STRICT_ENTRIES = 1 << 20
MAX_UNCAPPED_ENTRIES = 1 << 19
MAX_DEPTH = 64
MAX_LINKED = 1 << 16


def limits_path(data):
    return f"{data}/{LIMITS_FILE}"


def read_limits(data):
    raw = read_private(limits_path(data), MAX_LIMITS_BYTES, "storage_limits_unreadable")
    try:
        scopes = provider_common.parse_limits(raw)
    except provider_common.Failure:
        raise HostError("storage_limits_invalid") from None
    return scopes, json.loads(raw)["max_reserved_bytes"]


def covered(scopes, path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise HostError("storage_scope_undeclared") from None
    try:
        real = os.readlink(f"/proc/self/fd/{fd}")
        return provider_common.covered(scopes, real, os.fstat(fd))
    except OSError:
        return False
    finally:
        os.close(fd)


def _open(path):
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _under(prefix, rest):
    return rest == prefix or rest.startswith(prefix + "/")


class _Measure:
    def __init__(self, scopes):
        self.scopes = scopes
        self.total = 0
        self.warnings = 0
        # Multiply-linked files and tree roots only, at most MAX_LINKED;
        # past that a file is charged again (an overcount, never under).
        self.seen = set()
        self.devices = set()
        self.trees = {s["path"] for s in scopes if s["measure"] == "tree"}
        # Observed bounds (the tests' evidence): entries read, deepest stack.
        self.entries = 0
        self.peak = 0

    def filesystems(self):
        for scope in self.scopes:
            if scope["measure"] != "filesystem":
                continue
            try:
                fd = _open(scope["path"])
            except OSError:
                raise HostError("storage_scan_incomplete") from None
            try:
                vfs, st = os.fstatvfs(fd), os.fstat(fd)
            finally:
                os.close(fd)
            if st.st_dev not in self.devices:
                self.devices.add(st.st_dev)
                self.total += (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize

    def charge(self, st, remember=False):
        if st.st_dev in self.devices:
            return
        if remember or (not stat.S_ISDIR(st.st_mode) and st.st_nlink > 1):
            key = (st.st_dev, st.st_ino)
            if key in self.seen:
                return
            if len(self.seen) < MAX_LINKED:
                self.seen.add(key)
        self.total += st.st_blocks * 512

    def gap(self, strict):
        if strict:
            raise HostError("storage_scan_incomplete")
        self.warnings += 1

    def tree(self, scope):
        """Depth first, one open directory and its iterator per level: the
        entries streamed, never listed whole. Past MAX_UNCAPPED_ENTRIES the
        rest of every wholly uncapped directory is pruned (a warning, the
        figure a lower bound); past MAX_STRICT_ENTRIES the walk refuses."""
        uncapped = scope.get("uncapped", [])
        try:
            root = _open(scope["path"])
        except OSError:
            raise HostError("storage_scan_incomplete") from None
        root_st = os.fstat(root)
        self.charge(root_st, remember=True)
        counts = {"strict": 0, "uncapped": 0}
        spent = False
        stack = []

        def push(fd, rel, depth, wholly):
            try:
                entries = os.scandir(fd)
            except OSError:
                os.close(fd)
                self.gap(not wholly)
                return
            stack.append((fd, entries, rel, depth, wholly))
            self.peak = max(self.peak, len(stack))

        def pop():
            fd, entries, _, _, _ = stack.pop()
            entries.close()
            os.close(fd)

        try:
            push(root, "", 0, False)
            while stack:
                fd, entries, rel, depth, wholly = stack[-1]
                if wholly and spent:
                    pop()
                    self.warnings += 1
                    continue
                try:
                    entry = next(entries, None)
                except OSError:
                    self.gap(not wholly)
                    entry = None
                if entry is None:
                    pop()
                    continue
                child = f"{rel}/{entry.name}" if rel else entry.name
                below = wholly or any(_under(p, child) for p in uncapped)
                counts["uncapped" if below else "strict"] += 1
                if counts["strict"] > MAX_STRICT_ENTRIES:
                    raise HostError("storage_scan_incomplete")
                if below and counts["uncapped"] > MAX_UNCAPPED_ENTRIES:
                    spent = True
                    self.warnings += 1
                    continue
                self.entries += 1
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    self.gap(not below)
                    continue
                if f"{scope['path']}/{child}" in self.trees:
                    continue
                self.charge(st)
                if not stat.S_ISDIR(st.st_mode):
                    continue
                if (st.st_dev != root_st.st_dev and st.st_dev not in self.devices) or depth + 1 > MAX_DEPTH:
                    self.gap(not below)
                    continue
                if below and spent:
                    self.warnings += 1
                    continue
                try:
                    sub = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=fd)
                except OSError:
                    self.gap(not below)
                    continue
                opened = os.fstat(sub)
                if (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                    os.close(sub)
                    self.gap(not below)
                    continue
                push(sub, child, depth + 1, below)
        finally:
            while stack:
                pop()


def measure(scopes):
    """Every declared scope's allocated bytes and the warnings counted."""
    m = _Measure(scopes)
    m.filesystems()
    for scope in scopes:
        if scope["measure"] == "tree":
            m.tree(scope)
    return m.total, m.warnings


def admit(store, state, publish, extra=0, required=()):
    """The growth admission of one execution or staging: under the store
    lock, STATE (if any) and every `required` path declared, every scope
    measured, the store's reservations plus that measurement plus `extra`
    (an operation's own reservation, not yet recorded) under the
    threshold; then `publish()` records it before the lock is released.
    Returns the figures for the capture."""
    with store.lock():
        scopes, maximum = read_limits(store.path)
        for path in ([state] if state is not None else []) + list(required):
            if not covered(scopes, path):
                raise HostError("storage_scope_undeclared")
        measured, warnings = measure(scopes)
        reserved = store.charges()
        if reserved + measured + extra > maximum:
            raise HostError("storage_limit")
        publish()
    return {"reserved_bytes": reserved, "measured_bytes": measured, "max_reserved_bytes": maximum,
            "scopes": len(scopes), "warnings": warnings}
