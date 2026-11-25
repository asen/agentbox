"""Delegated cgroup v2 domains for the providers' resource limits (the
user's decision for checkpoint B: delegated systemd user scopes for limits
and explicit cleanup, no supervisor; src/README.md).

```text
user manager: transient unit agentbox-launch-<hex>.scope, Delegate=yes,
              cpu memory pids, this controller moved in by pidfd
U = <unit>/                 subtree_control: cpu memory pids, no process
  controller/               this process (the holder)
  agentbox-<hex>/ = D       envelope: cpu.max memory.max memory.swap.max
                            pids.max written and read back; cpu memory
                            pids in subtree_control; no process of its own
    h-1 h-2 ...             one fresh leaf per child: the provider owner,
                            agentbox-server, each ssh (AGENTBOX_CUSTODY = D)
    s-1 .. s-32             shell transports' slots (`join_slot`): each
                            made once by the transport that joins it,
                            cumulative, never reused; the owner's kill
                            and removal cover them as any leaf
    engine/ tool-*/ ...     the provider's own children (providers/common.py)
```

No fallback: a missing bus, delegation, controller or a value that does
not read back refuses before any workload effect. D is recorded (path and
inode identity) before its first process. Killing is `cgroup.kill` of D,
settled only once `cgroup.events` reads `populated 0`; then its empty children
(the provider's too) and D are removed, D by its pinned identity. A controller killed meanwhile
may leave U and D with whatever runs there: this controller does no
automatic cleanup. (Natively, Podman's owner settles on its host's EOF and
systemd then collects the empty unit, D with it; other providers or
failures may leave them.) A later
explicit recovery adopts D only by its recorded path and identity, kills
and settles it the same way. Nothing here touches another cgroup, unit or
name pattern.

`Cgroups` is the real kernel and user manager; tests substitute a subclass
over an owned directory tree (no production argument, variable or file
selects one).
"""
import errno
import os
import re
import secrets
import stat
import subprocess
import time

from .host import HostError, find_tool

CONTROLLERS = ("cpu", "memory", "pids")
UNIT_PREFIX = "agentbox-launch-"
DOMAIN_PREFIX = "agentbox-"
HOLDER_LEAF = "controller"
LEAF_PREFIX = "h-"
SLOT_PREFIX = "s-"
MAX_SLOTS = 32
CPU_PERIOD_US = 100000
MAX_INTERFACE_BYTES = 4096
MAX_PATH_BYTES = 4096
UNIT_REQUEST_TIMEOUT = 2.0
KILL_POLL = 0.01
_UNIT = re.compile(r"agentbox-launch-[0-9a-f]{32}\.scope")
_NAME = re.compile(r"[!-~]{1,255}")

# The envelope: per dimension the request plus overhead, else the
# configuration's guard, else the default (Rust custody.rs `Envelope`).
DEFAULT_ENVELOPE = {"cpus": 4, "memory_mib": 8192, "pids": 2048}
OVERHEAD = {"cpus": 1, "memory_mib": 1024, "pids": 512}


def envelope(requested, guard=None):
    guard = guard or {}
    return {key: (requested[key] + OVERHEAD[key]) if key in requested
            else guard.get(key, DEFAULT_ENVELOPE[key]) for key in DEFAULT_ENVELOPE}


def limit_files(env):
    """Each interface file and its exact value, written then read back."""
    return [("cpu.max", f"{env['cpus'] * CPU_PERIOD_US} {CPU_PERIOD_US}"),
            ("memory.max", str(env["memory_mib"] << 20)),
            ("memory.swap.max", "0"),
            ("pids.max", str(env["pids"]))]


def parse_self(data):
    """The single `0::/PATH` line of a pure v2 hierarchy, as names."""
    try:
        text = data.decode()
    except UnicodeDecodeError:
        raise HostError("cgroup_unsupported") from None
    lines = text.splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise HostError("cgroup_unsupported")
    path = lines[0][3:]
    if len(path) > MAX_PATH_BYTES or path.endswith(" (deleted)"):
        raise HostError("cgroup_invalid")
    if path == "/":
        return []
    names = path[1:].split("/")
    if any(_NAME.fullmatch(n) is None or n in (".", "..") for n in names):
        raise HostError("cgroup_invalid")
    return names


def identity(fd):
    st = os.fstat(fd)
    return [st.st_dev, st.st_ino]


class Cgroups:
    """The real host. Subclassed only by tests."""

    root = "/sys/fs/cgroup"
    proc = "/proc/self/cgroup"

    def self_names(self):
        with open(self.proc, "rb") as stream:
            return parse_self(stream.read(MAX_INTERFACE_BYTES + 1))

    def path(self, names):
        return "/".join([self.root] + list(names))

    def open_root(self):
        """The cgroup2 mount, as /proc/self/mountinfo names it."""
        try:
            with open("/proc/self/mountinfo", "rb") as stream:
                mounted = any(line.split(b" - ")[1].split()[0] == b"cgroup2"
                              and line.split()[4] == self.root.encode()
                              for line in stream.read(1 << 20).splitlines() if b" - " in line)
        except (OSError, IndexError):
            mounted = False
        if not mounted:
            raise HostError("cgroup_unsupported")
        return os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def open_sub(self, dir_fd, name):
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=dir_fd)

    def read(self, dir_fd, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
        try:
            data = os.read(fd, MAX_INTERFACE_BYTES + 1)
        finally:
            os.close(fd)
        if len(data) > MAX_INTERFACE_BYTES:
            raise OSError(errno.E2BIG, "interface")
        return data.decode()

    def write(self, dir_fd, name, value):
        fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
        try:
            os.write(fd, value.encode())
        finally:
            os.close(fd)

    def procs_fd(self, dir_fd):
        """A write descriptor on a leaf's cgroup.procs, for a child's join."""
        return os.open("cgroup.procs", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)

    def make(self, dir_fd, name):
        os.mkdir(name, 0o755, dir_fd=dir_fd)

    def remove(self, dir_fd, name):
        os.rmdir(name, dir_fd=dir_fd)

    def kill(self, dir_fd):
        self.write(dir_fd, "cgroup.kill", "1")

    def populated(self, dir_fd):
        for line in self.read(dir_fd, "cgroup.events").splitlines():
            if line == "populated 0":
                return False
            if line == "populated 1":
                return True
        raise HostError("cgroup_invalid")

    def start_unit(self, unit, deadline):
        """StartTransientUnit on the user bus: a scope of this process (by
        pidfd), Delegate=yes with cpu memory pids, collected once empty.
        Fixed argv; only the uid, the fresh unit name and the pidfd vary."""
        uid = os.geteuid()
        runtime = f"/run/user/{uid}"
        try:
            st_dir, st_bus = os.lstat(runtime), os.lstat(runtime + "/bus")
        except OSError:
            raise HostError("delegation_missing") from None
        if not (stat.S_ISDIR(st_dir.st_mode) and st_dir.st_uid == uid and not st_dir.st_mode & 0o022
                and stat.S_ISSOCK(st_bus.st_mode) and st_bus.st_uid == uid):
            raise HostError("delegation_missing")
        busctl = find_tool("busctl")
        pidfd = os.pidfd_open(os.getpid())
        try:
            argv = [busctl, f"--address=unix:path={runtime}/bus", "--auto-start=no",
                    "--allow-interactive-authorization=no", "--timeout=2", "--no-pager", "--quiet",
                    "call", "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
                    "org.freedesktop.systemd1.Manager", "StartTransientUnit", "ssa(sv)a(sa(sv))",
                    unit, "fail", "5",
                    "Description", "s", "Agentbox controller launch context",
                    "Delegate", "b", "true",
                    "DelegateControllers", "as", "3", "cpu", "memory", "pids",
                    "PIDFDs", "ah", "1", str(pidfd),
                    "CollectMode", "s", "inactive-or-failed", "0"]
            left = deadline - time.monotonic()
            if left <= 0:
                raise HostError("delegation_missing")
            try:
                done = subprocess.run(argv, env={"LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      pass_fds=(pidfd,), timeout=left, cwd="/")
            except (OSError, subprocess.SubprocessError):
                raise HostError("delegation_uncertain") from None
        finally:
            os.close(pidfd)
        if done.returncode != 0 or done.stdout:
            raise HostError("delegation_uncertain")

    def move_self(self, leaf_fd):
        self.write(leaf_fd, "cgroup.procs", str(os.getpid()))


def _owned_dir(fd):
    st = os.fstat(fd)
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and st.st_mode & 0o200


def _has_controllers(text):
    return set(CONTROLLERS) <= set(text.split())


def enter(host, idle=time.sleep):
    """Moves this controller into a fresh delegated unit's `controller`
    leaf and enables the controllers for U's children; returns U's names.
    Verified at every step; any doubt refuses (`delegation_missing`).
    `idle(seconds)`: each pause of its polls (an owner's housekeeping)."""
    unit = UNIT_PREFIX + secrets.token_hex(16) + ".scope"
    deadline = time.monotonic() + UNIT_REQUEST_TIMEOUT
    os.close(host.open_root())
    host.self_names()
    host.start_unit(unit, deadline)
    # The reply acknowledges a job: membership is observed, never resent.
    while True:
        names = host.self_names()
        if names and names[-1] == unit:
            break
        if time.monotonic() >= deadline:
            raise HostError("delegation_uncertain")
        idle(0.01)
    root = host.open_root()
    fds = [root]
    try:
        current = root
        for name in names:
            current = host.open_sub(current, name)
            fds.append(current)
        unit_fd = current
        pid = str(os.getpid())
        if not _owned_dir(unit_fd) or host.read(unit_fd, "cgroup.type").strip() != "domain" \
                or not _has_controllers(host.read(unit_fd, "cgroup.controllers")) \
                or host.read(unit_fd, "cgroup.procs").split() != [pid]:
            raise HostError("delegation_missing")
        host.make(unit_fd, HOLDER_LEAF)
        leaf = host.open_sub(unit_fd, HOLDER_LEAF)
        fds.append(leaf)
        if not _owned_dir(leaf) or host.read(leaf, "cgroup.procs").split():
            raise HostError("delegation_missing")
        host.move_self(leaf)
        if host.self_names() != names + [HOLDER_LEAF] or host.read(unit_fd, "cgroup.procs").split() \
                or host.read(leaf, "cgroup.procs").split() != [pid]:
            raise HostError("delegation_missing")
        host.write(unit_fd, "cgroup.subtree_control", "+cpu +memory +pids")
        if not _has_controllers(host.read(unit_fd, "cgroup.subtree_control")):
            raise HostError("controllers_missing")
        if time.monotonic() >= deadline:
            raise HostError("delegation_uncertain")
        return names
    except OSError:
        raise HostError("delegation_missing") from None
    finally:
        for fd in fds:
            os.close(fd)


MAX_REMOVE_DEPTH = 8


def _remove_below(host, dir_fd, depth):
    """Every empty child cgroup of `dir_fd`, recursively; True once none is
    left."""
    left = False
    with os.scandir(dir_fd) as entries:
        names = [e.name for e in entries if e.is_dir(follow_symlinks=False)]
    for name in names:
        try:
            child = host.open_sub(dir_fd, name)
        except OSError:
            left = True
            continue
        try:
            cleared = depth < MAX_REMOVE_DEPTH and not host.populated(child) \
                and _remove_below(host, child, depth + 1)
        except (OSError, HostError):
            cleared = False
        finally:
            os.close(child)
        try:
            if cleared:
                host.remove(dir_fd, name)
            else:
                left = True
        except FileNotFoundError:
            pass
        except OSError:
            left = True
    return not left


def _identity_value(value):
    return isinstance(value, list) and len(value) == 2 and all(type(v) is int and v >= 0 for v in value)


class Domain:
    """D: one created or adopted domain, pinned by its directory
    descriptor and recorded identity. `settled` only after a kill that
    read `populated 0`."""

    def __init__(self, host, parent_fd, name, path, fd):
        self.host, self.parent_fd, self.name, self.path, self.fd = host, parent_fd, name, path, fd
        self.identity = identity(fd)
        self.next = 0
        self.settled = False
        self.removed = False

    def record(self):
        return {"path": self.path, "identity": list(self.identity)}

    @classmethod
    def create(cls, host, env):
        """A fresh D beside this controller's leaf, its envelope written and
        read back, the controllers enabled for its children. A failure
        removes what it made, else reports it left (`domain_residue`)."""
        names = host.self_names()
        if len(names) < 2 or names[-1] != HOLDER_LEAF:
            raise HostError("delegation_missing")
        parent_names = names[:-1]
        root = host.open_root()
        try:
            parent = root
            for name in parent_names:
                child = host.open_sub(parent, name)
                if parent != root:
                    os.close(parent)
                parent = child
        finally:
            os.close(root)
        name = DOMAIN_PREFIX + secrets.token_hex(16)
        try:
            if not _owned_dir(parent) or host.read(parent, "cgroup.type").strip() != "domain" \
                    or not _has_controllers(host.read(parent, "cgroup.subtree_control")):
                raise HostError("delegation_missing")
            host.make(parent, name)
            fd = host.open_sub(parent, name)
        except (OSError, HostError) as error:
            os.close(parent)
            raise HostError(getattr(error, "code", "domain_failed")) from None
        domain = cls(host, parent, name, host.path(parent_names + [name]), fd)
        try:
            if not _owned_dir(fd) or not _has_controllers(host.read(fd, "cgroup.controllers")) \
                    or host.read(fd, "cgroup.procs").split():
                raise HostError("domain_invalid")
            for file, value in limit_files(env):
                host.write(fd, file, value)
                if host.read(fd, file).rstrip("\n") != value:
                    raise HostError("limit_mismatch")
            host.write(fd, "cgroup.subtree_control", "+cpu +memory +pids")
            if not _has_controllers(host.read(fd, "cgroup.subtree_control")):
                raise HostError("controllers_missing")
        except (OSError, HostError) as error:
            code = getattr(error, "code", "limit_failed")
            if not domain.remove():
                raise HostError("domain_residue") from None
            raise HostError(code) from None
        return domain

    @classmethod
    def adopt(cls, host, record):
        """The recorded D for recovery: its exact recorded path from the
        root, no link followed, still its recorded identity and ours. None
        only when a level of that path is absent (ENOENT): the owned domain
        is gone (a removed cgroup holds no process; v2 has no rename). Any
        other failure, or another identity there, refuses."""
        path = record.get("path") if isinstance(record, dict) else None
        if not isinstance(path, str) or not path.startswith(host.root + "/") \
                or not _identity_value(record.get("identity")):
            raise HostError("domain_invalid")
        names = path[len(host.root) + 1:].split("/")
        if any(_NAME.fullmatch(n) is None or n in (".", "..") for n in names) \
                or not names[-1].startswith(DOMAIN_PREFIX):
            raise HostError("domain_invalid")
        parent = host.open_root()
        try:
            for name in names[:-1]:
                child = host.open_sub(parent, name)
                os.close(parent)
                parent = child
            fd = host.open_sub(parent, names[-1])
        except FileNotFoundError:
            os.close(parent)
            return None
        except OSError:
            os.close(parent)
            raise HostError("domain_invalid") from None
        domain = cls(host, parent, names[-1], path, fd)
        if domain.identity != record["identity"] or not _owned_dir(fd):
            domain.close()
            raise HostError("domain_invalid")
        return domain

    def leaf(self):
        """A fresh leaf `h-N`, empty, and a write descriptor on its
        cgroup.procs for one child's join."""
        return self.named_leaf()[0]

    def named_leaf(self):
        """`leaf()` and the leaf's name."""
        self.next += 1
        name = f"{LEAF_PREFIX}{self.next}"
        try:
            self.host.make(self.fd, name)
            fd = self.host.open_sub(self.fd, name)
        except OSError:
            raise HostError("leaf_failed") from None
        try:
            if self.host.read(fd, "cgroup.procs").split():
                raise HostError("leaf_failed")
            return self.host.procs_fd(fd), name
        except OSError:
            raise HostError("leaf_failed") from None
        finally:
            os.close(fd)

    def join_slot(self):
        """This process moved into the first slot `s-K` of D not yet made
        (K <= MAX_SLOTS; the mkdir is the claim, so two joins never share
        one), its membership read back; `shell_limit` once all are made.
        Cumulative: a slot is never reused, its directory stays until D's
        removal."""
        for number in range(1, MAX_SLOTS + 1):
            name = f"{SLOT_PREFIX}{number}"
            try:
                self.host.make(self.fd, name)
            except FileExistsError:
                continue
            except OSError:
                raise HostError("slot_failed") from None
            break
        else:
            raise HostError("shell_limit")
        try:
            fd = self.host.open_sub(self.fd, name)
        except OSError:
            raise HostError("slot_failed") from None
        try:
            if self.host.read(fd, "cgroup.procs").split():
                raise HostError("slot_failed")
            self.host.move_self(fd)
            if self.host.self_names() != self.path[len(self.host.root) + 1:].split("/") + [name]:
                raise HostError("slot_failed")
        except OSError:
            raise HostError("slot_failed") from None
        finally:
            os.close(fd)
        return name

    def kill_leaf(self, name, deadline, idle=time.sleep):
        """One leaf's processes killed (a worker's strays with it), read
        empty by `deadline`, the leaf removed; True once settled. `idle`:
        each poll's pause."""
        try:
            fd = self.host.open_sub(self.fd, name)
        except FileNotFoundError:
            return True
        except OSError:
            return False
        try:
            self.host.kill(fd)
            while self.host.populated(fd):
                if time.monotonic() >= deadline:
                    return False
                idle(KILL_POLL)
        except (OSError, HostError):
            return False
        finally:
            os.close(fd)
        try:
            self.host.remove(self.fd, name)
        except OSError:
            pass
        return True

    def kill_until(self, deadline, idle=time.sleep):
        """cgroup.kill of D, then `populated 0` observed by `deadline`;
        `idle`: each poll's pause."""
        try:
            self.host.kill(self.fd)
        except OSError:
            return False
        while True:
            try:
                if not self.host.populated(self.fd):
                    self.settled = True
                    return True
            except (OSError, HostError):
                return False
            if time.monotonic() >= deadline:
                return False
            idle(KILL_POLL)

    def remove(self):
        """Every child that reads empty, deepest first (the provider's own
        included: custody.rs `remove_empty_children`), then D, if the name
        still leads to the pinned directory; True only once D's removal is
        confirmed. Nothing populated is touched."""
        if self.removed:
            return True
        try:
            if not _remove_below(self.host, self.fd, 0):
                return False
            current = self.host.open_sub(self.parent_fd, self.name)
            try:
                same = identity(current) == self.identity
            finally:
                os.close(current)
            if not same:
                return False
            self.host.remove(self.parent_fd, self.name)
        except OSError:
            return False
        self.removed = True
        self.close()
        return True

    def close(self):
        for fd in (self.fd, self.parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.fd = self.parent_fd = None
