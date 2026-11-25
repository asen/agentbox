"""FakeCgroups: the cgroup v2 tree and user manager over an owned
directory. Interface files are ordinary files; `cgroup.kill` SIGKILLs every
pid listed beneath, `populated` reads whether any listed pid still runs
(a zombie no longer counts, as the kernel removes exiting tasks). Faults:
`fail_start`, `no_membership`, `deny_controllers`, `mismatch` (a limit file
that reads back otherwise), `stuck` (`cgroup.kill` kills nothing),
`stuck_remove` (a domain's own rmdir always busy). Membership is
approximated (`members`), below a domain with `cwd_scope`.
"""
import os
import signal

from agentbox_controller import cgroups

BASE = ("user.slice", "user-1000.slice", "user@1000.service", "app.slice")
FILES = {"cgroup.type": "domain\n", "cgroup.procs": "", "cgroup.subtree_control": "", "cgroup.kill": "",
         "cpu.max": "max 100000\n", "memory.max": "max\n", "memory.swap.max": "max\n", "pids.max": "max\n",
         "cgroup.events": "populated 0\n"}


def alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            state = stream.read().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X")
    except OSError:
        return False


def listed(path):
    found = []
    for directory, _, files in os.walk(path):
        if "cgroup.procs" in files:
            with open(os.path.join(directory, "cgroup.procs")) as stream:
                found += [int(t) for t in stream.read().split() if t.isdigit()]
    return found


def members(path, cwd_scope=None):
    """The kernel's membership, approximated (an unprivileged test sees no
    real cgroup): the pids listed beneath `path`, their descendants, and
    every process working under `cwd_scope` (a guest command orphaned by
    its session's end)."""
    found = set(listed(path))
    parents = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat") as stream:
                parents[int(name)] = int(stream.read().rsplit(")", 1)[1].split()[1])
            if cwd_scope:
                cwd = os.readlink(f"/proc/{name}/cwd")
                if cwd == cwd_scope or cwd.startswith(cwd_scope + "/"):
                    found.add(int(name))
        except (OSError, IndexError, ValueError):
            continue
    changed = True
    while changed:
        more = {pid for pid, parent in parents.items() if parent in found} - found
        found |= more
        changed = bool(more)
    found.discard(os.getpid())
    return sorted(found)


class FakeCgroups(cgroups.Cgroups):
    def __init__(self, directory):
        self.root = os.path.join(directory, "cg")
        self.proc = os.path.join(directory, f"proc-cgroup-{os.getpid()}")
        self.fail_start = False
        self.no_membership = False
        self.deny_controllers = False
        self.mismatch = None
        self.stuck = False
        self.stuck_remove = False
        self.cwd_scope = None
        self.units = []
        # Made once, by whichever process gets each mkdir (the harness, before
        # any controller starts); never reset under a running one.
        os.makedirs(directory, exist_ok=True)
        path = self.root
        for name in ("",) + BASE + ("terminal.scope",):
            path = os.path.join(path, name) if name else path
            try:
                os.mkdir(path)
            except FileExistsError:
                continue
            self._populate(path, "cpu memory pids")
        self._set_self(list(BASE) + ["terminal.scope"])

    def _set_self(self, names):
        with open(self.proc, "w") as stream:
            stream.write("0::/" + "/".join(names) + "\n")

    def _populate(self, path, controllers):
        for name, value in FILES.items():
            with open(os.path.join(path, name), "w") as stream:
                stream.write(value)
        with open(os.path.join(path, "cgroup.controllers"), "w") as stream:
            stream.write(controllers + "\n")

    def _path(self, dir_fd):
        return os.readlink(f"/proc/self/fd/{dir_fd}")

    def open_root(self):
        return os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)

    def start_unit(self, unit, deadline):
        if self.fail_start:
            raise cgroups.HostError("delegation_missing")
        path = os.path.join(self.root, *BASE, unit)
        os.mkdir(path)
        self._populate(path, "cpu memory pids")
        with open(os.path.join(path, "cgroup.procs"), "w") as stream:
            stream.write(f"{os.getpid()}\n")
        self.units.append(unit)
        if not self.no_membership:
            self._set_self(list(BASE) + [unit])

    def move_self(self, leaf_fd):
        leaf = self._path(leaf_fd)
        with open(os.path.join(leaf, "cgroup.procs"), "w") as stream:
            stream.write(f"{os.getpid()}\n")
        with open(os.path.join(os.path.dirname(leaf), "cgroup.procs"), "w") as stream:
            stream.write("")
        self._set_self(os.path.relpath(leaf, self.root).split("/"))

    def make(self, dir_fd, name):
        parent = self._path(dir_fd)
        os.mkdir(os.path.join(parent, name))
        with open(os.path.join(parent, "cgroup.subtree_control")) as stream:
            controllers = stream.read().strip()
        self._populate(os.path.join(parent, name), controllers)

    def write(self, dir_fd, name, value):
        path = os.path.join(self._path(dir_fd), name)
        if name == "cgroup.kill":
            self.kill(dir_fd)
            return
        if name == "cgroup.subtree_control":
            if self.deny_controllers:
                raise OSError(13, "denied")
            value = " ".join(sorted(token[1:] for token in value.split() if token.startswith("+"))) + "\n"
        if name == self.mismatch:
            value = "1\n"
        with open(path, "w") as stream:
            stream.write(value)

    def procs_fd(self, dir_fd):
        return os.open("cgroup.procs", os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC, dir_fd=dir_fd)

    def pids(self, path):
        # The cwd approximation for D as a whole only, never one of its
        # leaves (a worker's leaf must not take the guest's command).
        name = os.path.basename(path)
        domain = name.startswith("agentbox-") and not name.startswith("agentbox-launch-")
        return members(path, self.cwd_scope if domain else None)

    def kill(self, dir_fd):
        for pid in self.pids(self._path(dir_fd)):
            if self.stuck or pid == os.getpid():
                continue
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def populated(self, dir_fd):
        return any(alive(pid) for pid in self.pids(self._path(dir_fd)))

    def remove(self, dir_fd, name):
        path = os.path.join(self._path(dir_fd), name)
        if self.stuck_remove and name.startswith("agentbox-") and not name.startswith("agentbox-launch-"):
            raise OSError(16, "busy")
        if any(alive(p) for p in self.pids(path)):
            raise OSError(16, "busy")
        if any(os.path.isdir(os.path.join(path, e)) for e in os.listdir(path)):
            raise OSError(16, "busy")
        for entry in os.listdir(path):
            os.unlink(os.path.join(path, entry))
        os.rmdir(path)
