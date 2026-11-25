"""Stages one installable Agentbox tree (README.md here). Stdlib only; runs
nothing, downloads nothing, writes only the new output directory.

  package.py --source SRC --relay-binary RELAY --out PREFIX

SRC is an Agentbox source tree, RELAY the built `agentbox-relay` (the
transport server's tunnel child, crates/agentbox-relay), PREFIX a
directory that must not exist; all absolute. PREFIX gets:

  bin/agentbox                  0755, SRC/src/agentbox: the Python
                                controller's entry (#!/usr/bin/python3 -IB)
  bin/agentbox-server           0755, SRC/src/agentbox-server: the
                                transport server's entry (the same shebang)
  bin/agentbox-relay            0755, RELAY's bytes
  share/agentbox-assets/        the provider and acquisition asset tree (ASSETS)
    providers/ acquisitions/ inputs/ agents/ images/worker/
    images/qemu/default/ images/podman/{default,dev}/ images/agents/
    guest/ controller/ (SRC/src's main.py and packages)

Only the fixed allowlist below is copied, each file through no link at any
level below SRC, single-link and regular, its SHA-256 measured while copied
and again in place. Directories 0755, files 0644: every asset is run by an
interpreter (Packer runs finalize.sh with /bin/sh).

PREFIX's parent must be ours or root's and not group/world writable (a
root-owned sticky directory such as /tmp is fine); it is opened once and
everything after goes through that descriptor. PREFIX is created there
exclusively, reopened without following links and accepted only as an empty
0700 directory of ours; it stays private (0700) until complete. Nothing is
ever deleted: a failure after PREFIX exists leaves it, incomplete and
private, for you to remove. Exit 0 with ASSETS on stdout; 1 with `package:
refused: CODE` on stderr (and `package: incomplete output left: PREFIX`
when it was made); 2 for usage.
"""
import hashlib
import os
import stat
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "images", "worker"))

import stage  # noqa: E402
import worker  # noqa: E402

ASSETS = "share/agentbox-assets"
SERVER = "bin/agentbox-server"
SERVER_SOURCE = "src/agentbox-server"
RELAY = "bin/agentbox-relay"
# The packaged entry: a small Python script, its first line exactly this.
LAUNCHER = "bin/agentbox"
LAUNCHER_SOURCE = "src/agentbox"
LAUNCHER_SHEBANG = b"#!/usr/bin/python3 -IB\n"
MAX_LAUNCHER_BYTES = 8192
PROVIDERS = ("protocol.py", "common.py", "qemu.py", "podman.py")
# The trusted handler tree: the shared import directory and each shipped
# handler's manifest, worker and packaged default policy. Test handlers and
# suites stay behind.
# Each handler's jail sources ship too, as the worker builder selects them
# (`allowlist`), so its host and jail parts stay siblings in ASSETS.
ACQUISITIONS = (
    "lib/agentbox_handler.py",
    "lib/agentbox_packages.py",
    "git/manifest.json",
    "git/policy.json",
    "git/host/worker.py",
    "npm/manifest.json",
    "npm/policy.json",
    "npm/host/worker.py",
    "pip/manifest.json",
    "pip/policy.json",
    "pip/host/worker.py",
)
# The host's own input staging worker (crates/agentbox/src/host_tools.rs):
# standalone, run as `INTERPRETER -I -S -B ASSETS/inputs/stage.py`.
INPUTS = ("stage.py",)
# `run AGENT`'s agents (docs/agents.md): the common jail runner once, each
# one's trusted host adapter, and `--install-agent`'s npm registry policy.
AGENTS = ("jail/run.py", "npm-registry.json",
          "pi/adapter.py", "codex/adapter.py", "claude/adapter.py")
# The Python controller (src/README.md), staged from SRC/src to
# ASSETS/controller (`installed`), as its assets.py expects: its entry and
# packages, never tests/.
CONTROLLER = ("main.py",) + tuple(f"agentbox_controller/{name}.py" for name in (
    "__init__", "acquisition", "agent", "agentrun", "assets", "attached", "builtin", "capture", "cgroups",
    "checkpoints", "cli", "commandrun", "config", "dev", "display", "doctor", "execute", "export", "fetch", "guest",
    "handlers", "host", "images", "inputs", "interactive", "lifecycle", "mounts", "owner", "provider",
    "scopes", "server", "shell", "ssh", "states", "store")) + tuple(f"agentbox_server/{name}.py" for name in (
    # The transport server (bin/agentbox-server).
    "__init__", "address", "broker", "codec", "ingress", "main", "policy", "relay", "request", "strictjson",
    "tools", "transport", "wire"))
MAX_BINARY_BYTES = 1 << 30
# The one place ASSETS departs from SRC's layout.
SOURCE_DIR, INSTALLED_DIR = "src/", "controller/"


class Refused(Exception):
    def __init__(self, code, left=None):
        super().__init__(code)
        self.left = left


def allowlist(source, guest=None):
    """Every asset's path below SRC, sorted (`installed`: its place below
    ASSETS); the worker sources (`guest`, else measured now: guest/ and each
    handler's jail tree) exactly as the worker builder selects them."""
    paths = [f"providers/{name}" for name in PROVIDERS]
    paths += [f"acquisitions/{name}" for name in ACQUISITIONS]
    paths += [f"inputs/{name}" for name in INPUTS]
    paths += [f"agents/{name}" for name in AGENTS]
    paths += [f"{SOURCE_DIR}{name}" for name in CONTROLLER]
    paths += [f"images/worker/{name}" for name in stage.WORKER_TOOLS + ("stage.py", "agentlock.py")]
    paths += [f"images/qemu/default/{name}" for name in (stage.QEMU_RECIPE,) + stage.QEMU_GUEST
              + ("inputs.lock.json", "ubuntu-cloudimage-keyring.gpg", "nodejs-release-keyring.gpg")]
    paths += [f"images/podman/{name}" for name in stage.PODMAN_RECIPES]
    paths += ["images/agents/resolve.sh"]
    paths += [f"guest/home/{name}" for name in stage.HOME_GUIDANCE]
    if guest is None:
        guest = guest_sources(source)
    paths += [entry["path"] for entry in guest]
    return sorted(paths)


def installed(rel):
    """An allowlisted path's place below ASSETS: its own, except SRC/src/
    is ASSETS/controller/."""
    return INSTALLED_DIR + rel[len(SOURCE_DIR):] if rel.startswith(SOURCE_DIR) else rel


def guest_sources(source):
    try:
        return worker.source_files(source)
    except (worker.Refused, OSError):
        raise Refused("source") from None


def open_below(root_fd, rel, single_link=True):
    """`rel` below the directory `root_fd`, no component a link; returns a
    read fd of the regular file."""
    parts = rel.split("/")
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            except OSError:
                raise Refused("source") from None
            os.close(fd)
            fd = nxt
        try:
            out = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
        except OSError:
            raise Refused("source") from None
    finally:
        os.close(fd)
    st = os.fstat(out)
    if not stat.S_ISREG(st.st_mode) or (single_link and st.st_nlink != 1):
        os.close(out)
        raise Refused("source")
    return out


def copy(src_fd, out_fd, rel, mode, limit=None):
    """Copies the open `src_fd` to the new file `rel` below `out_fd`
    (directories made 0700), then measures the copy again; returns its
    (size, sha256)."""
    parts = rel.split("/")
    parent = os.dup(out_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = nxt
        dst = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                      dir_fd=parent)
        try:
            size, digest = 0, hashlib.sha256()
            before = os.fstat(src_fd)
            while True:
                chunk = os.read(src_fd, 1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                if limit is not None and size > limit:
                    raise Refused("limit")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    view = view[os.write(dst, view):]
            after = os.fstat(src_fd)
            if size != before.st_size or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise Refused("changed")
            os.fchmod(dst, mode)
            os.fsync(dst)
        finally:
            os.close(dst)
        check = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(check, "rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest.hexdigest():
                raise Refused("changed")
        return size, digest.hexdigest()
    finally:
        os.close(parent)


def elf_x86_64(head):
    """A 64-bit little-endian x86-64 ELF header (as worker.elf_x86_64).
    BIN may have several links: cargo links target/*/agentbox to deps/."""
    return (len(head) == 20 and head[:4] == b"\x7fELF" and head[4] == 2 and head[5] == 1
            and head[7] in (0, 3) and head[18:20] == b"\x3e\x00")


def seal_dirs(fd):
    """Every directory below `fd`, then `fd` itself, 0755."""
    for name in os.listdir(fd):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            sub = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                seal_dirs(sub)
            finally:
                os.close(sub)
    os.fchmod(fd, 0o755)


def trusted_parent(fd):
    """The output's parent: ours or root's, not group/world writable, or
    root-owned and sticky. Nobody else can then rename its entries."""
    st = os.fstat(fd)
    mine = st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022
    sticky = st.st_uid == 0 and st.st_mode & stat.S_ISVTX
    return stat.S_ISDIR(st.st_mode) and (mine or sticky)


def make_output(parent_fd, name):
    """Creates `name` in the pinned parent and returns its descriptor, only
    if what the name then opens is an empty 0700 directory of ours."""
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    except FileExistsError:
        raise Refused("exists") from None
    except OSError:
        raise Refused("out") from None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    except OSError:
        raise Refused("out") from None
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700 or os.listdir(fd):
        os.close(fd)
        raise Refused("out")
    return fd


def open_binary(path, code):
    """An executable regular x86-64 ELF file, opened without following a
    final link; refused with `code`."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refused(code) from None
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o100 or not elf_x86_64(os.pread(fd, 20, 0)):
        os.close(fd)
        raise Refused(code)
    return fd


def package(source, relay, out):
    for path in (source, relay, out):
        if not os.path.isabs(path) or os.path.normpath(path) != path or path == "/":
            raise Refused("path")
    try:
        src_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused("source") from None
    fds = []
    try:
        guest = guest_sources(source)
        paths = allowlist(source, guest)
        expected = {e["path"]: (e["size"], e["sha256"]) for e in guest}
        fds.append(open_binary(relay, "relay"))
        try:
            parent_fd = os.open(os.path.dirname(out), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            raise Refused("out") from None
        try:
            if not trusted_parent(parent_fd):
                raise Refused("out")
            out_fd = make_output(parent_fd, os.path.basename(out))
        finally:
            os.close(parent_fd)
        try:
            copy(fds[0], out_fd, RELAY, 0o755, MAX_BINARY_BYTES)
            for source_rel, target in ((LAUNCHER_SOURCE, LAUNCHER), (SERVER_SOURCE, SERVER)):
                fd = open_below(src_fd, source_rel)
                try:
                    if os.pread(fd, len(LAUNCHER_SHEBANG), 0) != LAUNCHER_SHEBANG:
                        raise Refused("source")
                    copy(fd, out_fd, target, 0o755, MAX_LAUNCHER_BYTES)
                finally:
                    os.close(fd)
            for rel in paths:
                fd = open_below(src_fd, rel)
                try:
                    copied = copy(fd, out_fd, f"{ASSETS}/{installed(rel)}", 0o644)
                finally:
                    os.close(fd)
                # The worker sources exactly as first measured: the same
                # listing, so the same source revision.
                if rel in expected and copied != expected[rel]:
                    raise Refused("changed")
            seal_dirs(out_fd)
        except Refused as error:
            raise Refused(str(error), out) from None
        except OSError:
            raise Refused("io", out) from None
        finally:
            os.close(out_fd)
    finally:
        for fd in fds:
            os.close(fd)
        os.close(src_fd)
    return os.path.join(out, ASSETS)


def main(argv):
    names = ("--source", "--relay-binary", "--out")
    if len(argv) != 6 or argv[0::2] != list(names):
        sys.stderr.write("usage: package.py --source SRC --relay-binary RELAY --out PREFIX\n")
        return 2
    try:
        assets = package(argv[1], argv[3], argv[5])
    except Refused as error:
        sys.stderr.write(f"package: refused: {error}\n")
        if error.left is not None:
            sys.stderr.write(f"package: incomplete output left: {error.left}\n")
        return 1
    except OSError:
        sys.stderr.write("package: refused: io\n")
        return 1
    sys.stdout.write(assets + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
