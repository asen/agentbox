"""Offline checks of providers/podman.py.

  python3 -I -B -m unittest discover -s providers -p 'test_*.py'

Nothing real is built, loaded, started or delegated: `podman` is a local
stand-in script whose state lives in the store it is given (--root), whose
detached helpers (pause, conmon, an exec's conmon) double-fork, hold the
leader's inherited stdout/stderr and join the caller's fake custody child,
and whose `exec` is an sshd stand-in speaking a small line protocol over
the relayed bytes. conmon and crun are inert stand-in paths. The custody
domain is test_qemu's ordinary-directory stand-in; only the installed
`ssh-keygen` runs for real (fresh temporary keys).

Orphans go to the nearest subreaper, as the kernel does: a control
invocation or a bridge (common.subreaper). One divergence: the stand-in
sshd runs in the exec process itself, so a guest `spawn` is adopted (and
at its end killed) by the bridge; a real guest's orphans go to the
container's init, which only native runs show.
"""
import base64
import errno
import gzip
import hashlib
import io
import json
import os
import select
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import common  # noqa: E402
import podman  # noqa: E402
import protocol  # noqa: E402
import test_qemu  # noqa: E402
from test_qemu import _alive, make_domain, public_key, slurp, write  # noqa: E402

import worker  # noqa: E402  (images/worker, via podman's explicit path)

sys.path.insert(0, podman.WORKER_DIR)
import test_worker  # noqa: E402

KEYGEN = "/usr/bin/ssh-keygen"
HAVE_KEYGEN = os.access(KEYGEN, os.X_OK)
REVISION = "b" * 64


def remove_tree(root):
    """Removes a test tree, read-only directories included (links are
    never followed or changed)."""
    for path, dirs, _ in os.walk(root):
        for name in dirs:
            if not os.path.islink(os.path.join(path, name)):
                os.chmod(os.path.join(path, name), 0o700)
    shutil.rmtree(root, True)


# ---------------------------------------------------------------------------
# Stand-in OCI archives: one squashed layer with the baked worker.

def _tar_bytes(entries, gz=False):
    """entries: (name, kind 'dir'|'file'|'link'|'sym', mode, data, uid)."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, kind, mode, data, uid in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.uid, info.gid, info.mtime = mode, uid, uid, 0
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif kind == "sym":
                info.type, info.linkname = tarfile.SYMTYPE, data
                tar.addfile(info)
            elif kind == "link":
                info.type, info.linkname = tarfile.LNKTYPE, data
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    data = out.getvalue()
    return gzip.compress(data, mtime=0) if gz else data


# An account-free image's account files (podman.image_accounts).
PASSWD = b"root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
GROUP = b"root:x:0:\nsudo:x:27:ops\nnogroup:x:65534:\n"
ACCOUNTS = ["nobody", "nogroup", "ops", "root", "sudo"]


def agent_entries(root, version="2.0.0", registry=None):
    """The canonical recipe's agents as layer entries (podman.agent_files):
    each agent's checked lock for its own package at `version` and the
    installed package, from fresh stand-in locks under `root`; and
    {agent: lock bytes}."""
    agentlock = podman._agentlock()
    locks = os.path.join(test_worker.fake_agents(root, registry or agentlock.REGISTRY, agentlock.PACKAGES,
                                                 version)[0])
    entries, found = [(podman.AGENTS_ROOT, "dir", 0o755, None, 0)], {}
    for agent in agentlock.AGENTS:
        base, package = f"{podman.AGENTS_ROOT}/{agent}", agentlock.PACKAGES[agent]
        entries.append((base, "dir", 0o755, None, 0))
        for name in agentlock.LOCK_FILES:
            entries.append((f"{base}/{name}", "file", 0o644, slurp(os.path.join(locks, agent, name)), 0))
        found[agent] = slurp(os.path.join(locks, agent, "package-lock.json"))
        installed = json.dumps({"name": package, "version": version, "bin": {agent: "x.js"}}).encode()
        scope = package.split("/")[0]
        entries += [(f"{base}/node_modules", "dir", 0o755, None, 0),
                    (f"{base}/node_modules/{scope}", "dir", 0o755, None, 0),
                    (f"{base}/node_modules/{package}", "dir", 0o755, None, 0),
                    (f"{base}/node_modules/{package}/package.json", "file", 0o644, installed, 0)]
    return entries, found


def baked_entries(root, revision=REVISION, change=None, agents="2.0.0"):
    """The layer entries of a sealed bundle at /opt/agentbox/worker and its
    metadata, from a fresh synthetic bundle under `root`, and the agents at
    version `agents` (none when None)."""
    manifest = test_worker.synthetic_bundle(root)
    release = hashlib.sha256(manifest).hexdigest()
    metadata = json.dumps({"schema": worker.METADATA["schema"], "release": release,
                           "install_root": worker.INSTALL_ROOT, "manifest": manifest.decode(),
                           "sources": {"revision": revision}}).encode()
    entries = [("etc", "dir", 0o755, None, 0), ("etc/passwd", "file", 0o644, PASSWD, 0),
               ("etc/group", "file", 0o644, GROUP, 0), ("home", "dir", 0o755, None, 0),
               ("usr", "dir", 0o755, None, 0), ("usr/bin", "dir", 0o755, None, 0),
               ("usr/bin/tini", "file", 0o755, b"tini", 0), ("opt", "dir", 0o755, None, 0),
               ("opt/agentbox", "dir", 0o755, None, 0), ("opt/agentbox/worker", "dir", 0o555, None, 0)]
    for path, dirs, files in sorted(os.walk(root)):
        dirs.sort()
        rel = os.path.relpath(path, root)
        for name in dirs:
            entries.append((f"opt/agentbox/worker/{os.path.normpath(os.path.join(rel, name))}", "dir", 0o555,
                            None, 0))
        for name in sorted(files):
            item = os.path.normpath(os.path.join(rel, name))
            entries.append((f"opt/agentbox/worker/{item}", "file", worker.mode(item, "file"),
                            slurp(os.path.join(path, name)), 0))
    entries.append(("opt/agentbox/worker-metadata.json", "file", 0o444, metadata, 0))
    if agents is not None:
        entries += agent_entries(root + "-agents", agents)[0]
    if change is not None:
        entries = change(entries)
    return entries, release


def oci_archive(entries, gz=False, arch="amd64", extra_layer=False, change=None):
    """(archive bytes, image id = config digest) of `podman save
    --format=oci-archive` shape."""
    raw = _tar_bytes(entries)
    layer = gzip.compress(raw, mtime=0) if gz else raw
    blobs = {}

    def blob(data):
        digest = hashlib.sha256(data).hexdigest()
        blobs[digest] = data
        return digest

    layer_ref = {"mediaType": "application/vnd.oci.image.layer.v1.tar" + ("+gzip" if gz else ""),
                 "digest": "sha256:" + blob(layer), "size": len(layer)}
    config = {"architecture": arch, "os": "linux", "config": {"Entrypoint": ["/bin/evil"], "Volumes": {"/x": {}}},
              "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()]}}
    layers = [layer_ref] + ([layer_ref] if extra_layer else [])
    if extra_layer:
        config["rootfs"]["diff_ids"] *= 2
    config_bytes = json.dumps(config).encode()
    image_id = blob(config_bytes)
    manifest = {"schemaVersion": 2, "mediaType": podman.OCI_MANIFEST,
                "config": {"mediaType": podman.OCI_CONFIG, "digest": "sha256:" + image_id,
                           "size": len(config_bytes)}, "layers": layers}
    if change is not None:
        change(manifest)
    manifest_bytes = json.dumps(manifest).encode()
    index = {"schemaVersion": 2, "mediaType": podman.OCI_INDEX,
             "manifests": [{"mediaType": podman.OCI_MANIFEST, "digest": "sha256:" + blob(manifest_bytes),
                            "size": len(manifest_bytes)}]}
    outer = [("oci-layout", "file", 0o644, b'{"imageLayoutVersion":"1.0.0"}', 0),
             ("index.json", "file", 0o644, json.dumps(index).encode(), 0),
             ("blobs", "dir", 0o755, None, 0), ("blobs/sha256", "dir", 0o755, None, 0)]
    outer += [(f"blobs/sha256/{d}", "file", 0o644, data, 0) for d, data in sorted(blobs.items())]
    return _tar_bytes(outer), image_id


def archive_image_id(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as tar:
        index = json.loads(tar.extractfile("index.json").read())
        digest = index["manifests"][0]["digest"][7:]
        manifest = json.loads(tar.extractfile(f"blobs/sha256/{digest}").read())
        return manifest["config"]["digest"][7:]


def _agent_change(name, edit):
    """A layer change of the agent file ending in `name` (None: removed)."""
    def change(entries):
        out = []
        for entry in entries:
            if entry[0].startswith(podman.AGENTS_ROOT + "/") and entry[0].endswith(name):
                entry = edit(entry)
            if entry is not None:
                out.append(entry)
        return out
    return change


def _relock(entry, registry):
    n, k, m, d, u = entry
    return n, k, m, d.replace(b"https://registry.npmjs.org/", registry.encode()), u


# A canonical image whose agents are not what its build checked.
AGENT_VARIANTS = {
    "agent_missing": _agent_change("claude-code/package.json", lambda e: None),
    "agent_version": _agent_change("codex/package.json", lambda e: (*e[:3], e[3].replace(b"2.0.0", b"2.0.1"), e[4])
                                   if "node_modules" in e[0] else e),
    "agent_registry": _agent_change("pi/package-lock.json", lambda e: _relock(e, "https://evil.example/")),
    "agent_writable": _agent_change("claude/package-lock.json", lambda e: (*e[:2], 0o666, *e[3:])),
    "agent_owner": _agent_change("pi/package.json", lambda e: (*e[:4], 1000)),
    "agent_link": _agent_change("codex/package-lock.json", lambda e: (e[0], "sym", 0o777, "/etc/passwd", 0)),
    "agent_twice": lambda entries: entries + [e for e in entries if e[0].endswith("pi/package.json")
                                              and "node_modules" not in e[0]],
}


# ---------------------------------------------------------------------------
# The stand-in podman. State: <graph>/fake.json (images, containers,
# volumes), one per store, as the engine's own database would be.

class Fake:
    def __init__(self, config_path):
        with open(config_path) as stream:
            self.config = json.load(stream)
        self.behaviour = self.config.get("podman", {})
        args = sys.argv[1:]
        self.globals = {}
        while args and args[0].startswith("--"):
            key, _, value = args.pop(0)[2:].partition("=")
            self.globals[key] = value
        self.args = args
        # A shared store (no --root): the user's own, under the given HOME.
        self.graph = self.globals.get("root") or os.path.join(os.environ["HOME"], "store")
        os.makedirs(self.graph, exist_ok=True)
        self.child = self.my_child()
        self.dispose = "/dispose-" in self.globals.get("runroot", "")

    def my_child(self):
        domain, me = self.config["domain"], str(os.getpid())
        for name in os.listdir(domain):
            procs = os.path.join(domain, name, "cgroup.procs")
            if os.path.isfile(procs) and me in slurp(procs, "r").split():
                return os.path.join(domain, name)
        return None

    def record(self):
        limits = {}
        if self.child is not None:
            for name in ("cpu.max", "memory.max", "memory.swap.max", "pids.max"):
                limits[name] = slurp(os.path.join(self.child, name), "r")
        fds = sorted(int(n) for n in os.listdir("/proc/self/fd"))
        record = {"pid": os.getpid(), "argv": sys.argv, "args": self.args, "globals": self.globals,
                  "env": dict(os.environ), "child": os.path.basename(self.child) if self.child else None,
                  "limits": limits, "fds": [fd for fd in fds if os.path.exists(f"/proc/self/fd/{fd}")],
                  "stdin": os.readlink("/proc/self/fd/0"), "time": time.monotonic(),
                  "fsize": __import__("resource").getrlimit(__import__("resource").RLIMIT_FSIZE)[0]}
        path = os.path.join(self.config["records"], f"call-{time.monotonic_ns()}-{os.getpid()}.json")
        write(path + ".tmp", json.dumps(record))
        os.rename(path + ".tmp", path)

    def db(self):
        try:
            with open(os.path.join(self.graph, "fake.json")) as stream:
                return json.load(stream)
        except FileNotFoundError:
            return {"images": [], "containers": {}, "volumes": [], "built": {}}

    def save_db(self, db):
        path = os.path.join(self.graph, "fake.json")
        write(path + ".tmp", json.dumps(db))
        os.rename(path + ".tmp", path)

    def daemon(self, kind, escape=False, init=False):
        """A detached helper: double fork + setsid, joins this caller's
        custody child (as the kernel's inheritance would), keeps every
        inherited descriptor (stdout/stderr included) and sleeps. With
        `escape`, one outside every custody child (no kill reaches it) that
        holds no inherited stdio, recorded apart (`escaped-PID`, its start
        time) so that only its own subreaper, never a later sweep, ends it.
        With `init` (a container's conmon): it forks the container's init
        into the same child, reaps it and exits with it; (pid, init pid).
        Killed first, conmon leaves that init to its subreaper unreaped."""
        r, w = os.pipe()
        first = os.fork()
        if first == 0:
            os.setsid()
            if os.fork() != 0:
                os._exit(0)
            if escape:
                null = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(null, fd)
                os.close(null)
            elif self.child is not None:
                with open(os.path.join(self.child, "cgroup.procs"), "a") as stream:
                    stream.write(f"{os.getpid()}\n")
            if escape:
                write(os.path.join(self.config["records"], f"escaped-{os.getpid()}"), str(stat_of(os.getpid())[2]))
            else:
                write(os.path.join(self.config["records"], f"daemon-{kind}-{os.getpid()}"), "")
            child = 0
            if init:
                child = os.fork()
                if child == 0:
                    os.close(w)
                    while True:
                        time.sleep(3600)
                if self.child is not None:
                    with open(os.path.join(self.child, "cgroup.procs"), "a") as stream:
                        stream.write(f"{child}\n")
                write(os.path.join(self.config["records"], f"daemon-init-{child}"), "")
            os.write(w, b"%d %d\n" % (os.getpid(), child))
            os.close(w)
            if init:
                os.waitpid(child, 0)
                os._exit(0)
            while True:
                time.sleep(3600)
        os.close(w)
        os.waitpid(first, 0)
        pid, child = (int(n) for n in os.read(r, 64).split())
        os.close(r)
        return (pid, child) if init else pid

    def pause(self):
        """The rootless pause process of this profile's XDG_RUNTIME_DIR."""
        tmp = os.path.join(os.environ["XDG_RUNTIME_DIR"], "libpod", "tmp")
        os.makedirs(tmp, exist_ok=True)
        pidfile = os.path.join(tmp, "pause.pid")
        if os.path.exists(pidfile):
            if _alive(int(slurp(pidfile, "r"))):
                return
            write(os.path.join(self.config["records"], f"stale-pause-{os.getpid()}"), "")
        write(pidfile, str(self.daemon("pause")))

    def fail(self, kind):
        if self.behaviour.get("fail") == kind:
            sys.exit(1)
        if self.behaviour.get("hang") == kind:
            while True:
                time.sleep(3600)

    def run(self):
        self.record()
        if not self.args and "version" in self.globals:
            # `--version` answers before any store or helper is touched.
            print(f"podman version {self.behaviour.get('version', '5.7.0')}")
            return
        command = self.args[0] if self.args else ""
        kind = command if command not in ("volume", "image", "container") else f"{command}-{self.args[1]}"
        if kind == "run":
            kind = "prepare" if podman.PREPARE_SCRIPT in self.args else "init"
        self.pause()
        if self.behaviour.get("escape") == kind:
            self.daemon("escaped", escape=True)
        self.fail(kind)
        getattr(self, "cmd_" + kind.replace("-", "_"))(self.args[2 if command in ("volume", "image", "container")
                                                               else 1:])

    # Commands.

    def cmd_load(self, args):
        source = next((a[8:] for a in args if a.startswith("--input=")), None)
        data = slurp(source) if source else sys.stdin.buffer.read()
        image_id = archive_image_id(data)
        db = self.db()
        db["images"].append(image_id)
        layers = os.path.join(self.graph, "vfs", "dir", image_id)
        os.makedirs(layers)
        write(os.path.join(layers, "layer"), data[:64])
        if not self.behaviour.get("writable"):
            os.chmod(layers, 0o555)  # subordinate-owned to the host
        self.save_db(db)
        print(f"Loaded image: sha256:{image_id}")

    def mounts(self, args):
        out = []
        for arg in args:
            if arg.startswith("--mount="):
                fields = dict(f.partition("=")[::2] for f in arg[8:].split(","))
                out.append({"type": fields["type"], "destination": fields["destination"],
                            "source": fields.get("source"), "subpath": fields.get("subpath"),
                            "access": "ro" if "ro" in fields else "rw"})
            elif arg.startswith("--tmpfs="):
                out.append({"type": "tmpfs", "destination": arg[8:].split(":")[0]})
        return out

    def cmd_create(self, args):
        db = self.db()
        image = next(a for a in args if not a.startswith("-") and len(a) == 64)
        if image not in db["images"]:
            sys.exit(125)
        if self.behaviour.get("create_out") is not None:
            print(self.behaviour["create_out"])
            return
        options = dict(a[2:].partition("=")[::2] for a in args if a.startswith("--") and "=" in a)
        name = options.get("name")
        if name is not None and any(c.get("name") == name and c["state"] != "removed"
                                    for c in db["containers"].values()):
            sys.exit(125)
        cid = hashlib.sha256(os.urandom(16)).hexdigest()
        mounts = self.mounts(args)
        if "volumepath" not in self.globals:
            # The user's store, as Podman does: a named volume that does
            # not exist is made by the create itself.
            for mount in mounts:
                if mount["type"] == "volume" and not os.path.isdir(self.volume_root(mount["source"])):
                    os.makedirs(os.path.join(self.volume_root(mount["source"]), "_data"))
                    write(os.path.join(self.config["records"], f"implicit-volume-{os.getpid()}"), "")
        db["containers"][cid] = {"args": args, "mounts": mounts, "image": image, "state": "created",
                                 "conmon": None, "volumepath": self.globals.get("volumepath")
                                 or os.path.join(self.graph, "volumes"), "name": name,
                                 "prepare": podman.PREPARE_SCRIPT in args}
        os.makedirs(os.path.join(self.graph, "containers", cid, "etc"))
        self.save_db(db)
        crash = self.behaviour.get("create")
        if "cidfile" in options and crash != "crash_nocid":
            write(options["cidfile"], cid)
        if crash in ("crash", "crash_nocid"):
            # Made (and, but for crash_nocid, its cidfile written); the
            # caller dies before it reads the ID.
            os.kill(os.getppid(), signal.SIGKILL)
            return
        print(cid)

    def cmd_cp(self, args):
        assert args[:2] == ["--archive=false", "-"], args
        cid, _, target = args[2].partition(":")
        db = self.db()
        container = db["containers"][cid]
        assert container["state"] == "created" and target == "/etc"
        files = {}
        with tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read()), mode="r:") as tar:
            for info in tar:
                data = tar.extractfile(info).read() if info.isreg() else None
                files[info.name] = {"mode": info.mode, "uid": info.uid, "gid": info.gid,
                                    "data": data.decode() if data is not None else None}
        container["provisioned"] = files
        self.save_db(db)

    def cmd_start(self, args):
        db = self.db()
        if args[0] == "--attach":
            # A shared store's transient preparation: runs to its end.
            container = db["containers"][args[1]]
            assert container["prepare"] and container["state"] == "created"
            container["state"] = "exited"
            self.save_db(db)
            if self.behaviour.get("prepare_attach") == "hang":
                while True:
                    time.sleep(3600)
            self.cmd_prepare(container["args"])
            return
        container = db["containers"][args[0]]
        container["conmon"], container["pid"] = self.daemon("conmon", init=True)
        container["state"] = "running"
        if not self.behaviour.get("writable"):
            os.chmod(os.path.join(self.graph, "containers", args[0]), 0o555)
        self.save_db(db)
        print(args[0])

    def cmd_rm(self, args):
        db = self.db()
        container = db["containers"].get(args[-1])
        if container is None or container["state"] == "removed":
            sys.exit(0 if "--ignore" in args else 1)
        if container.get("pid"):
            # Podman's StopContainer: SIGKILL, then kill(pid, 0) until ESRCH
            # (killContainerTimeout); an unreaped zombie never is.
            try:
                os.kill(container["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + self.behaviour.get("kill_timeout", 1.0)
            while True:
                try:
                    os.kill(container["pid"], 0)
                except ProcessLookupError:
                    break
                if time.monotonic() >= deadline:
                    print("given PID did not die within timeout", file=sys.stderr)
                    sys.exit(125)
                time.sleep(0.01)
        if container["conmon"]:
            try:
                os.kill(container["conmon"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        container["state"] = "removed"
        self.save_db(db)

    def cmd_info(self, args):
        """The user's store's paths (SHARED_INFO_COMMAND) on stdout, its
        static and tmp dirs in stderr's debug lines; `info_out`, `info_err`:
        those texts instead; `static_dir`, `tmp_dir`: those dirs."""
        assert args == list(podman.SHARED_INFO_COMMAND[1:]), args
        if self.behaviour.get("info_err") is not None:
            sys.stderr.write(self.behaviour["info_err"])
        else:
            sys.stderr.write('time="t" level=info msg="podman filtering at log level debug"\n')
            for kind, default in (("static", self.graph + "/libpod"),
                                  ("tmp", os.environ["XDG_RUNTIME_DIR"] + "/libpod/tmp")):
                path = self.behaviour.get(f"{kind}_dir", default)
                sys.stderr.write(f'time="t" level=debug msg="Using {kind} dir {path}"\n')
        if self.behaviour.get("info_out") is not None:
            print(self.behaviour["info_out"])
            return
        print(json.dumps([self.graph, os.environ["XDG_RUNTIME_DIR"] + "/containers",
                          os.path.join(self.graph, "volumes"), os.environ["HOME"] + "/.config/containers/storage.conf",
                          self.config["tools"]["crun"], self.config["tools"]["conmon"]], separators=(",", ":")))

    def cmd_image_exists(self, args):
        sys.exit(0 if args[0] in self.db()["images"] else 1)

    def cmd_container_exists(self, args):
        container = self.db()["containers"].get(args[0])
        sys.exit(0 if container is not None and container["state"] != "removed" else 1)

    def cmd_rmi(self, args):
        assert args == ["--all", "--force"], args
        if self.dispose and self.behaviour.get("dispose_fail"):
            sys.exit(1)
        for sub in ("vfs", "containers"):
            path = os.path.join(self.graph, sub)
            if os.path.exists(path):
                remove_tree(path)
        db = self.db()
        db["images"], db["containers"] = [], {}
        self.save_db(db)

    def volume_root(self, name):
        return os.path.join(self.globals.get("volumepath") or os.path.join(self.graph, "volumes"), name)

    def cmd_volume_exists(self, args):
        if self.behaviour.get("volume_absent"):
            # Taken right after this answer (a concurrent create).
            sys.exit(1)
        sys.exit(0 if os.path.isdir(self.volume_root(args[0])) else 1)

    def cmd_volume_create(self, args):
        if "volumepath" not in self.globals:
            # The user's store: the name must be free; labels kept.
            assert args[:4] in (["--driver=local", "--uid=1000", "--gid=1000", "--opt=nocopy"],
                                ["--driver=local", "--uid=0", "--gid=0", "--opt=nocopy"]) and len(args) == 6 \
                and args[4].startswith(f"--label={podman.LABEL_RUN}="), args
            if os.path.isdir(self.volume_root(args[-1])):
                sys.exit(125)
            os.makedirs(os.path.join(self.volume_root(args[-1]), "_data"))
            write(os.path.join(self.volume_root(args[-1]), "labels"), args[4])
            if self.behaviour.get("volume_create") == "crash":
                os.kill(os.getppid(), signal.SIGKILL)
            print(self.behaviour.get("volume_create_out", args[-1]))
            return
        assert args[:5] in (["--driver=local", "--uid=1000", "--gid=1000", "--opt=nocopy", podman.VOLUME],
                            ["--driver=local", "--uid=0", "--gid=0", "--opt=nocopy", podman.VOLUME]), args
        data = os.path.join(self.volume_root(args[-1]), "_data")
        os.makedirs(data, exist_ok=True)
        os.chmod(data, 0o555)
        if self.behaviour.get("volume_create") == "crash":
            # Allocated; the caller dies before it can publish the pin.
            os.kill(os.getppid(), signal.SIGKILL)
        print(args[-1])

    def cmd_volume_rm(self, args):
        if self.behaviour.get("volume_rm_fail"):
            sys.exit(1)
        if "volumepath" not in self.globals:
            # The user's store: 1 no such volume, 2 in use, never forced.
            assert args == [args[-1]], args
            if self.behaviour.get("volume_rm_status"):
                sys.exit(self.behaviour["volume_rm_status"])
            if not os.path.isdir(self.volume_root(args[-1])):
                sys.exit(1)
            if any(c["state"] != "removed" and any(m["type"] == "volume" and m["source"] == args[-1]
                                                   for m in c["mounts"]) for c in self.db()["containers"].values()):
                sys.exit(2)
            remove_tree(self.volume_root(args[-1]))
            print(args[-1])
            return
        if self.behaviour.get("volume_rm") == "rename_out":
            # Gone from its parent, not detached: still linked elsewhere.
            os.rename(self.volume_root(args[-1]), os.path.join(self.config["records"], "renamed-volume"))
            print(args[-1])
            return
        remove_tree(self.volume_root(args[-1]))
        if self.behaviour.get("volume_rm") == "crash":
            # Physically detached; the caller dies before its receipt.
            os.kill(os.getppid(), signal.SIGKILL)
        print(args[-1])

    def cmd_init(self, args):
        script = args[-1]
        mount = next(m for m in self.mounts(args) if m["type"] == "volume")
        data = os.path.join(self.volume_root(mount["source"]), "_data")
        os.chmod(data, 0o755)
        os.makedirs(os.path.join(data, "home"), 0o700, exist_ok=True)
        if "/home/agentbox/tmp" in script:
            os.makedirs(os.path.join(data, "tmp"), exist_ok=True)
            os.chmod(os.path.join(data, "tmp"), 0o1777)
        os.chmod(data, 0o555)

    def cmd_prepare(self, args):
        """PREPARE_SCRIPT on the volume's `home` subpath: exit 3 at a
        symlink or non-directory, else each missing component made (exit 4
        if it cannot be); `prepare_exit`: that status at once."""
        if self.behaviour.get("prepare_exit"):
            sys.exit(self.behaviour["prepare_exit"])
        mount = next(m for m in self.mounts(args) if m["type"] == "volume")
        home = os.path.join(self.volume_root(mount["source"]), "_data", (mount["subpath"] or "").lstrip("/"))
        destinations = args[args.index(podman.PREPARE_SCRIPT) + 3:]
        retarget = self.behaviour.get("retarget")
        if retarget:
            # A host change while the helper runs: the source's symlink now
            # names another directory.
            os.unlink(retarget[0])
            os.symlink(retarget[1], retarget[0])
        if self.behaviour.get("unlink_limits"):
            # ... and the host's limits file gone with it.
            os.unlink(self.config["scopes"])
        for destination in destinations:
            at = home
            for part in destination.split("/"):
                at = os.path.join(at, part)
                if os.path.islink(at):
                    sys.exit(3)
                if not os.path.exists(at):
                    try:
                        os.mkdir(at, 0o700)
                    except OSError:
                        sys.exit(4)
                if not os.path.isdir(at):
                    sys.exit(3)

    def cmd_exec(self, args):
        cid = args[4]
        db = self.db()
        container = db["containers"].get(cid)
        if container is None or container["state"] != "running" or not _alive(container["conmon"]):
            sys.exit(125)
        self.daemon("exec-conmon")
        Sshd(self, container, cid).serve()

    def cmd_build(self, args):
        with open(self.config["records"] + "/build-count", "a") as stream:
            stream.write("x")
        options = dict(a[2:].partition("=")[::2] for a in args if a.startswith("--") and "=" in a)
        context = args[-1]
        with open(os.path.join(os.path.dirname(context), "stage.json")) as stream:
            revision = json.load(stream)["worker"]["sources"]["revision"]
        variant = self.behaviour.get("variant")
        work = tempfile.mkdtemp(dir=os.environ["TMPDIR"])
        change = None
        if variant == "tamper":
            def change(entries):
                return [(n, k, m, (d + b"\n" if n.endswith("protocol.py") else d), u) for n, k, m, d, u in entries]
        elif variant == "unsealed":
            def change(entries):
                return [(n, k, (0o644 if n.endswith("main.py") else m), d, u) for n, k, m, d, u in entries]
        elif variant in AGENT_VARIANTS:
            change = AGENT_VARIANTS[variant]
        entries, _ = baked_entries(os.path.join(work, "bundle"),
                                   revision="c" * 64 if variant == "revision" else revision, change=change,
                                   agents=self.behaviour.get("agents", "2.0.0"))
        data, image_id = oci_archive(entries)
        db = self.db()
        db["built"][image_id] = data.hex()
        db["images"].append(image_id)
        self.save_db(db)
        layers = os.path.join(self.graph, "vfs", "dir", image_id)
        os.makedirs(layers)
        write(os.path.join(layers, "layer"), b"x")
        os.chmod(layers, 0o555)  # subordinate-owned to the host
        if variant != "no_iid":
            write(options["iidfile"], "sha256:" + ("0" * 64 if variant == "iid" else image_id))
        if variant == "lock_scratch":
            locked = os.path.join(context, "locked")
            os.makedirs(os.path.join(locked, "x"))
            os.chmod(locked, 0o555)
        write(os.path.join(self.config["records"], "build-file"), slurp(options["file"]))

    def cmd_save(self, args):
        assert args[0] == "--format=oci-archive", args
        out = args[1].partition("=")[2]
        db = self.db()
        write(out, bytes.fromhex(db["built"].get(args[2]) or next(iter(db["built"].values()))))


class Sshd:
    """The bridge's sshd stand-in: a banner, then line commands."""

    def __init__(self, fake, container, cid):
        self.fake, self.container, self.cid = fake, container, cid
        self.out = sys.stdout.buffer
        self.inp = sys.stdin.buffer

    def host_path(self, path):
        best = None
        for mount in self.container["mounts"]:
            dest = mount["destination"]
            if (path == dest or path.startswith(dest + "/")) and (best is None or len(dest) > len(best["destination"])):
                best = mount
        rest = path[len(best["destination"]):]
        if best["type"] == "bind":
            return best["source"] + rest, best["access"]
        if best["type"] == "volume":
            return (os.path.join(self.container["volumepath"], best["source"], "_data") + (best["subpath"] or "")
                    + rest, best["source"])
        base = os.path.join(self.fake.graph, "tmpfs", self.cid, best["destination"].strip("/").replace("/", "_"))
        return base + rest, False

    def reply(self, data):
        self.out.write(data)
        self.out.flush()

    def serve(self):
        self.reply(b"SSH-2.0-stand-in\r\n")
        while True:
            line = self.inp.readline()
            if not line:
                return
            words = line.decode().split()
            if words[0] == "put":
                path, volume = self.host_path(words[1])
                if volume == "ro":
                    self.reply(b"erofs\n")
                    continue
                if volume == "rw":
                    write(path, bytes.fromhex(words[2]))
                    self.reply(b"ok\n")
                    continue
                data_root = os.path.join(self.container["volumepath"] or "", volume or "", "_data")
                if volume:
                    os.chmod(data_root, 0o755)
                write(path, bytes.fromhex(words[2]))
                if volume:
                    os.chmod(data_root, 0o555)
                self.reply(b"ok\n")
            elif words[0] == "get":
                path, _ = self.host_path(words[1])
                self.reply((slurp(path).hex() if os.path.exists(path) else "missing").encode() + b"\n")
            elif words[0] == "raw":
                size = int(words[1])
                data = b""
                while len(data) < size:
                    chunk = self.inp.read(size - len(data))
                    if not chunk:
                        return
                    data += chunk
                self.reply(hashlib.sha256(data).hexdigest().encode() + b"\n" + data)
            elif words[0] == "auth":
                files = self.container.get("provisioned", {})
                self.reply(json.dumps(files).encode() + b"\n")
            elif words[0] == "spawn":
                self.reply(b"%d\n" % self.fake.daemon("session"))
            elif words[0] == "exit":
                return


def fake_podman(config_path):
    Fake(config_path).run()


# ---------------------------------------------------------------------------
# The stand-in host.

class AppendChild(common.Child):
    """The kernel keeps every member; an ordinary file needs O_APPEND for
    several joins to the same child (bridges, helpers) to all stay listed."""

    def join_fd(self):
        return os.open("cgroup.procs", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)


class FakeCustody(test_qemu.FakeCustody):
    immune_prefixes = ()

    def existing(self, name, identity=None):
        child = super().existing(name, identity)
        if child is not None:
            child.__class__ = AppendChild
        return child

    def kill(self, child):
        if self.immune_prefixes and child.name.startswith(tuple(self.immune_prefixes)):
            return
        super().kill(child)


# The host PATH a stand-in invocation gets: its relative and empty entries
# ignored, so the engine's own PATH is SEARCH.
HOST_PATH, SEARCH = "/usr/bin:relative::/bin", "/usr/bin:/bin"
# Ambient host values the provider inherits (tools.rs host_env) that must
# never select a remote engine, configuration or credential, nor reach any
# engine invocation's environment or argv.
AMBIENT = {"CONTAINER_HOST": "unix:///tmp/agentbox-synthetic-remote.sock",
           "CONTAINER_CONNECTION": "agentbox-synthetic-connection", "DOCKER_HOST": "tcp://synthetic.invalid:2375",
           "CONTAINERS_CONF": "/tmp/agentbox-synthetic-containers.conf",
           "CONTAINERS_STORAGE_CONF": "/tmp/agentbox-synthetic-storage.conf",
           "REGISTRY_AUTH_FILE": "/tmp/agentbox-synthetic-auth.json", "HOST_FAKE_SECRET": "synthetic-secret-9d04",
           "https_proxy": "http://synthetic-proxy.invalid:3128", "XDG_RUNTIME_DIR": "/tmp/agentbox-synthetic-xdg"}


class TestHost(podman.Host):
    def __init__(self, config):
        # The real limits-file read: the case's own declared scopes.
        environ = dict(test_qemu.scopes_environ(config), PATH=HOST_PATH, **AMBIENT)
        environ.update(config.get("environ", {}))
        super().__init__(environ=environ)
        self.config = config

    def proc(self):
        return self.config.get("proc", "/proc")

    def tool(self, name):
        return self.config["tools"][name]

    def custody(self):
        if self._custody is None:
            domain = self.config["domain"]
            fd = os.open(domain, os.O_RDONLY | os.O_DIRECTORY)
            self._custody = FakeCustody(domain, fd)
            self._custody.immune_prefixes = tuple(self.config.get("immune", ()))
        return self._custody

    def rootless(self):
        pass

    def executable_tmpfs(self, fd):
        # Only the filesystem type is assumed; safe_dir's walk is real.
        return self.config.get("tmpfs", True)

    def sync(self):
        write(os.path.join(self.config["records"], f"sync-{time.monotonic_ns()}"), "")

    def admitted(self):
        """A bridge paused between its live check and its spawn, its shared
        admission lock held, until the test's `pause_bridge` file exists."""
        go = self.config.get("pause_bridge")
        if go is None:
            return
        write(os.path.join(self.config["records"], f"bridge-paused-{os.getpid()}"), "")
        deadline = time.monotonic() + 60
        while not os.path.exists(go) and time.monotonic() < deadline:
            time.sleep(0.02)


def run_stand_in():
    with open(os.environ["AGENTBOX_TEST_HOST"]) as stream:
        config = json.load(stream)
    common.KILL_RESERVE = config.get("kill_reserve", common.KILL_RESERVE)
    # The asset root a Prepare case's fake source tree stands in for.
    podman.ROOT = config.get("root", podman.ROOT)
    podman.ADMISSION_WAIT = config.get("admission_wait", podman.ADMISSION_WAIT)
    if config.get("deny_pidfd"):
        test_qemu.deny_pidfd(config["deny_pidfd"])
    podman.PREPARE_MIN_FREE = config.get("min_free", 0)
    podman.STORE_MIN_FREE = config.get("min_free", 0)
    test_qemu.fake_devices(config.get("fake_devices", {}))
    test_qemu.fail_methods(podman.Provider, config.get("fail_methods", {}))
    if config.get("replace_staging"):
        replace_staging()
    if config.get("move_work"):
        test_qemu.move_work(config["move_work"])
    if config.get("fail_unlink"):
        fail_unlink(config["fail_unlink"])
    if config.get("record_fault"):
        record_fault(config["record_fault"])
    sys.exit(podman.main(sys.argv[1:], host=TestHost(config)))


def stat_of(pid):
    """(state, ppid, start time) of `pid`; None once it is gone."""
    try:
        with open(f"/proc/{pid}/stat") as stream:
            fields = stream.read().rsplit(")", 1)[1].split()
    except OSError:
        return None
    return fields[0], int(fields[1]), int(fields[19])


def reaped(pid, seen):
    """`pid`, seen as `seen` (stat_of), is gone: not even a zombie."""
    now = stat_of(pid)
    return now is None or now[2] != seen[2]


def barrier_fixture():
    """`barrier_fixture REPORT ARGV...`: a stand-in worker. A child
    subreaper that runs ARGV (one control invocation, on this process's
    stdin/stdout/stderr and environment) in its own session, as the host
    does. Any other child of this fixture, live or exited, while the
    control runs or after its exit, is an orphan the control did not keep:
    each is recorded once; an exited one is reaped at once, live ones are
    killed through pidfds and reaped once the control ended. Only this
    fixture's own children are ever signalled."""
    report, argv = sys.argv[1], sys.argv[2:]
    common.subreaper()
    strays, code = {}, None
    control = subprocess.Popen([sys.executable, "-I", "-B"] + argv, start_new_session=True)
    # The test gave up: end the control (exactly, through its Popen), then
    # settle as ever.
    signal.signal(signal.SIGTERM, lambda *_: control.send_signal(signal.SIGKILL))
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            done = control.poll() is not None
            for pid in common.children() or []:
                if pid != control.pid and pid not in strays:
                    seen = stat_of(pid)
                    strays[pid] = seen[0] if seen is not None else "?"
                if pid != control.pid:
                    os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG)
            if done:
                code = control.returncode
                break
            time.sleep(0.02)
    finally:
        if control.poll() is None:
            control.kill()
            control.wait()
        # The control reaped: every child left is an orphan of this fixture.
        common.settle_children(time.monotonic() + 10, kill=True)
        write(report, json.dumps({"strays": sorted(strays.values()), "code": code}))


def fail_unlink(names):
    """Unlinking these names in podman.remove_secrets fails (ENOSPC)."""
    real = common.Dir.unlink

    def unlink(self, name):
        if name in names and sys._getframe(1).f_code.co_name == "remove_secrets":
            raise OSError(errno.ENOSPC, "fault")
        return real(self, name)
    common.Dir.unlink = unlink


def record_fault(fault):
    """Writing resource.json whose volume state is `fault["volume"]` fails
    (ENOSPC) or kills this process first (`fault["action"]` "kill")."""
    real = common.Dir.write_json

    def write_json(self, name, value, mode=0o600):
        if name == "resource.json" and (value.get("volume") or {}).get("state") == fault["volume"]:
            if fault["action"] == "kill":
                os.kill(os.getpid(), signal.SIGKILL)
            raise OSError(errno.ENOSPC, "fault")
        return real(self, name, value, mode)
    common.Dir.write_json = write_json


def replace_staging():
    """The staging entry is swapped for another directory, then a write
    fails."""
    def write_entry(self, entry, name, data):
        os.chmod(entry.path, 0o700)
        os.rename(entry.path, entry.path + "-original")
        os.mkdir(entry.path)
        write(os.path.join(entry.path, "keep"), "replacement")
        raise OSError(errno.ENOSPC, "fault")
    podman.Provider.write_entry = write_entry


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abp-")
        self.addCleanup(remove_tree, self.tmp)
        self.state = os.path.join(self.tmp, "state")
        os.mkdir(self.state, 0o700)
        self.storage = os.path.join(self.tmp, "storage")
        os.mkdir(self.storage, 0o700)
        self.domain = make_domain(self.tmp)
        self.records = os.path.join(self.tmp, "records")
        os.mkdir(self.records)
        tools = os.path.join(self.tmp, "tools")
        os.mkdir(tools)
        self.config_path = os.path.join(self.tmp, "host.json")
        self.config = {"domain": self.domain, "records": self.records, "podman": {},
                       "tools": {"ssh-keygen": KEYGEN}}
        test_qemu.declare(self.tmp, self.config, [
            {"path": os.path.realpath(self.state), "measure": "tree", "uncapped": ["resources"]},
            {"path": os.path.realpath(self.storage), "measure": "filesystem"}])
        write(os.path.join(tools, "podman"), f"#!{sys.executable} -IBS\nimport sys\nsys.path.insert(0, {HERE!r})\n"
                                             f"import test_podman\ntest_podman.fake_podman({self.config_path!r})\n",
              0o755)
        for name in ("conmon", "crun"):
            write(os.path.join(tools, name), "#!/bin/false\n", 0o755)
        for name in podman.PROGRAMS:
            self.config["tools"][name] = os.path.join(tools, name)
        self.save()
        inputs = os.path.join(self.state, "inputs")
        os.mkdir(inputs, 0o700)
        write(os.path.join(inputs, podman.INPUTS), json.dumps({
            "schema": podman.INPUTS_SCHEMA, "storage_root": self.storage,
            "build_args": {"GIT_SHA256": "1" * 64}}), 0o600)
        self.runner = os.path.join(self.tmp, "runner.py")
        write(self.runner, f"import sys\nsys.path.insert(0, {HERE!r})\nimport test_podman\n"
                           "test_podman.run_stand_in()\n")
        self.ops = 0
        self.live = []
        self.addCleanup(self.reap)

    def reap(self):
        for invocation in self.live:
            if invocation.proc.poll() is None:
                invocation.proc.kill()
                invocation.proc.wait()
            for stream in (invocation.proc.stdin, invocation.proc.stdout, invocation.proc.stderr):
                try:
                    stream.close()
                except OSError:
                    pass
        for pid in self.daemons():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def save(self):
        write(self.config_path, json.dumps(self.config))

    def op(self):
        self.ops += 1
        return f"op-{self.ops}"

    def frame(self, kind, timeout_ms=30000, **fields):
        frame = {"type": kind, "operation": self.op(), "timeout_ms": timeout_ms}
        frame.update(fields)
        return frame

    def invoke(self, args=None):
        invocation = test_qemu.Invocation(self, args or ["control", self.state])
        self.live.append(invocation)
        return invocation

    def call(self, kind, **fields):
        invocation = self.invoke()
        request = self.frame(kind, **fields)
        invocation.send(request)
        answer = invocation.read(60)
        code, rest, _ = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        self.assertEqual(answer["operation"], request["operation"])
        return answer

    def assert_failed(self, answer, code, settlement="settled", durability="unchanged"):
        self.assertEqual(answer["type"], "failed", answer)
        self.assertEqual((answer["code"], answer["settlement"], answer["durability"]),
                         (code, settlement, durability))

    def calls(self, command=None):
        out = []
        for name in sorted(os.listdir(self.records)):
            if name.startswith("call-") and name.endswith(".json"):
                with open(os.path.join(self.records, name)) as stream:
                    record = json.load(stream)
                if command is None or (record["args"][:1] == [command] if " " not in command
                                       else record["args"][:2] == command.split(" ")):
                    out.append(record)
        return out

    def daemons(self, kind=None):
        if not os.path.isdir(self.records):
            return []
        return [int(n.rsplit("-", 1)[1]) for n in os.listdir(self.records)
                if n.startswith("daemon-") and (kind is None or n.startswith(f"daemon-{kind}-"))]

    def stale(self):
        return [n for n in os.listdir(self.records) if n.startswith("stale-")]

    def install_image(self, entries=None, **kw):
        """A cached image as prepare publishes it."""
        if entries is None:
            entries, _ = baked_entries(os.path.join(self.tmp, f"bundle-{self.op()}"))
        data, image_id = oci_archive(entries, **kw)
        image = hashlib.sha256(data).hexdigest()
        entry = os.path.join(self.state, "images", image)
        os.makedirs(entry)
        os.chmod(os.path.join(self.state, "images"), 0o700)
        write(os.path.join(entry, "image.oci.tar"), data, 0o400)
        metadata = next(d for n, _, _, d, _ in entries if n == podman.WORKER_METADATA)
        write(os.path.join(entry, "worker-metadata.json"), metadata, 0o400)
        release = json.loads(metadata)["release"]
        record = {"schema": podman.CACHE_SCHEMA, "image": image, "image_id": image_id, "bytes": len(data),
                  "fingerprint": common.fingerprint(os.stat(os.path.join(entry, "image.oci.tar"))),
                  "worker": release, "layer": {}, "origin": {}, "accounts": ACCOUNTS}
        write(os.path.join(entry, "record.json"), json.dumps(record), 0o400)
        os.chmod(entry, 0o500)
        return image, release, image_id

    def create(self, image, resource="res-1", run="run-1", retention="none", user="agentbox"):
        answer = self.call("create", run=run, resource=resource, image=image, retention=retention, user=user)
        self.assertEqual(answer["type"], "created", answer)
        return answer

    def resource_dir(self, resource="res-1"):
        return os.path.join(self.state, "resources", resource)

    def read_json(self, *parts):
        with open(os.path.join(*parts)) as stream:
            return json.load(stream)

    def instance(self, instance="in-1", resource="res-1"):
        return self.read_json(self.resource_dir(resource), "instances", instance, "instance.json")

    def start(self, generation=0, resource="res-1", run="run-1", execution="ex-1", instance="in-1",
              accept_unclean=False, limits=None, timeout_ms=60000, key=None, invocation=None):
        invocation = invocation or self.invoke()
        request = self.frame("start", timeout_ms=timeout_ms, run=run, resource=resource, execution=execution,
                             instance=instance, generation=generation, accept_unclean=accept_unclean,
                             authorized_key=key or public_key(), limits=limits or {})
        invocation.send(request)
        return invocation, request

    def started(self, **kw):
        invocation, request = self.start(**kw)
        answer = invocation.read(60)
        self.assertEqual(answer["type"], "started", answer)
        return invocation, request, answer

    def stop_frame(self, start, timeout_ms=60000):
        return self.frame("stop", timeout_ms=timeout_ms, run=start["run"], resource=start["resource"],
                          execution=start["execution"], instance=start["instance"], generation=start["generation"])

    def owner_stop(self, invocation, request, timeout_ms=60000):
        invocation.send(self.stop_frame(request, timeout_ms))
        answer = invocation.read(60)
        code, rest, _ = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        return answer

    def standalone_stop(self, request):
        return self.call("stop", run=request["run"], resource=request["resource"], execution=request["execution"],
                         instance=request["instance"], generation=request["generation"])

    def connect(self, request):
        return Bridge(self, request)

    def stores(self):
        return sorted(os.listdir(self.storage))

    def assert_no_daemons(self):
        alive = [pid for pid in self.daemons() if _alive(pid)]
        self.assertEqual(alive, [])


class Mirrored(test_qemu.Invocation):
    """One control invocation under `barrier_fixture`, which writes
    `report` once it ends. Not ended in time: SIGTERM, on which the fixture
    kills its control and settles its own children itself."""

    def __init__(self, case, report, args):
        fixture = os.path.join(case.tmp, "fixture.py")
        write(fixture, f"import sys\nsys.path.insert(0, {HERE!r})\nimport test_podman\n"
                       "test_podman.barrier_fixture()\n")
        self.proc = subprocess.Popen([sys.executable, "-I", "-B", fixture, report, case.runner] + list(args),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={"AGENTBOX_TEST_HOST": case.config_path})
        self.buffer = b""

    def finish(self, timeout=30):
        try:
            return super().finish(timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            self.proc.wait(30)
            raise


class Bridge:
    """One `connect` subprocess and its raw byte stream."""

    def __init__(self, case, request):
        self.invocation = case.invoke(["connect", case.state, request["run"], request["execution"],
                                       request["instance"]])
        self.proc = self.invocation.proc
        self.buffer = b""

    def send(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read(self, size=None, line=False, timeout=30):
        deadline = time.monotonic() + timeout
        while (line and b"\n" not in self.buffer) or (size is not None and len(self.buffer) < size):
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.proc.stdout], [], [], left)[0]:
                raise AssertionError("bridge read timed out")
            data = os.read(self.proc.stdout.fileno(), 1 << 16)
            if not data:
                raise AssertionError("bridge closed")
            self.buffer += data
        if line:
            out, self.buffer = self.buffer.split(b"\n", 1)
            return out + b"\n"
        out, self.buffer = self.buffer[:size], self.buffer[size:]
        return out

    def command(self, text):
        self.send(text.encode() + b"\n")
        return self.read(line=True).decode().strip()

    def finish(self, timeout=30):
        return self.invocation.finish(timeout)


# ---------------------------------------------------------------------------
# Pure checks.

class Profile(unittest.TestCase):
    PROGRAMS = {"podman": "/usr/bin/podman", "conmon": "/usr/bin/conmon", "crun": "/usr/bin/crun"}

    def test_every_engine_invocation_is_closed_and_private(self):
        store = podman.Store("/srv/s/s-" + "a" * 32, self.PROGRAMS, volumes="/st/resources/r/volumes",
                             search=SEARCH)
        root = store.path
        # Without a host PATH the engine gets none, never an empty one.
        self.assertNotIn("PATH", podman.Store(root, self.PROGRAMS).env())
        self.assertEqual(store.env(), {
            "PATH": SEARCH, "LC_ALL": "C", "HOME": root + "/home", "TMPDIR": root + "/tmp",
            "XDG_RUNTIME_DIR": root + "/xdg-run", "XDG_CONFIG_HOME": root + "/xdg-config",
            "XDG_DATA_HOME": root + "/xdg-data", "XDG_CACHE_HOME": root + "/xdg-cache",
            "CONTAINERS_CONF": root + "/conf/containers.conf", "CONTAINERS_STORAGE_CONF": root + "/conf/storage.conf",
            "CONTAINERS_REGISTRIES_CONF": root + "/conf/registries.conf",
            "DBUS_SESSION_BUS_ADDRESS": f"unix:path={root}/absent-bus"})
        self.assertEqual(store.global_args(), [
            "--remote=false", f"--root={root}/graph", f"--runroot={root}/run", "--storage-driver=vfs",
            "--cgroup-manager=cgroupfs", "--events-backend=none", f"--tmpdir={root}/run/libpod",
            "--runtime=/usr/bin/crun", "--conmon=/usr/bin/conmon", f"--hooks-dir={root}/hooks",
            f"--network-config-dir={root}/network", "--log-level=error", "--volumepath=/st/resources/r/volumes"])
        conf = store.containers_conf()
        for line in ('cgroups = "disabled"', 'netns = "none"', 'read_only = true', "default_capabilities = []",
                     "env_host = false", "http_proxy = false", "volumes = []", "devices = []",
                     f'hooks_dir = ["{root}/hooks"]', 'detach_keys = ""', 'agentbox = ["/usr/bin/crun"]',
                     'conmon_path = ["/usr/bin/conmon"]', 'events_logger = "none"'):
            self.assertIn(line + "\n", conf)
        self.assertEqual(store.registries_conf(), 'unqualified-search-registries = []\nshort-name-mode = "enforcing"\n')
        files = dict(store.files())
        self.assertEqual(files["home/.config/containers/mounts.conf"], b"")
        self.assertEqual(json.loads(files["home/.config/containers/policy.json"]),
                         {"default": [{"type": "insecureAcceptAnything"}]})
        # The disposal profile: its own everything but graph/, no volumes.
        dispose = podman.Store(root, self.PROGRAMS, volumes="/st/v", dispose="dispose-3")
        args = dispose.global_args("dispose")
        self.assertIn(f"--root={root}/graph", args)
        self.assertTrue(all(a.startswith(f"--{k}={root}/dispose-3/") for a in args
                            for k in ("runroot", "tmpdir", "hooks-dir", "network-config-dir")
                            if a.startswith(f"--{k}=")))
        self.assertFalse(any(a.startswith("--volumepath") for a in args))
        env = dispose.env("dispose")
        self.assertTrue(all(v.startswith(f"{root}/dispose-3/") for k, v in env.items()
                            if k not in ("PATH", "LC_ALL", "DBUS_SESSION_BUS_ADDRESS")))
        dconf = dispose.containers_conf("dispose")
        self.assertIn('database_backend = "sqlite"\nlock_type = "file"\n', dconf)
        self.assertNotIn(f"{root}/static", dconf)
        self.assertIn(f'graphroot = "{root}/graph"', dispose.storage_conf("dispose"))

    def test_the_container_profile_is_fixed(self):
        image = "f" * 64
        none = podman.create_command(image, "none", "agentbox")
        for word in podman.SANDBOX + ("--user=1000:1000", "--workdir=/home/agentbox", "--entrypoint=/usr/bin/tini",
                                      "--env=HOME=/home/agentbox", "--env=USER=agentbox",
                                      "--passwd-entry=agentbox:x:1000:1000:agentbox:/home/agentbox:/bin/sh",
                                      "--group-entry=agentbox:x:1000:"):
            self.assertIn(word, none)
        # /dev/shm: the container's own writable tmpfs, bounded (`--read-only-tmpfs=false`
        # left the engine's read-only: interactive staging failed natively).
        shm = "--mount=type=tmpfs,destination=/dev/shm,rw,noexec,nosuid,nodev,tmpfs-size=64m,tmpfs-mode=1777"
        for retention in podman.RETENTION:
            words = podman.create_command(image, retention, "agentbox")
            self.assertEqual([w for w in words if "/dev/shm" in w or w.startswith("--shm")], [shm])
            self.assertIn("--read-only", words)
            self.assertIn("--ipc=private", words)
        self.assertEqual(none[-4:], [image, "--", "/usr/bin/sleep", "infinity"])
        self.assertIn("--mount=type=tmpfs,destination=/home/agentbox,rw,exec,nosuid,nodev,tmpfs-size=1024m,"
                      "tmpfs-mode=0700,U=true", none)
        self.assertFalse(any("type=volume" in w or "--volume" in w or "--publish" in w or "-p" == w for w in none))
        # The launcher's control tmpfs whatever the retention (`started` `control`).
        control = ("--mount=type=tmpfs,destination=/run/agentbox-control,rw,exec,nosuid,nodev,tmpfs-size=1024m,"
                   "tmpfs-mode=0700,U=true")
        self.assertIn(control, none)
        home = podman.create_command(image, "home", "agentbox")
        self.assertIn("--mount=type=volume,source=agentbox-workspace,destination=/home/agentbox,subpath=/home,rw,"
                      "exec,nosuid,nodev", home)
        self.assertIn("--mount=type=tmpfs,destination=/run/agentbox-control,rw,exec,nosuid,nodev,tmpfs-size=1024m,"
                      "tmpfs-mode=0700,U=true", home)
        self.assertIn("--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=512m,mode=1777", home)
        both = podman.create_command(image, "home_tmp", "agentbox")
        self.assertIn("--mount=type=volume,source=agentbox-workspace,destination=/tmp,subpath=/tmp,rw,noexec,"
                      "nosuid,nodev", both)
        # Never the volume's root in a task container.
        self.assertFalse(any("type=volume" in w and "subpath=" not in w for w in home + both))
        self.assertEqual(podman.exec_command("e" * 64), [
            "exec", "-i", "--tty=false", "--detach-keys=", "--user=1000:1000", "e" * 64, "/usr/sbin/sshd", "-i", "-f",
            "/etc/agentbox-ssh/sshd_config"])
        for bad in ("../x", "F" * 64, "f" * 63):
            with self.assertRaises(common.Failure):
                podman.create_command(bad, "none", "agentbox")
        for bad in ("Asen", "a.b", "", "a" * 33, "1a", "a b"):
            for build in (lambda: podman.create_command(image, "none", bad),
                          lambda: podman.init_command(image, "home", bad), lambda: podman.sshd_config(bad)):
                with self.assertRaises(common.Failure):
                    build()

    def test_a_selected_account_is_engine_generated_at_its_home(self):
        image = "f" * 64
        for retention in podman.RETENTION:
            words = podman.create_command(image, retention, "dev_1")
            self.assertIn("--passwd-entry=dev_1:x:1000:1000:dev_1:/home/dev_1:/bin/sh", words)
            self.assertIn("--group-entry=dev_1:x:1000:", words)
            self.assertIn("--user=1000:1000", words)
            for word in ("--workdir=/home/dev_1", "--env=HOME=/home/dev_1", "--env=USER=dev_1"):
                self.assertIn(word, words)
            self.assertFalse(any("agentbox-workspace" not in w and "/home/agentbox" in w for w in words), words)
            self.assertIn("--read-only", words)
            # The engine's own passwd/group copies: never a host share.
            self.assertFalse(any(w.startswith(("--volume", "-v", "--mount=type=bind")) for w in words))
        self.assertIn("--mount=type=tmpfs,destination=/home/dev_1,rw,exec,nosuid,nodev,tmpfs-size=1024m,"
                      "tmpfs-mode=0700,U=true", podman.create_command(image, "none", "dev_1"))
        self.assertIn("--mount=type=volume,source=agentbox-workspace,destination=/home/dev_1,subpath=/home,rw,"
                      "exec,nosuid,nodev", podman.create_command(image, "home", "dev_1"))
        init = podman.init_command(image, "home_tmp", "dev_1")
        self.assertIn("--mount=type=volume,source=agentbox-workspace,destination=/home/dev_1,rw,noexec,nosuid,nodev",
                      init)
        self.assertEqual(init[-1], "mkdir -p -m 0700 /home/dev_1/home && mkdir -p -m 1777 /home/dev_1/tmp")
        self.assertEqual(podman.init_command(image, "home", "dev_1")[-1], "mkdir -p -m 0700 /home/dev_1/home")
        self.assertIn("AllowUsers dev_1\n", podman.sshd_config("dev_1"))

    def test_image_accounts_must_leave_the_workload_free(self):
        good = {"etc": True, "home": True, "beneath": False, "etc/passwd": PASSWD, "etc/group": GROUP}
        self.assertEqual(podman.image_accounts(good), ACCOUNTS)
        refused = [
            dict(good, home=None), dict(good, etc=None), dict(good, beneath=True),
            dict(good, **{"etc/passwd": None}), dict(good, **{"etc/group": None}),
            dict(good, **{"etc/passwd": PASSWD + b"agentbox:x:1000:1000::/home/agentbox:/bin/sh\n"}),
            dict(good, **{"etc/passwd": PASSWD + b"other:x:01000:5::/x:/bin/sh\n"}),
            dict(good, **{"etc/group": GROUP + b"staff:x:1000:\n"}),
            dict(good, **{"etc/passwd": PASSWD + b"+::::::\n"}),
            dict(good, **{"etc/passwd": PASSWD + b"# comment\n"}),
            dict(good, **{"etc/passwd": PASSWD + b"\n"}),
            dict(good, **{"etc/passwd": b"root:x:0:0:root:/root\n"}),
            dict(good, **{"etc/passwd": b"root:x:zero:0:root:/root:/bin/sh\n"}),
            dict(good, **{"etc/group": b"\xff:x:5:\n"}),
        ]
        for facts in refused:
            with self.assertRaises(common.Failure) as caught:
                podman.image_accounts(facts)
            self.assertEqual(caught.exception.code, "unsupported", facts)
        self.assertTrue(podman.account_names(ACCOUNTS))
        self.assertTrue(podman.account_names([]))
        for bad in (None, ["b", "a"], ["a", "a"], [""], [1], "root"):
            self.assertFalse(podman.account_names(bad), bad)

    def test_the_provisioning_tar_carries_only_public_client_material(self):
        data = podman.provisioning_tar(b"PRIVATE HOST KEY\n", b"ssh-ed25519 AAAA\n", "agentbox")
        with tarfile.open(fileobj=io.BytesIO(data)) as tar:
            members = [(m.name, m.type, m.mode, m.uid, m.gid) for m in tar]
            config = tar.extractfile("agentbox-ssh/sshd_config").read().decode()
        self.assertEqual(members, [("agentbox-ssh", tarfile.DIRTYPE, 0o755, 0, 0),
                                   ("agentbox-ssh/sshd_config", tarfile.REGTYPE, 0o644, 0, 0),
                                   ("agentbox-ssh/ssh_host_ed25519_key", tarfile.REGTYPE, 0o600, 1000, 1000),
                                   ("agentbox-ssh/authorized_keys", tarfile.REGTYPE, 0o400, 1000, 1000)])
        for line in ("PermitTTY yes", "AllowTcpForwarding remote", "PermitListen 127.0.0.1:18080", "PermitOpen none",
                     "UsePAM no", "AllowUsers agentbox", "Subsystem sftp internal-sftp"):
            self.assertIn(line + "\n", config)

    def test_limits_capabilities_and_unsupported_disk(self):
        self.assertEqual(podman.limits_of({}), (2, 6144, 1024))
        self.assertEqual(podman.engine_limits(3, 2048, 99), {"cpu.max": "300000 100000",
                                                             "memory.max": str(2048 << 20),
                                                             "memory.swap.max": "0", "pids.max": "99"})
        with self.assertRaises(common.Failure) as caught:
            podman.limits_of({"disk_mib": 10})
        self.assertEqual(caught.exception.code, "unsupported")
        for bad in ({"memory_mib": 512}, {"pids": 10}):
            with self.assertRaises(common.Failure):
                podman.limits_of(bad)
        provider = podman.Provider("/x", TestHost({}), None)
        described = provider.op_capabilities({"operation": "o"})
        self.assertEqual((described["transport"], described["retention"], described["limits"],
                          described["features"]),
                         ("stdio", ["none", "home", "home_tmp"], ["cpus", "memory_mib", "pids"],
                          ["select_user", "project_layout", "host_mounts"]))
        self.assertEqual(described["operations"], list(protocol.REQUIRED_OPERATIONS))
        protocol.decode_response(protocol.encode(dict(described, type="described")))


class SafeDirs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abp-")
        self.addCleanup(remove_tree, self.tmp)

    def test_storage_roots_are_private_and_unlinked(self):
        good = os.path.join(self.tmp, "root")
        os.mkdir(good, 0o700)
        podman.safe_dir(good).close()
        os.chmod(good, 0o750)
        with self.assertRaises(common.Failure):
            podman.safe_dir(good)
        os.chmod(good, 0o700)
        os.symlink(good, os.path.join(self.tmp, "link"))
        with self.assertRaises(common.Failure):
            podman.safe_dir(os.path.join(self.tmp, "link"))
        os.chmod(self.tmp, 0o770)
        with self.assertRaises(common.Failure):
            podman.safe_dir(good)
        os.chmod(self.tmp, 0o700)
        host = TestHost({"tmpfs": False})
        with self.assertRaises(common.Failure):
            host.storage_root(good)
        with self.assertRaises(common.Failure):
            podman.Host().storage_root("/" + "x" * 70)

    def test_clear_tree_never_changes_modes(self):
        root = os.path.join(self.tmp, "store")
        os.makedirs(os.path.join(root, "a", "b"))
        write(os.path.join(root, "a", "b", "f"), "x")
        os.symlink("/etc", os.path.join(root, "a", "link"))
        locked = os.path.join(root, "locked")
        os.makedirs(os.path.join(locked, "inner"))
        os.chmod(locked, 0o555)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            budget = podman.Budget(1000, time.monotonic() + 10)
            self.assertFalse(podman.clear_tree(fd, os.fstat(fd).st_dev, budget))
            self.assertEqual(stat.S_IMODE(os.stat(locked).st_mode), 0o555)
            self.assertTrue(os.path.isdir(os.path.join(locked, "inner")))
            self.assertTrue(os.path.isdir("/etc"))
            os.chmod(locked, 0o755)
            self.assertTrue(podman.clear_tree(fd, os.fstat(fd).st_dev, podman.Budget(1000, time.monotonic() + 10)))
            self.assertEqual(os.listdir(root), [])
            os.mkdir(os.path.join(root, "x"))
            self.assertFalse(podman.clear_tree(fd, os.fstat(fd).st_dev, podman.Budget(0, time.monotonic() + 10)))
        finally:
            os.close(fd)


class ArchiveIdentity(unittest.TestCase):
    """The image is the measured archive; the baked worker and its metadata
    come from that archive's one layer."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abp-")
        self.addCleanup(remove_tree, self.tmp)
        self.n = 0

    def inspect(self, entries=None, agents=False, **kw):
        self.n += 1
        if entries is None:
            entries, _ = baked_entries(os.path.join(self.tmp, f"b{self.n}"))
        data, image_id = oci_archive(entries, **kw)
        path = os.path.join(self.tmp, f"a{self.n}.tar")
        write(path, data)
        fd = os.open(path, os.O_RDONLY)
        try:
            archive = podman.Archive(fd, lambda: None)
            try:
                found = archive.inspect()
                metadata, dirs, self.accounts, self.agents = archive.baked_worker(
                    found["layer"], found["compression"], os.path.join(self.tmp, f"out{self.n}"), agents=agents)
            finally:
                archive.close()
        finally:
            os.close(fd)
        release, files = worker.validate(os.path.join(self.tmp, f"out{self.n}", "worker"))
        self.assertEqual(dirs, worker.directories(files))
        return found, image_id, metadata, release

    def refused(self, entries=None, **kw):
        with self.assertRaises(common.Failure):
            self.inspect(entries, **kw)

    def entries(self, change=None, **kw):
        self.n += 1
        return baked_entries(os.path.join(self.tmp, f"e{self.n}"), change=change, **kw)[0]

    def test_a_valid_archive_names_its_config_and_baked_worker(self):
        for gz in (False, True):
            found, image_id, metadata, release = self.inspect(gz=gz)
            self.assertEqual(found["image_id"], image_id)
            self.assertEqual(json.loads(metadata)["release"], release)

    def test_the_layer_names_its_accounts_in_the_same_pass(self):
        self.inspect()
        self.assertEqual(self.accounts, ACCOUNTS)

        def swap(name, *replacement):
            return lambda e: [r for n, k, m, d, u in e
                              for r in ((replacement if n == name else ((n, k, m, d, u),)))]
        for change in (
                swap("etc/passwd", ("etc/passwd", "sym", 0o777, "/x/passwd", 0)),
                swap("etc/passwd", ("etc/passwd", "link", 0o644, "usr/bin/tini", 0)),
                swap("etc/passwd", ("etc/passwd", "file", 0o664, PASSWD, 0)),
                swap("etc/passwd", ("etc/passwd", "file", 0o644, PASSWD, 1000)),
                swap("etc/passwd", ("etc/passwd", "file", 0o644, b"x" * (podman.MAX_ACCOUNT_FILE + 1), 0)),
                swap("etc/passwd"),
                swap("etc/group", ("etc/group", "file", 0o644, GROUP + b"users:x:1000:\n", 0)),
                swap("etc/passwd", ("etc/passwd", "file", 0o644, PASSWD + b"u:x:1000:5::/h:/bin/sh\n", 0)),
                swap("home"),
                swap("home", ("home", "sym", 0o777, "/var/home", 0)),
                swap("home", ("home", "dir", 0o777, None, 0)),
                swap("etc", ("etc", "dir", 0o755, None, 1000)),
                lambda e: e + [("home/agentbox", "dir", 0o700, None, 1000)],
                lambda e: e + [("home/x", "file", 0o644, b"", 0)]):
            with self.assertRaises(common.Failure) as caught:
                self.inspect(self.entries(change))
            self.assertEqual(caught.exception.code, "unsupported", change)
        # Twice in the one layer, or a whiteout of it: never chosen between.
        for change in (lambda e: e + [("etc/passwd", "file", 0o644, PASSWD, 0)],
                       lambda e: e + [("etc/.wh.passwd", "file", 0o444, b"", 0)]):
            self.refused(self.entries(change))

    def test_the_layer_names_its_agents_in_the_same_pass_when_asked(self):
        self.inspect()
        self.assertEqual(self.agents, {})
        self.inspect(agents=True)
        self.assertEqual(set(self.agents), podman.agent_files())
        _, locks = agent_entries(os.path.join(self.tmp, "same"))
        provenance = podman.agent_provenance(self.agents)
        self.assertEqual(provenance, {agent: {"package": podman._agentlock().PACKAGES[agent], "version": "2.0.0",
                                              "lock_sha256": hashlib.sha256(locks[agent]).hexdigest()}
                                      for agent in podman._agentlock().AGENTS})
        # A layer without them still is one (a custom recipe's), but no
        # canonical image's.
        self.inspect(self.entries(agents=None), agents=True)
        self.assertEqual(self.agents, {})
        with self.assertRaises(common.Failure):
            podman.agent_provenance(self.agents)
        # Not root's, writable, a link, oversized or twice: never read.
        for variant in ("agent_writable", "agent_owner", "agent_link", "agent_twice"):
            self.refused(self.entries(AGENT_VARIANTS[variant]), agents=True)
            self.inspect(self.entries(AGENT_VARIANTS[variant]))
        big = _agent_change("pi/package-lock.json", lambda e: (*e[:3], b" " * (podman.MAX_AGENT_FILE + 1), e[4]))
        self.refused(self.entries(big), agents=True)
        # Read, but not what the build checked.
        for variant in ("agent_missing", "agent_version", "agent_registry"):
            self.inspect(self.entries(AGENT_VARIANTS[variant]), agents=True)
            with self.assertRaises(common.Failure):
                podman.agent_provenance(self.agents)

    def test_agent_files_are_reached_only_through_their_own_root_directories(self):
        pi = f"{podman.AGENTS_ROOT}/pi"
        codex = f"{podman.AGENTS_ROOT}/codex/node_modules/@openai"

        def swap(name, *replacement):
            return lambda e: [r for n, k, m, d, u in e for r in (replacement if n == name else ((n, k, m, d, u),))]

        def added(*extra):
            return lambda e: e + list(extra)

        for label, change in (
                ("ancestor a link", swap(pi, (pi, "sym", 0o777, "/tmp", 0))),
                ("agents root a link", swap(podman.AGENTS_ROOT, (podman.AGENTS_ROOT, "sym", 0o777, "/srv", 0))),
                ("ancestor a hard link", swap(codex, (codex, "link", 0o644, "usr/bin/tini", 0))),
                ("ancestor a file", swap(codex, (codex, "file", 0o644, b"", 0))),
                ("ancestor missing", swap(codex)),
                ("opt missing", swap("opt")),
                ("ancestor twice", added((pi, "dir", 0o755, None, 0))),
                ("ancestor replaced later", added((pi, "sym", 0o777, "/tmp", 0))),
                ("ancestor not root's", swap(pi, (pi, "dir", 0o755, None, 1000))),
                ("ancestor writable", swap(pi, (pi, "dir", 0o777, None, 0))),
                ("another spelling of a file", added((f"{pi}/../pi/package.json", "file", 0o644, b"{}", 0))),
                ("absolute spelling", added((f"/{pi}/package.json", "file", 0o644, b"{}", 0))),
                ("doubled slash", added(("opt//agentbox-agents/pi/package.json", "file", 0o644, b"{}", 0))),
                ("dot component", added((f"{podman.AGENTS_ROOT}/./pi", "dir", 0o755, None, 0))),
                ("beneath, other spelling", added(("opt/./agentbox-agents/pi/x", "file", 0o644, b"", 0)))):
            with self.subTest(label):
                self.refused(self.entries(change), agents=True)
        # Only asked for: an image's other paths and its agents when not
        # measured gain no new rule.
        self.inspect(self.entries(swap(pi, (pi, "sym", 0o777, "/tmp", 0))))
        self.inspect(self.entries(added(("usr/./bin/odd", "file", 0o644, b"", 0),
                                        ("opt/./agentbox/x", "file", 0o644, b"", 0))), agents=True)
        self.assertEqual(podman.agent_provenance(self.agents)["pi"]["version"], "2.0.0")
        # The tar conventions: `./` names (and directories' trailing `/`,
        # which tarfile drops) are the same paths.
        dotted = self.entries(lambda e: [(f"./{n}" + ("/" if k == "dir" else ""), k, m, d, u)
                                         for n, k, m, d, u in e])
        self.inspect(dotted, agents=True)
        self.assertEqual(set(self.agents), podman.agent_files())

    def test_anything_else_is_refused(self):
        self.refused(arch="arm64")
        self.refused(extra_layer=True)
        self.refused(change=lambda m: m["layers"][0].update(size=1))
        self.refused(change=lambda m: m["config"].update(digest="sha256:" + "0" * 64))
        self.refused(change=lambda m: m.update(layers=[dict(m["layers"][0], mediaType="application/x-zstd")]))

        def tamper_file(entries):
            return [(n, k, m, d + b"x" if n.endswith("anchor.py") else d, u) for n, k, m, d, u in entries]
        with self.assertRaises(worker.Refused):
            self.inspect(self.entries(tamper_file))
        for change in (
                lambda e: [x for x in e if x[0] != podman.WORKER_METADATA],
                lambda e: [(n, k, 0o644 if n.endswith("main.py") else m, d, u) for n, k, m, d, u in e],
                lambda e: [(n, k, m, d, 1000 if n.endswith("main.py") else u) for n, k, m, d, u in e],
                lambda e: [("opt/agentbox", "sym", 0o777, "/tmp", 0) if n == "opt/agentbox" else (n, k, m, d, u)
                           for n, k, m, d, u in e],
                lambda e: e + [("opt/agentbox/worker/guest/src/.wh.main.py", "file", 0o444, b"", 0)],
                lambda e: e + [("etc/.wh..wh..opq", "file", 0o444, b"", 0)],
                lambda e: e + [("opt/agentbox/worker/guest/src/extra.py", "link", 0o444, "usr/bin/tini", 0)],
                lambda e: e + [("opt/agentbox/worker/guest/src/main.py", "file", 0o444, b"again", 0)]):
            self.refused(self.entries(change))
        # Metadata naming another bundle.
        manifest_swap = self.entries(lambda e: [
            (n, k, m, json.dumps(dict(json.loads(d), release="0" * 64)).encode() if n == podman.WORKER_METADATA else d, u)
            for n, k, m, d, u in e])
        found, _, metadata, release = self.inspect(manifest_swap)
        path = os.path.join(self.tmp, "meta.json")
        write(path, metadata)
        with self.assertRaises(worker.Refused):
            worker.check_metadata(path, release)


# ---------------------------------------------------------------------------
# Provider invocations against stand-ins.

@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class Adoption(unittest.TestCase):
    """common.settle_children, each case in a forked child made a subreaper
    (never this test process). The child kills and reaps whatever the case
    left, its own children only, before it exits; its exit code is the
    verdict."""

    def in_subreaper(self, case):
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                common.Process.owned.clear()
                common.subreaper()
                code = case()
            except BaseException:  # noqa: BLE001 - the verdict is the exit code
                import traceback
                traceback.print_exc()
            finally:
                for process in list(common.Process.owned):
                    try:
                        process.popen.kill()
                        process.popen.wait(10)
                    except (OSError, subprocess.SubprocessError):
                        pass
                common.settle_children(time.monotonic() + 10, kill=True)
                os._exit(code)
        fd = os.pidfd_open(pid)
        try:
            if not select.select([fd], [], [], 60)[0]:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
        finally:
            _, status = os.waitpid(pid, 0)
            os.close(fd)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_an_owned_status_is_never_taken(self):
        def case():
            process = common.Process(subprocess.Popen(["/bin/sh", "-c", "exit 3"]), None)
            # An orphan: its parent exits at once, it a moment later.
            first = os.fork()
            if first == 0:
                if os.fork() == 0:
                    time.sleep(0.2)
                    os._exit(0)
                os._exit(0)
            # The owned leader has exited, unreaped, before the drain.
            select.select([process.pidfd], [], [], 10)
            if not common.settle_children(time.monotonic() + 10):
                return 2
            # Collected through its own Popen: its status, not a stolen 0.
            if (process.status, process.popen.returncode) != (3, 3):
                return 3
            return 0 if common.children() == [] and common._owned() == [] else 4
        self.in_subreaper(case)

    def test_a_live_adopted_child_is_unconfirmed_until_killed(self):
        def case():
            if os.fork() == 0:
                time.sleep(20)
                os._exit(0)
            began = time.monotonic()
            if common.settle_children(began + 0.2) or time.monotonic() - began > 5:
                return 2
            if not common.settle_children(time.monotonic() + 10, kill=True):
                return 3
            return 0 if common.children() == [] else 4
        self.in_subreaper(case)

    def test_a_second_thread_is_unconfirmed(self):
        def case():
            import threading
            release = threading.Event()
            thread = threading.Thread(target=release.wait)
            thread.start()
            try:
                if common.children() is not None or common.settle_children(time.monotonic() + 1):
                    return 2
            finally:
                release.set()
                thread.join()
            # The joined thread's task may linger a moment.
            deadline = time.monotonic() + 5
            while common.children() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            return 0 if common.children() == [] else 3
        self.in_subreaper(case)


    def test_an_owned_debt_is_never_settled_before_its_status(self):
        def case():
            # A leader left unreaped by an earlier cleanup (its custody
            # child may read empty): still live at the first gate.
            process = common.Process(subprocess.Popen(["/bin/sh", "-c", "sleep 0.5; exit 7"]), None)
            if common.settle_children(time.monotonic() + 0.05, kill=True):
                return 2
            # Never signalled, never collected by anyone else.
            select.select([process.pidfd], [], [], 10)
            if process.popen.returncode is not None:
                return 3
            # Exited, unreaped: the next gate collects it through its Popen.
            if not common.settle_children(time.monotonic() + 10):
                return 4
            return 0 if (process.status, common.children()) == (7, []) else 5
        self.in_subreaper(case)

    def test_an_expired_cleanup_bound_gets_no_fresh_reserve(self):
        def case():
            common.KILL_RESERVE = 2.0
            if os.fork() == 0:
                time.sleep(20)
                os._exit(0)
            ours, theirs = os.pipe()
            back, out = os.pipe()
            session = common.Session(ours, out)
            provider = podman.Provider("/nonexistent", podman.Host(environ={}), session)
            described = podman.Provider.op_capabilities

            def slow(self, request):
                # The operation outlives its deadline and its reserve.
                time.sleep(2.5)
                return described(self, request)
            podman.Provider.op_capabilities = slow
            began = time.monotonic()
            provider.handle({"type": "capabilities", "operation": "o", "timeout_ms": 100})
            took = time.monotonic() - began
            answer = protocol.decode_response(os.read(back, 4096).strip())
            if (answer["type"], answer["settlement"]) != ("failed", "unsettled"):
                return 2
            # Its bound (receipt + 0.1 + 2.0 s) passed inside the operation:
            # one pass, no fresh reserve (that would take 4.5 s).
            return 0 if took < 3.5 else 3
        self.in_subreaper(case)


class Lifecycle(Case):
    def test_a_secret_cleanup_error_after_settlement_is_a_warning(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["fail_unlink"] = list(podman.SECRET_FILES)
        self.save()
        invocation, request, _ = self.started()
        invocation.send(self.stop_frame(request))
        answer = invocation.read(60)
        _, _, err = invocation.finish(60)
        self.assertEqual((answer["type"], answer["settlement"]), ("stopped", "settled"), answer)
        self.assertIn(b"warning: instance secret files left", err)
        self.assertEqual(self.instance()["phase"], "settled")
        # A standalone stop after a killed owner: settled the same way.
        invocation, request, _ = self.started(generation=answer["generation"], execution="ex-2", instance="in-2")
        invocation.proc.kill()
        invocation.proc.wait()
        invocation.finish()
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"), stopped)
        # Reuse and discard are not blocked by the leftover files.
        self.config["fail_unlink"] = []
        self.save()
        invocation, request, _ = self.started(generation=stopped["generation"], accept_unclean=True,
                                              execution="ex-3", instance="in-3")
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assert_no_daemons()

    def test_a_selected_account_is_fixed_at_create_and_conflicts_refuse_first(self):
        image, _, image_id = self.install_image()
        # Every name the image knows (user, group, member) refuses before
        # anything exists.
        for user in ACCOUNTS:
            self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home",
                                         user=user), "user_conflict")
            self.assertFalse(os.path.exists(self.resource_dir()))
        self.assertEqual(self.calls(), [])
        created = self.create(image, retention="home", user="dev_1")
        self.assertEqual((created["user"], created["home"]), ("dev_1", "/home/dev_1"))
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["user"], record["home"]), ("dev_1", "/home/dev_1"))
        invocation, request, started = self.started()
        self.assertEqual((started["user"], started["home"]), ("dev_1", "/home/dev_1"))
        self.assertEqual(self.calls("create")[-1]["args"], podman.create_command(image_id, "home", "dev_1"))
        init = [c for c in self.calls() if c["args"][0] == "run"]
        self.assertEqual(init[-1]["args"], podman.init_command(image_id, "home", "dev_1"))
        stopped = self.owner_stop(invocation, request)
        self.assertEqual(stopped["type"], "stopped")
        # A record whose account was altered is never started.
        record = self.read_json(self.resource_dir(), "resource.json")
        record["home"] = "/home/other"
        write(os.path.join(self.resource_dir(), "resource.json"), json.dumps(record))
        invocation, request = self.start(generation=stopped["generation"], execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "failed")
        invocation.finish(60)
        self.assertFalse(os.path.exists(os.path.join(self.resource_dir(), "instances", "in-2")))

    def test_create_start_connect_stop_with_a_closed_profile(self):
        image, release, image_id = self.install_image()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image="0" * 64, retention="none",
                                     user="agentbox"), "not_found")
        created = self.create(image)
        self.assertEqual((created["user"], created["home"]), ("agentbox", "/home/agentbox"))
        self.assert_failed(self.call("create", run="run-2", resource="res-1", image=image, retention="none",
                                     user="agentbox"), "binding_mismatch")
        key = public_key()
        invocation, request, started = self.started(key=key, limits={"cpus": 1, "memory_mib": 2048, "pids": 128})
        self.assertEqual((started["transport"], started["user"], started["worker_sha256"], started["generation"]),
                         ({"kind": "stdio"}, "agentbox", release, 0))
        self.assertEqual((started["home"], started["control"]), ("/home/agentbox", "/run/agentbox-control"))
        protocol._ssh_key(started["host_key"])
        self.assertNotEqual(started["host_key"], key)
        inst = self.instance()
        self.assertEqual(inst["phase"], "live")
        store = os.path.join(self.storage, inst["store"]["name"])
        self.assertEqual(self.stores(), [inst["store"]["name"]])
        self.assertEqual(stat.S_IMODE(os.stat(store).st_mode), 0o700)
        self.assertEqual(podman.identity(os.stat(store)), inst["store"]["identity"])
        # No secret stays on the host once provisioned.
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        self.assertEqual(sorted(os.listdir(idir)), ["admission.lock", "instance.json", "owner.lock"])
        calls = self.calls()
        self.assertEqual([c["args"][0] for c in calls], ["load", "create", "cp", "start"])
        expected_env = podman.Store(store, self.config["tools"], search=SEARCH).env()
        first_start = min(c["time"] for c in calls)
        for call in calls:
            # Every engine process: the engine child, its limits already
            # there, exactly the profile's environment and globals, no
            # inherited descriptor, no file size limit.
            self.assertEqual(call["child"], "engine")
            self.assertEqual(call["limits"], podman.engine_limits(1, 2048, 128))
            self.assertEqual(call["env"], expected_env)
            self.assertFalse(any(value in json.dumps(call) for value in AMBIENT.values()))
            self.assertIn("--remote=false", json.dumps(call["globals"]) + json.dumps(call.get("argv", [])))
            self.assertEqual(call["fds"], [0, 1, 2])
            self.assertEqual(call["fsize"], -1)
            self.assertEqual(call["globals"]["root"], store + "/graph")
            self.assertNotIn("volumepath", call["globals"])
        self.assertTrue(calls[0]["stdin"].endswith("image.oci.tar"))
        self.assertTrue(calls[2]["stdin"].endswith("provision.tar"))
        self.assertEqual(calls[1]["args"], podman.create_command(image_id, "none", "agentbox"))
        self.assertGreater(first_start, 0)
        for name in ("containers.conf", "storage.conf", "registries.conf"):
            self.assertEqual(slurp(os.path.join(store, "conf", name)), dict(podman.Store(
                store, self.config["tools"]).files())["conf/" + name])
        self.assertEqual(slurp(os.path.join(store, "home/.config/containers/mounts.conf")), b"")
        # The baked bundle is used in place: nothing of the worker is copied in.
        self.assertFalse(any("worker" in a for c in calls for a in c["args"]))

        bridge = self.connect(request)
        self.assertEqual(bridge.read(line=True), b"SSH-2.0-stand-in\r\n")
        provisioned = json.loads(bridge.command("auth"))
        self.assertEqual(provisioned["agentbox-ssh/authorized_keys"]["data"], key + "\n")
        host_key = provisioned["agentbox-ssh/ssh_host_ed25519_key"]
        self.assertEqual((host_key["uid"], host_key["mode"]), (1000, 0o600))
        payload = bytes(range(256)) * 8192
        bridge.send(b"raw %d\n" % len(payload) + payload)
        self.assertEqual(bridge.read(line=True).strip().decode(), hashlib.sha256(payload).hexdigest())
        self.assertEqual(bridge.read(len(payload)), payload)
        self.assertEqual(bridge.command("put /home/agentbox/a " + b"hello".hex()), "ok")
        self.assertEqual(bridge.command("get /home/agentbox/a"), b"hello".hex())
        exec_call = self.calls("exec")[-1]
        self.assertEqual(exec_call["args"], podman.exec_command(inst["container"]))
        self.assertEqual((exec_call["child"], exec_call["env"]), ("engine", expected_env))
        bridge.proc.stdin.close()
        self.assertEqual(bridge.finish()[:2], (0, b""))

        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["type"], stopped["settlement"], stopped["durability"], stopped["generation"],
                          stopped["storage"]), ("stopped", "settled", "unchanged", 0, "clean"))
        # The container went first, then the child with every helper, then
        # the disposal in a fresh profile, then the store itself.
        self.assertEqual(self.calls("rm")[-1]["args"], ["rm", "--force", "--time=0", inst["container"]])
        dispose = self.calls("rmi")[-1]
        self.assertTrue(dispose["globals"]["runroot"].startswith(store + "/dispose-1/"))
        self.assertEqual(dispose["globals"]["root"], store + "/graph")
        self.assertTrue(dispose["child"].startswith("tool-"))
        self.assertEqual(self.stores(), [])
        self.assert_no_daemons()
        self.assertEqual(self.stale(), [])
        self.assertEqual(sorted(os.listdir(self.domain)), ["cgroup.kill", "cgroup.procs", "cgroup.subtree_control",
                                                          "leaf"])
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["store"]["removed"]), ("settled", None, True))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("ready", "settled"))
        again = self.standalone_stop(request)
        self.assertEqual((again["type"], again["durability"]), ("stopped", "unchanged"))
        # A settled instance has no bridge.
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        # Fresh store, keys and container next time.
        invocation, request2, started2 = self.started(execution="ex-2", instance="in-2")
        self.assertNotEqual(started2["host_key"], started["host_key"])
        self.assertNotEqual(self.instance("in-2")["store"]["name"], inst["store"]["name"])
        self.assertEqual(self.owner_stop(invocation, request2)["type"], "stopped")
        self.assert_failed(self.call("start", run="run-1", resource="res-1", execution="ex-3", instance="in-2",
                                     generation=0, accept_unclean=False, authorized_key=key, limits={}), "exists")

    def test_unsupported_operations_and_limits(self):
        image, _, _ = self.install_image()
        self.create(image)
        for kind, fields in (("checkpoint", {"checkpoint": "c", "generation": 0, "accept_unclean": False}),
                             ("restore", {"checkpoint": "c", "generation": 0}),
                             ("discard", {"checkpoint": "c"})):
            self.assert_failed(self.call(kind, run="run-1", resource="res-1", **fields), "unsupported")
        invocation, _ = self.start(limits={"disk_mib": 100})
        self.assert_failed(invocation.read(), "unsupported")
        invocation.finish()
        self.assertEqual(self.calls(), [])

    def test_a_retained_home_and_tmp_resume_and_discard_through_the_engine(self):
        image, _, image_id = self.install_image()
        self.create(image, retention="home_tmp")
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["capacity"], record["volume"]["state"]), ("uncapped", None))
        invocation, request, _ = self.started()
        volume = os.path.join(self.resource_dir(), "volumes", podman.VOLUME)
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual(record["volume"]["pin"], podman.volume_pin(os.stat(volume)))
        init = self.calls("run")[-1]
        self.assertEqual(init["args"], podman.init_command(image_id, "home_tmp", "agentbox"))
        self.assertEqual(init["globals"]["volumepath"], os.path.join(self.resource_dir(), "volumes"))
        bridge = self.connect(request)
        bridge.read(line=True)
        for path in ("/home/agentbox/kept", "/tmp/kept", "/run/agentbox-control/gone"):
            self.assertEqual(bridge.command(f"put {path} {b'data'.hex()}"), "ok")
        bridge.proc.stdin.close()
        bridge.finish()
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["durability"], stopped["storage"], stopped["generation"]),
                         ("retained", "clean", 1))
        self.assertTrue(any(n.startswith("sync-") for n in os.listdir(self.records)))
        self.assertEqual(self.stores(), [])
        invocation, request, _ = self.started(generation=1, execution="ex-2", instance="in-2")
        self.assertEqual(len(self.calls("run")), 1)  # initialized once only
        bridge = self.connect(request)
        bridge.read(line=True)
        self.assertEqual(bridge.command("get /home/agentbox/kept"), b"data".hex())
        self.assertEqual(bridge.command("get /tmp/kept"), b"data".hex())
        self.assertEqual(bridge.command("get /run/agentbox-control/gone"), "missing")
        bridge.proc.stdin.close()
        bridge.finish()
        self.assertEqual(self.owner_stop(invocation, request)["generation"], 2)
        # Discard: refused nothing else first, the volume removed by the
        # engine only; the host never walks it (its data is 0555 here).
        discarded = self.call("discard", run="run-1", resource="res-1")
        self.assertEqual(discarded["type"], "discarded", discarded)
        self.assertEqual([c["args"][:2] for c in self.calls("volume")][-2:],
                         [["volume", "create"], ["volume", "rm"]])
        self.assertFalse(os.path.exists(os.path.join(self.resource_dir(), "volumes")))
        self.assertEqual(self.read_json(self.resource_dir(), "resource.json")["state"], "discarded")
        self.assertEqual(self.stores(), [])
        self.assertFalse(os.path.exists(os.path.join(self.state, "bindings", "in-1")))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "absent")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assert_no_daemons()

    def test_a_retained_home_keeps_tmp_fresh(self):
        image, _, image_id = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started()
        self.assertEqual(self.calls("create")[-1]["args"], podman.create_command(image_id, "home", "agentbox"))
        bridge = self.connect(request)
        bridge.read(line=True)
        bridge.command(f"put /tmp/x {b'1'.hex()}")
        bridge.command(f"put /home/agentbox/y {b'2'.hex()}")
        bridge.proc.stdin.close()
        bridge.finish()
        self.owner_stop(invocation, request)
        invocation, request, _ = self.started(generation=1, execution="ex-2", instance="in-2")
        bridge = self.connect(request)
        bridge.read(line=True)
        self.assertEqual(bridge.command("get /tmp/x"), "missing")
        self.assertEqual(bridge.command("get /home/agentbox/y"), b"2".hex())
        bridge.proc.stdin.close()
        bridge.finish()
        self.owner_stop(invocation, request)

    def test_discard_never_removes_a_replaced_or_unconfirmed_volume(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started()
        self.owner_stop(invocation, request)
        volumes = os.path.join(self.resource_dir(), "volumes")
        original = os.path.join(volumes, podman.VOLUME)
        # A failing engine removal: unconfirmed, data kept, then retried.
        self.config["podman"] = {"volume_rm_fail": True}
        self.save()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertTrue(os.path.isdir(os.path.join(original, "_data", "home")))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "partial")
        self.assert_failed(self.call("start", run="run-1", resource="res-1", execution="ex-9", instance="in-9",
                                     generation=1, accept_unclean=True, authorized_key=public_key(), limits={}),
                           "partial")
        self.assertEqual(self.stores(), [])
        # A replaced directory is never the original: refused, untouched.
        os.chmod(original, 0o700)
        os.rename(original, os.path.join(self.tmp, "moved"))
        os.mkdir(original)
        write(os.path.join(original, "keep"), "replacement")
        self.config["podman"] = {}
        self.save()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertEqual(slurp(os.path.join(original, "keep")), b"replacement")
        self.assertEqual([c for c in self.calls("volume") if c["args"][1] == "rm"].__len__(), 1)
        # Nor from a fresh domain, the later standalone cleanup: the host's
        # process precondition settles processes only, never retained data.
        self.config["domain"] = make_domain(os.path.join(self.tmp, "fresh"))
        self.save()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertEqual(slurp(os.path.join(original, "keep")), b"replacement")
        # Its own directory back: removed through the engine, proven, also
        # from that fresh domain (the earlier one gone with its unit).
        remove_tree(original)
        os.rename(os.path.join(self.tmp, "moved"), original)
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertFalse(os.path.exists(volumes))

    def test_a_missing_pinned_volume_is_never_proof(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started()
        self.owner_stop(invocation, request)
        original = os.path.join(self.resource_dir(), "volumes", podman.VOLUME)
        os.chmod(original, 0o700)
        os.rename(original, os.path.join(self.tmp, "moved"))
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertFalse(any(c["args"][:2] == ["volume", "rm"] for c in self.calls("volume")))
        # Nor is a fresh start allowed to recreate it.
        os.rename(os.path.join(self.tmp, "moved"), original)

    def test_concurrent_bridges_and_stop_closes_admission(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        bridges = [self.connect(request) for _ in range(3)]
        for bridge in bridges:
            self.assertEqual(bridge.read(line=True), b"SSH-2.0-stand-in\r\n")
        for n, bridge in enumerate(bridges):
            self.assertEqual(bridge.command(f"put /tmp/{n} {b'x'.hex()}"), "ok")
        session = bridges[0].command("spawn")
        self.assertTrue(_alive(int(session)))
        # Stop with bridges open: admission closes, every bridge process
        # (and what it started) goes with the engine child.
        stopped = self.owner_stop(invocation, request)
        self.assertEqual(stopped["type"], "stopped", stopped)
        for bridge in bridges:
            code, _, _ = bridge.finish()
            self.assertEqual(code, 0)
        self.assert_no_daemons()
        code, rest, err = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        self.assertIn(b"connect refused", err)

    def test_a_bridge_ends_at_its_leader_not_at_a_held_pipe(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        bridge = self.connect(request)
        bridge.read(line=True)
        (conmon,) = self.daemons("exec-conmon")
        seen = stat_of(conmon)
        # Detached by the leader, adopted by the bridge, a subreaper.
        self.assertEqual(seen[1], bridge.proc.pid)
        # The leader exits; its exec conmon still holds the pipe.
        bridge.send(b"exit\n")
        began = time.monotonic()
        code, rest, err = bridge.finish(20)
        self.assertEqual((code, rest), (0, b""))
        self.assertLess(time.monotonic() - began, 10)
        # Killed and reaped before the bridge exited, never awaited.
        self.assertTrue(reaped(conmon, seen))
        self.assertNotIn(b"unconfirmed", err)
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")
        self.assert_no_daemons()

    def test_a_signalled_bridge_kills_and_reaps_what_it_adopted(self):
        self.signalled_bridge(signal.SIGTERM)

    def test_a_hung_up_bridge_ends_the_same(self):
        # ssh's end of its ProxyCommand (`jail shell-transport` becomes this
        # bridge): SIGHUP.
        self.signalled_bridge(signal.SIGHUP)

    def signalled_bridge(self, number):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        bridge = self.connect(request)
        bridge.read(line=True)
        (conmon,) = self.daemons("exec-conmon")
        seen = stat_of(conmon)
        self.assertEqual(seen[1], bridge.proc.pid)
        # The host's transport barrier: a signal, the session still open.
        began = time.monotonic()
        bridge.proc.send_signal(number)
        code, rest, err = bridge.finish(20)
        self.assertEqual((code, rest), (0, b""))
        self.assertLess(time.monotonic() - began, 10)
        self.assertTrue(reaped(conmon, seen))
        self.assertNotIn(b"unconfirmed", err)
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")
        self.assert_no_daemons()

    def test_the_owner_keeps_and_reaps_what_its_engine_detaches(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        detached = {pid: stat_of(pid) for pid in self.daemons("pause") + self.daemons("conmon")}
        detached = {pid: seen for pid, seen in detached.items() if seen is not None}
        self.assertEqual(sorted(seen[0] != "Z" for seen in detached.values()), [True, True])
        # Orphaned to the owner, a subreaper, not past it.
        for seen in detached.values():
            self.assertEqual(seen[1], invocation.proc.pid)
        invocation.send(self.stop_frame(request))
        stopped = invocation.read(60)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"), stopped)
        # Reaped before the answer, not left to whoever outlives the owner.
        for pid, seen in detached.items():
            self.assertTrue(reaped(pid, seen))
        code, rest, _ = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        self.assert_no_daemons()

    def test_no_detached_process_reaches_the_host_worker(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        report = os.path.join(self.tmp, "barrier.json")
        invocation = Mirrored(self, report, ["control", self.state])
        self.live.append(invocation)
        _, request = self.start(invocation=invocation)
        self.assertEqual(invocation.read(60)["type"], "started")
        for _ in range(2):
            bridge = self.connect(request)
            bridge.read(line=True)
            bridge.send(b"exit\n")
            self.assertEqual(bridge.finish(20)[0], 0)
        # Pause, conmon, the container's exit and the disposal's own pause
        # all stay the owner's; none reaches the worker, live or exited.
        invocation.send(self.stop_frame(request))
        self.assertEqual(invocation.read(60)["type"], "stopped")
        code, rest, _ = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        self.assertEqual(self.read_json(report), {"strays": [], "code": 0})
        # A standalone discard (volume removal, its own pause) likewise.
        report = os.path.join(self.tmp, "discard.json")
        invocation = Mirrored(self, report, ["control", self.state])
        self.live.append(invocation)
        invocation.send(self.frame("discard", run="run-1", resource="res-1"))
        self.assertEqual(invocation.read(60)["type"], "discarded")
        code, rest, _ = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        self.assertEqual(self.read_json(report), {"strays": [], "code": 0})
        self.assertTrue(self.daemons("pause"))
        self.assert_no_daemons()

    def escaped(self):
        """The one escaped process: (pid, its recorded start time)."""
        (name,) = [n for n in os.listdir(self.records) if n.startswith("escaped-")]
        return int(name.split("-")[1]), int(slurp(os.path.join(self.records, name)))

    def test_a_live_adopted_child_is_never_settled_by_the_owner(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["kill_reserve"] = 1
        self.save()
        report = os.path.join(self.tmp, "owner.json")
        invocation = Mirrored(self, report, ["control", self.state])
        self.live.append(invocation)
        try:
            _, request = self.start(invocation=invocation)
            self.assertEqual(invocation.read(60)["type"], "started")
            # `rm` leaves one detached process no custody kill reaches.
            self.config["podman"] = {"escape": "rm"}
            self.save()
            invocation.send(self.stop_frame(request, timeout_ms=2000))
            answer = invocation.read(60)
        finally:
            code, rest, err = invocation.finish(60)
        self.assert_failed(answer, "failed", "unsettled", "uncertain")
        self.assertEqual((code, rest), (0, b""))
        self.assertIn(b"adopted children unconfirmed", err)
        # Handed live to the outer subreaper, which killed and reaped it.
        self.assertEqual(self.read_json(report), {"strays": ["S"], "code": 0})
        pid, start = self.escaped()
        self.assertTrue(reaped(pid, (None, None, start)))
        # Its record is kept: a standalone stop settles it by handle.
        self.config["podman"] = {}
        self.save()
        self.assertNotEqual(self.instance()["phase"], "settled")
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assert_no_daemons()

    def test_a_live_adopted_child_turns_a_settled_answer_unsettled(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["kill_reserve"] = 1
        self.save()
        invocation, request, _ = self.started()
        invocation.proc.kill()
        invocation.proc.wait()
        # The standalone stop's disposal leaves one beyond every kill.
        self.config["podman"] = {"escape": "rmi"}
        self.save()
        report = os.path.join(self.tmp, "stop.json")
        invocation = Mirrored(self, report, ["control", self.state])
        self.live.append(invocation)
        try:
            invocation.send(self.frame("stop", timeout_ms=2000, run=request["run"], resource=request["resource"],
                                       execution=request["execution"], instance=request["instance"],
                                       generation=request["generation"]))
            answer = invocation.read(60)
        finally:
            code, rest, err = invocation.finish(60)
        self.assert_failed(answer, "failed", "unsettled", "uncertain")
        self.assertEqual((code, rest), (0, b""))
        self.assertIn(b"adopted children unconfirmed", err)
        self.assertEqual(self.read_json(report), {"strays": ["S"], "code": 0})
        pid, start = self.escaped()
        self.assertTrue(reaped(pid, (None, None, start)))
        # What the stop recorded stands: the next one answers by handle.
        self.config["podman"] = {}
        self.save()
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assert_no_daemons()

    def test_bridges_check_binding_custody_and_liveness(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        for change in ({"run": "run-2"}, {"execution": "ex-2"}, {"instance": "in-2"}):
            code, rest, _ = self.connect(dict(request, **change)).finish()
            self.assertEqual((code, rest), (2, b""))
        # Another custody domain is refused.
        other = make_domain(os.path.join(self.tmp, "other"))
        self.config["domain"] = other
        self.save()
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        self.config["domain"] = self.domain
        self.save()
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")

    def test_eof_and_cancel_force_and_record_by_handle(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started()
        invocation.close()
        code, rest, _ = invocation.finish()
        self.assertEqual((code, rest), (0, b""))
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["result"]["durability"]), ("settled", "uncertain"))
        self.assertEqual(self.calls("rm"), [])  # forced: no graceful step
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])
        status = self.call("status", run="run-1", resource="res-1")
        self.assertEqual((status["resource_state"], status["generation"]), ("unclean", 1))
        self.assert_failed(self.call("start", run="run-1", resource="res-1", execution="ex-2", instance="in-2",
                                     generation=1, accept_unclean=False, authorized_key=public_key(), limits={}),
                           "unclean")
        # A cancelled stop is forced as well.
        invocation, request, _ = self.started(generation=1, accept_unclean=True, execution="ex-3", instance="in-3")
        stop = self.stop_frame(request)
        invocation.send(stop)
        invocation.send({"type": "cancel", "operation": stop["operation"]})
        answer = invocation.read(60)
        invocation.finish()
        self.assertEqual((answer["type"], answer["durability"], answer["storage"]), ("stopped", "uncertain",
                                                                                      "unclean"))
        self.assert_no_daemons()

    def test_cancel_before_started_settles_what_ran(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["podman"] = {"hang": "start"}
        self.save()
        invocation, request = self.start()
        deadline = time.monotonic() + 30
        while not self.calls("start") and time.monotonic() < deadline:
            time.sleep(0.05)
        invocation.send({"type": "cancel", "operation": request["operation"]})
        answer = invocation.read(60)
        invocation.finish()
        self.assert_failed(answer, "cancelled")
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "ready")

    def test_a_coalesced_start_and_cancel_runs_nothing(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation = self.invoke()
        request = self.frame("start", run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0,
                             accept_unclean=False, authorized_key=public_key(), limits={})
        invocation.proc.stdin.write(protocol.encode(request) + b"\n" + protocol.encode(
            {"type": "cancel", "operation": request["operation"]}) + b"\n")
        invocation.proc.stdin.flush()
        self.assert_failed(invocation.read(60), "cancelled")
        invocation.finish()
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.stores(), [])

    def test_a_start_killed_midway_is_settled_by_its_handles(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        self.config["podman"] = {"hang": "create"}
        self.save()
        invocation, request = self.start()
        deadline = time.monotonic() + 30
        while not self.calls("create") and time.monotonic() < deadline:
            time.sleep(0.05)
        invocation.proc.kill()
        invocation.proc.wait()
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["volume_used"]), ("engine", "engine", True))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("busy", "unsettled"))
        self.config["podman"] = {}
        self.save()
        stopped = self.standalone_stop(request)
        # The volume was mounted by what ran: possibly written.
        self.assertEqual((stopped["durability"], stopped["storage"], stopped["generation"]),
                         ("uncertain", "unclean", 1))
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.stale(), [])

    def test_a_stuck_key_tool_keeps_its_files_and_debt(self):
        image, _, _ = self.install_image()
        self.create(image)
        stuck = os.path.join(self.tmp, "tools", "ssh-keygen")
        write(stuck, f"#!{sys.executable} -IBS\nimport os, sys, time\n"
                     f"open({self.records!r} + '/daemon-keygen-%d' % os.getpid(), 'w').close()\n"
                     "path = sys.argv[-1]\n"
                     "while True:\n    open(path, 'w').write('x')\n    time.sleep(0.05)\n", 0o755)
        self.config["tools"]["ssh-keygen"] = stuck
        self.config["immune"] = ["tool-"]
        self.config["kill_reserve"] = 1.0
        self.save()
        invocation, request = self.start(timeout_ms=1500)
        self.assert_failed(invocation.read(60), "failed", "unsettled", "uncertain")
        invocation.finish()
        inst = self.instance()
        self.assertEqual(len(inst["tools"]), 1)
        self.assertEqual(self.calls(), [])
        self.assert_failed(self.standalone_stop(request), "busy", "unsettled", "uncertain")
        self.config["immune"] = []
        self.save()
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assertFalse(os.path.exists(os.path.join(self.resource_dir(), "instances", "in-1", "host_ed25519")))
        self.assert_no_daemons()

    def test_closed_admission_or_a_changed_profile_refuses_bridges(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        path = os.path.join(self.resource_dir(), "instances", "in-1", "instance.json")
        live = slurp(path)
        write(path, json.dumps(dict(json.loads(live), phase="stopping")), 0o600)
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        write(path, live, 0o600)
        conf = os.path.join(self.storage, self.instance()["store"]["name"], "conf", "registries.conf")
        original = slurp(conf)
        write(conf, original + b"# changed\n", 0o600)
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        write(conf, original, 0o600)
        self.assertEqual(self.calls("exec"), [])
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")

    def test_provider_loss_keeps_everything_for_a_standalone_stop(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started()
        bridge = self.connect(request)
        bridge.read(line=True)
        invocation.proc.kill()
        invocation.proc.wait()
        self.assertTrue(any(_alive(p) for p in self.daemons("conmon")))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("busy", "unsettled"))
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "busy", "unsettled")
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["durability"], stopped["storage"]),
                         ("stopped", "uncertain", "unclean"))
        bridge.finish()
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.stale(), [])

    def test_a_replaced_store_is_never_deleted(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        invocation.proc.kill()
        invocation.proc.wait()
        store = os.path.join(self.storage, self.instance()["store"]["name"])
        os.rename(store, os.path.join(self.tmp, "original-store"))
        os.mkdir(store, 0o700)
        write(os.path.join(store, "keep"), "x")
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assertEqual(slurp(os.path.join(store, "keep")), b"x")
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "original-store", "graph")))
        self.assertTrue(self.instance()["store"]["residue"])
        self.assert_no_daemons()  # the processes were settled strictly
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "ready")

    def test_a_failed_disposal_leaves_warned_residue_not_debt(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["podman"] = {"dispose_fail": True}
        self.save()
        invocation, request, _ = self.started()
        invocation.send(self.stop_frame(request))
        answer = invocation.read(60)
        code, rest, err = invocation.finish()
        self.assertEqual((answer["type"], answer["settlement"], answer["durability"]),
                         ("stopped", "settled", "unchanged"))
        self.assertIn(b"warning: engine store residue left", err)
        store = self.instance()["store"]
        self.assertEqual((store["residue"], store["disposed"], store["removed"]), (True, False, False))
        # The subordinate-like layers stay (never chmod-ed); every process went.
        self.assertTrue(os.path.isdir(os.path.join(self.storage, store["name"], "graph", "vfs")))
        self.assert_no_daemons()
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("ready", "settled"))
        # Residue blocks nothing: the next execution gets a fresh store.
        self.config["podman"] = {}
        self.save()
        invocation, request, _ = self.started(execution="ex-2", instance="in-2")
        self.assertEqual(len(self.stores()), 2)
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")
        self.assertEqual(self.stores(), [store["name"]])

    def test_an_engine_child_that_will_not_empty_keeps_its_debt(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["immune"] = ["engine"]
        self.config["kill_reserve"] = 1.0
        self.save()
        invocation, request, _ = self.started()
        self.assert_failed(self.owner_stop(invocation, request, timeout_ms=2000), "failed", "unsettled",
                           "uncertain")
        inst = self.instance()
        self.assertEqual((inst["engine"], inst["store"]["removed"]), ("engine", False))
        self.assertEqual(len(self.stores()), 1)  # never removed under live writers
        self.assertTrue(any(_alive(p) for p in self.daemons("pause")))
        self.config["immune"] = []
        self.save()
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])

    def test_a_refused_pidfd_still_settles_the_spawned_engine_call(self):
        image, _, _ = self.install_image()
        self.create(image)
        # 1, 2: ssh-keygen tools; 3: the load.
        self.config["deny_pidfd"] = 3
        self.save()
        invocation, _ = self.start()
        answer = invocation.read(60)
        invocation.finish()
        self.assert_failed(answer, "failed")
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["store"]["removed"]), ("settled", None, True))
        self.assertNotIn("engine", os.listdir(self.domain))
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.instance()["phase"], "settled")

    def test_bad_engine_output_fails_settled(self):
        image, _, _ = self.install_image()
        self.create(image)
        for behaviour in ({"create_out": "not-an-id"}, {"fail": "cp"}, {"fail": "load"}):
            self.config["podman"] = behaviour
            self.save()
            invocation, _ = self.start(execution=f"ex-{self.ops}", instance=f"in-{self.ops}")
            answer = invocation.read(60)
            invocation.finish()
            self.assert_failed(answer, "failed")
            self.assert_no_daemons()
            self.assertEqual(self.stores(), [])

    def test_prerequisites_fail_closed(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["tmpfs"] = False
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "prerequisite")
        invocation.finish()
        self.assertEqual(self.calls(), [])
        self.config["tmpfs"] = True
        self.save()
        os.chmod(self.storage, 0o750)
        invocation, _ = self.start(execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "prerequisite")
        invocation.finish()
        self.assertEqual(self.calls(), [])
        os.chmod(self.storage, 0o700)
        # A tampered archive never loads.
        entry = os.path.join(self.state, "images", image)
        os.chmod(entry, 0o700)
        path = os.path.join(entry, "image.oci.tar")
        os.chmod(path, 0o600)
        with open(path, "r+b") as stream:
            stream.seek(100)
            stream.write(b"X")
        os.chmod(path, 0o400)
        os.chmod(entry, 0o500)
        invocation, _ = self.start(execution="ex-3", instance="in-3")
        self.assert_failed(invocation.read(60), "failed")
        invocation.finish()
        self.assertEqual(self.calls(), [])


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class HostMounts(Case):
    """`host_mounts`: the keep-id mapping recorded at create and used by
    every engine step; sources resolved and destinations prepared at every
    start; host directories never removed."""

    def sources(self):
        project = os.path.join(self.tmp, "src", "proj")
        reference = os.path.join(self.tmp, "ref")
        os.makedirs(project, 0o755)
        os.makedirs(reference, 0o755)
        write(os.path.join(reference, "keep"), "reference")
        return project, reference, [{"source": project, "destination": "src/proj", "access": "rw"},
                                    {"source": reference, "destination": ".agentbox-root/ref", "access": "ro"}]

    def mounted_create(self, image, mounts, user="dev_1", retention="home"):
        return self.call("create", run="run-1", resource="res-1", image=image, retention=retention, user=user,
                         mounts=mounts)

    def test_a_mount_resource_runs_keep_id_through_every_engine_step(self):
        image, _, image_id = self.install_image()
        project, reference, mounts = self.sources()
        created = self.mounted_create(image, mounts)
        self.assertEqual(created["type"], "created", created)
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["mapping"], record["mounts"]), ("keep_id", mounts))
        invocation, request, _ = self.started()
        self.assertEqual(self.calls("volume create")[-1]["args"], podman.volume_create("keep_id"))
        self.assertIn("--uid=0", podman.volume_create("keep_id"))
        runs = self.calls("run")
        self.assertEqual(runs[0]["args"], podman.init_command(image_id, "home", "dev_1", "keep_id"))
        self.assertEqual(runs[1]["args"], podman.prepare_command(image_id, "dev_1", "keep_id",
                                                                 ["src/proj", ".agentbox-root/ref"]))
        for args in (runs[0]["args"], runs[1]["args"]):
            self.assertIn(podman.KEEP_ID, args)
            self.assertIn("--passwd-entry=dev_1:x:1000:1000:dev_1:/home/dev_1:/bin/sh", args)
        binds = [(os.path.realpath(project), "src/proj", "rw"), (os.path.realpath(reference), ".agentbox-root/ref", "ro")]
        create = self.calls("create")[-1]["args"]
        self.assertEqual(create, podman.create_command(image_id, "home", "dev_1", "keep_id", binds))
        self.assertIn(podman.KEEP_ID, create)
        self.assertIn(f"--mount=type=bind,source={os.path.realpath(project)},destination=/home/dev_1/src/proj,rw,"
                      "nosuid,nodev,bind-propagation=private,bind-nonrecursive", create)
        self.assertFalse(any(":U" in a or ",U" in a or ":z" in a.lower() for a in create if a.startswith("--mount=type=bind")))
        # The destinations were made in the retained HOME before the create.
        home = os.path.join(self.resource_dir(), "volumes", podman.VOLUME, "_data", "home")
        self.assertTrue(os.path.isdir(os.path.join(home, "src", "proj")))
        self.assertTrue(os.path.isdir(os.path.join(home, ".agentbox-root", "ref")))
        bridge = self.connect(request)
        bridge.read(line=True)
        self.assertEqual(bridge.command(f"put /home/dev_1/src/proj/new {b'w'.hex()}"), "ok")
        self.assertEqual(bridge.command(f"put /home/dev_1/.agentbox-root/ref/new {b'w'.hex()}"), "erofs")
        bridge.proc.stdin.close()
        bridge.finish()
        self.assertEqual(slurp(os.path.join(project, "new")), b"w")
        stopped = self.owner_stop(invocation, request)
        self.assertEqual(stopped["type"], "stopped", stopped)
        # A replaced source directory at the same path is simply used; a
        # symlink there is followed anew.
        os.rename(project, project + "-old")
        other = os.path.join(self.tmp, "other")
        os.mkdir(other, 0o755)
        os.symlink(other, project)
        invocation, request, _ = self.started(generation=stopped["generation"], execution="ex-2", instance="in-2")
        self.assertIn(f"--mount=type=bind,source={os.path.realpath(other)},destination=/home/dev_1/src/proj,rw,"
                      "nosuid,nodev,bind-propagation=private,bind-nonrecursive", self.calls("create")[-1]["args"])
        self.assertEqual(len(self.calls("run")), 3)  # init once, prepare every start
        stopped = self.owner_stop(invocation, request)
        # Discard: the volume through the same mapping; host directories kept.
        discarded = self.call("discard", run="run-1", resource="res-1")
        self.assertEqual(discarded["type"], "discarded", discarded)
        self.assertEqual(self.calls("volume create")[-1]["args"], podman.volume_create("keep_id"))
        for path in (project + "-old/new", os.path.join(reference, "keep")):
            self.assertTrue(os.path.isfile(path), path)
        self.assertTrue(os.path.isdir(other))
        self.assert_no_daemons()

    def test_a_resource_without_mounts_keeps_the_default_mapping(self):
        image, _, image_id = self.install_image()
        self.create(image, retention="home")
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertNotIn("mapping", record)
        self.assertNotIn("mounts", record)
        invocation, request, _ = self.started()
        self.assertEqual(self.calls("volume create")[-1]["args"], podman.volume_create("default"))
        self.assertIn("--uid=1000", podman.volume_create("default"))
        for call in self.calls("run") + self.calls("create"):
            self.assertFalse(any(a.startswith("--userns") for a in call["args"]))
        self.assertEqual(len(self.calls("run")), 1)  # no preparation
        self.owner_stop(invocation, request)

    def test_mounts_need_retained_storage_and_acceptable_sources(self):
        image, _, _ = self.install_image()
        project, _, mounts = self.sources()
        self.assert_failed(self.mounted_create(image, mounts, retention="none"), "unsupported")
        for source, code in ((os.path.join(self.tmp, "absent"), "mount_source_unavailable"),
                             (os.path.join(self.state, "resources"), "mount_source_protected"),
                             (self.state, "mount_source_protected"),
                             (os.path.dirname(self.state), "mount_source_protected"),
                             ("/proc", "mount_source_unsupported"), ("/dev", "mount_source_unsupported"),
                             ("/sys/kernel", "mount_source_unsupported")):
            os.makedirs(os.path.join(self.state, "resources"), 0o700, exist_ok=True)
            bad = [{"source": source, "destination": "x", "access": "ro"}]
            self.assert_failed(self.mounted_create(image, bad), code)
            self.assertFalse(os.path.exists(self.resource_dir()), source)
        # Two paths of one directory (a symlink alias) overlap.
        alias = os.path.join(self.tmp, "alias")
        os.symlink(project, alias)
        both = [{"source": project, "destination": "a", "access": "rw"},
                {"source": alias, "destination": "b", "access": "ro"}]
        self.assert_failed(self.mounted_create(image, both), "mount_source_overlap")
        self.assertEqual(self.calls(), [])

    def test_a_missing_source_or_a_symlinked_destination_refuses_the_start(self):
        image, _, _ = self.install_image()
        project, _, mounts = self.sources()
        self.mounted_create(image, mounts)
        invocation, request, _ = self.started()
        stopped = self.owner_stop(invocation, request)
        os.rename(project, project + "-away")
        creates = len(self.calls("create"))
        invocation, _ = self.start(generation=stopped["generation"], execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "mount_source_unavailable")
        invocation.finish(60)
        self.assertEqual(len(self.calls("create")), creates)
        self.assertTrue(os.path.isdir(project + "-away"))
        os.rename(project + "-away", project)
        # The workload replaced a destination's parent with a symlink.
        home = os.path.join(self.resource_dir(), "volumes", podman.VOLUME, "_data", "home")
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.mkdir(elsewhere)
        remove_tree(os.path.join(home, "src"))
        os.symlink(elsewhere, os.path.join(home, "src"))
        status = self.call("status", run="run-1", resource="res-1")
        invocation, _ = self.start(generation=status["generation"], execution="ex-3", instance="in-3")
        # The retained HOME was used: its state is uncertain, never repaired.
        self.assert_failed(invocation.read(60), "mount_destination_unsafe", durability="uncertain")
        invocation.finish(60)
        self.assertEqual(len(self.calls("create")), creates)
        self.assertEqual(os.listdir(elsewhere), [])

    def test_only_the_helpers_own_refusal_names_an_unsafe_destination(self):
        image, _, _ = self.install_image()
        _, _, mounts = self.sources()
        self.mounted_create(image, mounts)
        # Its mkdir failing (4), the engine's own statuses, a kill: `failed`.
        for n, (status, code) in enumerate(((4, "failed"), (125, "failed"), (126, "failed"), (127, "failed"),
                                            (137, "failed"), (3, "mount_destination_unsafe"))):
            self.config["podman"]["prepare_exit"] = status
            self.save()
            record = self.read_json(self.resource_dir(), "resource.json")
            invocation, _ = self.start(generation=record["generation"], execution=f"ex-{n}", instance=f"in-{n}",
                                       accept_unclean=record["storage"] == "unclean")
            answer = invocation.read(60)
            invocation.finish(60)
            self.assertEqual((answer["type"], answer["code"]), ("failed", code), status)
            self.assertEqual(self.calls("create"), [])

    def linked(self):
        """A mount resource whose one rw source is a symlink to an ordinary
        directory, created and started once; (link, stopped generation)."""
        image, _, _ = self.install_image()
        ordinary = os.path.join(self.tmp, "ordinary")
        os.mkdir(ordinary, 0o755)
        link = os.path.join(self.tmp, "src-link")
        os.symlink(ordinary, link)
        created = self.mounted_create(image, [{"source": link, "destination": "proj", "access": "rw"}])
        self.assertEqual(created["type"], "created", created)
        invocation, request, _ = self.started()
        self.assertIn(f"source={os.path.realpath(ordinary)},", " ".join(self.calls("create")[-1]["args"]))
        return link, self.owner_stop(invocation, request)["generation"]

    def retarget(self, link, target):
        os.unlink(link)
        os.symlink(target, link)

    def refused_start(self, generation, execution, durability="unchanged", code="prerequisite"):
        counts = (len(self.calls("run")), len(self.calls("create")), len(self.calls("volume")))
        invocation, _ = self.start(generation=generation, execution=execution, instance="in-" + execution)
        self.assert_failed(invocation.read(60), code, durability=durability)
        invocation.finish(60)
        self.assertEqual(len(self.calls("create")), counts[1])
        return counts

    def test_a_source_retargeted_into_a_protected_root_refuses_the_next_start(self):
        link, generation = self.linked()
        data = os.path.dirname(self.config["scopes"])
        extra = os.path.join(self.tmp, "declared")
        os.mkdir(extra, 0o700)
        test_qemu.declare(self.tmp, self.config, [
            {"path": os.path.realpath(self.state), "measure": "tree", "uncapped": ["resources"]},
            {"path": os.path.realpath(self.storage), "measure": "filesystem"},
            {"path": os.path.realpath(extra), "measure": "tree"}])
        self.save()
        # The host's run store (the limits file's directory), inside or
        # equal, a newly declared scope, STATE, the assets: each refused
        # before the retained HOME or the engine's container is touched.
        inside = os.path.join(data, "runs")
        os.mkdir(inside, 0o700)
        for n, target in enumerate((data, inside, extra, self.state, podman.ROOT, self.storage)):
            self.retarget(link, target)
            runs, _, volumes = self.refused_start(generation, f"ex-p{n}", code="mount_source_protected")
            self.assertEqual((len(self.calls("run")), len(self.calls("volume"))), (runs, volumes), target)
        # Ordinary replacement stays allowed.
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.mkdir(elsewhere, 0o755)
        self.retarget(link, elsewhere)
        invocation, request, _ = self.started(generation=generation, execution="ex-ok", instance="in-ok")
        self.assertIn(f"source={os.path.realpath(elsewhere)},", " ".join(self.calls("create")[-1]["args"]))
        self.owner_stop(invocation, request)

    def test_the_old_cli_default_stores_stay_protected(self):
        """Whichever store asked: a source retargeted into the old CLI's
        default store roots (by the host environment) refuses every start."""
        link, generation = self.linked()
        home, xdg = os.path.join(self.tmp, "host-home"), os.path.join(self.tmp, "host-xdg")
        stores = [os.path.join(xdg, "agentbox"), os.path.join(home, ".local", "share", "agentbox")]
        for store in stores:
            os.makedirs(os.path.join(store, "runs"), 0o700)
        self.config["environ"] = {"HOME": home, "XDG_DATA_HOME": xdg}
        self.save()
        provider = podman.Provider(self.state, TestHost(self.config), None)
        self.assertEqual(provider.protected()[-2:], stores)
        for n, target in enumerate(stores + [os.path.join(stores[1], "runs"), os.path.dirname(stores[1])]):
            self.retarget(link, target)
            self.refused_start(generation, f"ex-l{n}", code="mount_source_protected")
        # Without those variables: nothing invented, the rest unchanged.
        self.config["environ"] = {"XDG_DATA_HOME": "relative"}
        self.save()
        self.assertFalse(set(stores) & set(podman.Provider(self.state, TestHost(self.config), None).protected()))
        elsewhere = os.path.join(self.tmp, "elsewhere-l")
        os.mkdir(elsewhere, 0o755)
        self.retarget(link, elsewhere)
        invocation, request, _ = self.started(generation=generation, execution="ex-lok", instance="in-lok")
        self.owner_stop(invocation, request)

    def test_the_second_resolution_after_preparation_keeps_the_full_set(self):
        link, generation = self.linked()
        data = os.path.dirname(self.config["scopes"])
        self.config["podman"]["retarget"] = [link, data]
        self.save()
        # Retargeted while the helper ran: the resolution before `create`
        # refuses; the retained HOME was used, so its state is uncertain.
        self.refused_start(generation, "ex-2", durability="uncertain", code="mount_source_protected")
        self.assertEqual(os.path.realpath(link), os.path.realpath(data))

    def test_a_missing_or_malformed_limits_file_refuses_a_mounted_start(self):
        link, generation = self.linked()
        # Absent: never an empty set.
        limits = slurp(self.config["scopes"])
        os.unlink(self.config["scopes"])
        self.refused_start(generation, "ex-1")
        write(self.config["scopes"], limits, 0o600)
        write(self.config["scopes"], "{not json", 0o600)
        self.refused_start(generation, "ex-2")
        # The limits path must be the store's limits file.
        other = os.path.join(self.tmp, "data", "other.json")
        write(other, json.dumps({"max_reserved_bytes": 1 << 40, "storage_scopes": []}), 0o600)
        self.config["scopes"] = other
        self.save()
        self.refused_start(generation, "ex-3")

    def test_a_limits_file_removed_during_preparation_refuses_before_create(self):
        link, generation = self.linked()
        extra = os.path.join(self.tmp, "declared")
        os.mkdir(extra, 0o700)
        test_qemu.declare(self.tmp, self.config, [
            {"path": os.path.realpath(self.state), "measure": "tree", "uncapped": ["resources"]},
            {"path": os.path.realpath(self.storage), "measure": "filesystem"},
            {"path": os.path.realpath(extra), "measure": "tree"}])
        # While the helper runs the source turns into a once-declared scope
        # and the limits file is unlinked: the second resolution refuses
        # (no empty set stands in), before `create`; HOME was used.
        self.config["podman"].update(retarget=[link, extra], unlink_limits=True)
        self.save()
        self.refused_start(generation, "ex-2", durability="uncertain")
        self.assertFalse(os.path.exists(self.config["scopes"]))
        self.assertEqual(self.stores(), [])
        self.assert_no_daemons()

    def test_a_resource_without_mounts_ignores_an_absent_limits_file_as_before(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        os.unlink(self.config["scopes"])
        # The optional reader, as ever: nothing declared, so the start's new
        # store is refused by admission (no mount check involved).
        invocation, _ = self.start()
        answer = invocation.read(60)
        invocation.finish(60)
        self.assert_failed(answer, "prerequisite")
        self.assertEqual(self.calls("run"), [])

    def test_a_mount_resource_below_its_minimum_memory_refuses_each_start_before_allocation(self):
        image, _, _ = self.install_image()
        _, _, mounts = self.sources()
        self.mounted_create(image, mounts)
        for n in range(2):
            invocation, _ = self.start(execution=f"ex-low{n}", instance=f"in-low{n}",
                                       limits={"memory_mib": podman.MOUNT_MIN_MEMORY_MIB - 1})
            self.assert_failed(invocation.read(60), "mounts_need_memory")
            invocation.finish(60)
            self.assertEqual(self.calls(), [])
            self.assertFalse(os.path.exists(os.path.join(self.resource_dir(), "instances", f"in-low{n}")))
            self.assertFalse(os.path.exists(os.path.join(self.state, "bindings", f"in-low{n}")))
        self.assertEqual(self.stores(), [])
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["generation"], record["storage"], record["instance"]), (0, "clean", None))
        # The minimum itself, then the default, start.
        invocation, request, _ = self.started(limits={"memory_mib": podman.MOUNT_MIN_MEMORY_MIB})
        self.assertEqual(self.calls("create")[-1]["limits"]["memory.max"], str(podman.MOUNT_MIN_MEMORY_MIB << 20))
        generation = self.owner_stop(invocation, request)["generation"]
        invocation, request, _ = self.started(generation=generation, execution="ex-2", instance="in-2")
        self.owner_stop(invocation, request)
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assert_no_daemons()

    def test_a_resource_without_mounts_keeps_the_global_minimum(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started(limits={"memory_mib": podman.MIN_MEMORY_MIB})
        self.owner_stop(invocation, request)
        invocation, _ = self.start(execution="ex-2", instance="in-2", generation=1,
                                   limits={"memory_mib": podman.MIN_MEMORY_MIB - 1})
        self.assert_failed(invocation.read(60), "failed")
        invocation.finish(60)

    def test_the_closed_mount_commands(self):
        image_id = "a" * 64
        with self.assertRaises(common.Failure):
            podman.create_command(image_id, "none", "dev_1", "keep_id", [("/s", "d", "rw")])
        for bad in ([("/s,x", "d", "rw")], [("/s", "d", "rwx")], [("relative", "d", "ro")]):
            with self.assertRaises(common.Failure):
                podman.bind_flags("/home/dev_1", bad)
        for bad in ([".agentbox"], [".agentbox-inputs-x"], [".agentbox-root"], ["a/../b"], [], ["/abs"]):
            with self.assertRaises(common.Failure):
                podman.prepare_command(image_id, "dev_1", "keep_id", bad)
        with self.assertRaises(common.Failure):
            podman.userns_flags("auto")
        with self.assertRaises(common.Failure):
            podman.mapping_of({"mapping": "auto"})
        self.assertEqual(podman.mapping_of({}), "default")
        # Destinations are arguments, never script text.
        command = podman.prepare_command(image_id, "dev_1", "keep_id", ["src/proj", ".pi"])
        self.assertEqual(command[command.index("-c") + 1:],
                         [podman.PREPARE_SCRIPT, "sh", "/home/dev_1", "src/proj", ".pi"])
        self.assertEqual(podman.bind_flags("/home/dev_1", [("/s/.pi", ".pi", "rw")]),
                         ["--mount=type=bind,source=/s/.pi,destination=/home/dev_1/.pi,rw,nosuid,nodev,"
                          "bind-propagation=private,bind-nonrecursive"])


class RemovalProof(Case):
    """Removal is proven only by the held original's own detachment,
    recorded while it is held; nothing absent stands for it."""

    def retained(self, stop=True):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        invocation, request, _ = self.started()
        if stop:
            self.owner_stop(invocation, request)
        return invocation, request

    def volume(self):
        return self.read_json(self.resource_dir(), "resource.json")["volume"]

    def rm_calls(self):
        return [c for c in self.calls("volume") if c["args"][1] == "rm"]

    def test_a_volume_renamed_out_after_the_intent_is_never_removed(self):
        self.retained()
        self.config["podman"] = {"volume_rm": "rename_out"}
        self.save()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertEqual((self.volume()["state"], self.volume()["receipt"]), ("ready", None))
        self.assertTrue(os.path.isdir(os.path.join(self.records, "renamed-volume", "_data", "home")))
        self.config["podman"] = {}
        self.save()
        # Missing after the intent, without a receipt: still unconfirmed.
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertEqual(len(self.rm_calls()), 1)
        self.assertEqual(self.stores(), [])

    def test_a_crash_after_detach_but_before_the_receipt_stays_unconfirmed(self):
        self.retained()
        self.config["podman"] = {"volume_rm": "crash"}
        self.save()
        invocation = self.invoke()
        invocation.send(self.frame("discard", run="run-1", resource="res-1"))
        self.assertIsNone(invocation.read(30))
        invocation.finish()
        self.assertEqual(self.volume()["receipt"], None)
        self.config["podman"] = {}
        self.save()
        # The lost discard's engine and store are settled by this retry;
        # the volume is gone but unproven.
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertEqual(len(self.rm_calls()), 1)
        self.assertEqual(self.stores(), [])
        self.assert_no_daemons()

    def test_the_receipt_is_durable_before_later_cleanup(self):
        self.retained()
        self.config["immune"] = ["engine"]
        self.config["kill_reserve"] = 1.0
        self.save()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        volume = self.volume()
        self.assertEqual(volume["state"], "removed")
        self.assertEqual(volume["receipt"], {"pin": volume["pin"], "nlink": 0})
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["engine"], record["store"]["removed"]), ("engine", False))
        self.config["immune"] = []
        self.save()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(len(self.rm_calls()), 1)
        self.assertEqual(self.stores(), [])
        self.assert_no_daemons()

    def test_the_parent_must_be_the_original_and_reachable(self):
        self.retained()
        volumes = os.path.join(self.resource_dir(), "volumes")
        os.rename(volumes, os.path.join(self.tmp, "volumes-original"))
        os.mkdir(volumes, 0o700)
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        os.rmdir(volumes)
        os.rename(os.path.join(self.tmp, "volumes-original"), volumes)
        os.chmod(volumes, 0)
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        os.chmod(volumes, 0o700)
        self.assertEqual(self.rm_calls(), [])
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertFalse(os.path.exists(volumes))

    def test_only_a_durably_unallocated_volume_needs_no_receipt(self):
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.calls(), [])
        # An allocation that began but published no pin and left no
        # directory is not "never allocated".
        self.create(image, resource="res-2", retention="home")
        self.config["podman"] = {"hang": "volume-create"}
        self.save()
        invocation, request = self.start(resource="res-2")
        deadline = time.monotonic() + 30
        while not self.calls("volume") and time.monotonic() < deadline:
            time.sleep(0.05)
        invocation.proc.kill()
        invocation.proc.wait()
        self.config["podman"] = {}
        self.save()
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        record = self.read_json(self.resource_dir("res-2"), "resource.json")
        self.assertEqual((record["volume"]["state"], record["volume"]["pin"]), ("allocating", None))
        self.assert_failed(self.call("discard", run="run-1", resource="res-2"), "failed", "unsettled", "uncertain")
        self.assertEqual(self.rm_calls(), [])

    def killed_start(self, hang, behaviour=None):
        """A start that dies at `hang` (an engine call), then settled."""
        image, _, _ = self.install_image()
        self.create(image, retention="home")
        self.config["podman"] = behaviour or {"hang": hang}
        self.save()
        invocation, request = self.start()
        deadline = time.monotonic() + 30
        while invocation.proc.poll() is None and not self.calls("run" if hang == "init" else "volume"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        if behaviour is None:
            invocation.proc.kill()
        invocation.proc.wait()
        invocation.finish()
        self.config["podman"] = {}
        self.save()
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        return image

    def refuse_reuse(self):
        invocation, _ = self.start(generation=1, accept_unclean=True, execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "failed")
        invocation.finish()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertEqual(self.rm_calls(), [])

    def test_an_allocation_without_its_published_pin_is_never_adopted(self):
        self.killed_start("volume-create", {"volume_create": "crash"})
        volume = self.volume()
        self.assertEqual((volume["state"], volume["pin"]), ("allocating", None))
        original = os.path.join(self.resource_dir(), "volumes", podman.VOLUME)
        self.assertTrue(os.path.isdir(original))
        self.assertEqual(len(self.calls("volume")), 1)
        # Neither discard nor a later start pins whatever the name holds.
        self.refuse_reuse()
        self.assertEqual(len(self.calls("volume")), 1)
        self.assertTrue(os.path.isdir(os.path.join(original, "_data")))
        self.assertEqual((self.volume()["state"], self.volume()["pin"]), ("allocating", None))

    def test_a_published_pin_refuses_a_replacement_everywhere(self):
        self.killed_start("init")
        volume = self.volume()
        self.assertEqual(volume["state"], "allocated")
        original = os.path.join(self.resource_dir(), "volumes", podman.VOLUME)
        self.assertEqual(volume["pin"], podman.volume_pin(os.stat(original)))
        os.rename(original, os.path.join(self.tmp, "original-volume"))
        os.mkdir(original)
        write(os.path.join(original, "keep"), "replacement")
        self.refuse_reuse()
        self.assertEqual(slurp(os.path.join(original, "keep")), b"replacement")
        os.unlink(os.path.join(original, "keep"))
        os.rmdir(original)
        os.rename(os.path.join(self.tmp, "original-volume"), original)
        # Its own directory again: removed through the engine, proven.
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(len(self.rm_calls()), 1)

    def test_a_published_allocation_is_initialized_by_the_next_start(self):
        self.killed_start("init")
        self.assertEqual(self.volume()["state"], "allocated")
        invocation, request, _ = self.started(generation=1, accept_unclean=True, execution="ex-2", instance="in-2")
        self.assertEqual(self.volume()["state"], "ready")
        self.assertEqual(len(self.calls("run")), 2)
        self.owner_stop(invocation, request)

    def test_a_start_refuses_a_replaced_ready_volume(self):
        self.retained()
        original = os.path.join(self.resource_dir(), "volumes", podman.VOLUME)
        os.chmod(original, 0o700)
        os.rename(original, os.path.join(self.tmp, "original-volume"))
        os.mkdir(original)
        invocation, _ = self.start(generation=1, execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "failed")
        invocation.finish()
        self.assertEqual(os.listdir(original), [])
        self.assertEqual(len([c for c in self.calls("volume") if c["args"][1] == "create"]), 1)

    def test_a_renamed_store_is_never_chased(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        invocation.proc.kill()
        invocation.proc.wait()
        name = self.instance()["store"]["name"]
        os.rename(os.path.join(self.storage, name), os.path.join(self.tmp, "moved-store"))
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assertTrue(os.path.isdir(os.path.join(self.tmp, "moved-store", "graph")))
        self.assertTrue(self.instance()["store"]["residue"])
        self.assert_no_daemons()

    def test_disposal_is_never_refused_by_admission_or_a_changed_declaration(self):
        """A discard's fresh engine store only removes: no capacity
        threshold (residue count, free space) refuses it; it uses the
        resource's recorded storage root, not a later edit of the inputs,
        and needs no declared scope: missing or invalid limits files never
        block disposal. (Physical ENOSPC still fails honestly.)"""
        self.retained()
        recorded = self.read_json(self.resource_dir(), "resource.json")["storage_root"]
        self.assertEqual(recorded, self.storage)
        for n in range(podman.STORE_RESIDUE + 1):
            os.mkdir(os.path.join(self.storage, f"s-{n:032x}"))
        self.config["min_free"] = 1 << 62
        # The operator now points new stores elsewhere, outside every scope,
        # and the limits file is unreadable.
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.mkdir(elsewhere, 0o700)
        write(os.path.join(self.state, "inputs", podman.INPUTS), json.dumps({
            "schema": podman.INPUTS_SCHEMA, "storage_root": elsewhere,
            "build_args": {"GIT_SHA256": "1" * 64}}), 0o600)
        write(self.config["scopes"], "not json", 0o600)
        self.save()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        # The removal's engine store was made on the recorded root only.
        self.assertEqual(os.listdir(elsewhere), [])
        self.assertTrue(self.rm_calls())

    def test_new_allocation_needs_declared_scopes(self):
        """Growth (create, start) refuses before any effect when STATE or the
        opened storage root lies in no declared scope, or the limits file is
        absent; a declared root admits it again."""
        image, _, _ = self.install_image()
        test_qemu.declare(self.tmp, self.config, [{"path": os.path.realpath(self.state), "measure": "tree"}])
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image,
                                     retention="home", user="agentbox"), "prerequisite")
        self.assertFalse(os.path.exists(self.resource_dir()))
        os.unlink(self.config["scopes"])
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image,
                                     retention="none", user="agentbox"), "prerequisite")
        self.assertFalse(os.path.exists(self.resource_dir()))
        test_qemu.declare(self.tmp, self.config, [{"path": os.path.realpath(self.state), "measure": "tree"},
                                                  {"path": os.path.realpath(self.storage), "measure": "filesystem"}])
        self.save()
        self.create(image)
        test_qemu.declare(self.tmp, self.config, [{"path": os.path.realpath(self.state), "measure": "tree"}])
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "prerequisite")
        _, _, err = invocation.finish()
        self.assertIn(b"storage scope undeclared", err)
        self.assertEqual(self.stores(), [])

    def test_a_refused_growth_reconciles_nothing(self):
        """An undeclared resource directory (a fake topology) refuses
        before ready_resource's reconciliation writes: a settled but
        unapplied instance stays unapplied, every record and path
        unchanged. Declared, the same resource is reconciled."""
        image, _, _ = self.install_image()
        self.create(image)
        directory = self.resource_dir()
        record = self.read_json(directory, "resource.json")
        record["instance"] = {"execution": "ex-0", "instance": "in-0"}
        write(os.path.join(directory, "resource.json"), json.dumps(record), 0o600)
        os.makedirs(os.path.join(directory, "instances", "in-0"), 0o700)
        os.chmod(os.path.join(directory, "instances"), 0o700)
        write(os.path.join(directory, "instances", "in-0", "instance.json"),
              json.dumps({"phase": "settled", "result": {"generation": 7, "storage": "clean"}}), 0o600)

        def snapshot():
            seen = {}
            for top, dirs, files in os.walk(directory):
                for name in dirs:
                    seen[os.path.relpath(os.path.join(top, name), directory)] = None
                for name in files:
                    with open(os.path.join(top, name), "rb") as stream:
                        seen[os.path.relpath(os.path.join(top, name), directory)] = stream.read()
            return seen
        before = snapshot()
        self.config["fake_devices"] = {directory: 2 ** 40}
        self.save()
        refusals = [lambda: self.start()]
        for refusal in refusals:
            answer = refusal()
            if isinstance(answer, tuple):
                invocation, _ = answer
                answer = invocation.read(60)
                invocation.finish()
            self.assert_failed(answer, "prerequisite")
            self.assertEqual(snapshot(), before)
        # Declared: reconciled (then refused by its generation).
        del self.config["fake_devices"]
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "generation_mismatch")
        invocation.finish()
        self.assertEqual((self.read_json(directory, "resource.json")["generation"], self.read_json(directory, "resource.json")["instance"]), (7, None))

    def test_start_checks_the_resource_directory_before_making_anything(self):
        """A resource directory on an undeclared filesystem (a fake
        topology: STATE's device elsewhere) refuses start before anything
        is made or written; so does an existing instances directory on one,
        with nothing made in it."""
        image, _, _ = self.install_image()
        self.create(image)
        directory = self.resource_dir()
        listing = lambda path: sorted(os.listdir(path))

        def record():
            with open(os.path.join(directory, "resource.json"), "rb") as stream:
                return stream.read()
        before = (listing(directory), record())
        self.config["fake_devices"] = {directory: 2 ** 40}
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "prerequisite")
        _, _, err = invocation.finish()
        self.assertIn(b"storage scope undeclared", err)
        self.assertEqual((listing(directory), record()), before)
        bindings = os.path.join(self.state, "bindings")
        self.assertFalse(os.path.exists(bindings))
        instances = os.path.join(directory, "instances")
        os.mkdir(instances, 0o700)
        self.config["fake_devices"] = {instances: 2 ** 40}
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "prerequisite")
        invocation.finish()
        self.assertEqual(listing(instances), [])
        # Both existing directories are checked before either is made.
        self.assertFalse(os.path.exists(bindings))
        self.assertEqual(record(), before[1])

    def test_storage_root_admission_bounds_residue_and_space(self):
        image, _, _ = self.install_image()
        self.create(image)
        for n in range(podman.STORE_RESIDUE + 1):
            os.mkdir(os.path.join(self.storage, f"s-{n:032x}"))
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "prerequisite")
        _, _, err = invocation.finish()
        self.assertIn(b"warning: capacity admission refused", err)
        for n in range(podman.STORE_RESIDUE + 1):
            os.rmdir(os.path.join(self.storage, f"s-{n:032x}"))
        self.config["min_free"] = 1 << 62
        self.save()
        invocation, _ = self.start(execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "prerequisite")
        invocation.finish()
        self.assertEqual(self.calls(), [])

    def test_after_a_failed_disposal_only_our_writable_leftovers_go(self):
        image, _, _ = self.install_image()
        self.create(image)
        self.config["podman"] = {"dispose_fail": True, "writable": True}
        self.save()
        invocation, request, _ = self.started()
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")
        store = self.instance()["store"]
        self.assertEqual((store["disposed"], store["removed"], store["residue"]), (False, True, False))
        self.assertEqual(self.stores(), [])

@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class Admission(Case):
    """Teardown needs the exclusive admission lock: a bridge between its
    live check and its spawn, or a lock that cannot be had, keeps it."""

    def pause_bridges(self):
        self.go = os.path.join(self.tmp, "go")
        self.config.update(pause_bridge=self.go, admission_wait=1.0)
        self.save()

    def paused(self, request):
        bridge = self.connect(request)
        deadline = time.monotonic() + 30
        while not any(n.startswith("bridge-paused-") for n in os.listdir(self.records)):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        return bridge

    def assert_kept(self):
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["store"]["removed"]), ("stopping", "engine", False))
        self.assertEqual(self.stores(), [inst["store"]["name"]])
        self.assertTrue(any(_alive(p) for p in self.daemons("conmon")))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual(status["resource_state"], "busy")

    def release(self, bridge, request):
        write(self.go, "")
        self.assertEqual(bridge.read(line=True), b"SSH-2.0-stand-in\r\n")
        self.assertEqual(self.calls("exec")[-1]["child"], "engine")
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        stopped = self.standalone_stop(request)
        self.assertEqual(stopped["type"], "stopped", stopped)
        self.assertEqual(bridge.finish()[0], 0)
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])

    def test_the_owner_never_tears_down_under_a_paused_bridge(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        self.pause_bridges()
        bridge = self.paused(request)
        self.assert_failed(self.owner_stop(invocation, request), "failed", "unsettled", "uncertain")
        self.assertEqual(self.calls("rm"), [])
        self.assert_kept()
        self.release(bridge, request)

    def test_a_standalone_stop_never_tears_down_under_a_paused_bridge(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        self.pause_bridges()
        bridge = self.paused(request)
        invocation.proc.kill()
        invocation.proc.wait()
        self.assert_failed(self.standalone_stop(request), "busy", "unsettled", "uncertain")
        self.assert_kept()
        self.release(bridge, request)

    def break_lock(self):
        lock = os.path.join(self.resource_dir(), "instances", "in-1", "admission.lock")
        os.unlink(lock)
        os.symlink("/dev/null", lock)
        return lock

    def test_an_errored_admission_lock_keeps_everything(self):
        image, _, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        lock = self.break_lock()
        self.assert_failed(self.owner_stop(invocation, request), "failed", "unsettled", "uncertain")
        self.assert_kept()
        self.assert_failed(self.standalone_stop(request), "busy", "unsettled", "uncertain")
        self.assert_kept()
        os.unlink(lock)
        write(lock, "", 0o600)
        self.assertEqual(self.standalone_stop(request)["type"], "stopped")
        self.assert_no_daemons()
        self.assertEqual(self.stores(), [])


class Prepare(Case):
    def setUp(self):
        super().setUp()
        repo = os.path.join(self.tmp, "repo")
        test_worker.fake_guest(repo)
        self.repo = repo
        self.config["root"] = repo
        self.save()

    def prepare(self, recipe=podman.CANONICAL_RECIPE):
        return self.call("prepare", timeout_ms=600000, recipe=recipe, worker=self.repo)

    def test_the_worker_sources_are_the_providers_own_tree(self):
        other = os.path.join(self.tmp, "other")
        test_worker.fake_guest(other)
        answer = self.call("prepare", timeout_ms=600000, recipe=podman.CANONICAL_RECIPE, worker=other)
        self.assert_failed(answer, "prerequisite")
        self.assertEqual(self.builds(), 0)
        self.assertEqual(self.prepare()["type"], "prepared")

    def builds(self):
        path = os.path.join(self.records, "build-count")
        return len(slurp(path)) if os.path.exists(path) else 0

    def test_prepare_needs_a_declared_state_before_any_work(self):
        """A prepare (its work dir and build store under STATE) refuses
        before making anything when STATE is not declared."""
        test_qemu.declare(self.tmp, self.config, [{"path": os.path.realpath(self.records), "measure": "tree"}])
        self.save()
        self.assert_failed(self.prepare(), "prerequisite")
        self.assertFalse(os.path.exists(os.path.join(self.state, "work")))
        self.assertFalse(os.path.exists(os.path.join(self.state, "images")))

    def test_the_built_archive_is_the_image_and_carries_its_metadata(self):
        answer = self.prepare()
        self.assertEqual(answer["type"], "prepared", answer)
        image = answer["image"]
        entry = os.path.join(self.state, "images", image)
        self.assertEqual(stat.S_IMODE(os.stat(entry).st_mode), 0o500)
        for name in ("image.oci.tar", "worker-metadata.json", "record.json"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(entry, name)).st_mode), 0o400, name)
        data = slurp(os.path.join(entry, "image.oci.tar"))
        self.assertEqual(hashlib.sha256(data).hexdigest(), image)
        record = self.read_json(entry, "record.json")
        self.assertEqual(record["image_id"], archive_image_id(data))
        metadata = self.read_json(entry, "worker-metadata.json")
        self.assertEqual(metadata["release"], answer["worker_sha256"])
        # The canonical recipe's agents, measured in the layer: their
        # versions answered, their locks' digests recorded.
        agentlock = podman._agentlock()
        self.assertEqual(answer["agents"], {agent: "2.0.0" for agent in agentlock.AGENTS})
        self.assertEqual(list(answer["agents"]), list(protocol.AGENTS))
        self.assertEqual(set(record["agents"]), set(agentlock.AGENTS))
        for agent, value in record["agents"].items():
            self.assertEqual((value["package"], value["version"]), (agentlock.PACKAGES[agent], "2.0.0"))
            self.assertRegex(value["lock_sha256"], "^[0-9a-f]{64}$")
        build = self.calls("build")[-1]
        self.assertEqual(build["child"], "build")
        self.assertIn("--squash-all", build["args"])
        self.assertIn("--build-arg=GIT_SHA256=" + "1" * 64, build["args"])
        self.assertFalse(any(a.startswith("--target") or a.startswith("--output") for a in build["args"]))
        self.assertEqual(slurp(os.path.join(self.records, "build-file")), slurp(podman.CANONICAL_RECIPE))
        self.assertEqual(self.calls("save")[-1]["args"][3], record["image_id"])
        self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
        self.assert_no_daemons()
        # No source-key reuse: the recipe's inputs are not all locked. The
        # same output is cached once.
        again = self.prepare()
        self.assertEqual((again["image"], again["worker_sha256"]), (image, answer["worker_sha256"]))
        self.assertEqual(self.builds(), 2)
        # The prepared image starts.
        self.create(image)
        invocation, request, started = self.started()
        self.assertEqual(started["worker_sha256"], answer["worker_sha256"])
        self.owner_stop(invocation, request)

    def test_a_custom_recipe_builds_from_its_own_copy(self):
        recipe = os.path.join(self.tmp, "Custom.Dockerfile")
        write(recipe, "FROM scratch\n", 0o644)
        answer = self.prepare(recipe)
        self.assertEqual(answer["type"], "prepared", answer)
        record = self.read_json(self.state, "images", answer["image"], "record.json")
        self.assertEqual(record["origin"]["recipe"]["canonical"], False)
        self.assertEqual(slurp(os.path.join(self.records, "build-file")), b"FROM scratch\n")
        # Its agents (if any) are its own: neither answered nor recorded,
        # nor required.
        self.assertNotIn("agents", answer)
        self.assertNotIn("agents", record)
        self.config["podman"] = {"variant": "agent_missing"}
        self.save()
        self.assertEqual(self.prepare(recipe)["type"], "prepared")

    def test_each_canonical_recipe_is_measured_as_its_own(self):
        dev = os.path.join(podman.ROOT, "images", "podman", "dev", "Dockerfile")
        self.assertEqual(podman.CANONICAL_RECIPES,
                         {os.path.join(podman.ROOT, "images", "podman", "default", "Dockerfile"):
                          "podman/default/Dockerfile", dev: "podman/dev/Dockerfile"})
        self.assertEqual(podman.CANONICAL_RECIPES[podman.CANONICAL_RECIPE], "podman/default/Dockerfile")
        first = answer = self.prepare(dev)
        self.assertEqual(answer["type"], "prepared", answer)
        self.assertEqual(answer["agents"], {agent: "2.0.0" for agent in protocol.AGENTS})
        record = self.read_json(self.state, "images", answer["image"], "record.json")
        self.assertEqual(record["origin"]["recipe"], {"path": dev, "canonical": True,
                                                      "sha256": hashlib.sha256(slurp(dev)).hexdigest()})
        self.assertEqual(slurp(os.path.join(self.records, "build-file")), slurp(dev))
        # The same bytes elsewhere: the operator's own recipe, not measured.
        copy = os.path.join(self.tmp, "Dockerfile")
        write(copy, slurp(dev), 0o644)
        answer = self.prepare(copy)
        self.assertEqual(answer["type"], "prepared", answer)
        self.assertNotIn("agents", answer)
        # (The stand-in builds the same bytes: the entry is the first one's.)
        self.assertEqual(answer["image"], first["image"])

    def test_each_prepare_builds_the_agents_anew_and_keeps_earlier_images(self):
        first = self.prepare()
        entry = os.path.join(self.state, "images", first["image"])
        before = {name: slurp(os.path.join(entry, name)) for name in os.listdir(entry)}
        # The registry's latest moved: the next build, in a fresh store, has it.
        self.config["podman"] = {"agents": "2.1.0"}
        self.save()
        second = self.prepare()
        self.assertEqual(second["agents"], {agent: "2.1.0" for agent in protocol.AGENTS})
        self.assertNotEqual(second["image"], first["image"])
        self.assertEqual(self.builds(), 2)
        builds = self.calls("build")
        self.assertEqual(len(builds), 2)
        # Each in its own fresh build store: no layer of the first to reuse.
        self.assertNotEqual(builds[0]["globals"]["root"], builds[1]["globals"]["root"])
        self.assertEqual(sorted(self.images()), sorted([first["image"], second["image"]]))
        self.assertEqual({name: slurp(os.path.join(entry, name)) for name in os.listdir(entry)}, before)
        self.assertEqual(self.read_json(entry, "record.json")["agents"]["pi"]["version"], "2.0.0")
        # Both start.
        for n, image in enumerate((first["image"], second["image"])):
            self.create(image, resource=f"res-{n}", run=f"run-{n}")
            invocation, request, started = self.started(resource=f"res-{n}", run=f"run-{n}", execution=f"ex-{n}",
                                                        instance=f"in-{n}")
            self.owner_stop(invocation, request)

    def test_agents_other_than_the_checked_ones_are_no_image(self):
        good = self.prepare()
        for variant in sorted(AGENT_VARIANTS):
            self.config["podman"] = {"variant": variant}
            self.save()
            self.assert_failed(self.prepare(), "failed")
            self.assertEqual(self.images(), [good["image"]], variant)
            self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
            self.assert_no_daemons()

    def test_unproven_outputs_are_never_cached(self):
        for variant in ("tamper", "unsealed", "revision", "iid"):
            self.config["podman"] = {"variant": variant}
            self.save()
            self.assert_failed(self.prepare(), "failed")
            self.assertFalse(os.path.exists(os.path.join(self.state, "images")) and
                             [n for n in os.listdir(os.path.join(self.state, "images")) if not n.startswith(".")])
            self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
            self.assert_no_daemons()

    def work(self):
        return sorted(os.listdir(os.path.join(self.state, "work")))

    def images(self):
        path = os.path.join(self.state, "images")
        return os.listdir(path) if os.path.isdir(path) else []

    def test_a_build_child_that_will_not_empty_is_unsettled_and_kept(self):
        self.config.update(immune=["build"], kill_reserve=1.0)
        self.save()
        self.assert_failed(self.prepare(), "failed", "unsettled")
        # A live writer: its whole work dir stays, nothing is imported.
        self.assertEqual(self.work(), ["op-1"])
        self.assertTrue(os.path.isfile(os.path.join(self.state, "work", "op-1", "image.oci.tar")))
        self.assertEqual(self.images(), [])
        self.assertTrue(any(_alive(p) for p in self.daemons("pause")))

    def prepare_err(self):
        invocation = self.invoke()
        invocation.send(self.frame("prepare", timeout_ms=600000, recipe=podman.CANONICAL_RECIPE, worker=self.repo))
        answer = invocation.read(60)
        code, rest, err = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        return answer, err

    def test_a_failed_disposal_leaves_warned_build_residue(self):
        self.config["podman"] = {"fail": "rmi"}
        self.save()
        answer, err = self.prepare_err()
        # Every writer settled: the image is published; the build store's
        # subordinate-like layers stay, never chmod-ed, with warnings.
        self.assertEqual(answer["type"], "prepared", answer)
        self.assertIn(b"warning: engine store residue left", err)
        self.assertIn(b"warning: prepare scratch residue left", err)
        self.assertEqual(self.images(), [answer["image"]])
        self.assertEqual(self.work(), ["op-1"])
        self.assert_no_daemons()

    def test_unremovable_scratch_is_a_warning_and_bounded(self):
        self.config["podman"] = {"variant": "lock_scratch"}
        self.save()
        answer, err = self.prepare_err()
        self.assertEqual(answer["type"], "prepared", answer)
        self.assertIn(b"warning: prepare scratch residue left", err)
        self.assertEqual(self.work(), ["op-1"])
        self.config["podman"] = {}
        self.save()
        for n in range(podman.WORK_RESIDUE):
            os.mkdir(os.path.join(self.state, "work", f"left-{n}"))
        answer, err = self.prepare_err()
        self.assert_failed(answer, "prerequisite")
        self.assertIn(b"warning: capacity admission refused", err)

    def test_ordinary_failures_with_surviving_helpers_settle_first(self):
        for config in ({"deny_pidfd": 1}, {"podman": {"variant": "no_iid"}}):
            self.config.update(config)
            self.save()
            self.assert_failed(self.prepare(), "failed")
            self.assertEqual(self.work(), [])
            self.assertEqual(self.images(), [])
            self.assert_no_daemons()
            self.config.pop("deny_pidfd", None)
            self.config["podman"] = {}
            self.save()

    def test_a_failed_publication_is_settled_and_rolls_back_its_staging(self):
        self.config["fail_methods"] = {"write_entry": "enospc"}
        self.save()
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual((self.work(), self.images()), ([], []))
        self.assert_no_daemons()

    def test_a_replaced_staging_entry_is_never_removed(self):
        self.config["replace_staging"] = True
        self.save()
        answer, err = self.prepare_err()
        self.assert_failed(answer, "failed")
        self.assertIn(b"warning: cache staging residue left", err)
        staging = os.path.join(self.state, "images", ".staging-op-1")
        self.assertEqual(slurp(os.path.join(staging, "keep")), b"replacement")
        # The moved original is not chased either.
        self.assertTrue(os.path.isfile(staging + "-original/image.oci.tar"))

    def test_an_invalid_existing_entry_is_never_replaced(self):
        first = self.prepare()
        image = first["image"]
        self.create(image)
        entry = os.path.join(self.state, "images", image)
        self.corrupt(entry)
        before = {n: slurp(os.path.join(entry, n)) for n in os.listdir(entry)}
        answer, err = self.prepare_err()
        self.assert_failed(answer, "failed")
        self.assertIn(b"warning: cache entry invalid: left untouched", err)
        self.assertEqual({n: slurp(os.path.join(entry, n)) for n in os.listdir(entry)}, before)
        self.assertEqual((self.work(), self.images()), ([], [image]))
        # Its resource's start fails clearly; nothing was rebound under it.
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "failed")
        invocation.finish()
        self.assertEqual(self.calls("load"), [])
        # Nor is an empty directory in its place replaced (same inode).
        os.chmod(entry, 0o700)
        shutil.rmtree(entry)
        os.mkdir(entry, 0o500)
        inode = os.stat(entry).st_ino
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual((os.stat(entry).st_ino, os.listdir(entry)), (inode, []))

    def corrupt(self, entry):
        os.chmod(entry, 0o700)
        record = os.path.join(entry, "record.json")
        os.chmod(record, 0o600)
        write(record, json.dumps(dict(self.read_json(record), worker="0" * 64)), 0o400)
        os.chmod(entry, 0o500)

    def test_an_invalid_unused_entry_is_rebuilt(self):
        image = self.prepare()["image"]
        entry = os.path.join(self.state, "images", image)
        self.corrupt(entry)
        inode = os.stat(entry).st_ino
        answer, err = self.prepare_err()
        self.assertEqual((answer["type"], answer["image"]), ("prepared", image), answer)
        self.assertNotIn(b"warning:", err)
        self.assertNotEqual(os.stat(entry).st_ino, inode)
        self.assertEqual((self.work(), self.images()), ([], [image]))
        # Valid again: a discarded resource's tombstone is no use either.
        self.create(image)
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.corrupt(entry)
        self.assertEqual(self.prepare()["image"], image)
        self.assertEqual(self.images(), [image])
        self.create(image, resource="res-2")

    def test_malformed_resource_records_keep_an_invalid_entry(self):
        image = self.prepare()["image"]
        entry = os.path.join(self.state, "images", image)
        self.corrupt(entry)
        inode = os.stat(entry).st_ino
        for value in ({}, {"state": "ready"}, {"image": None, "state": "ready"},
                      {"image": "x" * 64, "state": "creating"}, {"image": [image], "state": "ready"}):
            with self.subTest(value=value):
                test_qemu.write_record(self.state, "resources", "resource.json", value)
                answer, err = self.prepare_err()
                self.assert_failed(answer, "failed")
                self.assertIn(b"warning: cache entry invalid: left untouched", err)
                self.assertEqual((os.stat(entry).st_ino, self.images()), (inode, [image]))
        test_qemu.write_record(self.state, "resources", "resource.json", {"image": "0" * 64, "state": "ready"})
        self.assertEqual(self.prepare()["image"], image)
        self.assertNotEqual(os.stat(entry).st_ino, inode)

    def test_cache_leftovers_are_bounded_before_a_build(self):
        images = os.path.join(self.state, "images")
        os.makedirs(images, 0o700, exist_ok=True)
        for n in range(common.CACHE_RESIDUE + 1):
            os.mkdir(os.path.join(images, (".staging-left-", ".quarantine-left-")[n % 2] + str(n)))
        answer, err = self.prepare_err()
        self.assert_failed(answer, "prerequisite")
        self.assertIn(b"warning: capacity admission refused", err)
        self.assertEqual((self.builds(), self.work()), (0, []))
        os.rmdir(os.path.join(images, ".quarantine-left-1"))
        self.assertEqual(self.prepare()["type"], "prepared")

    def test_a_moved_or_replaced_work_dir_is_never_deleted(self):
        for n, mode in enumerate(("rename", "replace"), start=1):
            self.config["move_work"] = mode
            self.save()
            answer, err = self.prepare_err()
            self.assertEqual(answer["type"], "prepared", answer)
            self.assertIn(b"warning: prepare scratch residue left", err)
            moved = os.path.join(self.state, "work", f"op-{n}-moved")
            self.assertTrue(os.path.isdir(os.path.join(moved, "stage")), mode)
            if mode == "replace":
                self.assertEqual(os.listdir(os.path.join(self.state, "work", f"op-{n}")), [])

    def test_a_failed_build_still_removes_its_engine_images(self):
        self.config["podman"] = {"fail": "save"}
        self.save()
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
        dispose = self.calls("rmi")[-1]
        self.assertIn("/dispose-1/", dispose["globals"]["runroot"])
        self.assert_no_daemons()


# ---------------------------------------------------------------------------
# The user's own store (`store` shared).

OWN_USERNS, HELPER_USERNS = "user:[4026531837]", "user:[4026532001]"


def fake_proc(root, pid, cmdline=podman.PAUSE_CMDLINE, comm=b"catatonit\n",
              cgroup=b"0::/user.slice/user-1000.slice/user@1000.service/user.slice/podman-pause-1.scope\n",
              userns=HELPER_USERNS):
    """A process table stand-in: ROOT/PID/{cmdline,comm,cgroup,ns/user}
    and ROOT/self/ns/user, as /proc shows them."""
    for name, link in (("self", OWN_USERNS), (str(pid), userns)):
        path = os.path.join(root, name, "ns", "user")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.lexists(path):
            os.unlink(path)
        os.symlink(link, path)
    for name, data in (("cmdline", cmdline), ("comm", comm), ("cgroup", cgroup)):
        write(os.path.join(root, str(pid), name), data)


class SharedHelper(unittest.TestCase):
    """The preflight alone, over a stand-in process table."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abps-")
        self.addCleanup(remove_tree, self.tmp)
        self.runtime = os.path.join(self.tmp, "xdg")
        self.proc = os.path.join(self.tmp, "proc")
        self.pidfile = os.path.join(self.runtime, "libpod", "tmp", "pause.pid")
        write(self.pidfile, "4242")
        fake_proc(self.proc, 4242)
        unit = common.CGROUP_ROOT + "/user.slice/user-1000.slice/user@1000.service/app.slice/agentbox-launch-" \
            + "a" * 32 + ".scope"
        self.custody = type("Custody", (), {"path": unit + "/agentbox-" + "b" * 32})()

    def check(self):
        podman.shared_helper(self.runtime, self.custody, self.proc)

    def refused(self):
        with self.assertRaises(common.Failure) as caught:
            self.check()
        self.assertEqual((caught.exception.code, caught.exception.settlement), ("shared_store_uninitialized",
                                                                                 "settled"))

    def test_a_live_helper_outside_custody_passes(self):
        self.check()
        # The engine's fallback helper names itself by comm only.
        fake_proc(self.proc, 4242, cmdline=b"podman\0info\0", comm=b"podman pause\n")
        self.check()
        write(self.pidfile, "4242\n")
        self.check()

    def test_anything_missing_or_ambiguous_refuses(self):
        os.unlink(self.pidfile)
        self.refused()
        for text in ("", "0", "-1", "42 43", "x", "4242\n\n", "1" * 11):
            write(self.pidfile, text)
            self.refused()
        write(self.pidfile, "4243")
        self.refused()                       # no such process
        os.unlink(self.pidfile)
        os.symlink(os.path.join(self.tmp, "elsewhere"), self.pidfile)
        write(os.path.join(self.tmp, "elsewhere"), "4242")
        self.refused()                       # never through a link
        os.unlink(self.pidfile)
        write(self.pidfile, "4242")
        self.check()
        for bad in (b"sleep\0600\0", b"catatonit\0", b"catatonit\0-P\0x\0", b""):
            fake_proc(self.proc, 4242, cmdline=bad, comm=b"sleep\n")
            self.refused()
        fake_proc(self.proc, 4242, userns=OWN_USERNS)
        self.refused()                       # our own user namespace
        for cgroup in (b"", b"0::/a\n0::/b\n", b"1:name=x:/a\n", b"0::/a"):
            fake_proc(self.proc, 4242, cgroup=cgroup)
            self.refused()
        rel = self.custody.path[len(common.CGROUP_ROOT):]
        for inside in (rel, rel + "/engine", os.path.dirname(rel) + "/controller",
                       "/user.slice/agentbox-launch-" + "c" * 32 + ".scope/x"):
            fake_proc(self.proc, 4242, cgroup=f"0::{inside}\n".encode())
            self.refused()
        fake_proc(self.proc, 4242)
        self.check()
        for runtime in (None, "", "relative/xdg", self.tmp):
            with self.assertRaises(common.Failure):
                podman.shared_helper(runtime, self.custody, self.proc)

    def test_the_profile_and_create_flags(self):
        recorded = {"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000"}
        shared = podman.Shared(recorded, "/usr/bin/podman", "/st/shared", SEARCH, self.custody)
        self.assertEqual(shared.env(), {
            "PATH": SEARCH, "LC_ALL": "C", "HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000",
            "CONTAINERS_CONF_OVERRIDE": "/st/shared/containers.conf",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/st/shared/absent-bus"})
        # The user's storage, database, runtime and conmon: no --root,
        # --runroot, driver, --tmpdir, --volumepath, --runtime or --conmon.
        self.assertEqual(shared.argv(["ps"]), [
            "/usr/bin/podman", "--remote=false", "--cgroup-manager=cgroupfs", "--events-backend=none",
            "--hooks-dir=/st/shared/hooks", "--default-mounts-file=/st/shared/mounts.conf", "--log-level=error",
            "ps"])
        for line in ("volumes = [{append=false}]", "mounts = [{append=false}]", "devices = [{append=false}]",
                     "env = [{append=false}]", "annotations = [{append=false}]", 'userns = "host"',
                     "privileged = false", 'cgroups = "disabled"', 'netns = "none"', "read_only = true"):
            self.assertIn(line + "\n", podman.SHARED_CONF)
        self.assertNotIn("[engine]", podman.SHARED_CONF)
        image = "f" * 64
        words = podman.shared_create_command(image, "agentbox", "run-1", "in-1", "/st/r/in-1/container.id")
        base = podman.create_command(image, "none", "agentbox")
        extra = ["--userns=host", "--privileged=false", "--name=agentbox-in-1", "--label=io.agentbox.run=run-1",
                 "--label=io.agentbox.instance=in-1", "--cidfile=/st/r/in-1/container.id"]
        self.assertEqual([w for w in words if w not in base], extra)
        self.assertEqual(words[-4:], base[-4:])
        self.assertTrue(all(w in words for w in podman.SANDBOX))
        for bad in (("bad run", "in-1", "/c"), ("run-1", "../x", "/c"), ("run-1", "in-1", "c")):
            with self.assertRaises(common.Failure):
                podman.shared_create_command(image, "agentbox", *bad)
        # The engine environment: HOME and XDG_RUNTIME_DIR required, the
        # rest of SHARED_ENV passed when set, nothing else.
        found = podman.shared_env({"HOME": "/h", "XDG_RUNTIME_DIR": "/r", "XDG_DATA_HOME": "",
                                   "CONTAINER_HOST": "unix:///x", "CONTAINERS_STORAGE_CONF": "/s.conf"})
        self.assertEqual(found, {"HOME": "/h", "XDG_RUNTIME_DIR": "/r", "CONTAINERS_STORAGE_CONF": "/s.conf"})
        for environ in ({"HOME": "/h"}, {"XDG_RUNTIME_DIR": "/r"}, {"HOME": "h", "XDG_RUNTIME_DIR": "/r"}):
            with self.assertRaises(common.Failure) as caught:
                podman.shared_env(environ)
            self.assertEqual(caught.exception.code, "shared_store_uninitialized")

    def test_an_archive_names_what_a_load_would_tag(self):
        entries, _ = baked_entries(os.path.join(self.tmp, "bundle"))
        data, _ = oci_archive(entries)
        path = os.path.join(self.tmp, "a.tar")
        write(path, data)
        fd = os.open(path, os.O_RDONLY)
        try:
            archive = podman.Archive(fd, lambda: None)
            try:
                self.assertEqual(archive.names(), [])
            finally:
                archive.close()
        finally:
            os.close(fd)


class SharedCase(Case):
    """Cases in a stand-in user store (HOME/store) whose helper runs (a
    live process outside every custody child, its pid file at the
    engine's place) and is described by a stand-in process table."""

    def setUp(self):
        super().setUp()
        self.home = os.path.join(self.tmp, "home")
        os.mkdir(self.home, 0o700)
        self.runtime = os.path.join(self.tmp, "xdg")
        os.mkdir(self.runtime, 0o700)
        self.proc = os.path.join(self.tmp, "proc")
        self.helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        self.addCleanup(self.end_helper)
        self.pidfile = os.path.join(self.runtime, "libpod", "tmp", "pause.pid")
        write(self.pidfile, str(self.helper.pid))
        fake_proc(self.proc, self.helper.pid)
        self.config.update(environ={"HOME": self.home, "XDG_RUNTIME_DIR": self.runtime}, proc=self.proc)
        self.save()
        write(os.path.join(self.state, "inputs", podman.INPUTS), json.dumps({
            "schema": podman.INPUTS_SCHEMA, "storage_root": self.storage, "store": "shared",
            "build_args": {"GIT_SHA256": "1" * 64}}), 0o600)
        self.conf = os.path.join(self.state, "shared")

    def end_helper(self):
        self.helper.kill()
        self.helper.wait()

    def user_db(self):
        try:
            return self.read_json(self.home, "store", "fake.json")
        except FileNotFoundError:
            return {"images": [], "containers": {}, "volumes": [], "built": {}}

    def save_user_db(self, db):
        write(os.path.join(self.home, "store", "fake.json"), json.dumps(db))

    def share(self, image_id):
        db = self.user_db()
        db["images"].append(image_id)
        self.save_user_db(db)

    def shared_image(self):
        image, release, image_id = self.install_image()
        self.share(image_id)
        return image, release, image_id

    def expected_env(self):
        return {"PATH": SEARCH, "LC_ALL": "C", "HOME": self.home, "XDG_RUNTIME_DIR": self.runtime,
                "CONTAINERS_CONF": AMBIENT["CONTAINERS_CONF"],
                "CONTAINERS_STORAGE_CONF": AMBIENT["CONTAINERS_STORAGE_CONF"],
                "CONTAINERS_CONF_OVERRIDE": self.conf + "/containers.conf",
                "DBUS_SESSION_BUS_ADDRESS": f"unix:path={self.conf}/absent-bus"}

    def kinds(self, calls=None):
        out = []
        for call in self.calls() if calls is None else calls:
            args = call["args"]
            out.append("--version" if not args else " ".join(args[:2]) if args[0] in ("image", "container", "volume")
                       else args[0])
        return out

    def without_helper(self):
        os.unlink(self.pidfile)

    def restore_helper(self):
        write(self.pidfile, str(self.helper.pid))

    def unrelated(self):
        """A container of the user's own, running, never Agentbox's."""
        db = self.user_db()
        db["containers"]["u" * 64] = {"args": [], "mounts": [], "image": "e" * 64, "state": "running",
                                      "conmon": None, "volumepath": None, "name": "mine"}
        self.save_user_db(db)

    def assert_unrelated_kept(self):
        self.assertEqual(self.user_db()["containers"]["u" * 64]["state"], "running")


class SharedStore(SharedCase):
    def test_capabilities_offer_an_explicit_home_and_mounts(self):
        answer = self.call("capabilities")
        self.assertEqual((answer["retention"], answer["features"]),
                         (["none", "home"], ["select_user", "project_layout", "host_mounts", "explicit_retention"]))
        self.assertEqual(self.calls(), [])

    def test_create_start_connect_stop_in_the_users_store(self):
        image, release, image_id = self.shared_image()
        self.unrelated()
        created = self.create(image)
        self.assertEqual(created["retention"], "none")
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["engine_store"], record["engine_env"]), ("shared", {
            "HOME": self.home, "XDG_RUNTIME_DIR": self.runtime, "CONTAINERS_CONF": AMBIENT["CONTAINERS_CONF"],
            "CONTAINERS_STORAGE_CONF": AMBIENT["CONTAINERS_STORAGE_CONF"]}))
        # The image checked there by ID, nothing else.
        self.assertEqual(self.kinds(), ["image exists"])
        self.assertEqual(self.calls("image")[0]["args"], ["image", "exists", image_id])
        # STATE/shared: the override, an empty mounts file and hooks dir.
        self.assertEqual(slurp(self.conf + "/containers.conf"), podman.SHARED_CONF.encode())
        self.assertEqual(slurp(self.conf + "/mounts.conf"), b"")
        self.assertEqual(os.listdir(self.conf + "/hooks"), [])
        self.assertEqual(stat.S_IMODE(os.stat(self.conf).st_mode), 0o700)
        before = len(self.calls())

        invocation, request, started = self.started(limits={"cpus": 1, "memory_mib": 2048, "pids": 128})
        self.assertEqual((started["worker_sha256"], started["home"]), (release, "/home/agentbox"))
        inst = self.instance()
        container = inst["container"]
        self.assertEqual((inst["engine_store"], inst["store"], inst["shared"]),
                         ("shared", None, {"intent": True, "removed": False, "residue": False}))
        calls = self.calls()[before:]
        self.assertEqual(self.kinds(calls), ["image exists", "create", "cp", "start"])
        for call in calls:
            self.assertEqual(call["child"], "engine")
            self.assertEqual(call["limits"], podman.engine_limits(1, 2048, 128))
            self.assertEqual(call["env"], self.expected_env())
            self.assertEqual(set(call["globals"]) - {"version"}, {"remote", "cgroup-manager", "events-backend", "hooks-dir",
                                                    "default-mounts-file", "log-level"})
            self.assertFalse(any(value in json.dumps(call["argv"]) for value in (
                AMBIENT["CONTAINER_HOST"], AMBIENT["HOST_FAKE_SECRET"], AMBIENT["https_proxy"])))
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        self.assertEqual(calls[1]["args"], podman.shared_create_command(image_id, "agentbox", "run-1", "in-1",
                                                                        idir + "/container.id"))
        self.assertEqual(slurp(idir + "/container.id", "r"), container)
        # Nothing private: no engine store, no image load at start.
        self.assertEqual(self.stores(), [])
        self.assertEqual(self.user_db()["containers"][container]["name"], "agentbox-in-1")
        self.assertEqual(self.user_db()["containers"][container]["state"], "running")

        bridge = self.connect(request)
        self.assertEqual(bridge.read(line=True), b"SSH-2.0-stand-in\r\n")
        self.assertEqual(bridge.command("put /home/agentbox/a " + b"hi".hex()), "ok")
        bridge.proc.stdin.close()
        self.assertEqual(bridge.finish()[:2], (0, b""))
        exec_call = self.calls("exec")[-1]
        self.assertEqual((exec_call["args"], exec_call["child"], exec_call["env"]),
                         (podman.exec_command(container), "engine", self.expected_env()))

        before = len(self.calls())
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["type"], stopped["settlement"], stopped["durability"], stopped["storage"]),
                         ("stopped", "settled", "unchanged", "clean"))
        calls = self.calls()[before:]
        self.assertEqual(self.kinds(calls), ["rm", "container exists"])
        self.assertEqual(calls[0]["args"], ["rm", "--force", "--ignore", "--time=0", container])
        self.assertEqual(calls[1]["args"], ["container", "exists", container])
        self.assertTrue(all(c["child"].startswith("tool-") and c["env"] == self.expected_env() for c in calls))
        self.assertEqual(self.user_db()["containers"][container]["state"], "removed")
        self.assert_unrelated_kept()
        self.assertEqual(self.user_db()["images"], [image_id])
        self.assertFalse(any(c["args"][:1] in (["rmi"], ["prune"], ["system"], ["volume"], ["image"])
                             and c["args"][:2] != ["image", "exists"] for c in self.calls()))
        self.assert_no_daemons()
        self.assertEqual(self.stale(), [])
        self.assertIsNone(self.helper.poll())
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["shared"]["removed"]), ("settled", None, True))
        self.assertEqual(sorted(os.listdir(idir)), ["admission.lock", "container.id", "instance.json", "owner.lock"])
        again = self.standalone_stop(request)
        self.assertEqual(again["type"], "stopped")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertFalse(os.path.exists(idir))
        self.assert_unrelated_kept()

    def test_refusals_run_no_engine_before_anything_exists(self):
        image, _, image_id = self.install_image()
        self.unrelated()
        # A retained /tmp, mounts without a retained HOME: never in a
        # shared store.
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home_tmp",
                                     user="agentbox"), "unsupported")
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="none",
                                     user="agentbox", mounts=[{"source": self.tmp, "destination": "src",
                                                               "access": "ro"}]), "unsupported")
        # No helper: refused before any engine process.
        self.without_helper()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="none",
                                     user="agentbox"), "shared_store_uninitialized")
        self.assertEqual(self.calls(), [])
        self.restore_helper()
        # A helper inside Agentbox custody (an earlier owner's) is none.
        fake_proc(self.proc, self.helper.pid,
                  cgroup=b"0::/user.slice/agentbox-launch-" + b"d" * 32 + b".scope/agentbox-x/engine\n")
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="none",
                                     user="agentbox"), "shared_store_uninitialized")
        self.assertEqual(self.calls(), [])
        fake_proc(self.proc, self.helper.pid)
        # The prepared image not in the user's store: never loaded here
        # (whatever the engine version, never asked).
        self.config["podman"] = {"version": "5.8.0"}
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="none",
                                     user="agentbox"), "shared_image_missing")
        self.assertEqual(self.kinds(), ["image exists"])
        self.config["podman"] = {}
        self.save()
        self.assertFalse(os.path.exists(self.resource_dir()))
        self.assertEqual(self.stale(), [])
        self.share(image_id)
        self.create(image)
        # Then the helper gone: the start refuses before any engine call.
        self.without_helper()
        count = len(self.calls())
        invocation, request = self.start()
        answer = invocation.read(60)
        self.assertEqual(invocation.finish(60)[:2], (0, b""))
        self.assert_failed(answer, "shared_store_uninitialized")
        self.assertEqual(len(self.calls()), count)
        self.assertEqual(self.instance()["phase"], "settled")
        self.restore_helper()
        # And the image removed from the user's store meanwhile.
        db = self.user_db()
        db["images"] = []
        self.save_user_db(db)
        invocation, request = self.start(execution="ex-2", instance="in-2")
        answer = invocation.read(60)
        self.assertEqual(invocation.finish(60)[:2], (0, b""))
        self.assert_failed(answer, "shared_image_missing")
        self.assertEqual(self.kinds()[count:], ["image exists"])
        self.assertEqual(self.instance("in-2")["shared"]["intent"], False)
        self.assert_unrelated_kept()
        self.assertEqual(self.stale(), [])

    def test_a_bridge_refuses_without_the_helper_and_spawns_nothing(self):
        image, _, _ = self.shared_image()
        self.create(image)
        invocation, request, _ = self.started()
        self.without_helper()
        code, rest, _ = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        self.assertEqual(self.calls("exec"), [])
        self.restore_helper()
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")

    def test_any_engine_version_is_used_never_asked(self):
        # No version gate: an engine of any version, changed after start
        # included, is used; only the helper is checked.
        self.config["podman"] = {"version": "4.9.3"}
        self.save()
        image, _, _ = self.shared_image()
        self.create(image)
        invocation, request, _ = self.started()
        self.config["podman"] = {"version": "9.0.0-dev"}
        self.save()
        count = len(self.calls())
        bridge = self.connect(request)
        self.assertEqual(bridge.read(line=True), b"SSH-2.0-stand-in\r\n")
        bridge.proc.stdin.close()
        self.assertEqual(bridge.finish()[:2], (0, b""))
        asked = self.calls()[count:]
        self.assertEqual(self.kinds(asked), ["exec"])
        self.assertEqual((asked[0]["child"], asked[0]["env"]), ("engine", self.expected_env()))
        self.assertEqual(asked[0]["globals"]["hooks-dir"], self.conf + "/hooks")
        # The helper still checked before the spawn: gone, no engine runs.
        self.without_helper()
        count = len(self.calls())
        code, rest, err = self.connect(request).finish()
        self.assertEqual((code, rest), (2, b""))
        self.assertIn(b"connect refused: shared_store_uninitialized", err)
        self.assertEqual(len(self.calls()), count)
        self.restore_helper()
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertNotIn("--version", self.kinds())

    def test_a_container_removed_by_hand_still_settles(self):
        image, _, _ = self.shared_image()
        self.create(image)
        invocation, request, _ = self.started()
        container = self.instance()["container"]
        db = self.user_db()
        del db["containers"][container]
        self.save_user_db(db)
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        self.assertTrue(self.instance()["shared"]["removed"])

    def test_a_name_in_use_fails_the_start_and_is_never_touched(self):
        image, _, image_id = self.shared_image()
        self.create(image)
        db = self.user_db()
        db["containers"]["n" * 64] = {"args": [], "mounts": [], "image": image_id, "state": "created",
                                      "conmon": None, "volumepath": None, "name": "agentbox-in-1"}
        self.save_user_db(db)
        invocation, request = self.start()
        answer = invocation.read(60)
        code, rest, err = invocation.finish(60)
        self.assert_failed(answer, "failed")
        self.assertIn(b"never-started container named for this instance", err)
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["container"], inst["shared"]["residue"]), ("settled", None, True))
        self.assertEqual(self.user_db()["containers"]["n" * 64]["state"], "created")
        self.assertFalse(any(c["args"][:1] == ["rm"] for c in self.calls()))

    def killed_start(self, behaviour):
        image, _, _ = self.shared_image()
        self.create(image)
        self.config["podman"] = {"create": behaviour}
        self.save()
        invocation, request = self.start()
        invocation.proc.wait(60)
        code, _, err = invocation.finish(60)
        self.assertEqual(code, -signal.SIGKILL, err)
        self.config["podman"] = {}
        self.save()
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["container"], inst["shared"]["intent"]), ("engine", None, True))
        return request

    def test_a_crash_after_create_is_removed_by_the_cidfile(self):
        request = self.killed_start("crash")
        container = next(iter(self.user_db()["containers"]))
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        inst = self.instance()
        self.assertEqual((inst["container"], inst["shared"]["removed"]), (container, True))
        self.assertEqual(self.user_db()["containers"][container]["state"], "removed")
        self.assertEqual(self.calls("rm")[-1]["args"][-1], container)

    def test_a_crash_before_the_cidfile_is_reported_never_chased(self):
        request = self.killed_start("crash_nocid")
        container = next(iter(self.user_db()["containers"]))
        invocation = self.invoke()
        invocation.send(self.frame("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1",
                                   generation=0))
        stopped = invocation.read(60)
        code, rest, err = invocation.finish(60)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        self.assertIn(b"never-started container named for this instance", err)
        self.assertEqual(self.instance()["shared"]["residue"], True)
        # Created, never started, never looked up or removed by name.
        self.assertEqual(self.user_db()["containers"][container]["state"], "created")
        self.assertEqual(self.calls("rm"), [])

    def test_a_refused_or_failed_removal_stays_unsettled_until_a_later_stop(self):
        image, _, _ = self.shared_image()
        self.unrelated()
        self.create(image)
        invocation, request, _ = self.started()
        container = self.instance()["container"]
        self.without_helper()
        count = len(self.calls())
        answer = self.owner_stop(invocation, request)
        self.assert_failed(answer, "shared_store_uninitialized", "unsettled", "uncertain")
        # The engine child is gone; the container's removal was never asked.
        self.assertEqual(len(self.calls()), count)
        self.assertEqual(self.user_db()["containers"][container]["state"], "running")
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["shared"]["removed"]), ("stopping", None, False))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("busy", "unsettled"))
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "busy", "unsettled", "unchanged")
        self.assert_failed(self.standalone_stop(request), "shared_store_uninitialized", "unsettled", "uncertain")
        self.restore_helper()
        self.config["podman"] = {"fail": "rm"}
        self.save()
        self.assert_failed(self.standalone_stop(request), "failed", "unsettled", "uncertain")
        self.config["podman"] = {}
        self.save()
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        self.assertEqual(self.user_db()["containers"][container]["state"], "removed")
        self.assert_unrelated_kept()
        self.assertIsNone(self.helper.poll())

    def test_a_graceful_stop_removes_while_conmon_still_reaps_the_init(self):
        # Killed first, conmon would leave the init a zombie of the owner:
        # Podman's stop then waits on its pid until it times out.
        image, _, _ = self.shared_image()
        self.config["podman"] = {"kill_timeout": 0.5}
        self.save()
        self.create(image)
        invocation, request, _ = self.started()
        container = self.instance()["container"]
        init = self.user_db()["containers"][container]["pid"]
        seen = stat_of(init)
        stopped = self.owner_stop(invocation, request)
        self.assertEqual(stopped["type"], "stopped", stopped)
        self.assertEqual((stopped["settlement"], stopped["storage"]), ("settled", "clean"))
        self.assertEqual(self.user_db()["containers"][container]["state"], "removed")
        self.assertTrue(reaped(init, seen))
        self.assert_no_daemons()

    def test_a_failed_graceful_removal_settles_the_owners_children_and_waits_for_a_stop(self):
        image, _, _ = self.shared_image()
        self.create(image)
        invocation, request, _ = self.started()
        container = self.instance()["container"]
        self.config["podman"] = {"fail": "rm"}
        self.save()
        before = len(self.calls())
        invocation.send(self.stop_frame(request))
        answer = invocation.read(60)
        code, rest, err = invocation.finish(60)
        self.assertEqual((code, rest), (0, b""))
        self.assert_failed(answer, "failed", "unsettled", "uncertain")
        # One attempt, never retried after the kill; engine and adopted
        # children settled all the same.
        self.assertEqual(self.kinds(self.calls()[before:]), ["rm"])
        self.assertNotIn(b"adopted children unconfirmed", err)
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["engine"], inst["shared"]["removed"]), ("stopping", None, False))
        self.assert_no_daemons()
        self.config["podman"] = {}
        self.save()
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        self.assertEqual(self.user_db()["containers"][container]["state"], "removed")


class SharedHome(SharedCase):
    """Retention `home` in the user's store: one volume named for the
    resource, made by create, kept by stop, removed only by discard."""

    NAME = podman.SHARED_VOLUME_PREFIX + "res-1"

    def volume_dir(self, name=NAME):
        return os.path.join(self.home, "store", "volumes", name)

    def own_volume(self, name, content=b"mine"):
        """A volume the user made by hand, with a file in it."""
        os.makedirs(os.path.join(self.volume_dir(name), "_data"))
        write(os.path.join(self.volume_dir(name), "_data", "file"), content)

    def implicit(self):
        return [n for n in os.listdir(self.records) if n.startswith("implicit-volume-")]

    def session(self, generation, execution, instance, put=None, get=None):
        """One start, a bridge putting/getting HOME files, an owner stop."""
        invocation, request, _ = self.started(generation=generation, execution=execution, instance=instance)
        bridge = self.connect(request)
        bridge.read(line=True)
        got = {}
        for path, data in (put or {}).items():
            self.assertEqual(bridge.command(f"put {path} {data.hex()}"), "ok")
        for path in get or ():
            got[path] = bridge.command(f"get {path}")
        bridge.proc.stdin.close()
        bridge.finish()
        return self.owner_stop(invocation, request), got

    def test_a_home_lives_from_create_to_discard(self):
        image, _, image_id = self.shared_image()
        self.unrelated()
        self.own_volume("mine")
        created = self.create(image, retention="home")
        self.assertEqual((created["retention"], created["volume"]), ("home", self.NAME))
        # Made by create, after the name was found free; nothing private.
        self.assertEqual(self.kinds(), ["image exists", "volume exists", "volume create"])
        self.assertEqual(self.calls("volume create")[0]["args"],
                         podman.shared_volume_create("run-1", self.NAME))
        self.assertEqual(slurp(os.path.join(self.volume_dir(), "labels"), "r"), "--label=io.agentbox.run=run-1")
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["volume"], record["storage_root"], record["capacity"]),
                         ({"name": self.NAME, "state": "ready"}, None, "uncapped"))
        self.assertEqual(sorted(os.listdir(self.resource_dir())), ["lock", "resource.json"])
        before = len(self.calls())

        stopped, _ = self.session(0, "ex-1", "in-1", put={"/home/agentbox/kept": b"data", "/tmp/gone": b"x"})
        self.assertEqual((stopped["durability"], stopped["storage"], stopped["generation"]),
                         ("retained", "clean", 1))
        calls = self.calls()[before:]
        self.assertEqual(self.kinds(calls)[:5], ["image exists", "volume exists", "create", "cp", "start"])
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        self.assertEqual(calls[2]["args"], podman.shared_create_command(image_id, "agentbox", "run-1", "in-1",
                                                                        idir + "/container.id", self.NAME))
        self.assertIn(f"--mount=type=volume,source={self.NAME},destination=/home/agentbox,rw,exec,nosuid,nodev",
                      calls[2]["args"])
        self.assertTrue(any(n.startswith("sync-") for n in os.listdir(self.records)))
        # Stop removed the container, never the volume.
        self.assertTrue(os.path.isdir(self.volume_dir()))
        self.assertEqual(self.calls("volume rm"), [])

        # Reopened: the same volume at HOME, /tmp fresh.
        stopped, got = self.session(1, "ex-2", "in-2", get=["/home/agentbox/kept", "/tmp/gone"])
        self.assertEqual(got, {"/home/agentbox/kept": b"data".hex(), "/tmp/gone": "missing"})
        self.assertEqual(stopped["generation"], 2)
        self.assertEqual(self.implicit(), [])

        before = len(self.calls())
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        calls = self.calls()[before:]
        self.assertEqual(self.kinds(calls), ["volume rm"])
        self.assertEqual(calls[0]["args"], ["volume", "rm", self.NAME])
        self.assertFalse(os.path.exists(self.volume_dir()))
        self.assertEqual(self.read_json(self.resource_dir(), "resource.json")["state"], "discarded")
        # The user's own volume and container were never touched.
        self.assertEqual(slurp(os.path.join(self.volume_dir("mine"), "_data", "file")), b"mine")
        self.assert_unrelated_kept()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(len(self.calls()), before + 1)
        self.assert_no_daemons()

    def test_a_missing_home_is_reported_never_made_again(self):
        image, _, _ = self.shared_image()
        self.create(image, retention="home")
        self.session(0, "ex-1", "in-1", put={"/home/agentbox/kept": b"data"})
        remove_tree(self.volume_dir())
        before = len(self.calls())
        invocation, _ = self.start(generation=1, execution="ex-2", instance="in-2")
        answer = invocation.read(60)
        code, _, err = invocation.finish(60)
        self.assert_failed(answer, "retained_home_missing")
        self.assertIn(b"retained HOME volume is gone", err)
        self.assertEqual(self.kinds(self.calls()[before:]), ["image exists", "volume exists"])
        self.assertFalse(os.path.exists(self.volume_dir()))
        self.assertEqual(self.implicit(), [])
        inst = self.instance("in-2")
        self.assertEqual((inst["phase"], inst["volume_used"], inst["shared"]["intent"]), ("settled", False, False))
        # The name is the identity: one the user makes again is the run's.
        self.own_volume(self.NAME, b"again")
        _, got = self.session(1, "ex-3", "in-3", get=["/home/agentbox/file"])
        self.assertEqual(got, {"/home/agentbox/file": b"again".hex()})
        # Gone again before discard: already absent counts as removed.
        remove_tree(self.volume_dir())
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.read_json(self.resource_dir(), "resource.json")["state"], "discarded")

    def test_a_name_already_taken_is_never_claimed_or_removed(self):
        image, _, _ = self.shared_image()
        self.own_volume(self.NAME)
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home",
                                     user="agentbox"), "exists")
        self.assertEqual(self.kinds(), ["image exists", "volume exists"])
        self.assertFalse(os.path.exists(self.resource_dir()))
        self.assertEqual(slurp(os.path.join(self.volume_dir(), "_data", "file")), b"mine")

    def test_a_refused_allocation_is_undone_and_an_unclear_one_discarded_by_name(self):
        image, _, _ = self.shared_image()
        # The engine refuses: nothing was made; the record undone.
        self.config["podman"] = {"fail": "volume-create"}
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home",
                                     user="agentbox"), "failed")
        self.assertFalse(os.path.exists(self.resource_dir()))
        # An unclear answer: the intent stays (partial), discard removes
        # whatever the name holds.
        self.config["podman"] = {"volume_create_out": "other"}
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home",
                                     user="agentbox"), "failed", "unsettled", "uncertain")
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["state"], record["volume"]["state"]), ("creating", "allocating"))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "partial")
        self.config["podman"] = {}
        self.save()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertFalse(os.path.exists(self.volume_dir()))

    def test_a_create_killed_during_allocation_is_discarded_by_name(self):
        image, _, _ = self.shared_image()
        self.config["podman"] = {"volume_create": "crash"}
        self.save()
        invocation = self.invoke()
        invocation.send(self.frame("create", run="run-1", resource="res-1", image=image, retention="home",
                                   user="agentbox"))
        invocation.proc.wait(60)
        self.assertEqual(invocation.finish(60)[0], -signal.SIGKILL)
        self.config["podman"] = {}
        self.save()
        self.assertEqual(self.read_json(self.resource_dir(), "resource.json")["volume"],
                         {"name": self.NAME, "state": "allocating"})
        self.assertTrue(os.path.isdir(self.volume_dir()))
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.calls("volume rm")[-1]["args"], ["volume", "rm", self.NAME])
        self.assertFalse(os.path.exists(self.volume_dir()))

    def test_a_failed_final_record_keeps_the_made_volume_for_discard(self):
        image, _, _ = self.shared_image()
        self.config["record_fault"] = {"volume": "ready", "action": "enospc"}
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home",
                                     user="agentbox"), "failed", "unsettled", "uncertain")
        del self.config["record_fault"]
        self.save()
        # Made, its intent durable: partial, never undone by name.
        self.assertTrue(os.path.isdir(self.volume_dir()))
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["state"], record["volume"]), ("creating", {"name": self.NAME, "state": "allocating"}))
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.calls("volume rm")[-1]["args"], ["volume", "rm", self.NAME])
        self.assertFalse(os.path.exists(self.volume_dir()))

    def test_a_create_killed_before_its_intent_discards_without_the_engine(self):
        image, _, _ = self.shared_image()
        self.config["record_fault"] = {"volume": "allocating", "action": "kill"}
        self.save()
        invocation = self.invoke()
        invocation.send(self.frame("create", run="run-1", resource="res-1", image=image, retention="home",
                                   user="agentbox"))
        invocation.proc.wait(60)
        self.assertEqual(invocation.finish(60)[0], -signal.SIGKILL)
        del self.config["record_fault"]
        self.save()
        # The first record names the volume, no allocation begun.
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["state"], record["volume"]), ("creating", {"name": self.NAME, "state": None}))
        self.assertEqual(self.calls("volume create"), [])
        # A same-named volume made meanwhile (by hand) is never removed.
        self.own_volume(self.NAME)
        count = len(self.calls())
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.calls("volume rm"), [])
        self.assertEqual(len(self.calls()), count)
        self.assertEqual(slurp(os.path.join(self.volume_dir(), "_data", "file")), b"mine")

    def test_a_record_without_a_volume_descriptor_discards_as_unallocated(self):
        image, _, _ = self.shared_image()
        self.create(image, retention="home")
        path = os.path.join(self.resource_dir(), "resource.json")
        record = self.read_json(path)
        record.update(state="creating", volume=None)
        write(path, json.dumps(record), 0o600)
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.calls("volume rm"), [])

    def test_a_known_refusal_never_removes_a_preexisting_volume(self):
        image, _, _ = self.shared_image()
        # Taken between the name check and the create: the engine refuses
        # (made nothing), the record is undone, the user's volume stays.
        self.config["podman"] = {"volume_absent": True}
        self.save()
        self.own_volume(self.NAME)
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="home",
                                     user="agentbox"), "failed")
        self.assertEqual(self.kinds(), ["image exists", "volume exists", "volume create"])
        self.assertFalse(os.path.exists(self.resource_dir()))
        self.assertEqual(self.calls("volume rm"), [])
        self.assertEqual(slurp(os.path.join(self.volume_dir(), "_data", "file")), b"mine")

    def test_discard_keeps_a_home_in_use_or_unreachable(self):
        image, _, image_id = self.shared_image()
        self.create(image, retention="home")
        # A container of the user's own mounts it: busy, kept.
        db = self.user_db()
        db["containers"]["u" * 64] = {"args": [], "image": image_id, "state": "running", "conmon": None,
                                      "volumepath": None, "name": "mine",
                                      "mounts": [{"type": "volume", "source": self.NAME, "destination": "/x"}]}
        self.save_user_db(db)
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "busy", "unsettled", "uncertain")
        self.assertTrue(os.path.isdir(self.volume_dir()))
        self.assertEqual(self.read_json(self.resource_dir(), "resource.json")["state"], "discarding")
        db["containers"]["u" * 64]["state"] = "removed"
        self.save_user_db(db)
        # No helper: refused, nothing run; a later discard completes.
        self.without_helper()
        count = len(self.calls())
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "shared_store_uninitialized",
                           "unsettled", "uncertain")
        self.assertEqual(len(self.calls()), count)
        self.restore_helper()
        self.config["podman"] = {"volume_rm_status": 125}
        self.save()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "failed", "unsettled", "uncertain")
        self.assertTrue(os.path.isdir(self.volume_dir()))
        self.config["podman"] = {}
        self.save()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertFalse(os.path.exists(self.volume_dir()))


class SharedCommands(unittest.TestCase):
    """The shared mount commands, closed."""

    IMAGE = "a" * 64
    NAME = podman.SHARED_VOLUME_PREFIX + "res-1"

    def test_exactly_one_userns_and_binds_only_with_the_volume(self):
        binds = [("/srv/p", "src/p", "rw"), ("/srv/r", "ref", "ro")]
        keep = podman.shared_create_command(self.IMAGE, "dev_1", "run-1", "in-1", "/s/container.id", self.NAME,
                                            "keep_id", binds)
        plain = podman.shared_create_command(self.IMAGE, "dev_1", "run-1", "in-1", "/s/container.id", self.NAME)
        self.assertEqual([a for a in keep if a.startswith("--userns")], [podman.KEEP_ID])
        self.assertEqual([a for a in plain if a.startswith("--userns")], ["--userns=host"])
        self.assertIn("--privileged=false", keep)
        self.assertEqual([a for a in keep if a.startswith("--mount=type=bind")],
                         podman.bind_flags("/home/dev_1", binds))
        self.assertIn(f"--mount=type=volume,source={self.NAME},destination=/home/dev_1,rw,exec,nosuid,nodev", keep)
        # Everything else is the default mapping's command.
        self.assertEqual([a for a in keep if not a.startswith(("--userns", "--mount=type=bind"))],
                         [a for a in plain if not a.startswith("--userns")])
        for bad in (lambda: podman.shared_create_command(self.IMAGE, "dev_1", "run-1", "in-1", "/s/c", None,
                                                         "keep_id", binds),
                    lambda: podman.shared_flags("other"),
                    lambda: podman.shared_volume_create("run-1", self.NAME, "other"),
                    lambda: podman.shared_prepare_command(self.IMAGE, "dev_1", "keep_id", ["src/p"], "run-1", "in-1",
                                                          "/s/prepare.id", "other")):
            with self.assertRaises(common.Failure):
                bad()

    def test_the_preparation_is_a_recorded_transient_with_the_home_alone(self):
        args = podman.shared_prepare_command(self.IMAGE, "dev_1", "keep_id", ["src/p", "ref"], "run-1", "in-1",
                                             "/s/prepare.id", self.NAME)
        self.assertEqual(args[0], "create")
        self.assertNotIn("--rm", args)
        self.assertEqual([a for a in args if a.startswith("--userns")], [podman.KEEP_ID])
        self.assertEqual([a for a in args if a.startswith(("--mount", "--tmpfs", "--volume", "-v"))],
                         [f"--mount=type=volume,source={self.NAME},destination=/home/dev_1,rw,noexec,nosuid,nodev"])
        for word in ("--name=agentbox-in-1-prepare", "--cidfile=/s/prepare.id", "--label=io.agentbox.run=run-1",
                     "--label=io.agentbox.instance=in-1", "--user=1000:1000", "--privileged=false"):
            self.assertIn(word, args)
        at = args.index(podman.PREPARE_SCRIPT)
        self.assertEqual(args[at - 3:], ["--entrypoint=/bin/sh", self.IMAGE, "-c", podman.PREPARE_SCRIPT, "sh",
                                         "/home/dev_1", "src/p", "ref"])
        self.assertEqual(podman.shared_volume_create("run-1", self.NAME, "keep_id")[:6],
                         ["volume", "create", "--driver=local", "--uid=0", "--gid=0", "--opt=nocopy"])
        self.assertEqual(podman.shared_volume_create("run-1", self.NAME)[3:5], ["--uid=1000", "--gid=1000"])



class SharedRoots(unittest.TestCase):
    """`shared_roots` over real files: the store's effective paths, every
    configuration candidate and drop-in, each with its link chain; root's
    sealed files left out; anything unclear refuses."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="absr-"))
        self.addCleanup(remove_tree, self.tmp)
        self.home = os.path.join(self.tmp, "home")
        self.config = os.path.join(self.home, ".config", "containers")
        os.makedirs(self.config)
        self.env = {"HOME": self.home, "XDG_RUNTIME_DIR": self.tmp + "/run"}
        self.graph = self.home + "/.local/share/containers/storage"
        self.static, self.temp = self.graph + "/libpod", self.tmp + "/run/libpod/tmp"
        # The system files: root's on any sane host, else under tmp.
        etc = os.path.join(self.tmp, "etc")
        for name, value in (("CONTAINERS_CONF_SYSTEM", ("/usr/share/containers/containers.conf",
                                                        etc + "/containers.conf")),
                            ("CONTAINERS_ROOTLESS_CONF", etc + "/containers.rootless.conf")):
            patcher = mock.patch.object(podman, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def out(self, static=None, temp=None, **changes):
        found = [self.graph, self.tmp + "/run/containers", self.graph + "/volumes", self.config + "/storage.conf",
                 "/usr/bin/crun", self.tmp + "/bin/conmon"]
        out = json.dumps(found).encode() + b"\n"
        err = (f'time="t" level=info msg="podman filtering at log level debug"\n'
               f'time="t" level=debug msg="Using static dir {static or self.static}"\n'
               f'time="t" level=debug msg="Using tmp dir {temp or self.temp}"\n').encode()
        return changes.get("out", out), changes.get("err", err)

    def roots(self, env=None, static=None, temp=None, **changes):
        out, err = self.out(static, temp, **changes)
        return podman.shared_roots(env or self.env, changes.get("status", 0), out, err, uid=4242)

    def refused(self, **changes):
        with self.assertRaises(common.Failure) as caught:
            self.roots(**changes)
        self.assertEqual(caught.exception.code, "prerequisite", changes)

    def test_the_default_layout_protects_the_users_paths_only(self):
        roots = self.roots()
        for path in (self.graph, self.graph + "/volumes", self.static, self.temp, self.tmp + "/run", self.config,
                     self.config + "/containers.conf", self.config + "/containers.conf.d",
                     self.config + "/storage.conf", self.tmp + "/bin/conmon", self.tmp + "/etc/containers.conf",
                     self.tmp + "/etc/containers.rootless.conf", self.tmp + "/etc/containers.rootless.conf.d",
                     self.tmp + "/etc/containers.rootless.conf.d/4242", self.tmp + "/etc/containers.rootless.d",
                     self.tmp + "/etc/containers.rootless.d/4242"):
            self.assertIn(path, roots)
        # Root's own files and programs: never refused (/usr, /etc mounts stay possible).
        self.assertEqual([r for r in roots if r.startswith(("/usr/", "/etc/"))], [])
        self.assertEqual(len(roots), len(set(roots)))

    def test_custom_engine_dirs_outside_every_known_root(self):
        static, temp = self.tmp + "/elsewhere/db", self.tmp + "/scratch/tmp"
        roots = self.roots(static=static, temp=temp)
        self.assertIn(static, roots)
        self.assertIn(temp, roots)
        # A link to the static dir: its location and its target.
        os.makedirs(self.tmp + "/real/db")
        os.symlink(self.tmp + "/real", self.tmp + "/alias")
        roots = self.roots(static=self.tmp + "/alias/db")
        self.assertIn(self.tmp + "/alias", roots)
        self.assertIn(self.tmp + "/real/db", roots)

    def test_linked_configuration_files_directories_and_drop_ins(self):
        dot = os.path.join(self.tmp, "dotfiles")
        os.makedirs(dot + "/containers/containers.conf.d")
        remove_tree(self.config)
        os.symlink("../../dotfiles/containers", self.config)
        write(dot + "/target.conf", "")
        os.symlink(dot + "/target.conf", dot + "/containers/containers.conf")
        drop = os.path.join(self.tmp, "drop")
        os.makedirs(drop)
        write(drop + "/a.conf", "")
        os.symlink(drop + "/a.conf", dot + "/containers/containers.conf.d/a.conf")
        write(dot + "/containers/containers.conf.d/ignored.txt", "")
        etc = self.tmp + "/etc/containers.conf.d"
        os.makedirs(etc)
        os.symlink(self.tmp + "/sys.conf", etc + "/50-x.conf")
        roots = self.roots(env=dict(self.env, CONTAINERS_CONF=self.tmp + "/cc/containers.conf",
                                    CONTAINERS_STORAGE_CONF=self.tmp + "/sc/storage.conf"))
        for path in (self.config, dot + "/containers", self.config + "/containers.conf", dot + "/target.conf",
                     dot + "/containers/containers.conf.d/a.conf", drop + "/a.conf", etc + "/50-x.conf",
                     self.tmp + "/sys.conf", self.tmp + "/cc/containers.conf", self.tmp + "/sc/storage.conf"):
            self.assertIn(path, roots)
        self.assertNotIn(dot + "/containers/containers.conf.d/ignored.txt", roots)
        # XDG_CONFIG_HOME, when set, is the user's configuration.
        roots = self.roots(env=dict(self.env, XDG_CONFIG_HOME=self.tmp + "/xdg"))
        self.assertIn(self.tmp + "/xdg/containers/containers.conf", roots)

    def test_rootless_drop_ins_both_spellings_and_the_uids(self):
        etc, other = self.tmp + "/etc", self.tmp + "/other"
        os.makedirs(other)
        for directory in ("containers.rootless.conf.d", "containers.rootless.conf.d/4242", "containers.rootless.d",
                          "containers.rootless.d/4242"):
            os.makedirs(f"{etc}/{directory}")
            name = directory.replace("/", "-")
            write(f"{other}/{name}.conf", "")
            os.symlink(f"{other}/{name}.conf", f"{etc}/{directory}/10-{name}.conf")
        os.makedirs(etc + "/containers.rootless.d/4243")
        os.symlink(other + "/x.conf", etc + "/containers.rootless.d/4243/x.conf")
        roots = self.roots()
        for directory in ("containers.rootless.conf.d", "containers.rootless.conf.d/4242", "containers.rootless.d",
                          "containers.rootless.d/4242"):
            name = directory.replace("/", "-")
            self.assertIn(f"{etc}/{directory}/10-{name}.conf", roots)
            self.assertIn(f"{other}/{name}.conf", roots)
        # Another uid's drop-ins are not this engine's.
        self.assertNotIn(other + "/x.conf", roots)

    def test_unclear_answers_and_unreadable_configuration_refuse(self):
        good_out, good_err = self.out()
        line = 'time="t" level=debug msg="Using static dir {}"\n'
        for changes in ({"status": 1}, {"out": b""}, {"out": b"{}"}, {"out": b'["/a","/b","/c","/d"]'},
                        {"out": b'["/a","/b","/c","/d","/e","rel"]'}, {"out": b'["/a","/b","/c","/d","/e",null]'},
                        {"out": b'["/a","/b","/c","/d","/e","/f/../g"]'},
                        {"err": b""}, {"err": good_err.replace(b"static dir", b"Static dir")},
                        {"err": good_err + line.format("/other").encode()},
                        {"err": good_err.replace(b"tmp dir " + self.temp.encode() + b'"', b"tmp dir /cut")},
                        {"err": good_err.replace(self.static.encode(), b"relative")},
                        {"err": good_err.replace(self.static.encode(), b"/a/../b")}):
            self.refused(**changes)
        # The same line twice is one value.
        self.roots(err=good_err + line.format(self.static).encode())
        # A link loop, an oversized or unreadable drop-in directory.
        os.symlink("loop", self.config + "/containers.conf.d")
        os.symlink("containers.conf.d", self.config + "/loop")
        self.refused()
        os.unlink(self.config + "/containers.conf.d")
        os.mkdir(self.config + "/containers.conf.d")
        for n in range(podman.MAX_DROP_INS + 1):
            write(f"{self.config}/containers.conf.d/{n}.conf", "")
        self.refused()
        remove_tree(self.config + "/containers.conf.d")
        if os.geteuid() != 0:
            os.mkdir(self.config + "/containers.conf.d", 0)
            self.addCleanup(os.chmod, self.config + "/containers.conf.d", 0o700)
            self.refused()

    def test_link_chains_and_root_sealing(self):
        os.makedirs(self.tmp + "/a/b")
        os.symlink("a/b", self.tmp + "/l1")
        os.symlink(self.tmp + "/l1/../b2", self.tmp + "/l2")
        self.assertEqual(podman.link_chain(self.tmp + "/l1/x"), [self.tmp + "/l1/x", self.tmp + "/l1",
                                                                 self.tmp + "/a/b/x"])
        self.assertEqual(podman.link_chain(self.tmp + "/l2/y"), [self.tmp + "/l2/y", self.tmp + "/l2",
                                                                 self.tmp + "/l1", self.tmp + "/a/b2/y"])
        self.assertEqual(podman.link_chain("/nonexistent-agentbox/x"), ["/nonexistent-agentbox/x"])
        self.assertTrue(podman.root_sealed("/"))
        self.assertTrue(podman.root_sealed("/nonexistent-agentbox/x"))
        self.assertFalse(podman.root_sealed(self.tmp + "/a/b"))
        self.assertFalse(podman.root_sealed(self.tmp + "/missing/x"))
        if os.stat("/tmp").st_mode & 0o002:
            self.assertFalse(podman.root_sealed("/tmp/agentbox-missing"))


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class SharedMounts(SharedCase):
    """`host_mounts` in the user's store: retention `home` only, keep-id
    recorded at create (the HOME volume owned for it), sources resolved
    against the user's store paths too, destinations prepared by a
    recorded transient removed by its ID."""

    NAME = podman.SHARED_VOLUME_PREFIX + "res-1"

    def volume_data(self):
        return os.path.join(self.home, "store", "volumes", self.NAME, "_data")

    def sources(self):
        project = os.path.join(self.tmp, "src", "proj")
        reference = os.path.join(self.tmp, "ref")
        os.makedirs(project, 0o755)
        os.makedirs(reference, 0o755)
        write(os.path.join(reference, "keep"), "reference")
        return project, reference, [{"source": project, "destination": "src/proj", "access": "rw"},
                                    {"source": reference, "destination": ".agentbox-root/ref", "access": "ro"}]

    def mounted_create(self, image, mounts, retention="home"):
        return self.call("create", run="run-1", resource="res-1", image=image, retention=retention, user="dev_1",
                         mounts=mounts)

    def prepared(self, image):
        project, reference, mounts = self.sources()
        created = self.mounted_create(image, mounts)
        self.assertEqual(created["type"], "created", created)
        return project, reference, mounts

    def container(self, name):
        return next(c for c in self.user_db()["containers"].values() if c["name"] == name)

    def test_a_mounted_home_lives_from_create_to_discard(self):
        image, _, image_id = self.shared_image()
        self.unrelated()
        project, reference, mounts = self.prepared(image)
        record = self.read_json(self.resource_dir(), "resource.json")
        self.assertEqual((record["mapping"], record["mounts"], record["volume"]),
                         ("keep_id", mounts, {"name": self.NAME, "state": "ready"}))
        # The store's paths read first; the HOME owned by the invoking user.
        self.assertEqual(self.kinds(), ["info", "image exists", "volume exists", "volume create"])
        self.assertEqual(self.calls("volume create")[0]["args"],
                         podman.shared_volume_create("run-1", self.NAME, "keep_id"))
        before = len(self.calls())

        invocation, request, started = self.started()
        self.assertEqual(started["home"], "/home/dev_1")
        calls = self.calls()[before:]
        self.assertEqual(self.kinds(calls)[:11], ["image exists", "info", "volume exists", "create", "start", "rm",
                                                  "container exists", "info", "create", "cp", "start"])
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        prepare = self.container("agentbox-in-1-prepare")
        self.assertEqual(calls[3]["args"], podman.shared_prepare_command(
            image_id, "dev_1", "keep_id", ["src/proj", ".agentbox-root/ref"], "run-1", "in-1",
            idir + "/prepare.id", self.NAME))
        self.assertEqual((prepare["state"], calls[4]["args"][:2]), ("removed", ["start", "--attach"]))
        binds = [(os.path.realpath(project), "src/proj", "rw"),
                 (os.path.realpath(reference), ".agentbox-root/ref", "ro")]
        self.assertEqual(calls[8]["args"], podman.shared_create_command(
            image_id, "dev_1", "run-1", "in-1", idir + "/container.id", self.NAME, "keep_id", binds))
        for call in (calls[3], calls[8]):
            self.assertEqual([a for a in call["args"] if a.startswith("--userns")], [podman.KEEP_ID])
            self.assertEqual(call["child"], "engine")
        inst = self.instance()
        self.assertEqual(inst["shared"]["prepare"], {"intent": True, "container": calls[4]["args"][2],
                                                     "removed": True, "residue": False})
        # The destinations made in the volume's root (HOME), 0700.
        made = os.path.join(self.volume_data(), "src", "proj")
        self.assertTrue(os.path.isdir(made))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.join(self.volume_data(), "src")).st_mode), 0o700)
        bridge = self.connect(request)
        bridge.read(line=True)
        self.assertEqual(bridge.command(f"put /home/dev_1/src/proj/new {b'w'.hex()}"), "ok")
        self.assertEqual(bridge.command(f"put /home/dev_1/.agentbox-root/ref/new {b'w'.hex()}"), "erofs")
        self.assertEqual(bridge.command(f"put /home/dev_1/kept {b'home'.hex()}"), "ok")
        bridge.proc.stdin.close()
        bridge.finish()
        self.assertEqual(slurp(os.path.join(project, "new")), b"w")
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["durability"], stopped["storage"], stopped["generation"]), ("retained", "clean", 1))

        # Reopened: prepared again by a new transient; HOME and project kept.
        invocation, request, _ = self.started(generation=1, execution="ex-2", instance="in-2")
        self.assertEqual(self.container("agentbox-in-2-prepare")["state"], "removed")
        bridge = self.connect(request)
        bridge.read(line=True)
        self.assertEqual(bridge.command("get /home/dev_1/kept"), b"home".hex())
        self.assertEqual(bridge.command("get /home/dev_1/src/proj/new"), b"w".hex())
        bridge.proc.stdin.close()
        bridge.finish()
        self.assertEqual(self.owner_stop(invocation, request)["generation"], 2)

        before = len(self.calls())
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertEqual(self.kinds(self.calls()[before:]), ["volume rm"])
        self.assertFalse(os.path.exists(os.path.dirname(self.volume_data())))
        self.assertEqual((slurp(os.path.join(project, "new")), slurp(os.path.join(reference, "keep"))),
                         (b"w", b"reference"))
        self.assert_unrelated_kept()
        self.assert_no_daemons()

    def test_the_users_store_paths_are_protected_and_read_fail_closed(self):
        image, _, _ = self.shared_image()
        config = os.path.join(self.home, ".config", "containers")
        os.makedirs(config)
        os.makedirs(os.path.join(self.home, "store", "volumes"), exist_ok=True)
        os.makedirs(os.path.join(self.runtime, "containers"))
        alias = os.path.join(self.tmp, "alias")
        os.symlink(os.path.join(self.home, "store"), alias)
        for source in (config, os.path.dirname(config), self.home, os.path.join(self.home, "store"),
                       os.path.join(self.home, "store", "volumes"), self.runtime,
                       os.path.join(self.runtime, "containers"), alias):
            bad = [{"source": source, "destination": "x", "access": "ro"}]
            self.assert_failed(self.mounted_create(image, bad), "mount_source_protected")
            self.assertFalse(os.path.exists(self.resource_dir()), source)
        # The engine's own static and tmp dirs, wherever configured; a
        # linked configuration file's target and a linked drop-in's.
        static, temp = os.path.join(self.tmp, "db", "libpod"), os.path.join(self.tmp, "scratch", "tmp")
        dot, drop = os.path.join(self.tmp, "dot"), os.path.join(self.tmp, "drop")
        for path in (static, temp, dot, drop, config + "/containers.conf.d"):
            os.makedirs(path)
        write(dot + "/c.conf", "")
        os.symlink(dot + "/c.conf", config + "/containers.conf")
        write(drop + "/d.conf", "")
        os.symlink(drop + "/d.conf", config + "/containers.conf.d/d.conf")
        self.config["podman"] = {"static_dir": static, "tmp_dir": temp}
        self.save()
        for source in (static, os.path.dirname(static), temp, dot, drop):
            bad = [{"source": source, "destination": "x", "access": "ro"}]
            self.assert_failed(self.mounted_create(image, bad), "mount_source_protected")
            self.assertFalse(os.path.exists(self.resource_dir()), source)
        _, _, mounts = self.sources()
        line = 'time="t" level=debug msg="Using {} dir {}"\n'
        for behaviour in ({"info_out": "garbage"}, {"info_out": '["/a","/b","/c","/d"]'},
                          {"info_out": '["/a","/b","/c","/d","/e","rel"]'},
                          {"info_err": line.format("static", static)},
                          {"info_err": line.format("static", static) + line.format("tmp", "rel")},
                          {"info_err": line.format("static", static) + line.format("static", temp)
                           + line.format("tmp", temp)}):
            self.config["podman"] = behaviour
            self.save()
            self.assert_failed(self.mounted_create(image, mounts), "prerequisite")
        self.config["podman"] = {"fail": "info"}
        self.save()
        self.assert_failed(self.mounted_create(image, mounts), "prerequisite")
        self.assertFalse(os.path.exists(self.resource_dir()))
        # No helper: nothing runs, not even the read.
        self.config["podman"] = {}
        self.save()
        self.without_helper()
        count = len(self.calls())
        self.assert_failed(self.mounted_create(image, mounts), "shared_store_uninitialized")
        self.assertEqual(len(self.calls()), count)
        self.assertEqual([c for c in self.calls() if c["args"][:1] not in (["info"],)], [])

    def test_a_missing_source_refuses_before_the_home_and_never_blocks_cleanup(self):
        image, _, _ = self.shared_image()
        project, _, _ = self.prepared(image)
        invocation, request, _ = self.started()
        stopped = self.owner_stop(invocation, request)
        os.rename(project, project + "-away")
        before = len(self.calls())
        invocation, _ = self.start(generation=stopped["generation"], execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "mount_source_unavailable")
        invocation.finish(60)
        self.assertEqual(self.kinds(self.calls()[before:]), ["image exists", "info"])
        inst = self.instance("in-2")
        self.assertEqual((inst["phase"], inst["volume_used"], inst["shared"]), ("settled", False, {
            "intent": False, "removed": False, "residue": False}))
        # The store's paths refused at a start too, before the HOME: an
        # unclear answer, a source now under the engine's tmp dir.
        os.rename(project + "-away", project)
        for n, behaviour in enumerate(({"info_out": "garbage"}, {"info_err": ""},
                                       {"tmp_dir": os.path.dirname(project)})):
            self.config["podman"] = behaviour
            self.save()
            before = len(self.calls())
            invocation, _ = self.start(generation=stopped["generation"], execution=f"ex-{n + 3}",
                                       instance=f"in-{n + 3}")
            self.assert_failed(invocation.read(60), "mount_source_protected" if "tmp_dir" in behaviour
                               else "prerequisite")
            invocation.finish(60)
            self.assertEqual(self.kinds(self.calls()[before:]), ["image exists", "info"])
        self.config["podman"] = {}
        self.save()
        # Gone again: discard needs no source.
        remove_tree(project)
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertFalse(os.path.exists(os.path.dirname(self.volume_data())))

    def test_an_unsafe_destination_refuses_and_its_transient_is_removed(self):
        image, _, _ = self.shared_image()
        self.prepared(image)
        invocation, request, _ = self.started()
        stopped = self.owner_stop(invocation, request)
        # The workload replaced a destination's parent with a symlink.
        elsewhere = os.path.join(self.tmp, "elsewhere")
        os.mkdir(elsewhere)
        remove_tree(os.path.join(self.volume_data(), "src"))
        os.symlink(elsewhere, os.path.join(self.volume_data(), "src"))
        creates = len(self.calls("create"))
        invocation, _ = self.start(generation=stopped["generation"], execution="ex-2", instance="in-2")
        self.assert_failed(invocation.read(60), "mount_destination_unsafe", durability="uncertain")
        invocation.finish(60)
        self.assertEqual(len(self.calls("create")), creates + 1)  # the transient alone
        self.assertEqual(self.container("agentbox-in-2-prepare")["state"], "removed")
        self.assertEqual(self.instance("in-2")["shared"]["intent"], False)
        self.assertEqual(os.listdir(elsewhere), [])
        # Only the script's own refusal names the cause.
        os.unlink(os.path.join(self.volume_data(), "src"))
        self.config["podman"] = {"prepare_exit": 4}
        self.save()
        status = self.call("status", run="run-1", resource="res-1")
        invocation, _ = self.start(generation=status["generation"], execution="ex-3", instance="in-3",
                                   accept_unclean=True)
        self.assert_failed(invocation.read(60), "failed", durability="uncertain")
        invocation.finish(60)
        self.assertEqual(self.container("agentbox-in-3-prepare")["state"], "removed")

    def killed_start(self, behaviour):
        image, _, _ = self.shared_image()
        self.prepared(image)
        self.config["podman"] = {"create": behaviour}
        self.save()
        invocation, request = self.start()
        invocation.proc.wait(60)
        code, _, err = invocation.finish(60)
        self.assertEqual(code, -signal.SIGKILL, err)
        self.config["podman"] = {}
        self.save()
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["container"], inst["shared"]["intent"],
                          inst["shared"]["prepare"]["intent"], inst["shared"]["prepare"]["container"]),
                         ("engine", None, False, True, None))
        return request

    def test_a_start_killed_in_its_preparation_is_settled_by_the_cidfile(self):
        request = self.killed_start("crash")
        container = next(k for k, c in self.user_db()["containers"].items() if c["name"] == "agentbox-in-1-prepare")
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        inst = self.instance()
        self.assertEqual(inst["shared"]["prepare"], {"intent": True, "container": container, "removed": True,
                                                     "residue": False})
        self.assertEqual(self.user_db()["containers"][container]["state"], "removed")
        self.assertEqual([c["args"][-1] for c in self.calls("rm")], [container])
        # The next start runs as ever; discard removes the files by name.
        invocation, request, _ = self.started(generation=stopped["generation"], execution="ex-2", instance="in-2",
                                              accept_unclean=True)
        self.owner_stop(invocation, request)
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")

    def test_a_preparation_killed_before_its_cidfile_is_residue_never_chased(self):
        request = self.killed_start("crash_nocid")
        container = next(k for k, c in self.user_db()["containers"].items() if c["name"] == "agentbox-in-1-prepare")
        invocation = self.invoke()
        invocation.send(self.stop_frame(request))
        stopped = invocation.read(60)
        _, _, err = invocation.finish(60)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        self.assertIn(b"never-started container named for this instance", err)
        self.assertEqual(self.instance()["shared"]["prepare"]["residue"], True)
        self.assertEqual(self.user_db()["containers"][container]["state"], "created")
        self.assertEqual(self.calls("rm"), [])

    def test_a_preparation_cut_short_is_removed_by_its_id(self):
        image, _, _ = self.shared_image()
        self.prepared(image)
        self.config["podman"] = {"prepare_attach": "hang"}
        self.save()
        invocation, _ = self.start(timeout_ms=3000)
        answer = invocation.read(60)
        invocation.finish(60)
        self.assertEqual((answer["type"], answer["settlement"]), ("failed", "settled"), answer)
        inst = self.instance()
        self.assertEqual((inst["phase"], inst["shared"]["prepare"]["removed"], inst["shared"]["intent"]),
                         ("settled", True, False))
        self.assertEqual(self.container("agentbox-in-1-prepare")["state"], "removed")
        self.assert_no_daemons()

    def test_an_unconfirmed_preparation_removal_stays_unsettled_until_a_later_stop(self):
        image, _, _ = self.shared_image()
        self.prepared(image)
        self.config["podman"] = {"fail": "rm"}
        self.save()
        invocation, request = self.start()
        self.assert_failed(invocation.read(60), "failed", "unsettled", "uncertain")
        invocation.finish(60)
        inst = self.instance()
        self.assertEqual((inst["shared"]["prepare"]["removed"], inst["shared"]["intent"]), (False, False))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "busy")
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "busy", "unsettled", "unchanged")
        self.config["podman"] = {}
        self.save()
        stopped = self.standalone_stop(request)
        self.assertEqual((stopped["type"], stopped["settlement"]), ("stopped", "settled"))
        self.assertEqual(self.container("agentbox-in-1-prepare")["state"], "removed")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")


class SharedPrepare(SharedCase):
    def setUp(self):
        super().setUp()
        repo = os.path.join(self.tmp, "repo")
        test_worker.fake_guest(repo)
        self.repo = repo
        self.config["root"] = repo
        self.save()

    def prepare(self):
        return self.call("prepare", timeout_ms=600000, recipe=podman.CANONICAL_RECIPE, worker=self.repo)

    def test_prepare_loads_the_measured_archive_once_by_id(self):
        # Any engine version: never asked.
        self.config["podman"] = {"version": "4.9.3"}
        self.save()
        answer = self.prepare()
        self.assertEqual(answer["type"], "prepared", answer)
        image = answer["image"]
        record = self.read_json(self.state, "images", image, "record.json")
        shared = [c for c in self.calls() if "root" not in c["globals"]]
        self.assertEqual(self.kinds(shared), ["image exists", "load", "image exists"])
        self.assertEqual(shared[1]["args"], ["load", "--quiet",
                                            f"--input={self.state}/images/{image}/image.oci.tar"])
        self.assertTrue(all(c["env"] == self.expected_env() and c["child"].startswith("tool-") for c in shared))
        self.assertEqual(self.user_db()["images"], [record["image_id"]])
        # The build itself stayed private.
        self.assertTrue(all(c["globals"]["root"].startswith(os.path.join(self.state, "work"))
                            for c in self.calls() if "root" in c["globals"]))
        # Already there: kept as it is, nothing loaded.
        count = len(self.calls())
        self.assertEqual(self.prepare()["type"], "prepared")
        later = [c for c in self.calls()[count:] if "root" not in c["globals"]]
        self.assertEqual(self.kinds(later), ["image exists"])
        self.assertEqual(self.user_db()["images"], [record["image_id"]])
        # Then usable as is.
        self.create(image)
        invocation, request, _ = self.started()
        self.assertEqual(self.owner_stop(invocation, request)["type"], "stopped")

    def test_an_uninitialized_store_refuses_before_any_build(self):
        self.without_helper()
        self.assert_failed(self.prepare(), "shared_store_uninitialized")
        self.assertEqual(self.calls(), [])
        self.assertFalse(os.path.exists(os.path.join(self.state, "work")))


class Programs(unittest.TestCase):
    def test_engine_programs_come_from_the_host_path_conmon_then_its_helper_dir(self):
        """podman, conmon, crun from the host PATH; conmon alone then from
        the engine's helper directory; each resolved once per invocation."""
        self.assertEqual(podman.PROGRAM_FALLBACK, {"conmon": ("/usr/libexec/podman",)})
        tmp = os.path.realpath(tempfile.mkdtemp(prefix="abp-"))
        self.addCleanup(remove_tree, tmp)
        bin_dir, helper = os.path.join(tmp, "bin"), os.path.join(tmp, "helper")
        for directory in (bin_dir, helper):
            os.mkdir(directory, 0o755)
        for name in ("podman", "crun"):
            write(os.path.join(bin_dir, name), "#!/bin/sh\n", 0o755)
        for name in ("conmon", "crun", "podman"):
            write(os.path.join(helper, name), "#!/bin/sh\n", 0o755)
        saved = podman.PROGRAM_FALLBACK
        self.addCleanup(setattr, podman, "PROGRAM_FALLBACK", saved)
        podman.PROGRAM_FALLBACK = {"conmon": (helper,)}
        if os.geteuid() == 0:
            return
        host = podman.Host(environ={"PATH": f"relative:{bin_dir}"})
        self.assertEqual(host.programs(), {"podman": os.path.join(bin_dir, "podman"),
                                           "conmon": os.path.join(helper, "conmon"),
                                           "crun": os.path.join(bin_dir, "crun")})
        self.assertEqual(host.search(), bin_dir)
        # Resolved once: the same path for every use of this invocation.
        os.unlink(os.path.join(bin_dir, "podman"))
        self.assertEqual(host.tool("podman"), os.path.join(bin_dir, "podman"))
        write(os.path.join(bin_dir, "conmon"), "#!/bin/sh\n", 0o755)
        self.assertEqual(podman.Host(environ={"PATH": bin_dir}).tool("conmon"), os.path.join(bin_dir, "conmon"))
        # No fallback for anything else, and no PATH at all finds nothing.
        with self.assertRaises(common.Failure):
            podman.Host(environ={"PATH": bin_dir}).tool("podman")
        with self.assertRaises(common.Failure):
            podman.Host(environ={}).tool("crun")
        self.assertIsNone(podman.Host(environ={}).search())


class Production(unittest.TestCase):
    def test_production_needs_a_custody_domain(self):
        tmp = tempfile.mkdtemp(prefix="abp-")
        self.addCleanup(remove_tree, tmp)
        state = os.path.join(tmp, "state")
        os.mkdir(state, 0o700)
        entry = os.path.join(HERE, "podman.py")
        for kind, fields in (("prepare", {"recipe": "/x", "worker": "/y"}),
                             ("create", {"run": "r", "resource": "s", "image": "0" * 64, "retention": "none",
                                         "user": "agentbox"}),
                             ("discard", {"run": "r", "resource": "s"})):
            proc = subprocess.Popen([sys.executable, "-I", "-B", entry, "control", state], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env={})
            proc.stdin.write(protocol.encode(dict({"type": kind, "operation": "o", "timeout_ms": 1000}, **fields))
                             + b"\n")
            proc.stdin.flush()
            answer = protocol.decode_response(proc.stdout.readline().strip())
            proc.stdin.close()
            self.assertEqual(proc.wait(30), 0)
            proc.stdout.close()
            self.assertEqual((answer["type"], answer["code"]), ("failed", "prerequisite"), kind)
        proc = subprocess.run([sys.executable, "-I", "-B", entry, "connect", state, "r", "e", "i"],
                              capture_output=True, env={}, timeout=30, stdin=subprocess.DEVNULL)
        self.assertEqual((proc.returncode, proc.stdout), (2, b""))

    def test_the_provider_writes_no_bytecode(self):
        before = {p for p in os.listdir(HERE)}
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "podman.py"), "control", "relative"],
                       capture_output=True, env={}, timeout=30)
        self.assertEqual({p for p in os.listdir(HERE)}, before)


if __name__ == "__main__":
    unittest.main()
