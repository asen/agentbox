"""Offline checks of providers/qemu.py and providers/common.py.

  python3 -I -B -m unittest discover -s providers -p 'test_*.py'

Nothing real is built, booted or delegated: QEMU, qemu-img, xorriso and
Packer are local stand-in scripts, the custody domain is an ordinary
directory tree whose kill/populated effects act on the stand-ins' own
pids, KVM is assumed. Only the installed `ssh-keygen` runs for real (fresh
temporary keys), and loopback TCP serves the stand-in's SSH banner.
"""
import base64
import gc
import hashlib
import json
import os
import resource
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import common  # noqa: E402
import protocol  # noqa: E402
import qemu  # noqa: E402

import stage  # noqa: E402  (images/worker, via qemu's explicit path)
import worker  # noqa: E402

sys.path.insert(0, qemu.WORKER_DIR)
import test_worker  # noqa: E402

KEYGEN = "/usr/bin/ssh-keygen"
HAVE_KEYGEN = os.access(KEYGEN, os.X_OK)
CLUSTER = 1 << 16
VSIZE = 1 << 30


# ---------------------------------------------------------------------------
# Stand-in disks.

def qcow2(size=VSIZE, backing=None, incompatible=0, autoclear=0, crypt=0, extensions=(), cluster_bits=16,
          length=None, backing_format=b"qcow2"):
    """A minimal QCOW2 v3: header, extensions, backing name, then L1,
    refcount table and refcount block clusters."""
    cluster = 1 << cluster_bits
    l1 = -(-size // (cluster * (cluster // 8)))
    exts = list(extensions)
    if backing is not None and backing_format is not None:
        exts.insert(0, (qemu.EXT_BACKING_FORMAT, backing_format))
    body = b""
    for kind, data in exts:
        body += kind.to_bytes(4, "big") + len(data).to_bytes(4, "big") + data + bytes((8 - len(data) % 8) % 8)
    body += bytes(8)
    name = backing.encode() if backing is not None else b""
    backing_offset = 104 + len(body) if name else 0
    header = (qemu.MAGIC + (3).to_bytes(4, "big") + backing_offset.to_bytes(8, "big")
              + len(name).to_bytes(4, "big") + cluster_bits.to_bytes(4, "big") + size.to_bytes(8, "big")
              + crypt.to_bytes(4, "big") + l1.to_bytes(4, "big") + cluster.to_bytes(8, "big")
              + (2 * cluster).to_bytes(8, "big") + (1).to_bytes(4, "big") + bytes(4) + bytes(8)
              + incompatible.to_bytes(8, "big") + bytes(8) + autoclear.to_bytes(8, "big")
              + (4).to_bytes(4, "big") + (104).to_bytes(4, "big"))
    data = header + body + name
    return data + bytes((length or 4 * cluster) - len(data))


def iso(files):
    """A stand-in seed: an ISO 9660 primary volume descriptor named CIDATA,
    then the grafted documents as JSON (only tests read them)."""
    pvd = bytearray(2048)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[40:72] = b"CIDATA".ljust(32)
    return bytes(16 * 2048) + bytes(pvd) + json.dumps(files).encode()


def slurp(path, mode="rb"):
    with open(path, mode) as stream:
        return stream.read()


def write(path, data, perm=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as stream:
        stream.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, perm)


def public_key():
    return "ssh-ed25519 " + base64.b64encode(protocol._ED25519_PREFIX + os.urandom(32)).decode()


# ---------------------------------------------------------------------------
# Stand-in custody: ordinary directories; kill and populated act on the
# pids the stand-in children wrote into cgroup.procs.

def _alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            return stream.read().rsplit(")", 1)[1].split()[0] not in ("Z", "X")
    except OSError:
        return False


class FakeCustody(common.Custody):
    FILES = ("cgroup.procs", "cgroup.kill", "cgroup.events", "cpu.max", "memory.max", "memory.swap.max",
             "pids.max")
    # Tool children whose members a kill does not reach (a stuck tool).
    immune = False

    def _make(self, name):
        os.mkdir(name, 0o755, dir_fd=self.fd)
        for item in self.FILES:
            fd = os.open(f"{name}/{item}", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644, dir_fd=self.fd)
            os.close(fd)

    def pids(self, child):
        return [int(p) for p in self._read("cgroup.procs", child.fd).split()]

    def kill(self, child):
        if self.immune and child.name.startswith("tool-"):
            return
        for pid in self.pids(child):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def populated(self, child):
        return any(_alive(pid) for pid in self.pids(child))

    def remove(self, child):
        for item in self.FILES:
            try:
                os.unlink(f"{child.name}/{item}", dir_fd=self.fd)
            except FileNotFoundError:
                pass
        os.rmdir(child.name, dir_fd=self.fd)


def make_domain(root):
    domain = os.path.join(root, "domain")
    os.makedirs(os.path.join(domain, "leaf"))
    for name, text in (("cgroup.procs", ""), ("cgroup.kill", ""), ("cgroup.subtree_control", "cpu memory pids\n")):
        write(os.path.join(domain, name), text)
    return domain


# ---------------------------------------------------------------------------
# Stand-in tools. Each script calls fake_tool(NAME, CONFIG); the config
# file selects behaviours and where to record observations.

def fake_tool(name, config_path):
    with open(config_path) as stream:
        config = json.load(stream)
    {"qemu-img": _fake_qemu_img, "xorriso": _fake_xorriso, "packer": _fake_packer,
     "qemu-system-x86_64": _fake_qemu, "ssh": _fake_ssh}[name](sys.argv[1:], config)


def _hang(config, path):
    """A stuck tool: records its pid, keeps (re)writing `path`."""
    write(os.path.join(config["records"], f"hang-{os.getpid()}"), "")
    while True:
        write(path, b"still writing", 0o600)
        time.sleep(0.05)


def _fake_qemu_img(args, config):
    if config.get("qemu_img_fail") == args[0]:
        sys.exit(1)
    if config.get("qemu_img_hang") == args[0]:
        _hang(config, args[-1] if args[0] != "create" else args[-2])
    path = args[-1] if args[0] != "create" else args[-2]
    if args[0] == "create":
        base = args[args.index("-b") + 1]
        write(path, qcow2(int(args[-1]), backing=base), 0o644)
        return
    with open(path, "rb") as stream:
        prefix = stream.read(1 << 16)
    h = qemu._header(prefix, os.path.getsize(path))
    if args[0] == "check":
        print(json.dumps({"check-errors": 0, "filename": path, "format": "qcow2"}))
        return
    info = {"virtual-size": h["size"], "filename": path, "format": "qcow2",
            "format-specific": {"type": "qcow2", "data": {"compat": "1.1"}}}
    if h["backing_offset"]:
        base = prefix[h["backing_offset"]:h["backing_offset"] + h["backing_size"]].decode()
        info.update({"backing-filename": base, "full-backing-filename": base, "backing-filename-format": "qcow2"})
    print(json.dumps(info))


def _fake_xorriso(args, config):
    if config.get("xorriso_fail"):
        sys.exit(1)
    if config.get("xorriso_hang"):
        _hang(config, args[args.index("-output") + 1])
    files = {}
    for item in args[args.index("-graft-points") + 1:]:
        name, _, path = item.partition("=")
        with open(path) as stream:
            files[name] = stream.read()
    write(args[args.index("-output") + 1], iso(files), 0o644)


def _fake_packer(args, config):
    with open(config["packer_count"], "a") as stream:
        stream.write("x")
    write(os.path.join(config["records"], "packer-env"), json.dumps(dict(os.environ)))
    write(os.path.join(config["records"], "packer-argv"), json.dumps(sys.argv))
    # Where Packer's relative TMPDIR lands: its cwd's own directory.
    write(os.path.join(config["records"], "packer-cwd"),
          json.dumps([os.getcwd(), os.path.isdir(os.environ["TMPDIR"])]))
    if config.get("packer_fail"):
        sys.exit(1)
    if config.get("lock_scratch"):
        # An unremovable leftover in the operation's scratch (cwd).
        os.makedirs("locked/x")
        os.chmod("locked", 0o555)
    var_file = next(a for a in args if a.startswith("-var-file="))[len("-var-file="):]
    variables = {}
    with open(var_file) as stream:
        for line in stream:
            key, _, value = line.partition(" = ")
            variables[key] = json.loads(value)
    output = variables["output"]
    os.mkdir(output)
    write(os.path.join(output, "agentbox.qcow2"), qcow2(), 0o644)
    data = test_worker.synthetic_bundle(os.path.join(output, "worker"))
    with open(os.path.join(os.path.dirname(var_file), "stage.json")) as stream:
        revision = json.load(stream)["worker"]["sources"]["revision"]
    write(os.path.join(output, "worker-metadata.json"), json.dumps({
        "schema": worker.METADATA["schema"], "release": hashlib.sha256(data).hexdigest(),
        "install_root": worker.INSTALL_ROOT, "manifest": data.decode(), "sources": {"revision": revision}}))
    if not config.get("no_manifest"):
        write(os.path.join(output, stage.SYSTEM_MANIFEST), json.dumps(test_worker.system_manifest()))


def _fake_ssh(args, config):
    """The check boot's SSH client: records its argv, answers as the
    guest's check would (`ssh_kernel`, `ssh_fail`)."""
    write(os.path.join(config["records"], f"ssh-{os.getpid()}.argv"), json.dumps(args))
    if config.get("ssh_fail"):
        print(f"agentbox-check-failed {config['ssh_fail']}")
        sys.exit(1)
    print(f"agentbox-check-kernel {config.get('ssh_kernel', '7.0.0-44-generic')}")
    print("agentbox-check-ok")


def _fake_qemu(args, config):
    if args == ["-version"]:
        print(config.get("version", "QEMU emulator version 8.2.2 (Debian 1:8.2.2)"))
        return
    behaviour = config.get("qemu", {})
    fds = sorted(int(n) for n in os.listdir("/proc/self/fd"))
    fds = [fd for fd in fds if os.path.exists(f"/proc/self/fd/{fd}")]
    qmp_fd = int(args[args.index("-chardev", args.index("-serial")) + 1].split("fd=")[1].split(",")[0])
    netdev = args[args.index("-netdev") + 1]
    port = int(netdev.split("hostfwd=tcp:127.0.0.1:")[1].split("-")[0])
    # Its own custody child: an instance's `engine`, a check boot's own name.
    engine = next(os.path.join(config["domain"], n) for n in sorted(os.listdir(config["domain"]))
                  if os.path.isfile(os.path.join(config["domain"], n, "cgroup.procs"))
                  and str(os.getpid()) in slurp(os.path.join(config["domain"], n, "cgroup.procs"), "r").split())
    with open(f"/proc/self/status") as stream:
        ignored = int(next(l for l in stream if l.startswith("SigIgn:")).split()[1], 16)
    record = {"pid": os.getpid(), "argv": args, "env": dict(os.environ), "fds": fds, "qmp_fd": qmp_fd,
              "port": port, "stdin": os.readlink("/proc/self/fd/0"),
              "fsize": resource.getrlimit(resource.RLIMIT_FSIZE)[0],
              "core": resource.getrlimit(resource.RLIMIT_CORE)[0],
              "xfsz_ignored": bool(ignored & (1 << (signal.SIGXFSZ - 1))),
              "joined": str(os.getpid()) in slurp(os.path.join(engine, "cgroup.procs"), "r").split(),
              "limits": {n: slurp(os.path.join(engine, n), "r") for n in
                         ("cpu.max", "memory.max", "memory.swap.max", "pids.max")}}
    seed = json.loads(args[[i for i, a in enumerate(args) if '"seed-file"' in a][0]])["filename"]
    with open(seed, "rb") as stream:
        record["seed"] = json.loads(stream.read()[17 * 2048:])
    path = os.path.join(config["records"], f"{os.getpid()}.json")
    write(path + ".tmp", json.dumps(record))
    os.rename(path + ".tmp", path)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    sys.stdout.write("console " * behaviour.get("console", 4) + "\n")
    sys.stdout.flush()
    if not behaviour.get("no_banner"):
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen(8)

        def serve():
            while True:
                conn, _ = listener.accept()
                try:
                    conn.sendall(b"SSH-2.0-OpenSSH_stand-in\r\n")
                finally:
                    conn.close()
        threading.Thread(target=serve, daemon=True).start()
    qmp = socket.socket(fileno=qmp_fd)
    qmp.sendall(b'{"QMP": {"version": {}, "capabilities": []}}\n')
    if "exit_after" in behaviour:
        def leave():
            time.sleep(behaviour["exit_after"])
            os._exit(behaviour.get("exit_code", 1))
        threading.Thread(target=leave, daemon=True).start()
    buffer = b""
    while True:
        data = qmp.recv(4096)
        if not data:
            while True:
                time.sleep(3600)
        buffer += data
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            command = json.loads(line)["execute"]
            qmp.sendall(b'{"return": {}}\n')
            if command == "system_powerdown" and not behaviour.get("ignore_powerdown"):
                event = {"event": "SHUTDOWN", "data": {"guest": True, "reason": behaviour.get("reason", "guest-shutdown")}}
                qmp.sendall(json.dumps(event).encode() + b"\n")
                os._exit(behaviour.get("shutdown_code", 0))


# ---------------------------------------------------------------------------
# The stand-in host, in this process or a provider subprocess.

# A custom interpreter only the case's own PATH has (Case.setUp).
WRAPPER_INTERPRETER = "agentbox-test-python"


class TestHost(qemu.Host):
    def __init__(self, config):
        # The real limits-file read: the case's own declared scopes; any
        # host values the case gives this invocation (`host_env`).
        path = {"PATH": config["path"]} if "path" in config else {}
        super().__init__(environ={**scopes_environ(config), **path, **config.get("host_env", {})})
        self.config = config

    def tool(self, name):
        return self.config["tools"][name]

    def custody(self):
        if self._custody is None:
            domain = self.config["domain"]
            fd = os.open(domain, os.O_RDONLY | os.O_DIRECTORY)
            self._custody = FakeCustody(domain, fd)
            self._custody.immune = self.config.get("immune", False)
        return self._custody

    def kvm(self):
        pass

    def stage(self, repo, inputs, out):
        stage.load_inputs = stand_in_inputs
        return super().stage(repo, inputs, out)


def fake_devices(spec):
    """Owned fixtures only, in the provider process: each listed path's
    inode reports the given device through os.fstat (a stand-in mount;
    nothing is mounted)."""
    inodes = {}
    for path, dev in spec.items():
        if os.path.lexists(path):
            inodes[os.lstat(path).st_ino] = dev
    real = os.fstat
    extra = ("st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns", "st_ctime_ns",
             "st_blocks", "st_blksize", "st_rdev")

    def fstat(fd):
        st = real(fd)
        if st.st_ino not in inodes:
            return st
        fields = list(st)
        fields[2] = inodes[st.st_ino]
        return os.stat_result(fields, {name: getattr(st, name) for name in extra})
    os.fstat = fstat


def scopes_environ(config):
    """The provider environment's one storage-scope path, when the case
    declares one (`declare`)."""
    return {common.SCOPES_ENV: config["scopes"]} if "scopes" in config else {}


def declare(tmp, config, scopes, max_reserved=1 << 40):
    """The case's host limits file: TMP/data/run-limits.json (0600 in a
    0700 data dir) declaring `scopes`, named in `config`."""
    data = os.path.join(tmp, "data")
    os.makedirs(data, 0o700, exist_ok=True)
    path = os.path.join(data, "run-limits.json")
    write(path, json.dumps({"max_reserved_bytes": max_reserved, "storage_scopes": scopes}), 0o600)
    config["scopes"] = path
    return path


def stand_in_inputs(path):
    """stage.load_inputs without opening the files (test_worker covers
    staging's own checks): the provider's checks of the staged base are
    what these tests exercise; everything else is the real staging."""
    base = os.path.dirname(path)
    value = json.loads(slurp(path))
    return value, {"base": os.path.join(base, value["base"]["file"]), "node": os.path.join(base, value["node"]["file"])}


def deny_pidfd(nth):
    """The nth pidfd_open of this process is refused (after its Popen)."""
    real, calls = os.pidfd_open, [0]

    def pidfd_open(pid, *args):
        calls[0] += 1
        if calls[0] == nth:
            raise PermissionError("denied")
        return real(pid, *args)
    os.pidfd_open = pidfd_open
    return real


def run_stand_in():
    """The provider subprocess entry: production main with the stand-in host."""
    with open(os.environ["AGENTBOX_TEST_HOST"]) as stream:
        config = json.load(stream)
    common.KILL_RESERVE = config.get("kill_reserve", common.KILL_RESERVE)
    # The asset root a Prepare case's fake source tree stands in for.
    qemu.ROOT = config.get("root", qemu.ROOT)
    if config.get("deny_pidfd"):
        deny_pidfd(config["deny_pidfd"])
    qemu.PREPARE_MIN_FREE = config.get("min_free", 0)
    qemu.CHECK_POWERDOWN_SECONDS = config.get("check_powerdown", qemu.CHECK_POWERDOWN_SECONDS)
    fake_devices(config.get("fake_devices", {}))
    fail_methods(qemu.Provider, config.get("fail_methods", {}))
    if config.get("move_work"):
        move_work(config["move_work"])
    if config.get("foreign_staging"):
        def write_entry(self, entry, name, data):
            os.mkdir(os.path.join(entry.path, "foreign"))
            raise OSError(28, "fault")
        qemu.Provider.write_entry = write_entry
    sys.exit(qemu.main(sys.argv[1:], host=TestHost(config)))


def move_work(mode):
    """Before a prepare's scratch removal: the original work/OP renamed
    away, with `replace` an empty directory put under its name."""
    real = common.remove_scratch

    def remove_scratch(parent, name, fd):
        if name.startswith("op-"):
            path = os.path.join(parent.path, name)
            os.rename(path, path + "-moved")
            if mode == "replace":
                os.mkdir(path, 0o700)
        return real(parent, name, fd)
    common.remove_scratch = remove_scratch


def write_record(state, kind, record, value):
    """A provider record STATE/KIND/bad/RECORD, as if left by the provider."""
    for path in (os.path.join(state, kind), os.path.join(state, kind, "bad")):
        os.makedirs(path, 0o700, exist_ok=True)
        os.chmod(path, 0o700)
    write(os.path.join(state, kind, "bad", record), json.dumps(value), 0o600)


def fail_methods(cls, faults):
    """Test faults: each named method of `cls` raises ENOSPC, or with
    "false" returns False, instead of acting."""
    import errno

    def failing(result):
        def method(*_args, **_kw):
            if result == "false":
                return False
            raise OSError(errno.ENOSPC, "fault")
        return method
    for name, result in faults.items():
        setattr(cls, name, failing(result))


class Invocation:
    """One provider subprocess: frames in, frames out, diagnostics kept."""

    def __init__(self, case, args):
        self.proc = subprocess.Popen([sys.executable, "-I", "-B", case.runner] + list(args),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     env={"AGENTBOX_TEST_HOST": case.config_path})
        self.buffer = b""

    def send(self, frame):
        self.proc.stdin.write(protocol.encode(frame) + b"\n")
        self.proc.stdin.flush()

    def read(self, timeout=30):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            left = deadline - time.monotonic()
            if left <= 0 or not select.select([self.proc.stdout], [], [], left)[0]:
                return None
            data = os.read(self.proc.stdout.fileno(), 65536)
            if not data:
                return None
            self.buffer += data
        line, self.buffer = self.buffer.split(b"\n", 1)
        return protocol.decode_response(line)

    def close(self):
        self.proc.stdin.close()

    def finish(self, timeout=30):
        try:
            self.proc.stdin.close()
        except BrokenPipeError:
            pass
        code = self.proc.wait(timeout)
        rest = self.proc.stdout.read()
        err = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return code, rest, err


# ---------------------------------------------------------------------------

def remove_tree(root):
    """Removes a test tree, read-only cache entries included."""
    for path, dirs, _ in os.walk(root):
        for name in dirs:
            os.chmod(os.path.join(path, name), 0o700, follow_symlinks=False)
    shutil.rmtree(root, True)


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abq-")
        self.addCleanup(remove_tree, self.tmp)
        self.state = os.path.join(self.tmp, "state")
        os.mkdir(self.state, 0o700)
        self.domain = make_domain(self.tmp)
        self.records = os.path.join(self.tmp, "records")
        os.mkdir(self.records)
        tools = os.path.join(self.tmp, "tools")
        os.mkdir(tools)
        self.config_path = os.path.join(self.tmp, "host.json")
        self.config = {"domain": self.domain, "records": self.records, "tools": {"ssh-keygen": KEYGEN},
                       "packer_count": os.path.join(self.tmp, "packer-count"), "qemu": {}}
        declare(self.tmp, self.config, [{"path": os.path.realpath(self.state), "measure": "tree"}])
        # The host PATH the provider gets: only this case's tools. Its image
        # tools and QEMU are host wrappers whose interpreter is found there
        # alone (`#!/usr/bin/env`), as a user's would be: they run only if
        # the provider hands them that PATH.
        os.symlink(sys.executable, os.path.join(tools, WRAPPER_INTERPRETER))
        self.config["path"] = os.path.realpath(tools)
        for name in ("qemu-img", "xorriso", "packer", "qemu-system-x86_64", "ssh"):
            path = os.path.join(tools, name)
            head = (f"#!{sys.executable} -IBS\nimport sys\n" if name == "packer" else
                    f"#!/usr/bin/env {WRAPPER_INTERPRETER}\nimport sys\nsys.dont_write_bytecode = True\n")
            write(path, f"{head}sys.path.insert(0, {HERE!r})\n"
                        f"import test_qemu\ntest_qemu.fake_tool({name!r}, {self.config_path!r})\n", 0o755)
            self.config["tools"][name] = path
        self.save()
        self.runner = os.path.join(self.tmp, "runner.py")
        write(self.runner, f"import sys\nsys.path.insert(0, {HERE!r})\nimport test_qemu\ntest_qemu.run_stand_in()\n")
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
        for pid in self.qemu_pids() + self.hung():
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
        invocation = Invocation(self, args or ["control", self.state])
        self.live.append(invocation)
        return invocation

    def call(self, kind, **fields):
        invocation = self.invoke()
        request = self.frame(kind, **fields)
        invocation.send(request)
        answer = invocation.read()
        code, rest, _ = invocation.finish()
        self.assertEqual((code, rest), (0, b""))
        self.assertEqual(answer["operation"], request["operation"])
        return answer

    def assert_failed(self, answer, code, settlement="settled", durability="unchanged"):
        self.assertEqual(answer["type"], "failed", answer)
        self.assertEqual((answer["code"], answer["settlement"], answer["durability"]),
                         (code, settlement, durability))

    def qemu_records(self):
        out = []
        for name in sorted(os.listdir(self.records)):
            if name.endswith(".json"):
                with open(os.path.join(self.records, name)) as stream:
                    out.append(json.load(stream))
        return out

    def hung(self):
        if not os.path.isdir(self.records):
            return []
        return [int(n[5:]) for n in os.listdir(self.records) if n.startswith("hang-")]

    def qemu_pids(self):
        return [r["pid"] for r in self.qemu_records()] if os.path.isdir(self.records) else []

    def install_image(self, size=VSIZE):
        """A cached image as prepare publishes it."""
        data = qcow2(size)
        image = hashlib.sha256(data).hexdigest()
        entry = os.path.join(self.state, "images", image)
        os.makedirs(entry)
        os.chmod(os.path.join(self.state, "images"), 0o700)
        write(os.path.join(entry, "disk.qcow2"), data, 0o400)
        manifest = "{\"manifest\": \"stand-in\"}\n"
        release = hashlib.sha256(manifest.encode()).hexdigest()
        write(os.path.join(entry, "worker-metadata.json"), json.dumps({
            "schema": worker.METADATA["schema"], "release": release, "install_root": worker.INSTALL_ROOT,
            "manifest": manifest}), 0o400)
        write(os.path.join(entry, "image.json"), "{}", 0o400)
        record = {"schema": qemu.CACHE_SCHEMA, "image": image, "virtual_size": size, "bytes": len(data),
                  "fingerprint": common.fingerprint(os.stat(os.path.join(entry, "disk.qcow2"))),
                  "worker": release, "origin": {}}
        write(os.path.join(entry, "record.json"), json.dumps(record), 0o400)
        os.chmod(entry, 0o500)
        self.addCleanup(lambda: os.path.isdir(entry) and os.chmod(entry, 0o700))
        return image, release

    def create(self, image, resource="res-1", run="run-1", retention="disk", user="agentbox"):
        answer = self.call("create", run=run, resource=resource, image=image, retention=retention, user=user)
        self.assertEqual(answer["type"], "created", answer)
        return answer

    def resource_dir(self, resource="res-1"):
        return os.path.join(self.state, "resources", resource)

    def read_record(self, resource="res-1"):
        with open(os.path.join(self.resource_dir(resource), "resource.json")) as stream:
            return json.load(stream)

    def start(self, generation=0, resource="res-1", run="run-1", execution="ex-1", instance="in-1",
              accept_unclean=False, limits=None, timeout_ms=30000, key=None):
        invocation = self.invoke()
        request = self.frame("start", timeout_ms=timeout_ms, run=run, resource=resource, execution=execution,
                             instance=instance, generation=generation, accept_unclean=accept_unclean,
                             authorized_key=key or public_key(), limits=limits or {})
        invocation.send(request)
        return invocation, request

    def stop_frame(self, start, timeout_ms=30000, **change):
        frame = self.frame("stop", timeout_ms=timeout_ms, run=start["run"], resource=start["resource"],
                           execution=start["execution"], instance=start["instance"],
                           generation=start["generation"])
        frame.update(change)
        return frame

    def started(self, **kw):
        invocation, request = self.start(**kw)
        answer = invocation.read()
        self.assertEqual(answer["type"], "started", answer)
        return invocation, request, answer

    def owner_stop(self, invocation, request, timeout_ms=30000):
        stop = self.stop_frame(request, timeout_ms=timeout_ms)
        invocation.send(stop)
        answer = invocation.read(60)
        code, rest, _ = invocation.finish()
        self.assertEqual((code, rest), (0, b""))
        return answer


# ---------------------------------------------------------------------------
# Pure checks.

class Qcow2(unittest.TestCase):
    def test_a_standalone_base_is_admitted_with_its_size(self):
        data = qcow2()
        self.assertEqual(qemu.check_standalone(data, len(data)), VSIZE)

    def refused(self, code, data, length=None):
        with self.assertRaises(qemu.QcowError) as caught:
            qemu.check_standalone(data, len(data) if length is None else length)
        self.assertEqual(str(caught.exception), code)

    def test_chains_external_files_and_unsupported_features_are_refused(self):
        self.refused("backing", qcow2(backing="/elsewhere/base.qcow2"))
        self.refused("backing", qcow2(extensions=[(qemu.EXT_BACKING_FORMAT, b"raw")]))
        self.refused("external_data", qcow2(incompatible=qemu.INCOMPAT_DATA_FILE))
        self.refused("external_data", qcow2(extensions=[(qemu.EXT_DATA_FILE, b"/host/secret")]))
        self.refused("external_data", qcow2(autoclear=qemu.AUTOCLEAR_DATA_FILE_RAW))
        self.refused("encrypted", qcow2(crypt=1))
        self.refused("dirty", qcow2(incompatible=qemu.INCOMPAT_DIRTY))
        self.refused("corrupt", qcow2(incompatible=qemu.INCOMPAT_CORRUPT))
        self.refused("unsupported", qcow2(extensions=[(0x23852875, b"bitmaps!")]))
        self.refused("unsupported", qcow2(size=128 << 30))
        self.refused("invalid", b"QFI\xfb" + bytes(10))
        self.refused("invalid", b"\x7fELF" + bytes(200))
        self.refused("incomplete", qcow2(), length=CLUSTER)

    def test_an_overlay_is_bound_to_exactly_its_base(self):
        base = "/state/images/x/disk.qcow2"
        data = qcow2(backing=base)
        qemu.check_overlay(data, len(data), base, VSIZE)
        for bad, code in [(qcow2(backing="/other/disk.qcow2"), "backing"),
                          (qcow2(backing=base, backing_format=b"raw"), "backing"),
                          (qcow2(backing=base, backing_format=None), "backing"),
                          (qcow2(), "backing"),
                          (qcow2(backing=base, size=VSIZE * 2), "invalid"),
                          (qcow2(backing=base, incompatible=qemu.INCOMPAT_DATA_FILE), "invalid"),
                          (qcow2(backing=base, extensions=[(qemu.EXT_DATA_FILE, b"/x")]), "invalid")]:
            with self.assertRaises(qemu.QcowError) as caught:
                qemu.check_overlay(bad, len(bad), base, VSIZE)
            self.assertEqual(str(caught.exception), code)

    def test_tool_reports_are_checked_exactly(self):
        path, base = "/s/disk.qcow2", "/s/base.qcow2"
        self.assertTrue(qemu.check_report_ok({"check-errors": 0, "filename": path, "format": "qcow2"}, path))
        self.assertFalse(qemu.check_report_ok({"check-errors": 0, "filename": path, "format": "qcow2",
                                               "leaks": 1}, path))
        info = {"virtual-size": VSIZE, "filename": path, "format": "qcow2",
                "format-specific": {"type": "qcow2", "data": {"compat": "1.1"}}}
        self.assertTrue(qemu.info_report_ok(info, path, VSIZE))
        self.assertFalse(qemu.info_report_ok(dict(info, **{"backing-filename": base}), path, VSIZE))
        chained = dict(info, **{"backing-filename": base, "full-backing-filename": base,
                                "backing-filename-format": "qcow2"})
        self.assertTrue(qemu.info_report_ok(chained, path, VSIZE, base))
        external = json.loads(json.dumps(info))
        external["format-specific"]["data"]["data-file"] = "/host/file"
        self.assertFalse(qemu.info_report_ok(external, path, VSIZE))


class Profile(unittest.TestCase):
    def test_the_launch_profile_is_fixed_and_closed(self):
        args = qemu.qemu_argv("/usr/bin/qemu-system-x86_64", "/s/images/i/disk.qcow2", "/s/r/disk.qcow2",
                              "/s/r/i/seed.iso", 40000, 7, 2, 4096)
        text = " ".join(args)
        for required in ("-no-user-config", "-nodefaults", "-sandbox", "-accel kvm", "-display none",
                         "-monitor none", "restrict=on", "ipv6=off", "romfile="):
            self.assertIn(required, text)
        self.assertEqual(args.count("-netdev"), 1)
        self.assertIn("hostfwd=tcp:127.0.0.1:40000-:22", text)
        self.assertEqual(text.count("hostfwd"), 1)
        self.assertIn("socket,id=qmp,fd=7,server=off", args)
        for forbidden in ("-drive", "-virtfs", "-fsdev", "-vnc", "-spice", "-qmp", "guestfwd", "smb=",
                          "tftp", "-daemonize", "tcp::", "0.0.0.0", "-incoming", "-loadvm", "unix:"):
            self.assertNotIn(forbidden, text)
        nodes = [json.loads(args[i + 1]) for i, a in enumerate(args) if a == "-blockdev"]
        self.assertEqual([n["node-name"] for n in nodes],
                         ["base-file", "base", "overlay-file", "overlay", "seed-file", "seed"])
        self.assertTrue(nodes[0]["read-only"] and nodes[1]["read-only"] and nodes[4]["read-only"])
        self.assertEqual(nodes[3]["backing"], "base")
        with self.assertRaises(common.Failure):
            qemu.qemu_argv("/q", "/a", "/a", "/s", 40000, 7, 1, 64)
        with self.assertRaises(common.Failure):
            qemu.qemu_argv("/q", "/a,file=/etc/shadow", "/b", "/s", 40000, 7, 1, 64)

    def test_limits_and_defaults(self):
        self.assertEqual(qemu.limits_of({}, VSIZE), (2, 4096, 512, VSIZE + (1 << 30)))
        self.assertEqual(qemu.limits_of({"cpus": 4, "memory_mib": 1024, "pids": 64, "disk_mib": 100}, VSIZE),
                         (4, 1024, 64, 100 << 20))
        self.assertEqual(qemu.engine_limits(4, 1024, 64),
                         {"cpu.max": "400000 100000", "memory.max": str(1536 << 20), "memory.swap.max": "0",
                          "pids.max": "64"})

    def test_the_seed_carries_only_the_execution_identity(self):
        key = public_key()
        data = qemu.user_data(key, "PRIVATE", "ssh-ed25519 HOST").decode()
        self.assertTrue(data.startswith("#cloud-config\n"))
        config = json.loads(data.split("\n", 1)[1])
        self.assertNotIn("ssh_authorized_keys", config["users"][0])
        self.assertNotIn("runcmd", config)
        paths = {f["path"]: f for f in config["write_files"]}
        self.assertEqual(set(paths), {qemu.AUTHORIZED_KEYS, qemu.GUEST_HOST_KEY, qemu.GUEST_HOST_KEY + ".pub"})
        self.assertEqual(paths[qemu.AUTHORIZED_KEYS]["content"], key + "\n")
        self.assertTrue(all(f["owner"] == "root:root" and not f["path"].startswith("/home") for f in paths.values()))
        self.assertIn(["write_files", "always"], config["cloud_init_modules"])
        self.assertEqual(json.loads(qemu.meta_data("agentbox-x"))["instance-id"], "agentbox-x")

    def test_capabilities_are_truthful(self):
        provider = qemu.Provider("/nonexistent", None, None)
        described = provider.op_capabilities({"operation": "op-1"})
        protocol.encode(dict(described))
        self.assertEqual(described["limits"], ["cpus", "memory_mib", "pids", "disk_mib"])
        self.assertEqual(described["retention"], ["none", "disk"])
        self.assertIn("checkpoint", described["operations"])

    def test_no_canonical_cache_key_remains(self):
        # Every prepare builds (a fresh base, fresh packages): nothing keys a
        # finished image to its sources.
        self.assertFalse(hasattr(qemu, "cache_key"))


class Trust(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abq-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_installed_tools_come_from_the_host_path_in_order(self):
        """The first executable regular file in the host PATH's usable
        entries, links followed (tools.rs find_trusted); as root only a
        root-owned one through a path no one else may write."""
        tmp = os.path.realpath(self.tmp)
        plain, user, late, store = (os.path.join(tmp, n) for n in ("plain", "user", "late", "store"))
        for directory in (plain, user, late, store):
            os.mkdir(directory, 0o755)
        os.chmod(user, 0o775)
        write(os.path.join(plain, "tool"), "#!/bin/sh\n", 0o644)
        os.mkdir(os.path.join(late, "tool"))
        write(os.path.join(store, "real-tool"), "#!/bin/sh\n", 0o755)
        os.symlink(os.path.join(store, "real-tool"), os.path.join(user, "tool"))
        write(os.path.join(late, "other"), "#!/bin/sh\n", 0o755)
        environ = {"PATH": f"rel::{tmp}/absent:{plain}:{late}:{user}:/a b:{late}"}
        self.assertEqual(common.host_dirs(environ), [f"{tmp}/absent", plain, late, user, late])
        self.assertEqual(common.host_search({"PATH": "rel::"}), None)
        self.assertEqual(common.host_search({}), None)
        if os.geteuid() == 0:
            with self.assertRaises(common.Failure):
                common.trusted_executable("tool", environ)
            return
        self.assertEqual(common.trusted_executable("tool", environ), os.path.join(store, "real-tool"))
        self.assertEqual(common.trusted_executable("other", environ), os.path.join(late, "other"))
        self.assertEqual(common.trusted_executable("env", {"PATH": "/usr/bin"}), os.path.realpath("/usr/bin/env"))
        for env in ({}, {"PATH": ""}, {"PATH": "rel:."}, {"PATH": plain}):
            with self.assertRaises(common.Failure):
                common.trusted_executable("tool", env)
        # An explicit backend fallback only after the PATH.
        self.assertEqual(common.trusted_executable("tool", {}, (store, user)), os.path.join(store, "real-tool"))
        with self.assertRaises(common.Failure):
            common.trusted_executable("absent-agentbox", environ, (store,))
        # A real path the engine's argv and config cannot carry.
        spaced = os.path.join(tmp, "a b")
        os.mkdir(spaced)
        write(os.path.join(spaced, "spaced"), "#!/bin/sh\n", 0o755)
        os.symlink(os.path.join(spaced, "spaced"), os.path.join(late, "spaced"))
        with self.assertRaises(common.Failure):
            common.trusted_executable("spaced", environ)

    def test_root_needs_a_root_owned_chain_no_one_else_may_write(self):
        """As root a tool and every directory above it are root's and not
        group or world writable: no own-group or sticky exception (tools.rs
        root_owned_chain). Ownership and modes are mocked; nothing is
        written as root."""
        def chain(**override):
            modes = {"/": 0o40755, "/opt": 0o40755, "/opt/bin": 0o40755, "/opt/bin/tool": 0o100755}
            modes.update(override.get("modes", {}))
            owners = override.get("owners", {})

            def lstat(path):
                if path not in modes:
                    raise FileNotFoundError(path)
                return os.stat_result((modes[path], 1, 1, 1, owners.get(path, 0), 0, 0, 0, 0, 0))
            return common.root_executable("/opt/bin/tool", lstat=lstat,
                                          capable=lambda _: override.get("capable", False))
        self.assertTrue(chain())
        for case in ({"modes": {"/opt": 0o40775}}, {"modes": {"/opt/bin": 0o41777}},
                     {"modes": {"/": 0o40757}}, {"modes": {"/opt/bin/tool": 0o100775}},
                     {"modes": {"/opt/bin/tool": 0o104755}}, {"modes": {"/opt/bin/tool": 0o102755}},
                     {"modes": {"/opt/bin/tool": 0o100644}}, {"modes": {"/opt/bin/tool": 0o40755}},
                     {"modes": {"/opt/bin": 0o100755}}, {"owners": {"/opt/bin": 1000}},
                     {"owners": {"/opt/bin/tool": 1000}}, {"capable": True}):
            self.assertFalse(chain(**case), case)
        self.assertFalse(common.root_executable("/nonexistent-agentbox/tool"))
        # trusted_executable applies it as root: this user's scratch fails.
        tmp = os.path.realpath(self.tmp)
        write(os.path.join(tmp, "tool"), "#!/bin/sh\n", 0o755)
        real = os.geteuid
        self.addCleanup(setattr, common.os, "geteuid", real)
        common.os.geteuid = lambda: 0
        with self.assertRaises(common.Failure):
            common.trusted_executable("tool", {"PATH": tmp})
        common.os.geteuid = real
        if real() != 0:
            self.assertEqual(common.trusted_executable("tool", {"PATH": tmp}), os.path.join(tmp, "tool"))

    def test_a_tool_s_environment_carries_the_host_path_for_its_wrapper(self):
        """A host wrapper whose `#!/usr/bin/env` interpreter only the host
        PATH has runs with common.tool_env, never without it."""
        tmp = os.path.realpath(self.tmp)
        os.symlink("/bin/sh", os.path.join(tmp, "agentbox-test-sh"))
        tool = os.path.join(tmp, "tool")
        write(tool, "#!/usr/bin/env agentbox-test-sh\necho wrapped\n", 0o755)
        env = common.tool_env({"PATH": f"rel::{tmp}:/a b", "SECRET": "x", "HOME": "/h"})
        self.assertEqual(env, {"PATH": tmp, "LC_ALL": "C"})
        self.assertEqual(common.tool_env({"PATH": "rel"}), {"LC_ALL": "C"})
        ran = subprocess.run([tool], env=env, capture_output=True, timeout=30)
        self.assertEqual((ran.returncode, ran.stdout), (0, b"wrapped\n"))
        ran = subprocess.run([tool], env=common.tool_env({}), capture_output=True, timeout=30)
        self.assertNotEqual(ran.returncode, 0)

    def test_operator_files_refuse_links_and_foreign_writes(self):
        path = os.path.join(self.tmp, "recipe.pkr.hcl")
        write(path, "x", 0o644)
        common.trusted_path(path, "file")
        os.symlink(path, path + ".link")
        with self.assertRaises(common.Failure):
            common.trusted_path(path + ".link", "file")
        os.chmod(path, 0o666)
        with self.assertRaises(common.Failure):
            common.trusted_path(path, "file")


class CustodyDomain(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abq-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.root = os.path.join(self.tmp, "cg")
        os.mkdir(self.root)
        self.domain = make_domain(self.root)
        self.proc = os.path.join(self.tmp, "proc-cgroup")
        write(self.proc, "0::/domain/leaf\n")

    def open(self, environ=None, proc=None):
        env = {common.CUSTODY_ENV: self.domain} if environ is None else environ
        return common.Custody.from_environment(env, proc or self.proc, root=self.root)

    def test_the_host_domain_is_verified(self):
        custody = self.open()
        self.assertEqual(custody.path, self.domain)
        custody.close()

    def test_missing_or_foreign_domains_are_prerequisite_failures(self):
        cases = [({}, None), ({common.CUSTODY_ENV: "/tmp/x"}, None),
                 ({common.CUSTODY_ENV: self.domain + "/../x"}, None)]
        write(os.path.join(self.tmp, "elsewhere"), "0::/other/leaf\n")
        cases.append((None, os.path.join(self.tmp, "elsewhere")))
        write(os.path.join(self.tmp, "v1"), "12:pids:/x\n0::/domain/leaf\n")
        cases.append((None, os.path.join(self.tmp, "v1")))
        for environ, proc in cases:
            with self.assertRaises(common.Failure) as caught:
                self.open(environ, proc)
            self.assertEqual(caught.exception.code, "prerequisite")
        write(os.path.join(self.domain, "cgroup.subtree_control"), "cpu pids\n")
        with self.assertRaises(common.Failure):
            self.open()
        write(os.path.join(self.domain, "cgroup.subtree_control"), "cpu memory pids\n")
        write(os.path.join(self.domain, "cgroup.procs"), "123\n")
        with self.assertRaises(common.Failure):
            self.open()

    def test_systemd_user_cgroup_paths_are_valid_domains(self):
        # A real delegated domain lives under the user manager's unit names;
        # `@` and `\\` are outside the shell-inert STATE grammar but valid
        # kernel cgroup names, carried only in the environment.
        units = "user.slice/user-1000.slice/user@1000.service/app.slice/agentbox-launch-" + "a" * 32 + ".scope"
        os.makedirs(os.path.join(self.root, units))
        domain = make_domain(os.path.join(self.root, units))
        os.rename(domain, os.path.join(self.root, units, "agentbox-" + "b" * 32))
        domain = os.path.join(self.root, units, "agentbox-" + "b" * 32)
        proc = os.path.join(self.tmp, "proc-systemd")
        write(proc, "0::/" + units + "/agentbox-" + "b" * 32 + "/leaf\n")
        self.assertFalse(protocol.is_path(domain))
        custody = self.open({common.CUSTODY_ENV: domain}, proc)
        self.assertEqual(custody.path, domain)
        self.assertEqual(custody.record()["path"], domain)
        custody.close()
        escaped = os.path.join(self.root, "user.slice", "app-x\\x2dy.scope")
        self.assertTrue(common.is_cgroup_path(escaped, self.root))
        for bad in (domain + "/", domain + "//x", domain + "/./x", domain + "/../x", domain + "/a b",
                    domain + "/a\tb", domain + "/a\nb", domain + "/\u00e9", self.root, "/sys/fs/cgroupx/a",
                    domain + "/" + "n" * 256, None, 7):
            self.assertFalse(common.is_cgroup_path(bad, self.root), repr(bad))
        write(proc, "0::/" + units + "/agentbox-" + "b" * 32 + "/le af\n")
        with self.assertRaises(common.Failure):
            self.open({common.CUSTODY_ENV: domain}, proc)

    def test_limits_are_read_back_before_anything_joins(self):
        fd = os.open(self.domain, os.O_RDONLY | os.O_DIRECTORY)
        custody = FakeCustody(self.domain, fd)
        child = custody.child("engine", qemu.engine_limits(1, 64, 16))
        self.assertEqual(slurp(os.path.join(self.domain, "engine", "pids.max"), "r"), "16")
        with self.assertRaises(common.Failure):
            custody.child("engine")

        class Ignoring(FakeCustody):
            def _write(self, name, text, dir_fd):
                pass
        refusing = Ignoring(self.domain, os.open(self.domain, os.O_RDONLY | os.O_DIRECTORY))
        with self.assertRaises(common.Failure) as caught:
            refusing.child("other", {"pids.max": "16"})
        self.assertEqual(caught.exception.code, "prerequisite")
        self.assertTrue(child.settle(time.monotonic() + 5))
        self.assertFalse(os.path.exists(os.path.join(self.domain, "engine")))


class Control(unittest.TestCase):
    def session(self):
        r, w = os.pipe()
        out_r, out_w = os.pipe()
        session = common.Session(r, out_w)
        self.addCleanup(lambda: [os.close(f) for f in (out_r, out_w) if not _closed(f)])
        return session, w

    def test_cancel_stop_and_out_of_turn_frames(self):
        session, w = self.session()
        start = {"type": "capabilities", "operation": "op-1", "timeout_ms": 1000}
        os.write(w, protocol.encode(start) + b"\n")
        self.assertEqual(session.first()["operation"], "op-1")
        session.begin("op-1", 1000)
        os.write(w, protocol.encode({"type": "cancel", "operation": "op-1"}) + b"\n")
        session.pump()
        self.assertTrue(session.cancelled)
        with self.assertRaises(common.Interrupted) as caught:
            session.check()
        self.assertEqual(caught.exception.code, "cancelled")
        os.write(w, protocol.encode({"type": "cancel", "operation": "op-1"}) + b"\n")
        session.pump()
        self.assertEqual(session.refused, "unexpected_frame")
        os.close(w)

    def test_eof_mid_frame_and_deadlines(self):
        session, w = self.session()
        os.write(w, b'{"v":1,"type":"cap')
        os.close(w)
        self.assertIsNone(session.first())
        self.assertEqual(session.refused, "truncated_frame")
        session, w = self.session()
        session.begin("op-1", 1)
        time.sleep(0.01)
        with self.assertRaises(common.Interrupted) as caught:
            session.check()
        self.assertEqual(caught.exception.code, "timeout")
        os.close(w)


def _closed(fd):
    try:
        os.fstat(fd)
        return False
    except OSError:
        return True


# ---------------------------------------------------------------------------
# Provider invocations against stand-ins.

@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class Lifecycle(Case):
    def test_argv_and_connect_are_refused_without_output(self):
        for args in (["control", "relative"], ["connect", self.state, "run-1", "ex-1", "in-1"]):
            code, rest, _ = self.invoke(args).finish()
            self.assertEqual((code, rest), (2, b""))

    def test_create_start_stop_resume_with_fresh_identities(self):
        image, release = self.install_image()
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "absent")
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image="0" * 64, retention="disk",
                                     user="agentbox"), "not_found")
        # The image's own account only: no `select_user`, nothing made.
        self.assertEqual(self.call("capabilities")["features"], [])
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="disk",
                                     user="dev_1"), "unsupported")
        self.assertFalse(os.path.exists(self.resource_dir()))
        created = self.create(image)
        self.assertEqual((created["user"], created["home"]), ("agentbox", "/home/agentbox"))
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="disk",
                                     user="agentbox"), "exists")
        self.assert_failed(self.call("create", run="run-2", resource="res-1", image=image, retention="disk",
                                     user="agentbox"), "binding_mismatch")
        overlay = os.path.join(self.resource_dir(), "disk.qcow2")
        self.assertEqual(stat.S_IMODE(os.stat(overlay).st_mode), 0o600)
        status = self.call("status", run="run-1", resource="res-1")
        self.assertEqual((status["resource_state"], status["generation"]), ("ready", 0))

        key = public_key()
        invocation, request, started = self.started(key=key, limits={"cpus": 1, "memory_mib": 512})
        self.assertEqual(started["transport"]["host"], "127.0.0.1")
        self.assertEqual((started["user"], started["worker_sha256"], started["generation"]), ("agentbox", release, 0))
        self.assertEqual((started["home"], started["control"]), ("/home/agentbox", "/tmp"))
        record = self.qemu_records()[-1]
        # Limits before release, no inherited descriptor, fixed environment.
        self.assertTrue(record["joined"])
        self.assertEqual(record["limits"], qemu.engine_limits(1, 512, 512))
        self.assertEqual(record["fsize"], VSIZE + (1 << 30))
        self.assertEqual(record["core"], 0)
        self.assertTrue(record["xfsz_ignored"])
        # The host PATH (only the case's tools: the wrapper's interpreter).
        self.assertEqual(record["env"], {"PATH": self.config["path"], "LC_ALL": "C"})
        self.assertEqual(record["fds"], [0, 1, 2, record["qmp_fd"]])
        self.assertEqual(record["stdin"], "/dev/null")
        self.assertEqual(record["port"], started["transport"]["port"])
        # The seed: the host's client key and a fresh host key, root files only.
        files = {f["path"]: f["content"] for f in json.loads(record["seed"]["user-data"].split("\n", 1)[1])["write_files"]}
        self.assertEqual(files[qemu.AUTHORIZED_KEYS], key + "\n")
        self.assertEqual(files[qemu.GUEST_HOST_KEY + ".pub"].strip(), started["host_key"])
        self.assertIn("OPENSSH PRIVATE KEY", files[qemu.GUEST_HOST_KEY])
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        self.assertEqual(sorted(os.listdir(idir)), ["console.log", "instance.json", "owner.lock", "qemu.log", "seed.iso"])
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("busy", "live"))
        # A second owner or a standalone stop while the owner lives: busy.
        second, _ = self.start(instance="in-2")
        self.assert_failed(second.read(), "busy", "unsettled")
        second.finish()
        self.assert_failed(self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1",
                                     generation=0), "busy", "unsettled")

        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["type"], stopped["durability"], stopped["storage"], stopped["generation"]),
                         ("stopped", "retained", "clean", 1))
        self.assertFalse(_alive(record["pid"]))
        self.assertFalse(os.path.exists(os.path.join(self.domain, "engine")))
        self.assertEqual(sorted(os.listdir(idir)), ["console.log", "instance.json", "owner.lock", "qemu.log"])
        self.assertEqual(self.read_record()["generation"], 1)
        # Idempotent standalone stop of a settled instance.
        again = self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0)
        self.assertEqual((again["type"], again["generation"]), ("stopped", 1))
        self.assert_failed(self.call("stop", run="run-1", resource="res-1", execution="ex-9", instance="in-1",
                                     generation=0), "binding_mismatch")

        # Resume: a stale generation is refused; the next boot has a new host key.
        stale, _ = self.start(instance="in-2", execution="ex-2")
        self.assert_failed(stale.read(), "generation_mismatch")
        stale.finish()
        invocation, request, resumed = self.started(generation=1, instance="in-3", execution="ex-3")
        self.assertNotEqual(resumed["host_key"], started["host_key"])
        second_seed = self.qemu_records()[-1]["seed"]
        self.assertNotEqual(json.loads(second_seed["meta-data"])["instance-id"],
                            json.loads(record["seed"]["meta-data"])["instance-id"])
        self.assertEqual(self.owner_stop(invocation, request)["generation"], 2)

    def test_forced_stop_is_unclean_and_needs_acknowledgement(self):
        image, _ = self.install_image()
        self.create(image)
        self.config["qemu"] = {"ignore_powerdown": True}
        self.save()
        invocation, request, _ = self.started()
        stopped = self.owner_stop(invocation, request, timeout_ms=11000)
        self.assertEqual((stopped["durability"], stopped["storage"], stopped["generation"]),
                         ("uncertain", "unclean", 1))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "unclean")
        refused, _ = self.start(generation=1, instance="in-2")
        self.assert_failed(refused.read(), "unclean")
        refused.finish()
        self.config["qemu"] = {}
        self.save()
        invocation, request, _ = self.started(generation=1, instance="in-3", accept_unclean=True)
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["durability"], stopped["storage"]), ("retained", "clean"))

    def test_acknowledged_powerdown_without_evidence_is_not_clean(self):
        image, _ = self.install_image()
        self.create(image)
        for behaviour in ({"reason": "host-signal"}, {"shutdown_code": 1}):
            self.config["qemu"] = behaviour
            self.save()
            generation = self.read_record()["generation"]
            invocation, request, _ = self.started(generation=generation, instance=f"in-{generation}",
                                                  accept_unclean=True)
            stopped = self.owner_stop(invocation, request)
            self.assertEqual((stopped["durability"], stopped["storage"]), ("uncertain", "unclean"), behaviour)

    def test_an_unexpected_engine_exit_waits_for_stop(self):
        image, _ = self.install_image()
        self.create(image)
        self.config["qemu"] = {"exit_after": 0.3, "exit_code": 0}
        self.save()
        invocation, request, _ = self.started()
        time.sleep(0.8)
        self.assertIsNone(invocation.read(timeout=0.2))
        self.assertIsNone(invocation.proc.poll())
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["durability"], stopped["storage"]), ("uncertain", "unclean"))

    def test_eof_and_signals_force_stop_and_record_by_handle(self):
        image, _ = self.install_image()
        self.create(image)
        for number, end in enumerate(("eof", signal.SIGTERM, signal.SIGHUP)):
            generation = self.read_record()["generation"]
            invocation, _, _ = self.started(generation=generation, instance=f"in-{number}",
                                            execution=f"ex-{number}", accept_unclean=True)
            pid = self.qemu_records()[-1]["pid"]
            if end == "eof":
                invocation.close()
            else:
                invocation.proc.send_signal(end)
            code, rest, _ = invocation.finish()
            self.assertEqual((code, rest), (0, b""))
            self.assertFalse(_alive(pid))
            status = self.call("status", run="run-1", resource="res-1", execution=f"ex-{number}",
                               instance=f"in-{number}")
            self.assertEqual((status["instance_state"], status["resource_state"], status["generation"]),
                             ("settled", "unclean", generation + 1))

    def test_a_refused_owner_frame_ends_the_session_like_eof(self):
        image, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        invocation.send(self.stop_frame(request, instance="in-9"))
        code, rest, _ = invocation.finish()
        self.assertEqual((code, rest), (0, b""))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual(status["instance_state"], "settled")

    def test_provider_loss_keeps_the_engine_until_a_standalone_stop(self):
        image, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        pid = self.qemu_records()[-1]["pid"]
        invocation.proc.kill()
        invocation.proc.wait()
        self.assertTrue(_alive(pid))
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["instance_state"], status["resource_state"]), ("unsettled", "busy"))
        refused, _ = self.start(instance="in-2", execution="ex-2")
        self.assert_failed(refused.read(), "busy", "unsettled")
        refused.finish()
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "busy", "unsettled")
        self.assert_failed(self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1",
                                     generation=3), "generation_mismatch")
        stopped = self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0)
        self.assertEqual((stopped["type"], stopped["durability"], stopped["storage"], stopped["generation"]),
                         ("stopped", "uncertain", "unclean", 1))
        time.sleep(0.1)
        self.assertFalse(_alive(pid))
        self.assertFalse(os.path.exists(os.path.join(self.domain, "engine")))
        self.assertFalse(os.path.exists(os.path.join(self.resource_dir(), "instances", "in-1", "seed.iso")))

    def test_a_start_lost_before_its_engine_settles_unchanged(self):
        image, _ = self.install_image()
        self.create(image)
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        os.makedirs(idir, 0o700)
        os.chmod(os.path.dirname(idir), 0o700)
        write(os.path.join(idir, "instance.json"), json.dumps({
            "schema": qemu.INSTANCE_SCHEMA, "run": "run-1", "resource": "res-1", "execution": "ex-1",
            "instance": "in-1", "generation": 0, "retention": "disk", "phase": "intent", "domain": self.domain,
            "engine": "engine", "port": None, "host_key": None, "result": None}), 0o600)
        write(os.path.join(idir, "seed.iso"), b"secret seed", 0o600)
        record = self.read_record()
        record["instance"] = {"execution": "ex-1", "instance": "in-1"}
        write(os.path.join(self.resource_dir(), "resource.json"), json.dumps(record), 0o600)
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("busy", "unsettled"))
        stopped = self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0)
        self.assertEqual((stopped["durability"], stopped["storage"], stopped["generation"]), ("unchanged", "clean", 0))
        self.assertFalse(os.path.exists(os.path.join(idir, "seed.iso")))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "ready")

    def test_cancel_and_timeout_before_started(self):
        image, _ = self.install_image()
        self.create(image)
        self.config["qemu"] = {"no_banner": True}
        self.save()
        invocation, request = self.start()
        time.sleep(1.0)
        invocation.send({"type": "cancel", "operation": request["operation"]})
        self.assert_failed(invocation.read(), "cancelled", "settled", "uncertain")
        invocation.finish()
        self.assertFalse(any(_alive(p) for p in self.qemu_pids()))
        invocation, request = self.start(generation=1, instance="in-2", accept_unclean=True, timeout_ms=2500)
        self.assert_failed(invocation.read(), "timeout", "settled", "uncertain")
        invocation.finish()
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "unclean")

    def test_failures_before_launch_leave_storage_unchanged(self):
        image, _ = self.install_image()
        self.create(image)
        self.config["xorriso_fail"] = True
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(), "failed", "settled", "unchanged")
        invocation.finish()
        self.assertEqual(self.read_record()["generation"], 0)
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        self.assertEqual(sorted(os.listdir(idir)), ["instance.json", "owner.lock"])
        self.config["xorriso_fail"] = False
        self.config["version"] = "QEMU emulator version 6.2.0"
        self.save()
        invocation, _ = self.start(instance="in-2")
        self.assert_failed(invocation.read(), "prerequisite")
        invocation.finish()
        self.config.pop("version")
        self.save()
        os.truncate(os.path.join(self.resource_dir(), "disk.qcow2"), 2 << 20)
        invocation, _ = self.start(instance="in-3", limits={"disk_mib": 1})
        self.assert_failed(invocation.read(), "failed")
        invocation.finish()
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "ready")

    def test_a_tampered_base_or_overlay_never_boots(self):
        image, _ = self.install_image()
        self.create(image)
        overlay = os.path.join(self.resource_dir(), "disk.qcow2")
        good = slurp(overlay)
        write(overlay, qcow2(backing="/elsewhere/base.qcow2"), 0o600)
        invocation, _ = self.start()
        self.assert_failed(invocation.read(), "failed")
        invocation.finish()
        write(overlay, good, 0o600)
        entry = os.path.join(self.state, "images", image)
        os.chmod(entry, 0o700)
        os.chmod(os.path.join(entry, "disk.qcow2"), 0o600)
        with open(os.path.join(entry, "disk.qcow2"), "r+b") as stream:
            stream.seek(1 << 17)
            stream.write(b"x")
        os.chmod(os.path.join(entry, "disk.qcow2"), 0o400)
        os.chmod(entry, 0o500)
        invocation, _ = self.start(instance="in-2")
        self.assert_failed(invocation.read(), "failed")
        invocation.finish()
        self.assertEqual(self.qemu_records(), [])
        self.assert_failed(self.call("create", run="run-2", resource="res-2", image=image, retention="disk",
                                     user="agentbox"),
                           "failed")

    def test_retention_none_boots_a_fresh_overlay_each_time(self):
        image, _ = self.install_image()
        self.create(image, retention="none")
        self.assertFalse(os.path.exists(os.path.join(self.resource_dir(), "disk.qcow2")))
        invocation, request, _ = self.started()
        overlay = json.loads(self.qemu_records()[-1]["argv"][
            [i for i, a in enumerate(self.qemu_records()[-1]["argv"]) if '"overlay-file"' in a][0]])["filename"]
        self.assertIn("/instances/in-1/", overlay)
        stopped = self.owner_stop(invocation, request)
        self.assertEqual((stopped["durability"], stopped["generation"], stopped["storage"]), ("unchanged", 0, "clean"))
        self.assertFalse(os.path.exists(overlay))
        self.assert_failed(self.call("checkpoint", run="run-1", resource="res-1", checkpoint="ck-1", generation=0,
                                     accept_unclean=False), "unsupported")

    def test_create_failures_roll_back_or_stay_partial(self):
        image, _ = self.install_image()
        self.config["qemu_img_fail"] = "check"
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="disk",
                                     user="agentbox"),
                           "failed")
        self.assertFalse(os.path.exists(self.resource_dir()))
        self.config.pop("qemu_img_fail")
        self.save()
        # An interrupted create, found by its handle.
        os.makedirs(os.path.join(self.state, "resources", "res-2"), 0o700)
        os.chmod(os.path.join(self.state, "resources"), 0o700)
        write(os.path.join(self.resource_dir("res-2"), "resource.json"), json.dumps({
            "schema": qemu.RESOURCE_SCHEMA, "run": "run-1", "resource": "res-2", "image": image,
            "retention": "disk", "state": "creating", "generation": 0, "storage": "clean", "instance": None,
            "pending": None, "restoring": None}), 0o600)
        write(os.path.join(self.resource_dir("res-2"), "staging.qcow2"), b"partial", 0o600)
        self.assertEqual(self.call("status", run="run-1", resource="res-2")["resource_state"], "partial")
        refused, _ = self.start(resource="res-2")
        self.assert_failed(refused.read(), "partial")
        refused.finish()
        done = self.call("discard", run="run-1", resource="res-2")
        self.assertEqual((done["type"], done["settlement"]), ("discarded", "settled"))
        self.assertEqual(sorted(os.listdir(self.resource_dir("res-2"))), ["lock", "resource.json"])
        self.assertEqual(self.call("status", run="run-1", resource="res-2")["resource_state"], "absent")
        self.assertEqual(self.call("discard", run="run-1", resource="res-2")["type"], "discarded")
        self.assert_failed(self.call("discard", run="run-9", resource="res-2"), "binding_mismatch")
        self.assert_failed(self.call("discard", run="run-1", resource="res-404"), "not_found")


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class Checkpoints(Case):
    def cycle(self, generation, instance, accept=False, force=False):
        self.config["qemu"] = {"ignore_powerdown": True} if force else {}
        self.save()
        invocation, request, _ = self.started(generation=generation, instance=instance,
                                              execution="x" + instance, accept_unclean=accept)
        return self.owner_stop(invocation, request, timeout_ms=11000 if force else 30000)

    def checkpoint(self, name, generation, accept=False, resource="res-1", run="run-1"):
        return self.call("checkpoint", run=run, resource=resource, checkpoint=name, generation=generation,
                         accept_unclean=accept)

    def restore(self, name, generation, resource="res-1", run="run-1"):
        return self.call("restore", run=run, resource=resource, checkpoint=name, generation=generation)

    def disk(self, resource="res-1"):
        with open(os.path.join(self.resource_dir(resource), "disk.qcow2"), "rb") as stream:
            return stream.read()

    def scribble(self, text, resource="res-1"):
        path = os.path.join(self.resource_dir(resource), "disk.qcow2")
        with open(path, "r+b") as stream:
            stream.seek(3 * CLUSTER + 64)
            stream.write(text)

    def test_growth_needs_declared_state_and_disposal_never_does(self):
        """Create, start, checkpoint and restore refuse before any effect
        without a declared scope over STATE (absent, invalid or elsewhere);
        retention `none` still answers `unsupported` first. Stop and discard
        (of resources and checkpoints) never ask: they run with no
        declaration at all."""
        image, _ = self.install_image()
        self.create(image)
        self.assertEqual(self.cycle(0, "in-1")["generation"], 1)
        self.assertEqual(self.checkpoint("ck-1", 1)["type"], "checkpointed")
        before = sorted(os.listdir(os.path.join(self.state, "checkpoints")))
        for case in ("elsewhere", "invalid", "absent"):
            if case == "elsewhere":
                declare(self.tmp, self.config, [{"path": os.path.realpath(self.records), "measure": "tree"}])
            elif case == "invalid":
                write(self.config["scopes"], json.dumps({"max_reserved_bytes": 1, "storage_scopes": [
                    {"path": "/srv", "measure": "tree", "uncapped": ["x"]},
                    {"path": "/srv/x", "measure": "tree"}]}), 0o600)
            else:
                os.unlink(self.config["scopes"])
            self.save()
            self.assert_failed(self.checkpoint("ck-2", 1), "prerequisite")
            self.assert_failed(self.restore("ck-1", 1), "prerequisite")
            self.assert_failed(self.call("create", run="run-2", resource="res-2", image=image,
                                         retention="disk", user="agentbox"), "prerequisite")
            invocation, _ = self.start(generation=1, instance="in-2", execution="xin-2")
            self.assert_failed(invocation.read(60), "prerequisite")
            invocation.finish()
            self.assertEqual(sorted(os.listdir(os.path.join(self.state, "checkpoints"))), before)
            self.assertFalse(os.path.exists(self.resource_dir("res-2")))
            self.assertEqual(self.read_record()["generation"], 1)
        # Disposal with nothing declared.
        self.assertEqual(self.call("discard", run="run-1", resource="res-1", checkpoint="ck-1")["type"],
                         "discarded")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")

    def test_a_refused_growth_reconciles_nothing(self):
        """An undeclared resource directory (a fake topology) refuses
        before ready_resource's reconciliation writes: a settled but
        unapplied instance stays unapplied (and an interrupted
        staging, by name), every record and path
        unchanged. Declared, the same resource is reconciled."""
        image, _ = self.install_image()
        self.create(image)
        directory = self.resource_dir()
        record = self.read_record()
        record["instance"] = {"execution": "ex-0", "instance": "in-0"}
        record["pending"] = "restore.qcow2"
        write(os.path.join(directory, "restore.qcow2"), b"half", 0o600)
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
        refusals = [lambda: self.start(), lambda: self.checkpoint("ck-9", 0), lambda: self.restore("ck-1", 0)]
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
        self.assertEqual((self.read_record()["generation"], self.read_record()["instance"]), (7, None))
        self.assertFalse(os.path.exists(os.path.join(directory, "restore.qcow2")))

    def test_start_checks_the_resource_directory_before_making_anything(self):
        """A resource directory on an undeclared filesystem (a fake
        topology: STATE's device elsewhere) refuses start before anything
        is made or written; so does an existing instances directory on one,
        with nothing made in it."""
        image, _ = self.install_image()
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
        instances = os.path.join(directory, "instances")
        os.mkdir(instances, 0o700)
        self.config["fake_devices"] = {instances: 2 ** 40}
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(60), "prerequisite")
        invocation.finish()
        self.assertEqual(listing(instances), [])
        self.assertEqual(record(), before[1])

    def test_save_branch_rollback_and_independent_lifetime(self):
        image, _ = self.install_image()
        self.create(image)
        self.assertEqual(self.cycle(0, "in-1")["generation"], 1)
        self.scribble(b"generation one")
        saved = self.disk()
        answer = self.checkpoint("ck-1", 1)
        self.assertEqual((answer["type"], answer["generation"], answer["storage"]), ("checkpointed", 1, "clean"))
        self.assert_failed(self.checkpoint("ck-1", 1), "exists")
        self.assert_failed(self.checkpoint("ck-2", 0), "generation_mismatch")
        copy = os.path.join(self.state, "checkpoints", "ck-1", "disk.qcow2")
        self.assertEqual(stat.S_IMODE(os.stat(copy).st_mode), 0o400)

        # Branch: a new resource of the same image takes the checkpoint; the
        # source is untouched.
        self.create(image, resource="res-2", run="run-2")
        self.scribble(b"generation two")
        changed = self.disk()
        answer = self.restore("ck-1", 0, resource="res-2", run="run-2")
        self.assertEqual((answer["type"], answer["generation"], answer["storage"]), ("restored", 1, "clean"))
        self.assertEqual(self.disk("res-2"), saved)
        self.assertEqual(self.disk(), changed)
        self.assertEqual(self.read_record()["generation"], 1)
        # Rollback of the source itself.
        answer = self.restore("ck-1", 1)
        self.assertEqual(answer["generation"], 2)
        self.assertEqual(self.disk(), saved)
        self.assert_failed(self.restore("ck-1", 1), "generation_mismatch")
        # The checkpoint outlives its source resource; exact removal later.
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertTrue(os.path.exists(copy))
        self.assertEqual(self.restore("ck-1", 1, resource="res-2", run="run-2")["generation"], 2)
        self.assert_failed(self.call("discard", run="run-2", resource="res-2", checkpoint="ck-1"),
                           "binding_mismatch")
        done = self.call("discard", run="run-1", resource="res-1", checkpoint="ck-1")
        self.assertEqual((done["type"], done["checkpoint"]), ("discarded", "ck-1"))
        self.assertFalse(os.path.exists(copy))
        self.assertEqual(self.call("discard", run="run-1", resource="res-1", checkpoint="ck-1")["type"], "discarded")
        self.assert_failed(self.restore("ck-1", 2, resource="res-2", run="run-2"), "not_found")
        self.assert_failed(self.call("discard", run="run-1", resource="res-1", checkpoint="ck-404"), "not_found")
        # Discarding the branch resource left its own storage only.
        self.assertEqual(self.read_record("res-2")["generation"], 2)

    def test_unclean_sources_need_acknowledgement_and_stay_unclean(self):
        image, _ = self.install_image()
        self.create(image)
        self.assertEqual(self.cycle(0, "in-1", force=True)["storage"], "unclean")
        self.assert_failed(self.checkpoint("ck-1", 1), "unclean")
        self.assertFalse(os.path.exists(os.path.join(self.state, "checkpoints", "ck-1")))
        answer = self.checkpoint("ck-1", 1, accept=True)
        self.assertEqual(answer["storage"], "unclean")
        self.assertEqual(self.read_record()["storage"], "unclean")
        # A clean target restored from it becomes unclean, never laundered.
        self.create(image, resource="res-2", run="run-2")
        answer = self.restore("ck-1", 0, resource="res-2", run="run-2")
        self.assertEqual((answer["generation"], answer["storage"]), (1, "unclean"))
        self.assertEqual(self.call("status", run="run-2", resource="res-2")["resource_state"], "unclean")
        refused, _ = self.start(resource="res-2", run="run-2", generation=1)
        self.assert_failed(refused.read(), "unclean")
        refused.finish()
        # A clean checkpoint restored over unclean storage needs nothing.
        self.assertEqual(self.cycle(1, "in-2", accept=True)["storage"], "clean")
        self.checkpoint("ck-2", 2)
        self.assertEqual(self.restore("ck-2", 1, resource="res-2", run="run-2")["storage"], "clean")

    def test_image_mismatch_busy_tampering_and_partial_copies(self):
        image, _ = self.install_image()
        other, _ = self.install_image(size=VSIZE * 2)
        self.create(image)
        self.create(other, resource="res-2", run="run-2")
        self.checkpoint("ck-1", 0)
        self.assert_failed(self.restore("ck-1", 0, resource="res-2", run="run-2"), "binding_mismatch")
        invocation, request, _ = self.started()
        self.assert_failed(self.checkpoint("ck-2", 0), "busy", "unsettled")
        self.assert_failed(self.restore("ck-1", 0), "busy", "unsettled")
        self.owner_stop(invocation, request)
        copy = os.path.join(self.state, "checkpoints", "ck-1", "disk.qcow2")
        os.chmod(copy, 0o600)
        with open(copy, "r+b") as stream:
            stream.seek(3 * CLUSTER)
            stream.write(b"tampered")
        os.chmod(copy, 0o400)
        before = self.disk()
        self.assert_failed(self.restore("ck-1", 1), "failed")
        self.assertEqual(self.disk(), before)
        self.assertNotIn("restore.qcow2", os.listdir(self.resource_dir()))
        self.assertIsNone(self.read_record()["pending"])
        # An interrupted checkpoint copy: partial until its exact discard.
        cdir = os.path.join(self.state, "checkpoints", "ck-3")
        os.mkdir(cdir, 0o700)
        write(os.path.join(cdir, "checkpoint.json"), json.dumps({
            "schema": qemu.CHECKPOINT_SCHEMA, "checkpoint": "ck-3", "run": "run-1", "resource": "res-1",
            "generation": 1, "storage": "clean", "image": image, "state": "copying", "bytes": None,
            "sha256": None}), 0o600)
        self.assert_failed(self.restore("ck-3", 1), "partial")
        self.assertEqual(self.call("discard", run="run-1", resource="res-1", checkpoint="ck-3")["type"], "discarded")

    def test_an_interrupted_restore_staging_is_dropped_by_name(self):
        image, _ = self.install_image()
        self.create(image)
        self.checkpoint("ck-1", 0)
        record = self.read_record()
        record["pending"] = "restore.qcow2"
        write(os.path.join(self.resource_dir(), "resource.json"), json.dumps(record), 0o600)
        write(os.path.join(self.resource_dir(), "restore.qcow2"), b"half", 0o600)
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "ready")
        self.assertEqual(self.restore("ck-1", 0)["generation"], 1)
        self.assertNotIn("restore.qcow2", os.listdir(self.resource_dir()))
        # A record caught between naming the replacement and finishing.
        record = self.read_record()
        record.update(state="restoring", restoring={"checkpoint": "ck-1", "generation": 2})
        write(os.path.join(self.resource_dir(), "resource.json"), json.dumps(record), 0o600)
        self.assert_failed(self.restore("ck-1", 1), "partial")
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "partial")


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class ToolDebts(Case):
    """A tool child that cannot be confirmed gone stays a recorded debt;
    nothing it may write is removed until that exact child is settled."""

    def stuck(self, **behaviour):
        self.config.update(immune=True, kill_reserve=0.3, **behaviour)
        self.save()

    def unstuck(self):
        self.config.update(immune=False, qemu_img_hang=None, xorriso_hang=False)
        self.save()

    def test_create_keeps_its_record_files_and_debt_until_discard_settles_it(self):
        image, _ = self.install_image()
        self.stuck(qemu_img_hang="check")
        answer = self.call("create", run="run-1", resource="res-1", image=image, retention="disk",
                           timeout_ms=1500, user="agentbox")
        self.assert_failed(answer, "failed", "unsettled", "uncertain")
        record = self.read_record()
        self.assertEqual(record["state"], "creating")
        [debt] = record["tools"]
        self.assertTrue(os.path.isdir(os.path.join(self.domain, debt["name"])))
        self.assertIsNotNone(debt["identity"])
        [pid] = self.hung()
        self.assertTrue(_alive(pid))
        self.assertTrue(os.path.exists(os.path.join(self.resource_dir(), "staging.qcow2")))
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "partial")
        refused, _ = self.start()
        self.assert_failed(refused.read(), "partial")
        refused.finish()
        # Still stuck: discard settles nothing and removes nothing.
        self.assert_failed(self.call("discard", run="run-1", resource="res-1"), "busy", "unsettled", "uncertain")
        self.assertTrue(os.path.exists(os.path.join(self.resource_dir(), "staging.qcow2")))
        self.assertEqual(self.read_record()["tools"], [debt])
        # A fresh domain is entered only after the host killed and reaped
        # every earlier process (here the stuck tool, exactly, as the host
        # would through the old domain): the debt recorded with the old one
        # is then dropped, nothing of it signalled or removed, and the
        # staging file the writer held goes.
        os.kill(pid, signal.SIGKILL)
        for _ in range(100):
            if not _alive(pid):
                break
            time.sleep(0.02)
        self.assertFalse(_alive(pid))
        self.config["domain"] = make_domain(os.path.join(self.tmp, "other"))
        self.unstuck()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        self.assertTrue(os.path.isdir(os.path.join(self.domain, debt["name"])), "never touched")
        self.assertEqual(sorted(os.listdir(self.resource_dir())), ["lock", "resource.json"])

    def test_a_stuck_seed_tool_keeps_the_start_unsettled_until_a_later_stop(self):
        image, _ = self.install_image()
        self.create(image)
        self.stuck(xorriso_hang=True)
        invocation, _ = self.start(timeout_ms=2500)
        self.assert_failed(invocation.read(), "failed", "unsettled", "uncertain")
        invocation.finish()
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        inst = json.loads(slurp(os.path.join(idir, "instance.json")))
        self.assertEqual((inst["phase"], len(inst["tools"])), ("intent", 1))
        # The seed inputs a live writer may still use are kept, not unlinked.
        self.assertTrue({"user-data", "meta-data", "seed.iso"} <= set(os.listdir(idir)))
        [pid] = self.hung()
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual((status["resource_state"], status["instance_state"]), ("busy", "unsettled"))
        self.assert_failed(self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1",
                                     generation=0), "busy", "unsettled", "uncertain")
        self.assertTrue(os.path.exists(os.path.join(idir, "user-data")))
        self.unstuck()
        stopped = self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0)
        self.assertEqual((stopped["type"], stopped["durability"], stopped["generation"]), ("stopped", "unchanged", 0))
        time.sleep(0.1)
        self.assertFalse(_alive(pid))
        self.assertEqual(sorted(os.listdir(idir)), ["instance.json", "owner.lock"])
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "ready")


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class EngineObservation(Case):
    """Recovery in the engine's own domain never certifies the original
    engine child from a denied or replaced observation."""

    def test_denied_and_replaced_engines_stay_unsettled(self):
        image, _ = self.install_image()
        self.create(image)
        invocation, _, _ = self.started()
        pid = self.qemu_records()[-1]["pid"]
        invocation.proc.kill()
        invocation.proc.wait()
        engine = os.path.join(self.domain, "engine")
        stop = dict(run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0)
        os.chmod(engine, 0)
        try:
            self.assert_failed(self.call("stop", **stop), "busy", "unsettled", "uncertain")
        finally:
            os.chmod(engine, 0o755)
        self.assertTrue(_alive(pid))
        os.rename(engine, engine + "-original")
        FakeCustody._make(FakeCustody(self.domain, os.open(self.domain, os.O_RDONLY)), "engine")
        self.assert_failed(self.call("stop", **stop), "busy", "unsettled", "uncertain")
        self.assertTrue(_alive(pid))
        self.assertTrue(os.path.isdir(engine))
        shutil.rmtree(engine)
        # Absent under its name, but still in the domain under another.
        self.assert_failed(self.call("stop", **stop), "busy", "unsettled", "uncertain")
        self.assertTrue(_alive(pid))
        os.rename(engine + "-original", engine)
        # In its own domain the very child: killed, settled.
        self.assertEqual(self.call("stop", **stop)["type"], "stopped")
        time.sleep(0.1)
        self.assertFalse(_alive(pid))

    def test_a_fresh_domain_drops_the_old_engine_untouched(self):
        """The later standalone cleanup in a fresh domain, entered only once
        the host killed and reaped every earlier process: the engine child
        recorded with the old domain is gone by that precondition, settled
        without a signal or removal."""
        image, _ = self.install_image()
        self.create(image)
        invocation, _, _ = self.started()
        pid = self.qemu_records()[-1]["pid"]
        invocation.proc.kill()
        invocation.proc.wait()
        # The host's part, exactly: the old domain's processes gone.
        os.kill(pid, signal.SIGKILL)
        for _ in range(100):
            if not _alive(pid):
                break
            time.sleep(0.02)
        engine = os.path.join(self.domain, "engine")
        self.config["domain"] = make_domain(os.path.join(self.tmp, "fresh"))
        self.save()
        stop = dict(run="run-1", resource="res-1", execution="ex-1", instance="in-1", generation=0)
        self.assertEqual(self.call("stop", **stop)["type"], "stopped")
        self.assertTrue(os.path.isdir(engine), "the old domain is never touched")
        # A killed instance's storage stays honestly unclean.
        self.assertEqual(self.call("status", run="run-1", resource="res-1")["resource_state"], "unclean")

    def test_status_probes_without_creating_the_owner_lock(self):
        image, _ = self.install_image()
        self.create(image)
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        os.makedirs(idir, 0o700)
        os.chmod(os.path.dirname(idir), 0o700)
        write(os.path.join(idir, "instance.json"), json.dumps({"execution": "ex-1", "phase": "intent"}), 0o600)
        status = self.call("status", run="run-1", resource="res-1", execution="ex-1", instance="in-1")
        self.assertEqual(status["instance_state"], "unsettled")
        self.assertFalse(os.path.exists(os.path.join(idir, "owner.lock")))


class LaunchedFaults(unittest.TestCase):
    """Any failure after a tool exists goes through its exact settlement;
    an unconfirmed child outranks the original error."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abq-")
        self.addCleanup(remove_tree, self.tmp)
        self.domain = make_domain(self.tmp)
        self.custody = FakeCustody(self.domain, os.open(self.domain, os.O_RDONLY | os.O_DIRECTORY))
        self.addCleanup(self.custody.close)
        r, w = os.pipe()
        self.addCleanup(lambda: [os.close(f) for f in (r, w)])
        self.session = common.Session(r, w)
        self.session.begin("op-1", 30000)
        self.addCleanup(lambda: [os.close(f) for f in (self.session.wake_r, self.session.wake_w)])
        self.reserve = common.KILL_RESERVE
        common.KILL_RESERVE = 0.3
        self.addCleanup(setattr, common, "KILL_RESERVE", self.reserve)
        self.pidfile = os.path.join(self.tmp, "pid")
        # An unsettled stand-in's Popen is deliberately left unreaped.
        self.enterContext(warnings.catch_warnings())
        warnings.filterwarnings("ignore", "subprocess .* is still running", ResourceWarning)
        # Prints, records its pid, then waits to be killed.
        self.argv = [sys.executable, "-IBS", "-c", "import os, sys, time\n"
                     f"open({self.pidfile!r}, 'w').write(str(os.getpid()))\n"
                     "sys.stdout.write('x' * 100); sys.stdout.flush(); time.sleep(60)"]

    def run_tool(self, ledger, log=None):
        return common.run_tool(self.session, self.custody, "tool-t", self.argv, {}, log=log, ledger=ledger)

    def pid(self):
        for _ in range(200):
            if os.path.exists(self.pidfile) and slurp(self.pidfile):
                return int(slurp(self.pidfile))
            time.sleep(0.01)
        return None

    def fds(self):
        return sorted(os.listdir("/proc/self/fd"))

    def test_a_refused_pidfd_never_loses_the_spawned_leader(self):
        before = self.fds()
        real = deny_pidfd(1)
        try:
            ledger = common.Ledger()
            with self.assertRaises(common.Failure) as caught:
                self.run_tool(ledger)
            self.assertNotIsInstance(caught.exception, common.Unsettled)
            self.assertEqual(ledger.outstanding, [])
            self.assertFalse(os.path.exists(os.path.join(self.domain, "tool-t")))
            pid = int(slurp(self.pidfile)) if os.path.exists(self.pidfile) else None
            self.assertTrue(pid is None or not _alive(pid))
            self.assertEqual(self.fds(), before)
            # The same refusal with a child that cannot be emptied: a debt.
            self.custody.immune = True
            os.pidfd_open = real
            deny_pidfd(1)
            with self.assertRaises(common.Unsettled):
                self.run_tool(ledger)
            self.assertEqual(ledger.outstanding, ["tool-t"])
            self.assertTrue(os.path.isdir(os.path.join(self.domain, "tool-t")))
            pid = self.pid()
            self.assertTrue(_alive(pid))
            del caught
            self.forget(pid)
        finally:
            os.pidfd_open = real

    def forget(self, pid):
        """Kills an unsettled stand-in; its Popen is deliberately unreaped."""
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        gc.collect()

    def test_a_log_error_is_settled_first_and_outranked_when_unconfirmed(self):
        class Broken:
            def write(self, data):
                raise OSError("disk full")

        before = self.fds()
        ledger = common.Ledger()
        with self.assertRaises(OSError) as caught:
            self.run_tool(ledger, log=Broken())
        self.assertNotIsInstance(caught.exception, common.Failure)
        self.assertEqual(ledger.outstanding, [])
        self.assertFalse(_alive(self.pid()))
        self.assertFalse(os.path.exists(os.path.join(self.domain, "tool-t")))
        self.assertEqual(self.fds(), before)
        os.unlink(self.pidfile)
        self.custody.immune = True
        with self.assertRaises(common.Unsettled) as caught:
            self.run_tool(ledger, log=Broken())
        self.assertIsInstance(caught.exception.__cause__, OSError)
        self.assertEqual(ledger.outstanding, ["tool-t"])
        pid = self.pid()
        self.assertTrue(_alive(pid))
        del caught
        self.forget(pid)


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class AdmissionFaults(Case):
    """pidfd refusals inside the provider: state kept exactly while a writer
    is unconfirmed, cleaned only once none is outstanding."""

    def test_create_keeps_its_state_when_a_refused_tool_cannot_be_settled(self):
        image, _ = self.install_image()
        self.config.update(deny_pidfd=2, immune=True, kill_reserve=0.3, qemu_img_hang="check")
        self.save()
        self.assert_failed(self.call("create", run="run-1", resource="res-1", image=image, retention="disk",
                                     user="agentbox"),
                           "failed", "unsettled", "uncertain")
        record = self.read_record()
        self.assertEqual((record["state"], len(record["tools"])), ("creating", 1))
        self.assertTrue(os.path.exists(os.path.join(self.resource_dir(), "staging.qcow2")))
        self.config.update(deny_pidfd=None, immune=False)
        self.save()
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        time.sleep(0.1)
        self.assertFalse(any(_alive(p) for p in self.hung()))
        # Settled refusal: rolled back completely.
        self.config.update(deny_pidfd=2, qemu_img_hang=None)
        self.save()
        answer = self.call("create", run="run-1", resource="res-2", image=image, retention="disk", user="agentbox")
        self.assert_failed(answer, "failed")
        self.assertFalse(os.path.exists(self.resource_dir("res-2")))

    def test_seed_inputs_stay_while_their_writer_is_unconfirmed(self):
        image, _ = self.install_image()
        self.create(image)
        # qemu -version, ssh-keygen, ssh-keygen -y, xorriso: refuse the 4th.
        self.config.update(deny_pidfd=4, immune=True, kill_reserve=0.3, xorriso_hang=True)
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(), "failed", "unsettled", "uncertain")
        invocation.finish()
        idir = os.path.join(self.resource_dir(), "instances", "in-1")
        self.assertTrue({"user-data", "meta-data", "seed.iso"} <= set(os.listdir(idir)))
        self.config.update(deny_pidfd=None, immune=False, xorriso_hang=False)
        self.save()
        self.assertEqual(self.call("stop", run="run-1", resource="res-1", execution="ex-1", instance="in-1",
                                   generation=0)["durability"], "unchanged")
        self.assertEqual(sorted(os.listdir(idir)), ["instance.json", "owner.lock"])
        # Settled refusal: nothing outstanding, the key material is removed.
        self.config.update(deny_pidfd=4)
        self.save()
        invocation, _ = self.start(instance="in-2", execution="ex-2")
        self.assert_failed(invocation.read(), "failed", "settled", "unchanged")
        invocation.finish()
        self.assertEqual(sorted(os.listdir(os.path.join(self.resource_dir(), "instances", "in-2"))),
                         ["instance.json", "owner.lock"])
        self.assertFalse([n for n in os.listdir(self.domain) if n.startswith("tool-")])

    def test_a_refused_engine_pidfd_still_settles_qemu(self):
        image, _ = self.install_image()
        self.create(image)
        self.config.update(deny_pidfd=5)
        self.save()
        invocation, _ = self.start()
        self.assert_failed(invocation.read(), "failed", "settled", "uncertain")
        invocation.finish()
        time.sleep(0.1)
        self.assertFalse(any(_alive(p) for p in self.qemu_pids()))
        self.assertFalse(os.path.exists(os.path.join(self.domain, "engine")))
        self.assertEqual(self.read_record()["generation"], 1)


class ChildSettlement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abq-")
        self.addCleanup(remove_tree, self.tmp)
        self.domain = make_domain(self.tmp)
        self.custody = FakeCustody(self.domain, os.open(self.domain, os.O_RDONLY | os.O_DIRECTORY))

    def test_only_removal_of_the_pinned_child_counts(self):
        child = self.custody.child("tool-a")
        os.rename(os.path.join(self.domain, "tool-a"), os.path.join(self.domain, "moved"))
        FakeCustody._make(self.custody, "tool-a")
        self.assertFalse(child.settle(time.monotonic() + 1))
        self.assertTrue(os.path.isdir(os.path.join(self.domain, "tool-a")))
        self.assertTrue(os.path.isdir(os.path.join(self.domain, "moved")))

        class Denied(FakeCustody):
            def populated(self, child):
                raise PermissionError
        denied = Denied(self.domain, os.open(self.domain, os.O_RDONLY | os.O_DIRECTORY))
        other = denied.child("tool-b")
        self.assertFalse(other.settle(time.monotonic() + 1))
        self.assertTrue(os.path.isdir(os.path.join(self.domain, "tool-b")))
        # Removed by someone else after it emptied: its own control files
        # are gone beneath the pinned descriptor.
        gone = self.custody.child("tool-c")
        self.custody.remove(gone)
        self.assertTrue(gone.settle(time.monotonic() + 1))
        with self.assertRaises(common.Unsettled):
            self.custody.existing("tool-a", child.identity)


class Coalesced(unittest.TestCase):
    """Frames arriving together or split: a request is in flight as soon as
    it is parsed, so its cancel is never refused."""

    def pipes(self):
        r, w = os.pipe()
        out_r, out_w = os.pipe()
        self.addCleanup(lambda: [os.close(f) for f in (w, out_r, out_w) if not _closed(f)])
        return common.Session(r, out_w), w

    def test_request_and_cancel_in_one_chunk_or_split(self):
        request = protocol.encode({"type": "create", "operation": "op-1", "timeout_ms": 1000, "run": "r",
                                   "resource": "x", "image": "a" * 64, "retention": "disk",
                                   "user": "agentbox"}) + b"\n"
        cancel = protocol.encode({"type": "cancel", "operation": "op-1"}) + b"\n"
        for chunks in ([request + cancel], [request[:7], request[7:] + cancel[:5], cancel[5:]]):
            session, w = self.pipes()
            first = None
            for chunk in chunks:
                os.write(w, chunk)
                first = first or session.pump()
            self.assertEqual(first["operation"], "op-1")
            self.assertIsNone(session.refused)
            session.begin("op-1", 1000)
            with self.assertRaises(common.Interrupted) as caught:
                session.check()
            self.assertEqual(caught.exception.code, "cancelled")

    def test_stop_and_its_cancel_together(self):
        session, w = self.pipes()
        os.write(w, protocol.encode({"type": "capabilities", "operation": "op-1", "timeout_ms": 1000}) + b"\n")
        session.first()
        session.await_stop()
        stop = {"type": "stop", "operation": "op-2", "timeout_ms": 1000, "run": "r", "resource": "x",
                "execution": "e", "instance": "i", "generation": 0}
        os.write(w, protocol.encode(stop) + b"\n" + protocol.encode({"type": "cancel", "operation": "op-2"}) + b"\n")
        session.pump()
        self.assertEqual((len(session.stops), session.operation, session.cancelled, session.refused),
                         (1, "op-2", True, None))
        # A stop before `started`, or a second one, is out of turn.
        os.write(w, protocol.encode(dict(stop, operation="op-3")) + b"\n")
        session.pump()
        self.assertEqual(session.refused, "unexpected_frame")


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class CoalescedProvider(Case):
    def test_a_coalesced_request_and_cancel_are_answered_cancelled(self):
        image, _ = self.install_image()
        invocation = self.invoke()
        request = self.frame("create", run="run-1", resource="res-1", image=image, retention="disk", user="agentbox")
        invocation.proc.stdin.write(protocol.encode(request) + b"\n"
                                    + protocol.encode({"type": "cancel", "operation": request["operation"]}) + b"\n")
        invocation.proc.stdin.flush()
        self.assert_failed(invocation.read(), "cancelled")
        self.assertEqual(invocation.finish()[:2], (0, b""))
        self.assertFalse(os.path.exists(self.resource_dir()))

    def test_an_owner_stop_with_its_cancel_still_settles(self):
        image, _ = self.install_image()
        self.create(image)
        invocation, request, _ = self.started()
        stop = self.stop_frame(request)
        invocation.proc.stdin.write(protocol.encode(stop) + b"\n"
                                    + protocol.encode({"type": "cancel", "operation": stop["operation"]}) + b"\n")
        invocation.proc.stdin.flush()
        answer = invocation.read()
        self.assertEqual((answer["type"], answer["durability"], answer["storage"]), ("stopped", "uncertain", "unclean"))
        self.assertEqual(invocation.finish()[:2], (0, b""))


class InProcess(Case):
    """Cancellation inside a long copy, through the provider's own session."""

    def provider(self):
        r, w = os.pipe()
        out_r, out_w = os.pipe()
        session = common.Session(r, out_w)
        self.addCleanup(lambda: [os.close(f) for f in (w, out_r, out_w)])
        return qemu.Provider(self.state, TestHost(self.config), session), out_r

    @unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
    def test_a_cancelled_checkpoint_copy_leaves_nothing(self):
        image, _ = self.install_image()
        self.create(image)
        with open(os.path.join(self.resource_dir(), "disk.qcow2"), "r+b") as stream:
            stream.seek(4 << 20)
            stream.write(b"x")
        provider, out = self.provider()
        calls = [0]
        real = provider.session.check

        def check():
            calls[0] += 1
            if calls[0] > 2:
                raise common.Interrupted("cancelled")
            real()
        provider.session.check = check
        request = self.frame("checkpoint", run="run-1", resource="res-1", checkpoint="ck-1", generation=0,
                             accept_unclean=False)
        provider.handle(request)
        answer = protocol.decode_response(os.read(out, 65536).rstrip(b"\n"))
        self.assert_failed(answer, "cancelled")
        self.assertEqual(os.listdir(os.path.join(self.state, "checkpoints")), [])
        self.assertEqual(self.read_record()["generation"], 0)


@unittest.skipUnless(HAVE_KEYGEN, "no ssh-keygen")
class Prepare(Case):
    def setUp(self):
        super().setUp()
        repo = os.path.join(self.tmp, "repo")
        guest = os.path.join(test_worker.fake_guest(repo), "guest")
        write(os.path.join(guest, "home", "AGENTS.md"), "guidance\n")
        write(os.path.join(guest, "home", "CLAUDE.md"), "guidance\n")
        inputs = os.path.join(self.state, "inputs")
        os.mkdir(inputs, 0o700)
        files = {}
        for name, data in [("base.img", qcow2()), ("node-v24.18.0-linux-x64.tar.xz", b"node")]:
            write(os.path.join(inputs, name), data)
            files[name] = {"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        value = {"schema": stage.INPUTS_SCHEMA, "base": files["base.img"],
                 "node": dict(files["node-v24.18.0-linux-x64.tar.xz"], version="24.18.0")}
        write(os.path.join(inputs, "qemu-build-inputs.json"), json.dumps(value))
        self.inputs, self.value = inputs, value
        self.repo = repo
        self.config["root"] = repo
        self.save()
        self.addCleanup(setattr, stage, "load_inputs", stage.load_inputs)

    def prepare(self, recipe=qemu.CANONICAL_RECIPE):
        return self.call("prepare", timeout_ms=600000, recipe=recipe, worker=self.repo)

    def test_the_worker_sources_are_the_providers_own_tree(self):
        other = os.path.join(self.tmp, "other")
        test_worker.fake_guest(other)
        answer = self.call("prepare", timeout_ms=600000, recipe=qemu.CANONICAL_RECIPE, worker=other)
        self.assert_failed(answer, "prerequisite")
        self.assertEqual(self.packer_runs(), 0)
        self.assertEqual(self.prepare()["type"], "prepared")

    def packer_env(self):
        with open(os.path.join(self.config["records"], "packer-env")) as stream:
            return json.load(stream)

    def scratch_env(self, env):
        """Packer's scratch values, checked by shape: one operation's. Its
        TMPDIR is relative to its cwd, that operation's scratch, whatever
        STATE's length (plugin sockets stay within AF_UNIX's limit)."""
        work = os.path.realpath(os.path.join(self.state, "work"))
        tmp, cache = env.pop("TMPDIR"), env.pop("PACKER_CACHE_DIR")
        with open(os.path.join(self.config["records"], "packer-cwd")) as stream:
            cwd, tmp_is_dir = json.load(stream)
        self.assertEqual((tmp, tmp_is_dir), ("tmp", True))
        self.assertEqual(os.path.dirname(os.path.realpath(cwd)), work)
        self.assertEqual(os.path.dirname(cache), os.path.realpath(cwd))
        self.assertEqual(os.path.basename(cache), "cache")
        return env

    def test_packer_keeps_the_hosts_own_discovery(self):
        """No plugin directory of ours: Packer gets this invocation's host
        environment (no AGENTBOX_*, its PATH the usable host one), so its
        default ~/.config discovery or an explicit override is the host's;
        scratch temp and cache. Nothing of it on Packer's command line."""
        # A locale throughout: the stand-in packer's own interpreter would
        # otherwise add one (PEP 538 coercion).
        fixed = {"CHECKPOINT_DISABLE": "1", "PACKER_NO_COLOR": "1", "LANG": "C.UTF-8"}
        first = dict(fixed, PATH=self.config["path"])
        self.config["host_env"] = {"LANG": "C.UTF-8"}
        self.save()
        self.assertEqual(self.prepare()["type"], "prepared")
        self.assertEqual(self.scratch_env(self.packer_env()), first)
        tools = self.config["path"]
        host = {"LANG": "C.UTF-8", "PATH": f"{tools}:rel::/a b:/bin", "HOME": "/home/u", "XDG_CONFIG_HOME": "/home/u/.cfg",
                "PACKER_PLUGIN_PATH": "/opt/plugins", "https_proxy": "http://proxy.invalid:3128",
                "HOST_FAKE_SECRET": "synthetic-secret-51c2", "TMPDIR": "/host/tmp", "AGENTBOX_OTHER": "x"}
        self.config["host_env"] = host
        self.save()
        self.assertEqual(self.prepare()["type"], "prepared")
        self.assertEqual(self.scratch_env(self.packer_env()),
                         dict(fixed, PATH=f"{tools}:/bin", HOME="/home/u", XDG_CONFIG_HOME="/home/u/.cfg",
                              PACKER_PLUGIN_PATH="/opt/plugins", https_proxy="http://proxy.invalid:3128",
                              HOST_FAKE_SECRET="synthetic-secret-51c2"))
        with open(os.path.join(self.config["records"], "packer-argv")) as stream:
            argv = stream.read()
        for name in ("HOST_FAKE_SECRET", "https_proxy", "PACKER_PLUGIN_PATH", "XDG_CONFIG_HOME"):
            self.assertNotIn(host[name], argv)
        runs = self.packer_runs()
        for name, value in (("PACKER_PLUGIN_PATH", "plugins"), ("PACKER_PLUGIN_PATH", "/opt/a:rel"),
                            ("HOME", "home"), ("XDG_CONFIG_HOME", "./cfg"), ("PACKER_CONFIG_DIR", "pk")):
            self.config["host_env"] = {name: value}
            self.save()
            # Relative to the scratch cwd would be another place: refused
            # before any work.
            self.assert_failed(self.prepare(), "prerequisite")
            self.assertEqual(self.packer_runs(), runs, name)
        self.assertFalse(os.listdir(os.path.join(self.state, "work")))

    def packer_runs(self):
        path = self.config["packer_count"]
        if not os.path.exists(path):
            return 0
        with open(path) as stream:
            return len(stream.read())

    def test_prepare_needs_a_declared_state_before_any_work(self):
        """A prepare (its work dir and build store under STATE) refuses
        before making anything when STATE is not declared."""
        declare(self.tmp, self.config, [{"path": os.path.realpath(self.records), "measure": "tree"}])
        self.save()
        self.assert_failed(self.prepare(), "prerequisite")
        self.assertFalse(os.path.exists(os.path.join(self.state, "work")))
        self.assertFalse(os.path.exists(os.path.join(self.state, "images")))

    def test_every_prepare_builds_and_boots_its_disk_before_publishing(self):
        answer = self.prepare()
        self.assertEqual(answer["type"], "prepared", answer)
        image = answer["image"]
        entry = os.path.join(self.state, "images", image)
        self.assertEqual(stat.S_IMODE(os.stat(entry).st_mode), 0o500)
        for name in ("disk.qcow2", "image.json", "worker-metadata.json", "record.json"):
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(entry, name)).st_mode), 0o400, name)
        self.assertEqual(hashlib.sha256(slurp(os.path.join(entry, "disk.qcow2"))).hexdigest(), image)
        self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
        self.assertFalse(os.path.exists(os.path.join(self.state, "image-keys")))
        published = json.loads(slurp(os.path.join(entry, "image.json")))
        self.assertEqual(published["status"], "built_native_checked")
        self.assertEqual(published["system"], test_worker.system_manifest())
        # The agents the build resolved: answered by version, their locks
        # checked by the boot.
        self.assertEqual(answer["agents"], {"pi": "1.0.0", "codex": "1.0.0", "claude": "1.0.0"})
        self.assertEqual(published["checked"]["agents"], "locks")
        self.assertEqual(published["checked"]["kernel"], {"build": "7.0.0-43-generic", "intended": "7.0.0-44-generic",
                                                          "running": "7.0.0-44-generic", "upgraded": True})
        self.assertEqual(published["checked"]["worker"], answer["worker_sha256"])
        self.assertNotIn("key", json.loads(slurp(os.path.join(entry, "record.json")))["origin"])
        # The check boot: the runtime's launch and seed (restricted NIC, one
        # SSH forward, a fresh guest host key), the disk behind a fresh
        # overlay, its own custody child gone, QEMU stopped by the guest.
        [boot] = self.qemu_records()
        netdev = boot["argv"][boot["argv"].index("-netdev") + 1]
        self.assertTrue(netdev.startswith("user,id=net0,restrict=on,ipv4=on,ipv6=off,hostfwd=tcp:127.0.0.1:"))
        self.assertTrue(boot["joined"])
        self.assertEqual(boot["limits"]["memory.max"], str((qemu.DEFAULT_MEMORY_MIB + qemu.MEMORY_OVERHEAD_MIB) << 20))
        self.assertFalse([n for n in os.listdir(self.domain) if n.startswith("check-")])
        user = boot["seed"]["user-data"]
        [argv] = self.ssh_calls()
        self.assertEqual(argv[:7], ["-F", "/dev/null", "-T", "-p", str(boot["port"]), "-l", "agentbox"])
        options = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
        for needed in ("StrictHostKeyChecking=yes", "IdentityAgent=none", "ForwardAgent=no", "IdentitiesOnly=yes",
                       "ClearAllForwardings=yes", "HostKeyAlias=" + qemu.CHECK_ALIAS):
            self.assertIn(needed, options)
        self.assertEqual(argv[-2], "127.0.0.1")
        for needed in ("check manifest.json ", "[ \"$k\" = 7.0.0-44-generic ] || fail kernel",
                       "protocol.file.allow=always clone", "python3 -m venv"):
            self.assertIn(needed, argv[-1])
        for agent in ("pi", "codex", "claude"):
            lock = f"/opt/agentbox-agents/{agent}/package-lock.json"
            for needed in (f"sealed {lock}", f"{'a' * 64} {lock} | sha256sum -c --status - || fail agents",
                           f"[ -x /usr/local/bin/{agent} ] || fail agents"):
                self.assertIn(needed, argv[-1])
        self.assertIn(qemu.AUTHORIZED_KEYS, user)
        # The next prepare builds again (a fresh base and packages): the
        # same bytes here, so the same entry, verified.
        again = self.prepare()
        self.assertEqual((again["image"], again["worker_sha256"]), (image, answer["worker_sha256"]))
        self.assertEqual((self.packer_runs(), len(self.ssh_calls())), (2, 2))
        # A tampered entry no record uses is moved aside, the rebuild
        # published in its place.
        self.tamper(entry)
        before = os.stat(entry).st_ino
        self.assertEqual(self.prepare()["image"], image)
        self.assertNotEqual(os.stat(entry).st_ino, before)
        self.assertEqual(hashlib.sha256(slurp(os.path.join(entry, "disk.qcow2"))).hexdigest(), image)
        self.assertEqual((self.images(), self.work()), ([image], []))

    def ssh_calls(self):
        return [json.loads(slurp(os.path.join(self.records, n))) for n in sorted(os.listdir(self.records))
                if n.startswith("ssh-")]

    def test_a_failed_check_boot_publishes_nothing(self):
        """The kernel, the worker or anything else the check finds wrong; a
        guest that does not power itself off; a missing system record: no
        image, the scratch and the boot's child gone, QEMU stopped."""
        for name, change in (("kernel", {"ssh_fail": "kernel"}), ("worker", {"ssh_fail": "digest"}),
                             ("other kernel", {"ssh_kernel": "7.0.0-43-generic"}),
                             ("no power-off", {"qemu": {"ignore_powerdown": True}, "check_powerdown": 0.5}),
                             ("no record", {"no_manifest": True})):
            with self.subTest(name):
                self.config.update(change)
                self.save()
                answer, err = self.prepare_err()
                self.assert_failed(answer, "failed")
                if "ssh_fail" in change:
                    self.assertIn(f"agentbox-provider: check boot failed: {change['ssh_fail']}".encode(), err)
                self.assertEqual((self.images(), self.work()), ([], []))
                self.assertFalse([n for n in os.listdir(self.domain) if n.startswith("check-")])
                self.assertFalse([pid for pid in self.qemu_pids() if _alive(pid)])
                for key in change:
                    self.config.pop(key)
                self.config["qemu"] = {}
                self.save()
        self.assertEqual(self.prepare()["type"], "prepared")

    def tamper(self, entry, foreign=False):
        os.chmod(entry, 0o700)
        os.chmod(os.path.join(entry, "disk.qcow2"), 0o600)
        with open(os.path.join(entry, "disk.qcow2"), "r+b") as stream:
            stream.seek(3 * CLUSTER)
            stream.write(b"x")
        if foreign:
            write(os.path.join(entry, "foreign"), "x")
        os.chmod(entry, 0o500)

    def set_base(self, data, link=False):
        path = os.path.join(self.inputs, "base.img")
        os.unlink(path)
        if link:
            target = os.path.join(self.tmp, "elsewhere.img")
            write(target, data)
            os.symlink(target, path)
        else:
            write(path, data)
        value = json.loads(json.dumps(self.value))
        value["base"].update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        write(os.path.join(self.inputs, "qemu-build-inputs.json"), json.dumps(value))

    def test_an_unsafe_base_never_reaches_packer_or_an_image_tool(self):
        cases = [("malformed", b"base", False), ("backed", qcow2(backing="/host/other.qcow2"), False),
                 ("external data", qcow2(incompatible=qemu.INCOMPAT_DATA_FILE), False),
                 ("data file name", qcow2(extensions=[(qemu.EXT_DATA_FILE, b"/etc/shadow")]), False),
                 ("encrypted", qcow2(crypt=1), False), ("linked", qcow2(), True)]
        for name, data, link in cases:
            with self.subTest(name):
                self.set_base(data, link)
                self.assert_failed(self.prepare(), "prerequisite")
                self.assertEqual(self.packer_runs(), 0)
                self.assertEqual(os.listdir(self.records), [])
                self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
                self.assertFalse([n for n in os.listdir(self.domain) if n.startswith("tool-")])
        # A digest that differs from the declared input is refused as well.
        self.set_base(qcow2())
        write(os.path.join(self.inputs, "base.img"), qcow2(size=VSIZE * 2))
        self.assert_failed(self.prepare(), "prerequisite")
        self.assertEqual(self.packer_runs(), 0)

    def prepare_err(self, recipe=qemu.CANONICAL_RECIPE):
        invocation = self.invoke()
        invocation.send(self.frame("prepare", timeout_ms=600000, recipe=recipe, worker=self.repo))
        answer = invocation.read()
        code, rest, err = invocation.finish()
        self.assertEqual((code, rest), (0, b""))
        return answer, err

    def work(self):
        return sorted(os.listdir(os.path.join(self.state, "work")))

    def images(self):
        return sorted(os.listdir(os.path.join(self.state, "images")))

    def test_scratch_stays_while_a_refused_tool_is_unconfirmed(self):
        self.config.update(deny_pidfd=1, immune=True, kill_reserve=0.3, qemu_img_hang="check")
        self.save()
        self.assert_failed(self.prepare(), "failed", "unsettled", "unchanged")
        [kept] = self.work()
        self.assertTrue(os.path.isdir(os.path.join(self.state, "work", kept, "stage")))
        self.assertEqual(self.packer_runs(), 0)
        for pid in self.hung():
            os.kill(pid, signal.SIGKILL)
        time.sleep(0.1)
        shutil.rmtree(os.path.join(self.state, "work", kept))
        # The stuck writer really wrote its target (the base): restore it.
        self.set_base(qcow2())
        # Settled refusal: the scratch goes.
        self.config.update(immune=False, qemu_img_hang=None)
        self.save()
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual(self.work(), [])

    def test_a_failed_publication_rolls_back_its_own_staging_only(self):
        self.config["fail_methods"] = {"write_entry": "enospc"}
        self.save()
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual((self.images(), self.work()), ([], []))
        # A staging entry no longer only ours (a foreign name in it) is
        # left with a warning; the answer stays settled (nothing writes it).
        self.config["fail_methods"] = {}
        self.config["foreign_staging"] = True
        self.save()
        answer, err = self.prepare_err()
        self.assert_failed(answer, "failed")
        self.assertIn(b"warning: cache staging residue left", err)
        staging = os.path.join(self.state, "images", ".staging-op-2")
        self.assertEqual(sorted(os.listdir(staging)), ["disk.qcow2", "foreign"])
        self.assertEqual(self.work(), [])

    def test_scratch_residue_is_a_warning_and_bounded(self):
        self.config["lock_scratch"] = True
        self.save()
        answer, err = self.prepare_err()
        self.assertEqual(answer["type"], "prepared", answer)
        self.assertIn(b"warning: prepare scratch residue left", err)
        self.assertEqual(self.work(), ["op-1"])
        self.assertTrue(os.path.isdir(os.path.join(self.state, "work", "op-1", "locked")))
        # Residue is bounded by admission, never a quota or a block on
        # anything else: too much of it, or too little space, refuses.
        self.config.update(lock_scratch=False)
        self.save()
        for n in range(qemu.WORK_RESIDUE):
            os.mkdir(os.path.join(self.state, "work", f"left-{n}"))
        answer, err = self.prepare_err()
        self.assert_failed(answer, "prerequisite")
        self.assertIn(b"warning: capacity admission refused", err)
        for n in range(qemu.WORK_RESIDUE):
            os.rmdir(os.path.join(self.state, "work", f"left-{n}"))
        self.config["min_free"] = 1 << 62
        self.save()
        self.assert_failed(self.prepare(), "prerequisite")
        self.config["min_free"] = 0
        self.save()
        # A hit answers despite leftover scratch elsewhere.
        self.assertEqual(self.prepare()["type"], "prepared")

    def test_malformed_records_keep_an_invalid_entry(self):
        image = self.prepare()["image"]
        entry = os.path.join(self.state, "images", image)
        self.tamper(entry)
        inode = os.stat(entry).st_ino
        malformed = ({}, {"state": "ready"}, {"image": None, "state": "ready"},
                     {"image": "x" * 64, "state": "ready"}, {"image": 7, "state": "copying"})
        for kind, record in (("resources", "resource.json"), ("checkpoints", "checkpoint.json")):
            for n, value in enumerate(malformed):
                with self.subTest(kind=kind, value=value):
                    write_record(self.state, kind, record, value)
                    answer, err = self.prepare_err()
                    self.assert_failed(answer, "failed")
                    self.assertIn(b"warning: cache entry invalid: left untouched", err)
                    self.assertEqual(os.stat(entry).st_ino, inode)
                    self.assertEqual(self.images(), [image])
            # Another valid image, or a discarded record, is no use of it.
            write_record(self.state, kind, record, {"image": "0" * 64, "state": "ready"})
        write_record(self.state, "resources", "resource.json", {"state": "discarded"})
        self.assertEqual(self.prepare()["image"], image)
        self.assertNotEqual(os.stat(entry).st_ino, inode)
        self.assertEqual(self.images(), [image])

    def test_cache_leftovers_are_bounded_before_a_build(self):
        images = os.path.join(self.state, "images")
        os.makedirs(images, 0o700, exist_ok=True)
        for n in range(common.CACHE_RESIDUE + 1):
            os.mkdir(os.path.join(images, (".staging-left-", ".quarantine-left-")[n % 2] + str(n)))
        answer, err = self.prepare_err()
        self.assert_failed(answer, "prerequisite")
        self.assertIn(b"warning: capacity admission refused", err)
        self.assertEqual((self.packer_runs(), self.work()), (0, []))
        os.rmdir(os.path.join(images, ".quarantine-left-1"))
        self.assertEqual(self.prepare()["type"], "prepared")

    def test_a_moved_or_replaced_scratch_dir_is_never_deleted(self):
        for n, mode in enumerate(("rename", "replace"), start=1):
            self.config["move_work"] = mode
            self.config["lock_scratch"] = False
            self.save()
            answer, err = self.prepare_err()
            self.assertEqual(answer["type"], "prepared", answer)
            moved = os.path.join(self.state, "work", f"op-{n}-moved")
            self.assertTrue(os.path.isdir(os.path.join(moved, "stage")), mode)
            self.assertIn(b"warning: prepare scratch residue left", err)
            if mode == "replace":
                self.assertEqual(os.listdir(os.path.join(self.state, "work", f"op-{n}")), [])

    def test_an_in_use_base_is_never_replaced(self):
        first = self.prepare()
        image = first["image"]
        self.create(image, retention="disk")
        entry = os.path.join(self.state, "images", image)
        os.chmod(entry, 0o700)
        record = os.path.join(entry, "record.json")
        os.chmod(record, 0o600)
        value = json.loads(slurp(record))
        value["worker"] = "0" * 64
        write(record, json.dumps(value), 0o400)
        before = {n: slurp(os.path.join(entry, n)) for n in os.listdir(entry)}
        os.chmod(entry, 0o500)
        # The same content rebuilt cannot be published over it.
        answer, err = self.prepare_err()
        self.assert_failed(answer, "failed")
        self.assertIn(b"warning: cache entry invalid: left untouched", err)
        self.assertEqual({n: slurp(os.path.join(entry, n)) for n in os.listdir(entry)}, before)
        # Nor over an empty directory in its place: the name keeps its
        # inode (a no-replace rename), and the run's start fails clearly.
        os.chmod(entry, 0o700)
        shutil.rmtree(entry)
        os.mkdir(entry, 0o500)
        inode = os.stat(entry).st_ino
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual((os.stat(entry).st_ino, os.listdir(entry)), (inode, []))
        invocation, _ = self.start()
        self.assert_failed(invocation.read(), "failed")
        invocation.finish()
        # A discarded resource no longer uses it, a checkpoint record does.
        self.assertEqual(self.call("discard", run="run-1", resource="res-1")["type"], "discarded")
        cdir = os.path.join(self.state, "checkpoints", "cp-1")
        os.makedirs(cdir, 0o700)
        os.chmod(os.path.dirname(cdir), 0o700)
        write(os.path.join(cdir, "checkpoint.json"), json.dumps({"image": image, "state": "ready"}))
        self.assert_failed(self.prepare(), "failed")
        self.assertEqual(os.stat(entry).st_ino, inode)
        write(os.path.join(cdir, "checkpoint.json"), json.dumps({"image": image, "state": "discarded"}))
        self.assertEqual(self.prepare()["image"], image)
        self.assertEqual(self.images(), [image])
        self.assertNotEqual(os.stat(entry).st_ino, inode)

    def test_custom_recipes_always_build_and_failures_clean_up(self):
        # Canonical: exactly the default preset's path, never its bytes
        # elsewhere.
        self.assertEqual(qemu.CANONICAL_RECIPE,
                         os.path.join(qemu.ROOT, "images", "qemu", "default", "agentbox.pkr.hcl"))
        custom = os.path.join(self.tmp, "custom.pkr.hcl")
        write(custom, slurp(qemu.CANONICAL_RECIPE))
        first = self.prepare(custom)
        second = self.prepare(custom)
        self.assertEqual((first["type"], second["type"]), ("prepared", "prepared"))
        self.assertEqual(self.packer_runs(), 2)
        # The same disk again: the existing entry verified, ours removed.
        self.assertEqual(os.listdir(os.path.join(self.state, "images")), [first["image"]])
        self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
        # No check boot for an operator's recipe: its image as built, no
        # agents answered.
        self.assertEqual((self.ssh_calls(), self.qemu_records()), ([], []))
        self.assertNotIn("agents", first)
        self.assertNotIn("checked", json.loads(slurp(os.path.join(self.state, "images", first["image"],
                                                                  "image.json"))))
        self.config["packer_fail"] = True
        self.save()
        answer, err = self.prepare_err()
        self.assert_failed(answer, "failed")
        # A fixed, bounded line: the exit status, never Packer's log.
        self.assertIn(b"agentbox-provider: packer build failed: exit 1\n", err)
        self.assertEqual(os.listdir(os.path.join(self.state, "work")), [])
        os.symlink(custom, custom + ".link")
        self.assert_failed(self.prepare(custom + ".link"), "prerequisite")
        for entry in os.listdir(os.path.join(self.state, "images")):
            os.chmod(os.path.join(self.state, "images", entry), 0o700)


class Production(unittest.TestCase):
    def test_production_needs_a_custody_domain(self):
        host = qemu.Host(environ={})
        with self.assertRaises(common.Failure) as caught:
            host.custody()
        self.assertEqual(caught.exception.code, "prerequisite")

    def test_the_provider_writes_no_bytecode_and_reads_no_cwd_code(self):
        source = slurp(os.path.join(HERE, "qemu.py"), "r")
        self.assertIn("sys.dont_write_bytecode = True", source)
        self.assertNotIn("os.getcwd", source)
        # Tools are found only through common.trusted_executable's host PATH
        # lookup; this module never reads PATH itself.
        for read in ('environ["PATH"]', 'environ.get("PATH"', 'getenv("PATH"'):
            self.assertNotIn(read, source)


if __name__ == "__main__":
    unittest.main()
