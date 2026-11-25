"""One private test world: a provider asset copy and STATE, a data root,
the controller configuration, a stand-in `ssh`, the real `ssh-keygen` and
`agentbox-server`, a built worker payload and a prepared run.

```text
TMP/ (0700, under the caller's TMPDIR)
  assets/ entry.py protocol.py     0755/0644, the stand-in provider
  state/  behavior.json log.jsonl  the provider's STATE
  data/   run-limits.json ...      the controller's data root
  bin/    ssh scp sftp ssh.json     the ssh and transfer stand-ins, their logs
  handlers/acquisitions/            lib, echo, memo, git, fake (the handler asset tree)
  remote/                           an attached target's remote root
  guest/  home/ control/           the stand-in guest's paths
  cgroup/                          FakeCgroups
  payload/worker                   the built bundle (once per process)
```
"""
import atexit
import json
import os
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

from tests.support import REPO, SRC, relay, server  # noqa: E402,F401
from agentbox_controller import store as store_mod  # noqa: E402
from agentbox_controller.assets import worker_layout  # noqa: E402
from tests.controller import fakes  # noqa: E402

_PAYLOAD = {}
_FROZEN = {}


def payload():
    """The worker bundle built from this checkout, once per process, in a
    private directory removed at exit."""
    if "path" not in _PAYLOAD:
        directory = tempfile.mkdtemp(prefix="abp-")
        atexit.register(shutil.rmtree, directory, True)
        sources = os.path.join(directory, "payload-sources")
        out = os.path.join(directory, "payload")
        counterparts = os.path.join(directory, "counterparts")
        os.mkdir(counterparts, 0o755)
        shutil.copyfile(f"{REPO}/acquisitions/testing/memo/jail/memo.py", f"{counterparts}/memo.py")
        worker_layout.stage_sources(REPO, sources)
        metadata = worker_layout.build(sources, out, counterparts)
        _PAYLOAD.update(path=os.path.join(out, "worker"), manifest=metadata["manifest"],
                        release=metadata["release"], metadata=os.path.join(out, "worker-metadata.json"))
    return _PAYLOAD


def frozen_payload(fixture):
    """A worker bundle built by this checkout's builder from a frozen
    earlier release's sources (`fixture`: a tar.gz of their tree and
    counterparts/), once per fixture and process; never regenerated from
    this checkout. Its `revision` is the frozen sources'."""
    if fixture not in _FROZEN:
        directory = tempfile.mkdtemp(prefix="abf-")
        atexit.register(shutil.rmtree, directory, True)
        unpacked = os.path.join(directory, "frozen")
        with tarfile.open(fixture) as tar:
            tar.extractall(unpacked, filter="data")
        sources = os.path.join(directory, "payload-sources")
        out = os.path.join(directory, "payload")
        worker_layout.stage_sources(unpacked, sources)
        metadata = worker_layout.build(sources, out, os.path.join(unpacked, "counterparts"))
        _FROZEN[fixture] = dict(path=os.path.join(out, "worker"), manifest=metadata["manifest"],
                                release=metadata["release"], revision=metadata["sources"]["revision"],
                                metadata=os.path.join(out, "worker-metadata.json"))
    return _FROZEN[fixture]


def write_file(path, data, mode=0o600):
    with open(path, "w") as stream:
        stream.write(data if isinstance(data, str) else json.dumps(data))
    os.chmod(path, mode)


def _dir(path, mode=0o700):
    os.makedirs(path, exist_ok=True)
    os.chmod(path, mode)
    return path


def tool(name):
    for directory in os.environ.get("PATH", "").split(":"):
        path = os.path.join(directory, name)
        if directory and os.access(path, os.X_OK):
            return os.path.realpath(path)
    raise RuntimeError(f"{name} missing")


def copy_tree(source, target):
    """A trusted copy: directories 0755, files 0644, no bytecode."""
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
    for directory, names, files in os.walk(target):
        os.chmod(directory, 0o755)
        for name in files:
            os.chmod(os.path.join(directory, name), 0o644)


class World:
    def __init__(self, behavior=None, ssh=None, limits=None, transport="tcp", log_bytes=store_mod.DEFAULT_LOG_BYTES,
                 retention="none", kind="managed", create=(), built=None):
        """`built`: the worker bundle (payload(), else frozen_payload())."""
        server()
        self.tmp = tempfile.mkdtemp(prefix="abc-")
        os.chmod(self.tmp, 0o700)
        built = built or payload()
        self.release = built["release"]
        self.assets = _dir(f"{self.tmp}/assets", 0o755)
        shutil.copyfile(f"{HERE}/provider_standin.py", f"{self.assets}/entry.py")
        shutil.copyfile(f"{REPO}/providers/protocol.py", f"{self.assets}/protocol.py")
        for name in ("entry.py", "protocol.py"):
            os.chmod(f"{self.assets}/{name}", 0o644)
        self.state = _dir(f"{self.tmp}/state")
        self.data = _dir(f"{self.tmp}/data")
        self.bin = _dir(f"{self.tmp}/bin", 0o755)
        self.home = _dir(f"{self.tmp}/guest/home")
        self.control = _dir(f"{self.tmp}/guest/control")
        os.chmod(f"{self.tmp}/guest", 0o700)
        self.cgroup = _dir(f"{self.tmp}/cgroup")
        # The shared fake tree, before any concurrent controller.
        fakes.FakeCgroups(self.cgroup)
        self.host_key = self._host_key()
        self.behavior = {"transport": transport, "user": "agentbox", "home": self.home,
                         "control": self.control, "host_key": self.host_key,
                         "worker_sha256": self.release, "start": "ok", "stop": "settled",
                         "metadata": built["metadata"], "retention": ["none", "home", "home_tmp", "disk"]}
        self.behavior.update(behavior or {})
        self.set_behavior()
        self.ssh_log = f"{self.bin}/ssh.log"
        self.ssh_conf = {"log": self.ssh_log, "payload": built["path"],
                         "install_root": worker_layout.INSTALL_ROOT}
        self.ssh_conf.update(ssh or {})
        with open(f"{HERE}/ssh_standin.py") as stream:
            text = f"#!{sys.executable} -I\n" + stream.read()
        write_file(f"{self.bin}/ssh", text, 0o755)
        with open(f"{HERE}/transfer_standin.py") as stream:
            text = f"#!{sys.executable} -I\n" + stream.read()
        for name in ("scp", "sftp"):
            write_file(f"{self.bin}/{name}", text, 0o755)
        self.ssh_conf["harness"] = HERE
        self.set_ssh()
        self.handlers = _dir(f"{self.tmp}/handlers", 0o755)
        copy_tree(f"{REPO}/acquisitions/lib", f"{self.handlers}/acquisitions/lib")
        for name in ("echo", "memo"):
            copy_tree(f"{REPO}/acquisitions/testing/{name}", f"{self.handlers}/acquisitions/{name}")
        copy_tree(f"{REPO}/acquisitions/git", f"{self.handlers}/acquisitions/git")
        copy_tree(f"{HERE}/handlers/fake", f"{self.handlers}/acquisitions/fake")
        os.chmod(f"{self.handlers}/acquisitions", 0o755)
        # A fresh v3 store first: its marker before any controller entry.
        store_mod.Store(self.data).close()
        self.spool = _dir(f"{self.data}/controller-spool")
        write_file(f"{self.data}/run-limits.json",
                   {"max_reserved_bytes": 1 << 40, "storage_scopes": [{"path": self.state, "measure": "tree"},
                                                                    {"path": self.spool, "measure": "tree"}]})
        # The input worker's trusted copy (the checkout's directories are
        # group-writable), named by the default host configuration.
        copy_tree(f"{REPO}/inputs", f"{self.tmp}/host-assets/inputs")
        os.chmod(f"{self.tmp}/host-assets", 0o755)
        self.xdg_config = _dir(f"{self.tmp}/xdg-config")
        _dir(f"{self.xdg_config}/agentbox")
        write_file(f"{self.xdg_config}/agentbox/host.json",
                   {"schema": "agentbox.host-config.v1", "interpreter": sys.executable,
                    "assets": f"{self.tmp}/host-assets"})
        # No lane unless a test asks for one: never the packaged defaults
        # (the real registries' policies, the host's git).
        self.acquisition_default = f"{self.xdg_config}/agentbox/acquisition.json"
        write_file(self.acquisition_default, {"schema": "agentbox.acquisition-config.v2", "handlers": {}})
        self.config =f"{self.tmp}/controller.json"
        write_file(self.config, {"schema": "agentbox.controller-config.v1", "data": self.data, "server": server()})
        self.provider = {"schema": "agentbox.provider-config.v1", "provider": "standin",
                         "interpreter": sys.executable, "entry": f"{self.assets}/entry.py",
                         "state": self.state, "assets": self.assets}
        self.provider_file = f"{self.tmp}/provider.json"
        write_file(self.provider_file, self.provider)
        self.tools = {"ssh": f"{self.bin}/ssh", "scp": f"{self.bin}/scp", "sftp": f"{self.bin}/sftp",
                      "ssh-keygen": tool("ssh-keygen")}
        self.kind = kind
        if kind == "attached":
            self.remote = _dir(f"{self.tmp}/remote")
            self.identity = f"{self.tmp}/identity"
            write_file(self.identity, "not a key\n")
            self.bundle = f"{self.tmp}/bundle"
            shutil.copytree(built["path"], self.bundle)
            with open(f"{self.bundle}/manifest.json") as stream:
                revision = json.load(stream)["revision"]
            self.target = {"schema": "agentbox.ssh-target.v3", "host": "127.0.0.1", "port": 2222,
                           "user": "agentbox", "identity": self.identity, "host_key": self.host_key,
                           "remote_root": self.remote, "bundle": self.bundle, "revision": revision}
            self.target_file = f"{self.tmp}/target.json"
            write_file(self.target_file, self.target)
            code, out, err = self.run(("jail", "create"), ["--ssh-target", self.target_file], command_args=False)
            if code != 0:
                raise RuntimeError(err)
            self.run_id = out.split()[1]
            self.home = f"{self.remote}/agentbox-worker-v1/home"
            self._agents()
            return
        self.image_id = self.prepare()
        # The tag `jail create` and `run AGENT` name.
        self.image = "default"
        limits = limits if limits is not None else {"cpus": 1, "memory_mib": 512}
        args = ["--retention", retention] + [w for k, v in limits.items()
                                             for w in (f"--{k.replace('_', '-')}", str(v))] + list(create)
        self.run_id = self.create(args)
        if log_bytes != store_mod.DEFAULT_LOG_BYTES:
            self.edit_record(log_bytes=log_bytes)
        # The provider's log starts with the run's first execution.
        os.unlink(f"{self.state}/log.jsonl")
        self._agents()

    def _agents(self):
        """`run AGENT`'s test world: the agents' trusted assets beside the
        input worker's (the runner's /dev/shm replaced by a scratch root,
        its `npm` by the stand-in npm_standin.py), the npm handler with a
        network-free worker, stand-in agents in the guest's ~/.local/bin."""
        assets = f"{self.tmp}/host-assets"
        self.shm = _dir(f"{self.tmp}/shm")
        copy_tree(f"{REPO}/agents", f"{assets}/agents")
        with open(f"{HERE}/agents/npm_standin.py") as stream:
            write_file(f"{self.tmp}/npm-standin", f"#!{sys.executable} -I\n" + stream.read(), 0o755)
        runner = f"{assets}/agents/jail/run.py"
        with open(runner) as stream:
            text = stream.read()
        assert text.count('SHM = "/dev/shm"') == 1 and text.count('found = locate("npm")') == 1
        text = text.replace('SHM = "/dev/shm"', f"SHM = {self.shm!r}")
        text = text.replace('found = locate("npm")', f"found = {self.tmp + '/npm-standin'!r}")
        write_file(runner, text, 0o644)
        with open(f"{HERE}/agents/standin_agent.py") as stream:
            agent = f"#!{sys.executable} -I\n" + stream.read()
        copy_tree(f"{REPO}/acquisitions/lib", f"{assets}/acquisitions/lib")
        handler = f"{assets}/acquisitions/npm"
        _dir(f"{handler}/host", 0o755)
        shutil.copyfile(f"{REPO}/acquisitions/npm/manifest.json", f"{handler}/manifest.json")
        shutil.copyfile(f"{HERE}/agents/npm_worker.py", f"{handler}/host/worker.py")
        for name in ("manifest.json", "host/worker.py"):
            os.chmod(f"{handler}/{name}", 0o644)
        for directory in (f"{assets}/acquisitions", handler):
            os.chmod(directory, 0o755)
        # Every directory made private, one by one (an attached HOME's
        # parents too: the bootstrap refuses group-writable ones).
        for path in (os.path.dirname(self.home), self.home):
            if not os.path.isdir(path):
                _dir(path)
        local = self.home
        for part in (".local", "bin"):
            local = _dir(f"{local}/{part}")
        for name in ("pi", "codex", "claude"):
            write_file(f"{local}/{name}", agent, 0o755)
        self.agent_bin = local

    def agent_log(self):
        return _lines(f"{self.home}/agent-log.jsonl")

    def prepare(self, tag="default", recipe="recipe.json"):
        """`image prepare -t TAG standin --provider-config FILE --recipe
        STATE/inputs/RECIPE` (the stand-in's image: SHA-256 of the recipe
        path); the image id."""
        os.makedirs(f"{self.state}/inputs", exist_ok=True)
        write_file(f"{self.state}/inputs/{recipe}", "{}")
        code, out, err = self.run(("image", "prepare"), ["-t", tag, "standin", "--provider-config", self.provider_file,
                                                         "--recipe", f"{self.state}/inputs/{recipe}"],
                                  command_args=False)
        if code != 0:
            raise RuntimeError(err)
        return out.split()[3][len("id="):]

    def create(self, args, image=None):
        code, out, err = self.run(("jail", "create"), ["--image", image or self.image] + list(args),
                                  command_args=False)
        if code != 0:
            raise RuntimeError(err)
        return out.split()[1]

    def edit_record(self, run_id=None, **changes):
        """A test's direct change of a run record (under its lease)."""
        store = store_mod.Store(self.data)
        try:
            lease = store.claim(run_id or self.run_id)
            try:
                lease.save(dict(lease.record, **changes))
            finally:
                lease.release()
        finally:
            store.close()

    def acquisition(self, handlers=None, name="acquisition.json"):
        """An acquisition configuration enabling `handlers` ({id: operations
        or None}); each one's policy written beside it."""
        handlers = handlers if handlers is not None else {"echo": None, "fake": None}
        policies = {"echo": {"schema": "agentbox.echo.policy.v1", "prefix": "p:", "code": "echo_refused"},
                    "memo": {"schema": "agentbox.memo.policy.v1", "header": "memo", "names": ["n1"]},
                    "git": {"schema": "agentbox.git.request-policy.v1", "grant": "github-public-read-v1"},
                    "fake": {}}
        entries = {}
        for ident, operations in handlers.items():
            policy = f"{self.tmp}/policy-{ident}.json"
            write_file(policy, policies.get(ident, {}))
            entries[ident] = {"policy": policy}
            if operations is not None:
                entries[ident]["operations"] = operations
        path = f"{self.tmp}/{name}"
        write_file(path, {"schema": "agentbox.acquisition-config.v2", "interpreter": sys.executable,
                          "assets": self.handlers, "handlers": entries})
        return path

    def transfers(self):
        return _lines(f"{self.bin}/transfer.log")

    def _host_key(self):
        path = f"{self.tmp}/hostkey"
        subprocess.run([tool("ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", path],
                       check=True, stdin=subprocess.DEVNULL)
        with open(path + ".pub") as stream:
            return " ".join(stream.read().split()[:2])

    def set_behavior(self, **changes):
        self.behavior.update(changes)
        write_file(f"{self.state}/behavior.json", self.behavior)

    def set_ssh(self, **changes):
        self.ssh_conf.update(changes)
        write_file(f"{self.bin}/ssh.json", self.ssh_conf)

    # -- running -------------------------------------------------------

    def spec(self, faults=None, overrides=None):
        path = f"{self.tmp}/spec-{os.urandom(4).hex()}.json"
        faults = dict({"cwd_scope": f"{self.tmp}/guest"}, **(faults or {}))
        write_file(path, {"dir": self.cgroup, "tools": self.tools, "faults": faults,
                      "overrides": overrides or {}})
        return path

    # B2's flat names, as the nested commands they became.
    LEGACY = {"exec": ("jail", "exec"), "status": ("jail", "status"), "inputs": ("jail", "inputs"),
              "recover": ("jail", "stop"), "stop": ("jail", "stop"), "discard": ("jail", "discard"),
              "attach": ("jail", "create")}

    def argv(self, command, extra=(), faults=None, overrides=None, command_args=True, run_id=None):
        command = self.LEGACY.get(command, command)
        args = [sys.executable, "-I", "-B", f"{HERE}/launch.py", self.spec(faults, overrides), *command,
                "--config", self.config]
        if command_args:
            args.append(run_id or self.run_id)
        return args + list(extra)

    def env(self, extra=None):
        env = {"PATH": self.bin + ":" + os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/"),
               "LC_ALL": "C", "XDG_CONFIG_HOME": self.xdg_config}
        env.update(extra or {})
        return env

    def start(self, command, extra=(), faults=None, overrides=None, env=None, stdin=subprocess.DEVNULL,
              command_args=True, run_id=None):
        return subprocess.Popen(self.argv(command, extra, faults, overrides, command_args, run_id), env=self.env(env),
                                stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def run(self, command, extra=(), faults=None, overrides=None, env=None, input=None, timeout=60,
            command_args=True, cwd=None, run_id=None):
        done = subprocess.run(self.argv(command, extra, faults, overrides, command_args, run_id), env=self.env(env),
                              cwd=cwd,
                              input=input, stdin=None if input is not None else subprocess.DEVNULL,
                              capture_output=True, timeout=timeout)
        return done.returncode, done.stdout.decode(), done.stderr.decode()

    def exec(self, argv, extra=(), **kwargs):
        return self.run("exec", list(extra) + ["--"] + list(argv), **kwargs)

    # -- inspection ----------------------------------------------------

    def record(self, run_id=None):
        with open(f"{self.data}/controller-runs/{run_id or self.run_id}/run.json") as stream:
            return json.load(stream)

    def provider_log(self):
        return _lines(f"{self.state}/log.jsonl")

    def ssh_entries(self):
        return _lines(self.ssh_log)

    def events(self):
        logs = f"{self.data}/controller-logs/{self.run_id}"
        out = []
        for execution in sorted(os.listdir(logs)) if os.path.isdir(logs) else []:
            out += _lines(f"{logs}/{execution}/events.jsonl")
        return out

    def domains(self):
        """Every agentbox-<hex> directory left under the fake tree."""
        found = []
        for directory, names, _ in os.walk(f"{self.cgroup}/cg"):
            found += [os.path.join(directory, n) for n in names
                      if n.startswith("agentbox-") and not n.startswith("agentbox-launch-")]
        return found

    def listed_pids(self):
        """Every process the fake counts in a domain left, and any working
        anywhere in this world (fakes.members)."""
        found = set(fakes.members(f"{self.tmp}/none", self.tmp))
        for domain in self.domains():
            found |= set(fakes.members(domain))
        return sorted(found)

    def ours(self, pid):
        """A listed pid still running one of this world's programs (a pid
        may be reused once its process is gone)."""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as stream:
                cmdline = stream.read()
        except OSError:
            return False
        return cmdline == b"sleep\x001000\x00" or self.tmp.encode() in cmdline \
            or _PAYLOAD.get("path", "\0").encode() in cmdline or server().encode() in cmdline

    def close(self):
        for pid in self.listed_pids():
            if pid != os.getpid() and self.ours(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
        shutil.rmtree(self.tmp, ignore_errors=True)


DESCRIBED = {"operations": ["capabilities", "prepare", "create", "start", "status", "stop", "discard"],
             "transport": "tcp", "retention": ["none", "home", "home_tmp", "disk"],
             "limits": ["cpus", "memory_mib", "pids"], "features": []}


def fixture_run(opened, provider, manifest, **fields):
    """A ready managed record made directly (store units only)."""
    base = {"provider": provider, "resource": store_mod.new_id("res"), "image": "b" * 64, "limits": {},
            "described": DESCRIBED, "user": "agentbox", "retention": "none", "phase": "ready",
            "home": "/home/agentbox"}
    return opened.create_managed(dict(base, **fields), manifest)


def _lines(path):
    try:
        with open(path) as stream:
            return [json.loads(line) for line in stream if line.strip()]
    except FileNotFoundError:
        return []
