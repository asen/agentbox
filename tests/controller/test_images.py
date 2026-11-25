"""Tagged images, offline: `image prepare/list/recover`, `jail create` and
`run AGENT` resolving a tag, and the built-in profiles (builtin.py) with
a fake packaged tree whose providers are the stand-in, pins served by a
local HTTP stub (fetch.py's test seams), FakeCgroups.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t . -p test_images.py
"""
import base64
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

from agentbox_controller import builtin, images, scopes, states, store as store_mod
from agentbox_controller.host import HostError
from tests.controller.harness import HERE, REPO, World, server, write_file
from tests.controller.test_execution import QUICK, until

GIB64 = 64 << 30
CLOUD = f"{HERE}/fixtures/cloudimage"
# A test key's signed Node manifests (latest-vMAJOR.x shaped; SHA-512, also
# SHA-1 and another key's; one listing two linux-x64 releases, one only a
# Node 22): two RSA keys made for these fixtures alone, their private
# halves discarded.
NODEJS = f"{HERE}/fixtures/nodejs"
NODE = b"node" * 300
BASE = b"base disk" * 1000


class Names(unittest.TestCase):
    def test_tag_names(self):
        for good in ("default", "a", "my-image", "v1.2_x", "0" * 64):
            self.assertEqual(images.check_name(good), good)
        for bad in ("", ".", "..", ".hidden", "-x", "A", "a/b", "a b", "x" * 65, "é", "../x", None):
            with self.assertRaises(HostError):
                images.check_name(bad)


class Pins(unittest.TestCase):
    def setUp(self):
        self.previous = builtin.ASSETS
        builtin.ASSETS = REPO
        self.addCleanup(setattr, builtin, "ASSETS", self.previous)

    def test_the_tracked_pins_are_well_formed(self):
        base, node = builtin.qemu_pins()
        # Node: the current Node 24 release, its manifest signed by one of
        # the active releasers (nodejs/node README.md), the packaged keyring
        # exactly theirs.
        self.assertEqual((node["major"], node["index"], node["dist"]),
                         (24, "https://nodejs.org/dist/latest-v24.x/", "https://nodejs.org/dist/"))
        self.assertEqual(len(node["signers"]), 8)
        self.assertLessEqual(node["max_bytes"], builtin.MAX_NODE_BYTES)
        with open(f"{REPO}/{node['keyring']}", "rb") as stream:
            self.assertEqual(hashlib.sha256(stream.read()).hexdigest(),
                             "b2832747c829d714c281e31d63011bb606c40a8b96bb72cc42b8456a53aa6caa")
        for change in ({"major": 22}, {"signers": []}, {"signers": ["x"]}, {"index": "http://nodejs.org/dist/"},
                       {"keyring": "../k.gpg"}, {"max_bytes": builtin.MAX_NODE_BYTES + 1}, {"urls": []}):
            with self.subTest(change=change):
                with self.assertRaises(HostError) as caught:
                    builtin._node_spec(dict(node, **change))
                self.assertEqual(caught.exception.code, "builtin_pins_invalid")
        # Within staging's shared input bound (stage.MAX_INPUT_BYTES).
        self.assertLess(builtin.MAX_NODE_BYTES, 1 << 30)
        # The base: Ubuntu 26.04 LTS amd64 (not amd64v3), its manifest's
        # signer pinned, the packaged keyring holding exactly that key.
        self.assertEqual((base["index"], base["file"], base["signer"]),
                         ("https://cloud-images.ubuntu.com/releases/resolute/release/",
                          "ubuntu-26.04-server-cloudimg-amd64.img", "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"))
        # One base cap: the resolver's download bound, the pins' allowance
        # and staging's own.
        self.assertEqual(base["max_bytes"], builtin.MAX_BASE_BYTES)
        self.assertEqual(builtin.MAX_BASE_BYTES, 2 << 30)  # stage.MAX_BASE_BYTES
        with self.assertRaises(HostError) as caught:
            builtin._base_spec(dict(base, max_bytes=builtin.MAX_BASE_BYTES + 1))
        self.assertEqual(caught.exception.code, "builtin_pins_invalid")
        with open(f"{REPO}/{base['keyring']}", "rb") as stream:
            self.assertEqual(hashlib.sha256(stream.read()).hexdigest(),
                             "8d2fa6679588fe177ce4a2d76ee56a479e18307abd4d0afc115e4f55dc288767")

    def test_limits_are_bootstrapped_once(self):
        tmp = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, tmp, True)
        os.chmod(tmp, 0o700)
        os.mkdir(f"{tmp}/data", 0o700)
        os.mkdir(f"{tmp}/state", 0o755)
        held = store_mod.Store(f"{tmp}/data")
        try:
            self.assertTrue(builtin.bootstrap_limits(held, f"{tmp}/state", None))
            with open(scopes.limits_path(held.path), "rb") as stream:
                first = stream.read()
            os.chmod(scopes.limits_path(held.path), 0o600)
            self.assertFalse(builtin.bootstrap_limits(held, f"{tmp}/other", f"{tmp}/engine"))
            with open(scopes.limits_path(held.path), "rb") as stream:
                self.assertEqual(stream.read(), first)
            self.assertEqual(sorted(os.listdir(held.path)), ["controller-logs", "controller-runs",
                                                             "controller-spool", "controller-store.json",
                                                             "run-limits.json"])
        finally:
            held.close()


class Tagged(unittest.TestCase):
    """The custom profile: the stand-in through --provider-config."""

    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)

    def run_(self, command, extra=(), **kwargs):
        kwargs.setdefault("overrides", QUICK)
        return self.world.run(command, list(extra), command_args=False, **kwargs)

    def tag(self, name="default"):
        with open(f"{self.world.data}/images/{name}", "rb") as stream:
            return stream.read()

    def test_prepare_publishes_the_tag_and_list_shows_it(self):
        value = json.loads(self.tag())
        self.assertEqual((value["schema"], value["name"], value["image"], value["profile"], value["provider"]),
                         ("agentbox.image-tag.v1", "default", self.world.image_id, "custom", self.world.provider))
        self.assertEqual(os.stat(f"{self.world.data}/images/default").st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(f"{self.world.data}/images").st_mode & 0o777, 0o700)
        other = self.world.prepare("other", "other.json")
        self.assertNotEqual(other, self.world.image_id)
        code, out, err = self.run_(("image", "list"))
        self.assertEqual(code, 0, err)
        self.assertEqual([line.split() for line in out.splitlines()],
                         [["NAME", "PROVIDER", "IMAGE", "ID"], ["default", "standin", self.world.image_id],
                          ["other", "standin", other]])
        # The default is unchanged by a named prepare.
        self.assertEqual(json.loads(self.tag())["image"], self.world.image_id)

    def test_run_create_uses_the_default_or_the_named_tag(self):
        other = self.world.prepare("other", "other.json")
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.record(out.split()[1])["image"], self.world.image_id)
        code, out, err = self.run_(("jail", "create"), ["--image", "other"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.record(out.split()[1])["image"], other)
        code, _, err = self.run_(("jail", "create"), ["--image", "nope"])
        self.assertEqual((code, err), (1, "agentbox: jail create refused: image_unknown\n"
                                          "agentbox: hint: agentbox image list shows the prepared images\n"))
        code, _, err = self.run_(("jail", "create"), ["--image", "../x"])
        self.assertEqual((code, err), (1, "agentbox: jail create refused: image_name_invalid\n"))

    def test_the_tag_snapshots_the_provider_configuration(self):
        write_file(self.world.provider_file, "not json")
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.record(out.split()[1])["provider"], self.world.provider)

    def test_a_failed_prepare_leaves_the_tag(self):
        before = self.tag()
        self.world.set_behavior(prepare="fail")
        write_file(f"{self.world.state}/inputs/next.json", "{}")
        code, _, err = self.run_(("image", "prepare"), ["standin", "--provider-config", self.world.provider_file,
                                                        "--recipe", f"{self.world.state}/inputs/next.json"])
        self.assertEqual((code, err), (1, "agentbox: image prepare refused: provider_failed provider_code=failed\n"))
        self.assertEqual(self.tag(), before)
        self.assertEqual(sorted(os.listdir(f"{self.world.data}/images")), [".lock", "default"])

    def test_prepare_prints_the_measured_agent_versions(self):
        write_file(f"{self.world.state}/inputs/next.json", "{}")
        args = ["-t", "next", "standin", "--provider-config", self.world.provider_file,
                "--recipe", f"{self.world.state}/inputs/next.json"]
        code, out, err = self.run_(("image", "prepare"), args)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(out.splitlines()), 1)
        self.world.set_behavior(agents={"claude": "2.1.330", "codex": "0.171.0", "pi": "1.6.0-rc.1"})
        code, out, err = self.run_(("image", "prepare"), args)
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines()[1], "agents: pi=1.6.0-rc.1 codex=0.171.0 claude=2.1.330")
        # Anything else is the provider's protocol error: no tag moves.
        before = self.tag("next")
        for agents in ({"pi": "1.6.0", "codex": "0.171.0"}, {"pi": "latest", "codex": "1.0.0", "claude": "1.0.0"},
                       {"pi": "1.0.0", "codex": "1.0.0", "claude": "1.0.0", "x": "1.0.0"}):
            self.world.set_behavior(agents=agents)
            write_file(f"{self.world.state}/inputs/other.json", "{}")
            code, out, err = self.run_(("image", "prepare"), ["-t", "next", "standin", "--provider-config",
                                                              self.world.provider_file, "--recipe",
                                                              f"{self.world.state}/inputs/other.json"])
            self.assertEqual((code, out), (1, ""), agents)
            self.assertEqual(self.tag("next"), before)

    def test_retag_keeps_an_existing_run_on_its_image(self):
        old = self.world.run_id
        moved = self.world.prepare("default", "next.json")
        self.assertNotEqual(moved, self.world.image_id)
        self.assertEqual(json.loads(self.tag())["image"], moved)
        self.assertEqual(self.world.record(old)["image"], self.world.image_id)
        code, out, err = self.world.exec(["true"], overrides=QUICK)
        self.assertEqual(code, 0, err)
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.record(out.split()[1])["image"], moved)
        # The same image again: the tag stays on it.
        self.assertEqual(self.world.prepare("default", "next.json"), moved)

    def test_refusals_before_any_provider_work(self):
        log = len(self.world.provider_log())
        cases = ((["-t", "../x", "standin", "--provider-config", self.world.provider_file, "--recipe", "/r"],
                  "image_name_invalid"),
                 (["podman", "--provider-config", self.world.provider_file], "provider_mismatch"),
                 (["standin", "--provider-config", self.world.provider_file], "recipe_required"))
        for args, code_ in cases:
            code, _, err = self.run_(("image", "prepare"), args)
            self.assertEqual((code, err.splitlines()[0]), (1, f"agentbox: image prepare refused: {code_}"), args)
        self.assertEqual(len(self.world.provider_log()), log)
        code, _, err = self.run_(("image", "recover"), ["podman", "--provider-config", self.world.provider_file,
                                                        "o-" + "0" * 32])
        self.assertEqual((code, err), (1, "agentbox: image recover refused: provider_mismatch\n"))

    def test_agent_run_target_rules(self):
        code, _, err = self.run_(("run",), ["pi", "--jail", self.world.run_id, "--image", "x",
                                                    "--prompt", "p"])
        self.assertEqual((code, err), (1, "agentbox: run refused: target_conflict\n"))

    def test_list_and_missing_default_on_a_fresh_store(self):
        fresh = f"{self.world.tmp}/fresh"
        config = f"{self.world.tmp}/fresh.json"
        write_file(config, {"schema": "agentbox.controller-config.v1", "data": fresh, "server": server()})
        argv = self.world.argv(("image", "list"), command_args=False)
        argv[argv.index("--config") + 1] = config
        done = subprocess.run(argv, env=self.world.env(), capture_output=True, timeout=60)
        self.assertEqual((done.returncode, done.stdout.decode().split()), (0, ["NAME", "PROVIDER", "IMAGE", "ID"]))
        self.assertFalse(os.path.lexists(fresh))
        os.mkdir(fresh, 0o700)
        argv = self.world.argv(("jail", "create"), command_args=False)
        argv[argv.index("--config") + 1] = config
        done = subprocess.run(argv, env=self.world.env(), capture_output=True, timeout=60)
        self.assertEqual((done.returncode, done.stderr.decode()),
                         (1, "agentbox: jail create refused: default_image_missing\n"
                             "agentbox: hint: prepare one: agentbox image prepare podman (or qemu)\n"))

    def test_an_invalid_tag_is_listed_as_invalid(self):
        write_file(f"{self.world.data}/images/broken", "{}")
        code, out, err = self.run_(("image", "list"))
        self.assertEqual(code, 0, err)
        self.assertIn(["broken", "-", "invalid"], [line.split() for line in out.splitlines()])
        code, _, err = self.run_(("jail", "create"), ["--image", "broken"])
        self.assertEqual((code, err), (1, "agentbox: jail create refused: image_tag_invalid\n"))


# -- the built-in profiles ----------------------------------------------------

STUB = r"""
import http.server, json, os, sys, time
root = sys.argv[1]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(os.path.join(root, "log"), "a") as stream:
            stream.write(self.path + "\n")
        with open(os.path.join(root, "state.json")) as stream:
            state = json.load(stream)
        name = state["files"].get(self.path)
        if name is None:
            self.send_error(404)
            return
        with open(os.path.join(root, name), "rb") as stream:
            data = stream.read()
        if self.path in state["truncate"]:
            # Chunked, cut short: half of it, then the connection closed
            # with no terminating chunk.
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            half = data[:len(data) // 2]
            self.wfile.write(b"%x\r\n" % len(half) + half + b"\r\n")
            self.wfile.flush()
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.path in state["stall"]:
            self.wfile.write(data[:1])
            self.wfile.flush()
            time.sleep(30)
            return
        self.wfile.write(data)

    def log_message(self, *_):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.daemon_threads = True
print(server.server_address[1], flush=True)
server.serve_forever()
"""


class Stub:
    """A local HTTP server in its own process (no thread here): path ->
    bytes, 404 otherwise; `stall` paths send their headers and one byte,
    then wait; `truncate` paths a chunked body cut short; every request
    path logged."""

    def __init__(self, root):
        self.root = root
        os.mkdir(root, 0o700)
        self.files = _Files(self)
        self.stalled, self.truncated = [], []
        self.save()
        open(f"{root}/log", "w").close()
        self.process = subprocess.Popen([sys.executable, "-I", "-c", STUB, root], stdout=subprocess.PIPE,
                                        stdin=subprocess.DEVNULL)
        self.base = f"http://127.0.0.1:{int(self.process.stdout.readline())}"

    def save(self):
        names = {}
        for path, data in self.files.items():
            name = hashlib.sha256(data).hexdigest()
            names[path] = name
            if not os.path.exists(f"{self.root}/{name}"):
                with open(f"{self.root}/{name}", "wb") as stream:
                    stream.write(data)
        write_file(f"{self.root}/.state", {"files": names, "stall": self.stalled,
                                             "truncate": self.truncated})
        os.rename(f"{self.root}/.state", f"{self.root}/state.json")

    def stall(self, path):
        self.stalled.append(path)
        self.save()

    def truncate(self, path):
        self.truncated.append(path)
        self.save()

    @property
    def requests(self):
        with open(f"{self.root}/log") as stream:
            return stream.read().split()

    def clear(self):
        open(f"{self.root}/log", "w").close()

    def close(self):
        self.process.kill()
        self.process.wait()
        self.process.stdout.close()


class _Files(dict):
    def __init__(self, stub):
        super().__init__()
        self.stub = stub

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if hasattr(self.stub, "process"):
            self.stub.save()

    def __delitem__(self, key):
        super().__delitem__(key)
        self.stub.save()


def _sha512(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class Builtin(unittest.TestCase):
    """A fake packaged tree: the stand-in as providers/{podman,qemu}.py,
    the real stage.py and worker.py, fake pins and agent locks."""

    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        tmp = self.world.tmp
        self.stub = Stub(f"{tmp}/stub")
        self.addCleanup(self.stub.close)
        self.tree = self.fake_tree(f"{tmp}/pkg")
        self.stub.save()
        self.root = f"{tmp}/state-root"
        self.data = f"{tmp}/bdata"
        os.mkdir(self.data, 0o700)
        self.runtime = f"{tmp}/run"
        os.mkdir(self.runtime, 0o700)
        self.engine = f"{self.runtime}/agentbox-podman"
        os.mkdir(self.root, 0o755)
        for name in ("podman", "podman-shared", "podman-private", "qemu"):
            os.mkdir(f"{self.root}/{name}", 0o700)
            write_file(f"{self.root}/{name}/behavior.json", self.world.behavior)
        # The default engine store's STATE; the private one's; the old one.
        self.podman = f"{self.root}/podman-shared"
        self.private = f"{self.root}/podman-private"
        self.legacy = f"{self.root}/podman"
        self.config = f"{tmp}/bconfig.json"
        self.write_config()

    def write_config(self, **extra):
        write_file(self.config, dict({"schema": "agentbox.controller-config.v1", "data": self.data,
                                      "server": server(), "state_root": self.root}, **extra))

    def fake_tree(self, tree):
        os.makedirs(f"{tree}/providers")
        for name in ("podman", "qemu"):
            shutil.copyfile(f"{HERE}/provider_standin.py", f"{tree}/providers/{name}.py")
        shutil.copyfile(f"{REPO}/providers/protocol.py", f"{tree}/providers/protocol.py")
        os.makedirs(f"{tree}/images/worker")
        for name in ("stage.py", "agentlock.py", "worker.py", "layout.json"):
            shutil.copyfile(f"{REPO}/images/worker/{name}", f"{tree}/images/worker/{name}")
        os.makedirs(f"{tree}/images/podman/default")
        os.makedirs(f"{tree}/images/podman/dev")
        write_file(f"{tree}/images/podman/default/Dockerfile", "FROM scratch\n")
        write_file(f"{tree}/images/podman/dev/Dockerfile", "FROM scratch\n# dev\n")
        os.makedirs(f"{tree}/images/qemu/default")
        write_file(f"{tree}/images/qemu/default/agentbox.pkr.hcl", "# recipe\n")
        self.files, self.cloud = {}, {}
        # Node: the test key's signed latest-v24.x manifest listing it.
        for name in os.listdir(NODEJS):
            with open(f"{NODEJS}/{name}", "rb") as stream:
                self.cloud["node/" + name] = stream.read()
        self.stub.files["/node/latest-v24.x/SHASUMS256.txt"] = self.cloud["node/SHASUMS256.txt"]
        self.stub.files["/node/latest-v24.x/SHASUMS256.txt.sig"] = self.cloud["node/SHASUMS256.txt.sig"]
        self.stub.files["/node/dist/v24.1.0/node-v24.1.0-linux-x64.tar.xz"] = NODE
        self.files["node-v24.1.0-linux-x64.tar.xz"] = NODE
        shutil.copyfile(f"{NODEJS}/keyring-both.gpg", f"{tree}/images/qemu/default/test-node-keyring.gpg")
        with open(f"{NODEJS}/fingerprint") as stream:
            node_signer = stream.read().strip()
        node = {"major": 24, "index": "https://pins.test/node/latest-v24.x/", "dist": "https://pins.test/node/dist/",
                "keyring": "images/qemu/default/test-node-keyring.gpg", "signers": [node_signer], "max_bytes": 1 << 20,
                "provenance": "test"}
        # The base: a test key's signed manifest (fixtures/cloudimage,
        # SHA-512; also SHA-1 and another key's) listing it, an amd64v3
        # image and an arm64 one beside it.
        for name in ("SHA256SUMS", "SHA256SUMS.gpg", "SHA256SUMS.sha1.gpg", "SHA256SUMS.other.gpg"):
            with open(f"{CLOUD}/{name}", "rb") as stream:
                self.cloud[name] = stream.read()
        self.stub.files["/cloud/SHA256SUMS"] = self.cloud["SHA256SUMS"]
        self.stub.files["/cloud/SHA256SUMS.gpg"] = self.cloud["SHA256SUMS.gpg"]
        self.stub.files["/cloud/ubuntu-26.04-server-cloudimg-amd64.img"] = BASE
        self.stub.files["/cloud/ubuntu-26.04-server-cloudimg-amd64v3.img"] = b"amd64v3 disk" * 100
        shutil.copyfile(f"{CLOUD}/keyring-both.gpg", f"{tree}/images/qemu/default/test-keyring.gpg")
        with open(f"{CLOUD}/fingerprint") as stream:
            signer = stream.read().strip()
        self.files[f"base-{hashlib.sha256(BASE).hexdigest()}.img"] = BASE
        self.pins = {"schema": "agentbox.qemu-input-pins.v3", "node": node,
                     "base": {"index": "https://pins.test/cloud/", "file": "ubuntu-26.04-server-cloudimg-amd64.img",
                              "keyring": "images/qemu/default/test-keyring.gpg", "signer": signer, "max_bytes": 1 << 20,
                              "provenance": "test"}}
        write_file(f"{tree}/images/qemu/default/inputs.lock.json", self.pins)
        for directory, _, names in os.walk(tree):
            os.chmod(directory, 0o755)
            for name in names:
                os.chmod(os.path.join(directory, name), 0o644)
        return tree

    def overrides(self, extra=None):
        fd = os.open(self.runtime, os.O_RDONLY)
        try:
            fs = sorted(builtin._filesystem_types(fd))
        finally:
            os.close(fd)
        value = dict(QUICK, **{"builtin.ASSETS": self.tree, "fetch.SCHEMES": ["http", "https"],
                               "fetch.REWRITE": {"https://pins.test/": self.stub.base + "/"},
                               "builtin.ENGINE_FILESYSTEMS": fs})
        value.update(extra or {})
        return value

    def env(self, runtime=True):
        return {"XDG_RUNTIME_DIR": self.runtime} if runtime else {"XDG_RUNTIME_DIR": ""}

    def argv(self, command, args, extra=None):
        argv = self.world.argv(command, args, overrides=self.overrides(extra), command_args=False)
        argv[argv.index("--config") + 1] = self.config
        return argv

    def run_(self, command, args=(), runtime=True, extra=None, timeout=60):
        done = subprocess.run(self.argv(command, list(args), extra), env=self.world.env(self.env(runtime)),
                              capture_output=True, timeout=timeout)
        return done.returncode, done.stdout.decode(), done.stderr.decode()

    def limits(self):
        with open(scopes.limits_path(self.data)) as stream:
            return json.load(stream)

    def tag(self, name="default"):
        with open(f"{self.data}/images/{name}") as stream:
            return json.load(stream)

    def inputs(self, rel=""):
        return f"{self.root}/qemu/inputs{'/' + rel if rel else ''}"

    def leftovers(self):
        found = []
        for directory, _, names in os.walk(self.inputs()):
            found += [n for n in names if n.startswith(".fetch-")]
        return found

    def test_podman_prepare_bootstraps_and_publishes(self):
        code, out, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual(code, 0, err)
        image = hashlib.sha256(f"{self.tree}/images/podman/default/Dockerfile".encode()).hexdigest()
        self.assertEqual(out.split()[:4], ["image:", "default", "provider=podman", f"id={image}"])
        self.assertIn(f"agentbox: created {self.data}/run-limits.json", err)
        self.assertEqual(self.limits(), {"max_reserved_bytes": GIB64, "storage_scopes": [
            {"path": self.root, "measure": "tree",
             "uncapped": ["podman/resources", "podman/work", "podman-shared/resources", "podman-shared/work",
                          "podman-private/resources", "podman-private/work", "qemu/resources", "qemu/work"]},
            {"path": self.engine, "measure": "filesystem"},
            {"path": f"{self.data}/controller-spool", "measure": "tree"}]})
        self.assertEqual(os.stat(scopes.limits_path(self.data)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.engine).st_mode & 0o777, 0o700)
        # No --store, no podman_store: the shared store's STATE.
        with open(f"{self.podman}/inputs/podman-inputs.json") as stream:
            self.assertEqual(json.load(stream), {"schema": "agentbox.podman-inputs.v1", "storage_root": self.engine,
                                                 "build_args": {}, "store": "shared"})
        self.assertFalse(os.path.lexists(f"{self.private}/inputs"))
        self.assertFalse(os.path.lexists(f"{self.legacy}/inputs"))
        # The provider's identity and STATE, the recipe relative to the
        # assets: no path of this install.
        tag = self.tag()
        self.assertEqual((tag["profile"], tag["image"], tag["recipe"]),
                         ("builtin", image, "images/podman/default/Dockerfile"))
        self.assertEqual(tag["provider"], {"builtin": "podman", "state": self.podman})
        # The prepare itself ran this install's code with the host
        # configuration's interpreter.
        self.assertEqual(json.dumps(tag).count(self.tree), 0)
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record(out.split()[1])["provider"], tag["provider"])
        # A reboot emptied the runtime tmpfs: the next command makes the
        # declared engine root again.
        os.rmdir(self.engine)
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isdir(self.engine))
        self.assertEqual(self.stub.requests, [])

    def test_a_podman_start_failure_hints_the_engine_root(self):
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual(code, 0, err)
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        run_id = out.split()[1]
        write_file(f"{self.podman}/behavior.json", dict(self.world.behavior, start="prerequisite"))
        argv = self.world.argv(("jail", "exec"), ["--", "true"], overrides=self.overrides(), run_id=run_id)
        argv[argv.index("--config") + 1] = self.config
        done = subprocess.run(argv, env=self.world.env(self.env()), capture_output=True, timeout=60)
        lines = done.stderr.decode().splitlines()
        self.assertEqual(done.returncode, 1)
        self.assertIn("provider_code=prerequisite", lines[-2])
        self.assertTrue(lines[-1].startswith("agentbox: hint: if Podman's engine root ran out of space"), lines)

    def test_an_existing_limits_file_is_never_changed(self):
        original = json.dumps({"max_reserved_bytes": 1 << 30, "storage_scopes": []}).encode()
        with open(scopes.limits_path(self.data), "wb") as stream:
            stream.write(original)
        os.chmod(scopes.limits_path(self.data), 0o600)
        code, _, err = self.run_(("image", "prepare"), ["qemu"])
        self.assertEqual(err.splitlines()[0], "agentbox: image prepare refused: storage_scope_undeclared")
        self.assertIn(f"does not declare {self.root}/qemu", err)
        self.assertEqual(code, 1)
        with open(scopes.limits_path(self.data), "rb") as stream:
            self.assertEqual(stream.read(), original)
        self.assertFalse(os.path.lexists(self.inputs()))
        self.assertFalse(os.path.lexists(f"{self.data}/images"))
        self.assertEqual(self.stub.requests, [])

    def base(self):
        return self.inputs(f"base-{hashlib.sha256(BASE).hexdigest()}.img")

    def test_qemu_fetches_verifies_and_reuses(self):
        stale = (self.inputs("ubuntu-noble-20260926-amd64.img"), self.inputs("git_2.53.0_amd64.deb"),
                 self.inputs("base-" + "0" * 64 + ".img"), self.inputs("node-v24.18.0-linux-x64.tar.xz"))
        os.makedirs(self.inputs(), 0o700)
        for path in stale:
            write_file(path, "stale")
        # An older STATE's agent tarballs: no input any more, left alone.
        os.mkdir(self.inputs("agents"), 0o700)
        write_file(self.inputs("agents/old-1.0.0.tgz"), "old")
        os.chmod(self.inputs(), 0o700)
        code, out, err = self.run_(("image", "prepare"), ["-t", "vm", "qemu"], runtime=False)
        self.assertEqual(code, 0, err)
        self.assertIn("agentbox: fetching the current Ubuntu base ubuntu-26.04-server-cloudimg-amd64.img (sha256 "
                      f"{hashlib.sha256(BASE).hexdigest()[:16]})", err)
        self.assertIn(f"agentbox: fetching Node 24.1.0 (sha256 {hashlib.sha256(NODE).hexdigest()[:16]})", err)
        for rel, data in self.files.items():
            with open(self.inputs(rel), "rb") as stream:
                self.assertEqual(stream.read(), data, rel)
            self.assertEqual(os.stat(self.inputs(rel)).st_mode & 0o777, 0o600)
        with open(self.inputs("qemu-build-inputs.json")) as stream:
            value = json.load(stream)
        self.assertEqual(value["schema"], "agentbox.qemu-build-inputs.v1")
        self.assertEqual(set(value), {"schema", "base", "node"})
        source = value["base"].pop("source")
        self.assertEqual(value["base"], {"file": os.path.basename(self.base()), "bytes": len(BASE),
                                         "sha256": hashlib.sha256(BASE).hexdigest()})
        self.assertEqual((source["url"], source["signer"], source["sums_sha256"]),
                         ("https://pins.test/cloud/ubuntu-26.04-server-cloudimg-amd64.img", self.pins["base"]["signer"],
                          hashlib.sha256(self.cloud["SHA256SUMS"]).hexdigest()))
        self.assertIsInstance(source["signed"], int)
        # Node: the signed manifest's one linux-x64 release, from its own
        # release directory, its provenance recorded.
        source = value["node"].pop("source")
        self.assertEqual(value["node"], {"file": "node-v24.1.0-linux-x64.tar.xz", "bytes": len(NODE),
                                         "sha256": hashlib.sha256(NODE).hexdigest(), "version": "24.1.0"})
        self.assertEqual((source["url"], source["signer"], source["sums_sha256"]),
                         ("https://pins.test/node/dist/v24.1.0/node-v24.1.0-linux-x64.tar.xz",
                          self.pins["node"]["signers"][0], hashlib.sha256(self.cloud["node/SHASUMS256.txt"]).hexdigest()))
        self.assertIsInstance(source["signed"], int)
        # Superseded files of ours are gone; a directory is left alone.
        self.assertEqual([p for p in stale if os.path.lexists(p)], [])
        self.assertEqual(sorted(os.listdir(self.inputs())), sorted(
            ["agents", "cloud-SHA256SUMS", "cloud-SHA256SUMS.gpg", "node-SHASUMS256.txt", "node-SHASUMS256.txt.sig",
             "qemu-build-inputs.json", os.path.basename(self.base()), "node-v24.1.0-linux-x64.tar.xz"]))
        self.assertEqual(os.listdir(self.inputs("agents")), ["old-1.0.0.tgz"])
        # No runtime directory: QEMU does not need Podman's engine root.
        self.assertEqual([s["path"] for s in self.limits()["storage_scopes"]],
                         [self.root, f"{self.data}/controller-spool"])
        self.assertEqual(self.tag("vm")["provider"], {"builtin": "qemu", "state": f"{self.root}/qemu"})
        self.assertFalse(os.path.lexists(f"{self.data}/images/default"))
        # Every prepare refreshes both signed manifests; verified files are
        # reused by digest.
        manifests = ["/cloud/SHA256SUMS", "/cloud/SHA256SUMS.gpg", "/node/latest-v24.x/SHASUMS256.txt",
                     "/node/latest-v24.x/SHASUMS256.txt.sig"]
        self.stub.clear()
        code, _, err = self.run_(("image", "prepare"), ["-t", "vm", "qemu"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.stub.requests, manifests)
        # A corrupted cached file is fetched again, alone.
        with open(self.inputs("node-v24.1.0-linux-x64.tar.xz"), "r+b") as stream:
            stream.write(b"X")
        self.stub.clear()
        code, _, err = self.run_(("image", "prepare"), ["-t", "vm", "qemu"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.stub.requests, manifests + ["/node/dist/v24.1.0/node-v24.1.0-linux-x64.tar.xz"])
        self.assertEqual(self.leftovers(), [])

    def refused(self, code, base=False):
        done, _, err = self.run_(("image", "prepare"), ["qemu"])
        self.assertEqual((done, err.splitlines()[-1] if "hint" not in err.splitlines()[-1] else err.splitlines()[-2]),
                         (1, f"agentbox: image prepare refused: {code}"), err)
        self.assertEqual(os.path.lexists(self.base()), base)
        self.assertFalse(os.path.lexists(self.inputs("node-v24.1.0-linux-x64.tar.xz")))
        self.assertFalse(os.path.lexists(self.inputs("qemu-build-inputs.json")))
        self.assertFalse(os.path.lexists(f"{self.data}/images/default"))
        self.assertEqual(self.leftovers(), [])
        return err

    def test_only_the_signed_manifests_base_is_taken(self):
        """A manifest signed by another key, with SHA-1, or changed after
        signing; one not listing the image; an image other than its
        listing: nothing published, nothing kept."""
        for name, data in (("SHA256SUMS.gpg", self.cloud["SHA256SUMS.other.gpg"]),
                           ("SHA256SUMS.gpg", self.cloud["SHA256SUMS.sha1.gpg"]),
                           ("SHA256SUMS", self.cloud["SHA256SUMS"] + b"0" * 64 + b" *extra.img\n")):
            with self.subTest(name=name):
                self.stub.files[f"/cloud/{name}"] = data
                err = self.refused("base_signature_invalid")
                self.assertIn("agentbox: hint: the Ubuntu cloud image manifest's signature did not verify", err)
                self.assertFalse([r for r in self.stub.requests if r.endswith(".img")])
                self.stub.files["/cloud/SHA256SUMS"] = self.cloud["SHA256SUMS"]
                self.stub.files["/cloud/SHA256SUMS.gpg"] = self.cloud["SHA256SUMS.gpg"]
        self.pins["base"]["file"] = "ubuntu-26.04-server-cloudimg-riscv64.img"
        write_file(f"{self.tree}/images/qemu/default/inputs.lock.json", self.pins)
        self.refused("base_unlisted")
        self.pins["base"]["file"] = "ubuntu-26.04-server-cloudimg-amd64.img"
        write_file(f"{self.tree}/images/qemu/default/inputs.lock.json", self.pins)
        self.stub.files["/cloud/ubuntu-26.04-server-cloudimg-amd64.img"] = b"other" + BASE[5:]
        self.refused("input_mismatch")
        # Beyond the bound: refused the same way.
        self.stub.files["/cloud/ubuntu-26.04-server-cloudimg-amd64.img"] = BASE + b"x" * (1 << 20)
        self.refused("input_mismatch")
        del self.stub.files["/cloud/ubuntu-26.04-server-cloudimg-amd64.img"]
        self.refused("input_unavailable")
        del self.stub.files["/cloud/SHA256SUMS.gpg"]
        self.refused("input_unavailable")
        self.assertFalse(any(e.get("type") == "prepare" for e in _lines(f"{self.root}/qemu/log.jsonl")))

    def test_only_the_signed_manifests_node_is_taken(self):
        """A Node manifest signed by a key in the keyring but no pinned
        releaser, with SHA-1, or changed after signing; one listing two
        linux-x64 releases or only another major; a release other than its
        listing, or beyond the bound: nothing published, no Node kept."""
        latest = "/node/latest-v24.x/SHASUMS256.txt"
        good, sig = self.cloud["node/SHASUMS256.txt"], self.cloud["node/SHASUMS256.txt.sig"]
        for manifest, signature, code in (
                (good, self.cloud["node/SHASUMS256.txt.other.sig"], "node_signature_invalid"),
                (good, self.cloud["node/SHASUMS256.txt.sha1.sig"], "node_signature_invalid"),
                (good + b"0" * 64 + b"  extra.tar.xz\n", sig, "node_signature_invalid"),
                (self.cloud["node/SHASUMS256.two.txt"], self.cloud["node/SHASUMS256.two.txt.sig"], "node_unlisted"),
                (self.cloud["node/SHASUMS256.v22.txt"], self.cloud["node/SHASUMS256.v22.txt.sig"], "node_unlisted")):
            with self.subTest(code=code, manifest=len(manifest), signature=signature[-8:].hex()):
                self.stub.files[latest], self.stub.files[latest + ".sig"] = manifest, signature
                err = self.refused(code, base=True)
                self.assertIn("agentbox: hint: the ", err)
                self.assertFalse([r for r in self.stub.requests if r.endswith(".tar.xz")])
                self.stub.files[latest], self.stub.files[latest + ".sig"] = good, sig
        release = "/node/dist/v24.1.0/node-v24.1.0-linux-x64.tar.xz"
        self.stub.files[release] = b"other" + NODE[5:]
        self.refused("input_mismatch", base=True)
        self.stub.files[release] = NODE + b"x" * (1 << 20)
        self.refused("input_mismatch", base=True)
        del self.stub.files[release]
        self.refused("input_unavailable", base=True)
        self.stub.files[release] = NODE
        code, _, err = self.run_(("image", "prepare"), ["qemu"])
        self.assertEqual(code, 0, err)

    def test_a_truncated_response_publishes_nothing(self):
        # The base's only URL is cut short: refused, nothing kept.
        self.stub.truncate("/cloud/ubuntu-26.04-server-cloudimg-amd64.img")
        err = self.refused("input_unavailable")
        self.assertIn(f"agentbox: fetch: {os.path.basename(self.base())}: unavailable from", err)
        self.assertNotIn("Traceback", err)
        # So is Node's.
        self.stub.truncated.remove("/cloud/ubuntu-26.04-server-cloudimg-amd64.img")
        self.stub.truncate("/node/dist/v24.1.0/node-v24.1.0-linux-x64.tar.xz")
        self.stub.save()
        err = self.refused("input_unavailable", base=True)
        self.assertIn("agentbox: fetch: node-v24.1.0-linux-x64.tar.xz: unavailable from", err)
        self.stub.truncated.remove("/node/dist/v24.1.0/node-v24.1.0-linux-x64.tar.xz")
        self.stub.save()
        self.stub.clear()
        code, _, err = self.run_(("image", "prepare"), ["qemu"])
        self.assertEqual(code, 0, err)
        with open(self.inputs("node-v24.1.0-linux-x64.tar.xz"), "rb") as stream:
            self.assertEqual(stream.read(), NODE)
        self.assertEqual(self.leftovers(), [])

    def test_an_interrupt_cancels_the_fetch(self):
        self.stub.stall("/cloud/ubuntu-26.04-server-cloudimg-amd64.img")
        process = subprocess.Popen(self.argv(("image", "prepare"), ["qemu"]), env=self.world.env(self.env()),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        until(lambda: "/cloud/ubuntu-26.04-server-cloudimg-amd64.img" in self.stub.requests and self.leftovers())
        process.send_signal(signal.SIGINT)
        _, err = process.communicate(timeout=30)
        self.assertEqual((process.returncode, err.decode().splitlines()[-1]),
                         (1, "agentbox: image prepare refused: cancelled"))
        self.assertEqual(self.leftovers(), [])
        self.assertFalse(os.path.lexists(self.base()))
        self.assertFalse(os.path.lexists(f"{self.data}/images/default"))

    def test_a_preset_selects_the_canonical_recipe_and_the_tag_records_it(self):
        code, out, err = self.run_(("image", "prepare"), ["-t", "dev", "podman", "--preset", "dev"])
        self.assertEqual(code, 0, err)
        dev = hashlib.sha256(f"{self.tree}/images/podman/dev/Dockerfile".encode()).hexdigest()
        self.assertEqual(out.split()[:4], ["image:", "dev", "provider=podman", f"id={dev}"])
        tag = self.tag("dev")
        self.assertEqual((tag["profile"], tag["image"], tag["recipe"]),
                         ("builtin", dev, "images/podman/dev/Dockerfile"))
        self.assertEqual(tag["provider"], {"builtin": "podman", "state": self.podman})
        # `default` is the default recipe; neither tag moves the other.
        code, _, err = self.run_(("image", "prepare"), ["podman", "--preset", "default"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.tag()["recipe"], "images/podman/default/Dockerfile")
        self.assertEqual(self.tag("dev")["image"], dev)
        code, out, err = self.run_(("image", "list"))
        self.assertEqual(code, 0, err)
        self.assertEqual([line.split()[:2] for line in out.splitlines()[1:]], [["default", "podman"], ["dev", "podman"]])
        # A run of the tag uses its image, never preparing anything.
        prepares = len([e for e in _lines(f"{self.podman}/log.jsonl") if e.get("type") == "prepare"])
        code, out, err = self.run_(("jail", "create"), ["--image", "dev"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.record(out.split()[1])["image"], dev)
        self.assertEqual(len([e for e in _lines(f"{self.podman}/log.jsonl") if e.get("type") == "prepare"]),
                         prepares)
        # A tag naming any other recipe of the built-in profile is invalid.
        path = f"{self.data}/images/dev"
        with open(path) as stream:
            value = json.load(stream)
        write_file(path, dict(value, recipe="images/podman/other/Dockerfile"))
        code, _, err = self.run_(("jail", "create"), ["--image", "dev"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: jail create refused: image_tag_invalid"))
        # Nor the other provider's.
        write_file(path, dict(value, recipe="images/qemu/default/agentbox.pkr.hcl"))
        code, _, err = self.run_(("jail", "create"), ["--image", "dev"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: jail create refused: image_tag_invalid"))

    def test_preset_refusals_before_any_provider_work(self):
        custom = f"{self.world.tmp}/custom-podman.json"
        write_file(custom, dict(self.world.provider, provider="podman"))
        for args, code_ in (
                (["podman", "--preset", "nope"], "preset_unknown"),
                (["podman", "--preset", ""], "preset_unknown"),
                (["qemu", "--preset", "dev"], "preset_unsupported"),
                (["podman", "--preset", "dev", "--provider-config", custom, "--recipe", "/r"], "preset_conflict"),
                (["standin", "--preset", "dev", "--provider-config", self.world.provider_file],
                 "provider_unknown"),
                (["standin", "--preset", "default", "--provider-config", self.world.provider_file],
                 "provider_unknown")):
            code, _, err = self.run_(("image", "prepare"), args)
            self.assertEqual((code, err.splitlines()[0]), (1, f"agentbox: image prepare refused: {code_}"), args)
            self.assertTrue(err.splitlines()[1].startswith("agentbox: hint: "), args)
        self.assertFalse(os.path.lexists(f"{self.data}/images"))
        self.assertFalse(os.path.lexists(f"{self.podman}/log.jsonl"))
        # --preset without a value is usage.
        code, _, err = self.run_(("image", "prepare"), ["podman", "--preset"])
        self.assertEqual(code, 2, err)

    def store_of(self, state):
        with open(f"{state}/inputs/podman-inputs.json") as stream:
            return json.load(stream)["store"]

    def created_with(self, state, run_id):
        """The engine store the provider read for `run_id`'s create."""
        resource = self.record(run_id)["resource"]
        return [e["inputs_store"] for e in _lines(f"{state}/log.jsonl")
                if e.get("type") == "create" and e.get("resource") == resource]

    def test_the_store_choice_selects_its_own_state(self):
        """--store, else podman_store, else shared: each mode's own STATE,
        its inputs that mode's alone, whatever was prepared before."""
        for config, flag, mode in ((None, None, "shared"), ("private", None, "private"), ("shared", None, "shared"),
                                   (None, "private", "private"), ("private", "shared", "shared"),
                                   ("shared", "private", "private"), (None, "shared", "shared")):
            self.write_config(**({"podman_store": config} if config else {}))
            code, _, err = self.run_(("image", "prepare"), ["-t", "t", "podman"] + (["--store", flag] if flag else []))
            self.assertEqual(code, 0, (config, flag, err))
            self.assertEqual(self.tag("t")["provider"], {"builtin": "podman", "state": f"{self.root}/podman-{mode}"})
            self.assertEqual(self.store_of(f"{self.root}/podman-{mode}"), mode)
        self.assertEqual((self.store_of(self.podman), self.store_of(self.private)), ("shared", "private"))
        self.assertFalse(os.path.lexists(f"{self.legacy}/inputs"))
        self.write_config(podman_store="elsewhere")
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: config_invalid"))

    def test_each_tag_keeps_its_store_after_both_prepares(self):
        """The discriminator: one image (the same recipe, the same ID) in
        both stores; jails created from each tag only after both prepares,
        either order, each with its own store; neither prepare touches the
        other mode's inputs."""
        image = hashlib.sha256(f"{self.tree}/images/podman/default/Dockerfile".encode()).hexdigest()
        for first, second in (("shared", "private"), ("private", "shared")):
            for mode in (first, second):
                other = self.private if mode == "shared" else self.podman
                before = _slurp(f"{other}/inputs/podman-inputs.json")
                code, _, err = self.run_(("image", "prepare"), ["-t", mode, "podman", "--store", mode])
                self.assertEqual(code, 0, err)
                self.assertEqual(self.tag(mode)["image"], image)
                self.assertEqual(_slurp(f"{other}/inputs/podman-inputs.json"), before)
            for mode in ("shared", "private"):
                state = f"{self.root}/podman-{mode}"
                code, out, err = self.run_(("jail", "create"), ["--image", mode])
                self.assertEqual(code, 0, err)
                run_id = out.split()[1]
                self.assertEqual(self.record(run_id)["provider"], {"builtin": "podman", "state": state})
                self.assertEqual(self.created_with(state, run_id), [mode])
        self.assertFalse(os.path.lexists(f"{self.legacy}/inputs"))

    def test_an_old_single_state_tag_keeps_its_store(self):
        """A tag of the old single Podman STATE resolves to it as recorded,
        its inputs' store kept: no prepare writes it again."""
        os.makedirs(f"{self.legacy}/inputs", 0o700)
        legacy = {"schema": "agentbox.podman-inputs.v1", "storage_root": self.engine,
                  "build_args": {"GIT_SHA256": "ab" * 32}, "store": "shared"}
        write_file(f"{self.legacy}/inputs/podman-inputs.json", legacy)
        code, _, err = self.run_(("image", "prepare"), ["-t", "new", "podman", "--store", "private"])
        self.assertEqual(code, 0, err)
        new = self.tag("new")
        # The old STATE as an earlier prepare left it: claimed, its image.
        held = store_mod.Store(self.data)
        try:
            states.check_claim(held, self.legacy, make=True)
        finally:
            held.close()
        images.publish(self.data, "old", {"builtin": "podman", "state": self.legacy}, new["image"],
                       new["worker_release"], new["recipe"], "builtin")
        os.makedirs(f"{self.legacy}/images/{new['image']}", 0o700)
        metadata = f"{self.legacy}/images/{new['image']}/worker-metadata.json"
        shutil.copyfile(f"{self.private}/images/{new['image']}/worker-metadata.json", metadata)
        os.chmod(metadata, 0o600)
        code, out, err = self.run_(("jail", "create"), ["--image", "old"])
        self.assertEqual(code, 0, err)
        run_id = out.split()[1]
        self.assertEqual(self.record(run_id)["provider"], {"builtin": "podman", "state": self.legacy})
        self.assertEqual(self.created_with(self.legacy, run_id), ["shared"])
        with open(f"{self.legacy}/inputs/podman-inputs.json") as stream:
            self.assertEqual(json.load(stream), legacy)

    def test_store_refusals_before_anything_is_made(self):
        custom = f"{self.world.tmp}/custom-podman.json"
        write_file(custom, dict(self.world.provider, provider="podman"))
        fresh = f"{self.world.tmp}/fresh-root"
        self.write_config(state_root=fresh)
        for command, args, code_ in (
                (("image", "prepare"), ["podman", "--store", "Shared"], "store_invalid"),
                (("image", "prepare"), ["podman", "--store", ""], "store_invalid"),
                (("image", "prepare"), ["qemu", "--store", "private"], "store_unsupported"),
                (("image", "prepare"), ["podman", "--store", "private", "--provider-config", custom],
                 "store_conflict"),
                (("image", "recover"), ["qemu", "--store", "shared", "o-" + "0" * 32], "store_unsupported"),
                (("image", "recover"), ["podman", "--store", "x", "o-" + "0" * 32], "store_invalid"),
                (("image", "recover"), ["podman", "--store", "shared", "--provider-config", custom,
                                        "o-" + "0" * 32], "store_conflict")):
            code, _, err = self.run_(command, args)
            words = " ".join(command)
            self.assertEqual((code, err.splitlines()[0]), (1, f"agentbox: {words} refused: {code_}"), args)
            self.assertTrue(err.splitlines()[1].startswith("agentbox: hint: "), args)
        self.assertFalse(os.path.lexists(fresh))
        self.assertFalse(os.path.lexists(self.engine))
        self.assertEqual(sorted(os.listdir(self.data)), [])
        code, _, err = self.run_(("image", "prepare"), ["podman", "--store"])
        self.assertEqual(code, 2, err)

    def interrupted_prepare(self, state, args):
        """A prepare in `state` whose controller died: its pending id."""
        write_file(f"{state}/behavior.json", dict(self.world.behavior, prepare="hang"))
        process = subprocess.Popen(self.argv(("image", "prepare"), args), env=self.world.env(self.env()),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        until(lambda: any(e.get("type") == "prepare" for e in _lines(f"{state}/log.jsonl")))
        process.kill()
        process.communicate(timeout=30)
        write_file(f"{state}/behavior.json", self.world.behavior)
        with open(f"{self.data}/controller-states/{states.key(state)}/state.json") as stream:
            return json.load(stream)["pending"]["operation"]

    def test_recovery_follows_the_store_and_the_old_state(self):
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual(code, 0, err)
        operation = self.interrupted_prepare(self.private, ["-t", "p", "podman", "--store", "private"])
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual(err.splitlines(), ["agentbox: image prepare refused: prepare_unsettled",
                                            "agentbox: hint: settle it first: agentbox image recover podman --store "
                                            f"private {operation}"])
        # The other mode's prepare is not held up.
        code, _, err = self.run_(("image", "prepare"), ["-t", "s", "podman"])
        self.assertEqual(code, 0, err)
        # The default (shared) store's STATE: never the other mode's, and
        # the old STATE only read where it holds a record.
        code, _, err = self.run_(("image", "recover"), ["podman", operation])
        self.assertEqual((code, err), (1, "agentbox: image recover refused: operation_unknown\n"))
        self.assertFalse(os.path.lexists(f"{self.data}/controller-states/{states.key(self.legacy)}"))
        code, out, err = self.run_(("image", "recover"), ["podman", "--store", "private", operation])
        self.assertEqual((code, out), (0, f"image recover: {operation} recovered\n"), err)
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual(code, 0, err)
        # A prepare an earlier install left pending in the old single
        # STATE (made here through a configuration naming it): recovered
        # by `image recover podman`, whichever store is selected.
        config = {"schema": "agentbox.provider-config.v1", "provider": "podman", "interpreter": sys.executable,
                  "entry": f"{self.tree}/providers/podman.py", "state": self.legacy, "assets": self.tree}
        path = f"{self.world.tmp}/legacy.json"
        write_file(path, config)
        old = self.interrupted_prepare(self.legacy, ["-t", "old", "podman", "--provider-config", path])
        code, _, err = self.run_(("image", "recover"), ["podman", "--store", "private", "o-" + "0" * 32])
        self.assertEqual((code, err), (1, "agentbox: image recover refused: operation_unknown\n"))
        code, out, err = self.run_(("image", "recover"), ["podman", "--store", "private", old])
        self.assertEqual((code, out), (0, f"image recover: {old} recovered\n"), err)
        with open(f"{self.data}/controller-states/{states.key(self.legacy)}/state.json") as stream:
            self.assertIsNone(json.load(stream)["pending"])
        self.assertFalse(os.path.lexists(f"{self.legacy}/inputs"))

    def test_an_existing_limits_file_must_leave_podman_storage_uncapped(self):
        """The operator's limits, never changed: a Podman STATE's resources
        and work uncapped (at or above them) or measured by a filesystem
        scope alone, else refused before the provider runs."""
        def limits(declared):
            write_file(scopes.limits_path(self.data), {"max_reserved_bytes": GIB64, "storage_scopes": declared})
            os.chmod(scopes.limits_path(self.data), 0o600)
            with open(scopes.limits_path(self.data), "rb") as stream:
                return stream.read()

        engine = {"path": self.engine, "measure": "filesystem"}
        os.mkdir(self.engine, 0o700)
        old = [{"path": self.root, "measure": "tree", "uncapped": ["podman/resources", "podman/work",
                                                                  "qemu/resources", "qemu/work"]}, engine]
        original = limits(old)
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: storage_scope_strict"))
        self.assertIn(f'add "podman-shared/resources" in the uncapped list of {self.root}; "podman-shared/work" in '
                      f"the uncapped list of {self.root}", err)
        with open(scopes.limits_path(self.data), "rb") as stream:
            self.assertEqual(stream.read(), original)
        self.assertFalse(os.path.lexists(f"{self.podman}/inputs"))
        self.assertFalse(any(e.get("type") == "prepare" for e in _lines(f"{self.podman}/log.jsonl")))
        self.assertFalse(os.path.lexists(f"{self.data}/images"))
        # A tree scope exactly at one of them: strict whatever it says.
        limits([dict(old[0], uncapped=old[0]["uncapped"] + ["podman-shared/work"]),
                {"path": f"{self.podman}/resources", "measure": "tree"}, engine])
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: storage_scope_strict"))
        self.assertIn(f"{self.podman}/resources: a tree scope measuring {os.path.realpath(self.podman)}/resources "
                      "strictly", err)
        # The private mode named, the shared one adequate: only it refused.
        limits([dict(old[0], uncapped=old[0]["uncapped"] + ["podman-shared"]), engine])
        code, _, err = self.run_(("image", "prepare"), ["-t", "s", "podman"])
        self.assertEqual(code, 0, err)
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: storage_scope_strict"))
        self.assertIn('"podman-private/resources"', err)
        # An enclosing uncapped prefix covers both; a filesystem scope
        # alone walks nothing.
        limits([{"path": os.path.dirname(self.root), "measure": "tree",
                 "uncapped": [os.path.basename(self.root)]}, engine])
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual(code, 0, err)
        limits([{"path": self.root, "measure": "filesystem"}, engine])
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual(code, 0, err)
        # Through a symlinked state root's parent: the real paths compared.
        link = f"{self.world.tmp}/root-link"
        os.symlink(os.path.dirname(self.root), link)
        self.write_config(state_root=f"{link}/{os.path.basename(self.root)}")
        limits([dict(old[0], uncapped=["podman-private/resources", "podman-private/work"]), engine])
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual(code, 0, err)
        limits(old)
        code, _, err = self.run_(("image", "prepare"), ["-t", "p", "podman", "--store", "private"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: storage_scope_strict"))

    def test_podman_needs_an_engine_root(self):
        code, _, err = self.run_(("image", "prepare"), ["podman"], runtime=False)
        self.assertEqual(code, 1)
        self.assertEqual(err.splitlines()[0], "agentbox: image prepare refused: podman_engine_root_unavailable")
        self.assertTrue(err.splitlines()[1].startswith("agentbox: hint: XDG_RUNTIME_DIR is unset"))
        self.assertFalse(os.path.lexists(scopes.limits_path(self.data)))
        # The operator's engine root instead.
        engine = f"{self.world.tmp}/eng"
        self.write_config(podman_engine_root=engine)
        code, _, err = self.run_(("image", "prepare"), ["podman"], runtime=False)
        self.assertEqual(code, 0, err)
        with open(f"{self.podman}/inputs/podman-inputs.json") as stream:
            self.assertEqual(json.load(stream)["storage_root"], engine)
        self.assertIn({"path": engine, "measure": "filesystem"}, self.limits()["storage_scopes"])
        # Not a tmpfs (the accepted types emptied): refused.
        code, _, err = self.run_(("image", "prepare"), ["podman"], extra={"builtin.ENGINE_FILESYSTEMS": ["none"]})
        self.assertEqual(err.splitlines()[0], "agentbox: image prepare refused: podman_engine_root_unsuitable")

    def record(self, run_id):
        with open(f"{self.data}/controller-runs/{run_id}/run.json") as stream:
            return json.load(stream)

    def on(self, command, run_id, args=()):
        argv = self.world.argv(command, list(args), overrides=self.overrides(), run_id=run_id)
        argv[argv.index("--config") + 1] = self.config
        done = subprocess.run(argv, env=self.world.env(self.env()), capture_output=True, timeout=60)
        return done.returncode, done.stdout.decode(), done.stderr.decode()

    def test_another_install_serves_a_builtin_run_with_its_state(self):
        """Prepared, created and checkpointed with install A; A removed,
        install B (another asset tree) execs, stops, restores and discards
        them: the same STATE and resources, B's providers."""
        write_file(f"{self.podman}/behavior.json", dict(self.world.behavior, checkpoints=True))
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual(code, 0, err)
        code, out, err = self.run_(("jail", "create"), ["--retention", "home"])
        self.assertEqual(code, 0, err)
        run_id = out.split()[1]
        recorded = {"builtin": "podman", "state": self.podman}
        self.assertEqual(self.record(run_id)["provider"], recorded)
        resource = self.record(run_id)["resource"]
        code, out, err = self.on(("checkpoint", "create"), run_id)
        self.assertEqual(code, 0, err)
        checkpoint = out.split()[1]
        with open(f"{self.data}/controller-checkpoints/{checkpoint}.json") as stream:
            self.assertEqual(json.load(stream)["provider"], recorded)
        first = self.tree
        self.tree = self.fake_tree(f"{self.world.tmp}/pkg-b")
        shutil.rmtree(first)
        code, out, err = self.on(("jail", "exec"), run_id, ["--", "true"])
        self.assertEqual(code, 0, err)
        self.assertIn("outcome=completed", out)
        code, out, err = self.on(("jail", "stop"), run_id)
        self.assertEqual(code, 0, err)
        code, out, err = self.on(("checkpoint", "restore"), checkpoint, [])
        self.assertEqual(code, 0, err)
        restored = out.split()[1]
        self.assertEqual(self.record(restored)["provider"], recorded)
        for target in (run_id, restored):
            code, _, err = self.on(("jail", "discard"), target)
            self.assertEqual(code, 0, err)
        code, _, err = self.on(("checkpoint", "discard"), checkpoint)
        self.assertEqual(code, 0, err)
        log = _lines(f"{self.podman}/log.jsonl")
        self.assertIn(resource, [e.get("resource") for e in log if e.get("type") == "discard"])
        self.assertTrue(any(e.get("type") == "start" and e.get("resource") == resource for e in log), log)
        # The tag too: a new run from B, no new prepare.
        code, out, err = self.run_(("jail", "create"))
        self.assertEqual(code, 0, err)
        # No packaged providers in the running install: refused, nothing
        # falls back.
        shutil.rmtree(f"{self.tree}/providers")
        code, _, err = self.on(("jail", "discard"), out.split()[1])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: jail discard refused: builtin_unavailable"))

    def test_a_custom_provider_named_like_a_builtin_keeps_its_paths(self):
        """--provider-config naming `podman`: recorded whole, used as
        recorded; never replaced by the running install's built-in."""
        custom = f"{self.world.tmp}/custom-tree"
        shutil.copytree(self.tree, custom)
        state = f"{self.world.tmp}/custom-state"
        os.mkdir(state, 0o700)
        write_file(f"{state}/behavior.json", self.world.behavior)
        os.makedirs(f"{state}/inputs")
        write_file(f"{state}/inputs/recipe.json", "{}")
        config = {"schema": "agentbox.provider-config.v1", "provider": "podman", "interpreter": sys.executable,
                  "entry": f"{custom}/providers/podman.py", "state": state, "assets": custom}
        path = f"{self.world.tmp}/custom.json"
        write_file(path, config)
        self.write_config()
        with open(scopes.limits_path(self.data), "w") as stream:
            json.dump({"max_reserved_bytes": 1 << 40, "storage_scopes": [{"path": state, "measure": "tree"}]},
                      stream)
        os.chmod(scopes.limits_path(self.data), 0o600)
        code, _, err = self.run_(("image", "prepare"), ["-t", "mine", "podman", "--provider-config", path,
                                                        "--recipe", f"{state}/inputs/recipe.json"])
        self.assertEqual(code, 0, err)
        self.assertEqual((self.tag("mine")["profile"], self.tag("mine")["provider"]), ("custom", config))
        code, out, err = self.run_(("jail", "create"), ["--image", "mine"])
        self.assertEqual(code, 0, err)
        run_id = out.split()[1]
        self.assertEqual(self.record(run_id)["provider"], config)
        self.assertTrue(any(e.get("type") == "create" for e in _lines(f"{state}/log.jsonl")))
        # Its tree gone: refused, the built-in install never stands in.
        shutil.rmtree(custom)
        code, _, err = self.on(("jail", "discard"), run_id)
        self.assertEqual((code, err), (1, "agentbox: jail discard refused: provider_untrusted\n"))
        self.assertFalse(os.path.lexists(f"{self.podman}/log.jsonl"))

    def test_recorded_providers_are_closed(self):
        from agentbox_controller.config import check_recorded
        good = {"builtin": "qemu", "state": "/s/qemu"}
        self.assertEqual(check_recorded(good), good)
        for bad in ({"builtin": "standin", "state": "/s"}, {"builtin": "qemu"}, {"builtin": "qemu", "state": "s"},
                    dict(good, assets="/a"), dict(good, provider="qemu")):
            with self.assertRaises(HostError):
                check_recorded(bad)
        tag = {"schema": images.TAG_SCHEMA, "name": "t", "provider": good, "image": "a" * 64,
               "worker_release": "b" * 64, "recipe": "images/qemu/default/agentbox.pkr.hcl", "profile": "builtin"}
        self.assertEqual(images.check_tag(tag, "t"), tag)
        podman_tag = dict(tag, provider={"builtin": "podman", "state": "/s/podman"})
        for recipe in ("images/podman/default/Dockerfile", "images/podman/dev/Dockerfile"):
            self.assertEqual(images.check_tag(dict(podman_tag, recipe=recipe), "t"), dict(podman_tag, recipe=recipe))
        for change in ({"profile": "custom"}, {"recipe": "/x/images/qemu/default/agentbox.pkr.hcl"},
                       {"recipe": "images/qemu/agentbox.pkr.hcl"}, {"recipe": "images/podman/default/Dockerfile"},
                       {"recipe": "images/qemu/default/../agentbox.pkr.hcl"}):
            with self.assertRaises(HostError):
                images.check_tag(dict(tag, **change), "t")
        for recipe in ("images/podman/Dockerfile", "images/qemu/default/agentbox.pkr.hcl"):
            with self.assertRaises(HostError):
                images.check_tag(dict(podman_tag, recipe=recipe), "t")
        # The presets are exactly these paths.
        self.assertEqual(builtin.PRESETS, {
            "podman": {"default": "images/podman/default/Dockerfile", "dev": "images/podman/dev/Dockerfile"},
            "qemu": {"default": "images/qemu/default/agentbox.pkr.hcl"}})
        self.assertEqual(builtin.QEMU_PINS, "images/qemu/default/inputs.lock.json")

    def test_profile_refusals(self):
        code, _, err = self.run_(("image", "prepare"), ["standin"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: provider_unknown"))
        os.chmod(f"{self.tree}/providers", 0o777)
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: builtin_unavailable"))
        os.chmod(f"{self.tree}/providers", 0o755)
        self.write_config(state_root=f"{self.data}/state")
        code, _, err = self.run_(("image", "prepare"), ["podman"])
        self.assertEqual((code, err.splitlines()[0]), (1, "agentbox: image prepare refused: state_root_overlaps"))
        self.assertFalse(os.path.lexists(f"{self.data}/state"))
        self.write_config()
        # Recovery needs no tag (a claimed STATE: one prepare made it).
        code, _, err = self.run_(("image", "prepare"), ["-t", "x", "podman"])
        self.assertEqual(code, 0, err)
        os.unlink(f"{self.data}/images/x")
        code, _, err = self.run_(("image", "recover"), ["podman", "o-" + "0" * 32])
        self.assertEqual((code, err), (1, "agentbox: image recover refused: operation_unknown\n"))


def _slurp(path):
    try:
        with open(path, "rb") as stream:
            return stream.read()
    except FileNotFoundError:
        return None


def _lines(path):
    try:
        with open(path) as stream:
            return [json.loads(line) for line in stream if line.strip()]
    except FileNotFoundError:
        return []


if __name__ == "__main__":
    unittest.main()
