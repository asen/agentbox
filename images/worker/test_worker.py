"""Offline checks of the shared worker builder, the context staging and both
image recipes (README.md here). Synthetic trees under this run's temporary
directory, as this user, and one real assembly of the repository's sources
into fresh temporary output, its completeness checked by importing every
module from the bundle alone in a fresh isolated interpreter. No engine,
Packer, builder guest or network.

  python3 -I -B -m unittest discover -s images/worker -p 'test_*.py'
"""
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
IMAGES = os.path.dirname(HERE)
REPO = os.path.dirname(IMAGES)
sys.path.insert(0, HERE)

import agentlock  # noqa: E402
import stage  # noqa: E402
import worker  # noqa: E402

Refused = worker.Refused
SECRET = "agentbox-test-secret-7f3a"


def slurp(path, mode="r"):
    with open(path, mode) as stream:
        return stream.read()


def write(path, data=b"", perm=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as stream:
        stream.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(path, perm)


class Temp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentbox-worker-test-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)

    def refused(self, code, fn, *args):
        with self.assertRaises(Refused) as caught:
            fn(*args)
        self.assertEqual(str(caught.exception), code)


SOURCE_PY = ["guest/__init__.py", "guest/src/__init__.py", "guest/src/main.py", "guest/src/x.py",
             "acquisitions/__init__.py", "acquisitions/git/__init__.py", "acquisitions/git/jail/__init__.py",
             "acquisitions/git/jail/git.py", "acquisitions/git/jail/y.py"]


def fake_guest(root):
    """A repository with the worker allowlist (the guest's packages and a
    handler's jail package) plus everything that must stay out; returns
    `root`."""
    for name in SOURCE_PY:
        write(os.path.join(root, name), "pass\n")
    for noise in ("dist/main.js", "node_modules/x/index.js", "test/test_main.py", "test/__init__.py",
                  "HUMAN.md", ".env", "home/AGENTS.md", "home/CLAUDE.md", "README.md", "auth.json",
                  "src/__pycache__/main.cpython-314.pyc", "__pycache__/x.pyc"):
        write(os.path.join(root, "guest", noise), SECRET)
    # Host code, tests, fixtures and caches beside the jail packages: never sources.
    for noise in ("lib/agentbox_handler.py", "lib/jail/x.py", "git/host/worker.py", "git/manifest.json",
                  "testing/memo/jail/memo.py", "testing/jail/x.py", "__pycache__/x.pyc", "test_x.py",
                  "README.md", "npm/host/worker.py", "git/jail/__pycache__/git.cpython-314.pyc"):
        write(os.path.join(root, "acquisitions", noise), SECRET)
    write(os.path.join(root, ".git", "config"), SECRET)
    write(os.path.join(root, "HUMAN.md"), SECRET)
    return root


class Sources(Temp):
    def test_only_the_allowlist_is_staged(self):
        guest = fake_guest(self.tmp)
        files = worker.stage_sources(guest, self.path("staged"))
        self.assertEqual([f["path"] for f in files], sorted(SOURCE_PY))
        self.assertEqual(worker.handler_jails(guest), ["git"])
        staged = [rel for rel, kind, _, _ in worker.scan(self.path("staged")) if kind == "file"]
        self.assertEqual(sorted(staged), [f["path"] for f in files])
        self.assertEqual(worker.source_revision(files), worker.source_revision(worker.source_files(guest)))

    def test_unexpected_source_entries_are_refused(self):
        src = lambda g, *p: os.path.join(g, "guest", "src", *p)  # noqa: E731
        jail = lambda g, *p: os.path.join(g, "acquisitions", "git", "jail", *p)  # noqa: E731
        for name, make in [
            ("link", lambda g: os.symlink("/etc/passwd", src(g, "link.py"))),
            ("dir link", lambda g: os.symlink(self.tmp, src(g, "up"))),
            ("hard link", lambda g: os.link(src(g, "main.py"), src(g, "b.py"))),
            ("protected", lambda g: write(src(g, "HUMAN.md"))),
            ("other suffix", lambda g: write(src(g, "notes.txt"))),
            ("typescript", lambda g: write(src(g, "x.ts"))),
            ("bytecode", lambda g: write(src(g, "x.pyc"))),
            ("dotfile", lambda g: write(src(g, ".hidden.py"))),
            ("module name", lambda g: write(src(g, "request-main.py"))),
            ("fifo", lambda g: os.mkfifo(src(g, "f.py"))),
            ("subpackage", lambda g: write(src(g, "inner", "x.py"))),
            ("no package marker", lambda g: os.unlink(src(g, "__init__.py"))),
            ("guest marker link", lambda g: (os.unlink(os.path.join(g, "guest", "__init__.py")),
                                             os.symlink("src/__init__.py", os.path.join(g, "guest", "__init__.py")))),
            ("jail link", lambda g: os.symlink("/etc/passwd", jail(g, "link.py"))),
            ("jail ready js", lambda g: write(jail(g, "ready.js"))),
            ("jail protected", lambda g: write(jail(g, "HUMAN.md"))),
            ("jail without marker", lambda g: os.unlink(jail(g, "__init__.py"))),
            ("handler without marker", lambda g: os.unlink(os.path.join(g, "acquisitions", "git", "__init__.py"))),
            ("jail dir link", lambda g: os.symlink(jail(g), os.path.join(g, "acquisitions", "pip", "jail"))
             if os.makedirs(os.path.join(g, "acquisitions", "pip")) is None else None),
            ("handlers marker missing", lambda g: os.unlink(os.path.join(g, "acquisitions", "__init__.py"))),
            ("oversized", lambda g: write(src(g, "big.py"), b"#" * (worker.SOURCES["max_source_bytes"] + 1))),
        ]:
            with self.subTest(name):
                root = self.path(name.replace(" ", "-"))
                repo = fake_guest(root)
                make(repo)
                with self.assertRaises((Refused, OSError)):
                    worker.stage_sources(repo, os.path.join(root, "staged"))


def synthetic_bundle(root, modules=None):
    """A valid bundle at `root` (tiny modules, never run)."""
    modules = modules or {
        "guest/__init__.py": "",
        "guest/src/__init__.py": "",
        "guest/src/main.py": "from guest.src import protocol\n",
        "guest/src/anchor.py": "pass\n",
        "guest/src/request_main.py": "from guest.src import protocol\n",
        "guest/src/protocol.py": "A = 1\n",
        "acquisitions/__init__.py": "",
        "acquisitions/pip/jail/pip.py": "from guest.src import protocol\n",
        "acquisitions/npm/jail/npm.py": "from guest.src import protocol\n",
        "acquisitions/git/jail/git.py": "from acquisitions.git.jail import main\n",
        "acquisitions/git/jail/main.py": "from guest.src.protocol import A\n",
    }
    entries = []

    def put(rel, data, perm=0o644):
        write(os.path.join(root, rel), data, perm)
        size, digest = worker.measured(os.path.join(root, rel))
        entries.append({"path": rel, "size": size, "sha256": digest})

    for name, text in modules.items():
        put(name, text)
    data = worker.manifest_bytes(sorted(entries, key=lambda e: e["path"]), "a" * 64)
    write(os.path.join(root, worker.MANIFEST), data)
    return data


def rewrite_manifest(root, change):
    path = os.path.join(root, worker.MANIFEST)
    with open(path) as stream:
        manifest = json.load(stream)
    change(manifest)
    write(path, json.dumps(manifest))


class Bundle(Temp):
    def test_a_valid_bundle(self):
        data = synthetic_bundle(self.path("b"))
        release, files = worker.validate(self.path("b"))
        self.assertEqual(release, hashlib.sha256(data).hexdigest())
        self.assertIn("guest/src/main.py", files)
        self.assertEqual(worker.entrypoints(files), tuple(sorted(worker.ENTRYPOINTS)))

    def test_stale_missing_linked_and_mismatched_payloads_are_refused(self):
        cases = [
            ("stale extra file", "entry", lambda r: write(os.path.join(r, "guest", "src", "request.py"), "old")),
            ("stale bytecode", "entry", lambda r: write(os.path.join(r, "guest", "src", "__pycache__", "x.pyc"))),
            ("stale extra dir", "entry", lambda r: os.mkdir(os.path.join(r, "guest", "old"))),
            ("missing file", "entry", lambda r: os.unlink(os.path.join(r, "guest", "src", "protocol.py"))),
            ("symlinked file", "entry", lambda r: (os.unlink(os.path.join(r, "guest", "src", "protocol.py")),
                                                   os.symlink("main.py", os.path.join(r, "guest", "src", "protocol.py")))),
            ("hard link", "entry", lambda r: os.link(os.path.join(r, "guest", "src", "protocol.py"),
                                                     os.path.join(self.tmp, "hl-" + os.path.basename(r)))),
            ("changed bytes", "digest", lambda r: write(os.path.join(r, "guest", "src", "protocol.py"), "A = 2\n")),
            ("protected name", "path", lambda r: rewrite_manifest(r, lambda m: m["files"].append(
                {"path": "guest/HUMAN.md", "size": 0, "sha256": "0" * 64}))),
            ("traversal", "path", lambda r: rewrite_manifest(r, lambda m: m["files"].insert(
                0, {"path": "guest/../x", "size": 0, "sha256": "0" * 64}))),
            ("outside top dirs", "path", lambda r: rewrite_manifest(r, lambda m: m["files"].insert(
                0, {"path": "etc/x", "size": 0, "sha256": "0" * 64}))),
            ("a root file", "path", lambda r: rewrite_manifest(r, lambda m: m["files"].insert(
                0, {"path": "package.json", "size": 0, "sha256": "0" * 64}))),
            ("unsorted", "path", lambda r: rewrite_manifest(r, lambda m: m["files"].reverse())),
            ("required missing", "required", lambda r: rewrite_manifest(r, lambda m: m.__setitem__(
                "files", [f for f in m["files"] if f["path"] != "guest/src/anchor.py"]))),
            ("package marker missing", "required", lambda r: rewrite_manifest(r, lambda m: m.__setitem__(
                "files", [f for f in m["files"] if f["path"] != "guest/src/__init__.py"]))),
            ("unknown field", "manifest", lambda r: rewrite_manifest(r, lambda m: m.__setitem__("x", 1))),
            ("v2 node major", "manifest", lambda r: rewrite_manifest(r, lambda m: m.__setitem__(
                "node_min_major", 24))),
            ("bundled interpreter", "path", lambda r: rewrite_manifest(r, lambda m: m["files"].append(
                {"path": "python/bin/python3", "size": 0, "sha256": "0" * 64}))),
            ("root link", "entry", None),
        ]
        for name, code, change in cases:
            with self.subTest(name):
                root = self.path(name.replace(" ", "-"))
                synthetic_bundle(root)
                if change is None:
                    os.symlink(root, root + "-link")
                    root += "-link"
                else:
                    change(root)
                self.refused(code, worker.validate, root)

    def test_listed_jail_entry_modules_are_entrypoints(self):
        memo = "acquisitions/memo/jail/memo.py"
        self.assertIn(memo, worker.entrypoints([memo]))
        # Only `acquisitions/ID/jail/ID.py` is an entry; another module there is not.
        self.assertEqual(worker.entrypoints(["acquisitions/memo/jail/other.py", "acquisitions/memo/memo.py",
                                             "acquisitions/memo/jail/memo.js"]),
                         tuple(sorted(worker.ENTRYPOINTS)))

    def test_counterparts_are_plain_ready_modules(self):
        good = self.path("good")
        write(os.path.join(good, "memo.py"), "pass\n")
        write(os.path.join(good, "a-1.py"), "pass\n")
        self.assertEqual([n for n, _ in worker.counterparts(good)], ["a-1.py", "memo.py"])
        self.assertEqual(worker.counterparts(None), [])
        for name, change in [
            ("bad name", lambda d: write(os.path.join(d, "Memo.py"), "")),
            ("not py", lambda d: write(os.path.join(d, "memo.js"), "")),
            ("subdir", lambda d: write(os.path.join(d, "x", "memo.py"), "")),
            ("link", lambda d: os.symlink(os.path.join(good, "memo.py"), os.path.join(d, "memo.py"))),
            ("hard link", lambda d: os.link(os.path.join(good, "memo.py"), os.path.join(d, "memo.py"))),
        ]:
            with self.subTest(name):
                bad = self.path(name.replace(" ", "-"))
                os.mkdir(bad)
                change(bad)
                self.refused("counterpart", worker.counterparts, bad)

    def test_the_manifest_names_no_runtime(self):
        root = self.path("ok")
        synthetic_bundle(root)
        manifest = json.loads(slurp(os.path.join(root, worker.MANIFEST)))
        self.assertEqual(sorted(manifest), sorted(worker.KEYS))
        for key in ("node_min_major", "node_version", "python"):
            self.assertNotIn(key, manifest)
        self.assertFalse([f for f in manifest["files"] if f["path"].split("/")[0] not in ("guest", "acquisitions")])

    def test_seal_makes_everything_read_only(self):
        root = self.path("b")
        synthetic_bundle(root)
        worker.seal(root, os.getuid(), os.getgid())
        for rel, kind, _, st in worker.scan(root):
            expected = 0o555 if kind == "dir" else 0o444
            self.assertEqual(stat.S_IMODE(st.st_mode), expected, rel)
        self.assertEqual(worker.validate(root)[0], hashlib.sha256(
            slurp(os.path.join(root, worker.MANIFEST), "rb")).hexdigest())
        for rel, kind, _, _ in worker.scan(root):
            if kind == "dir":
                os.chmod(os.path.join(root, rel) if rel else root, 0o755)

    def test_metadata_must_name_the_bundle(self):
        data = synthetic_bundle(self.path("b"))
        release = hashlib.sha256(data).hexdigest()
        good = {"schema": worker.METADATA["schema"], "release": release, "install_root": worker.INSTALL_ROOT,
                "manifest": data.decode()}
        write(self.path("good.json"), json.dumps(good))
        worker.check_metadata(self.path("good.json"), release)
        for name, change in [("release", {"release": "0" * 64}), ("manifest", {"manifest": "{}"}),
                             ("root", {"install_root": "/tmp/x"}), ("schema", {"schema": "x"}),
                             ("v1 schema", {"schema": "agentbox.worker-build.v1"})]:
            with self.subTest(name):
                write(self.path(name.replace(" ", "-") + ".json"), json.dumps(dict(good, **change)))
                self.refused("metadata", worker.check_metadata, self.path(name.replace(" ", "-") + ".json"),
                             release)

    def test_seal_installed_refuses_a_nonroot_run(self):
        if os.geteuid() == 0:
            self.skipTest("runs as root")
        self.refused("root", worker.seal_installed, self.path("b"), self.path("m.json"))


PYTHON = sys.executable
# Every module of a bundle imported by absolute name from the bundle alone,
# in a fresh isolated interpreter: sys.path is the bundle root and the
# standard library only; each must come from the bundle.
IMPORT_ALL = """
import importlib, json, sys
root = sys.argv[1]
sys.path[:] = [root] + [p for p in sys.path[1:] if "site-packages" not in p and "dist-packages" not in p]
names = []
for entry in json.load(open(root + "/manifest.json"))["files"]:
    name = entry["path"][:-3].replace("/", ".")
    names.append(name[:-len(".__init__")] if name.endswith(".__init__") else name)
for name in names:
    module = importlib.import_module(name)
    assert module.__file__.startswith(root + "/"), name
print(len(names))
"""


def import_all(bundle):
    return subprocess.run([PYTHON, "-I", "-S", "-B", "-c", IMPORT_ALL, bundle], cwd="/",
                          env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL, capture_output=True,
                          timeout=60, check=False)


class RealBuild(Temp):
    """The repo's sources through the real builder, offline; nothing of
    them runs in this process."""

    def build(self, name, counterparts=None):
        stage.stage_podman(REPO, self.path(name), counterparts)
        ctx = self.path(name, "context")
        out = self.path(name, "out")
        metadata = worker.build(os.path.join(ctx, "worker-src"), out,
                                os.path.join(ctx, "worker-counterparts"))
        return ctx, out, metadata

    def test_the_repository_assembles_into_a_complete_measured_bundle(self):
        ctx, out, metadata = self.build("a")
        bundle = os.path.join(out, "worker")
        release, files = worker.validate(bundle)
        with open(os.path.join(bundle, worker.MANIFEST), "rb") as stream:
            manifest_data = stream.read()
        manifest = json.loads(manifest_data)
        for entry in manifest["files"]:
            self.assertEqual(worker.measured(os.path.join(bundle, entry["path"])),
                             (entry["size"], entry["sha256"]), entry["path"])
        # Exactly the staged sources: Python source only, every package a
        # regular one, no test, cache or bytecode.
        self.assertEqual(sorted(files), [f["path"] for f in metadata["sources"]["files"]])
        for path in files:
            self.assertTrue(path.endswith(".py"), path)
            self.assertNotIn("__pycache__", path)
            self.assertNotIn("/test", path)
        packages = {os.path.dirname(path) for path in files}
        for package in packages:
            self.assertIn(package + "/__init__.py", files)
        for name in worker.ENTRYPOINTS:
            self.assertIn(name, files)
        # Complete: every module imports from the bundle alone.
        imported = import_all(bundle)
        self.assertEqual((imported.returncode, imported.stdout.strip()), (0, str(len(files)).encode()),
                         imported.stderr.decode()[-2000:])
        # Every module parses as Python 3.12.
        import ast
        for path in files:
            ast.parse(slurp(os.path.join(bundle, path)), path, feature_version=(3, 12))
        # Metadata: separate from the bundle, naming it exactly.
        self.assertEqual(metadata["release"], release)
        self.assertEqual(metadata["manifest"].encode(), manifest_data)
        self.assertEqual(metadata["sources"]["revision"], manifest["revision"])
        self.assertEqual(metadata["sources"]["files"], worker.source_files(os.path.join(ctx, "worker-src")))
        for key in ("compile", "modules"):
            self.assertNotIn(key, metadata)
        worker.check_metadata(os.path.join(out, worker.METADATA["file"]), release)
        self.assertNotIn(worker.METADATA["file"], os.listdir(bundle))
        # The same inputs assemble the same bundle.
        _, _, again = self.build("b")
        self.assertEqual(again["release"], release)

    def test_an_additional_handler_package_joins_the_bundle(self):
        sources = self.path("sources")
        worker.stage_sources(REPO, sources)
        jail = os.path.join(sources, "acquisitions", "demo", "jail")
        write(os.path.join(sources, "acquisitions", "demo", "__init__.py"), "")
        write(os.path.join(jail, "__init__.py"), "")
        write(os.path.join(jail, "demo.py"),
              "if __name__ == '__main__':\n"
              "    import os, sys\n"
              "    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname("
              "os.path.abspath(__file__))))))\n"
              "import sys\n"
              "from acquisitions.demo.jail.message import MESSAGE\n"
              "from guest.src.counterpart import operation_shim, serve\n"
              "async def request(given):\n"
              "    given.print(MESSAGE)\n"
              "    return 0\n"
              "if __name__ == '__main__':\n"
              "    sys.exit(serve(sys.argv[1:], {'demo': operation_shim('demo', request)}))\n")
        write(os.path.join(jail, "message.py"), "MESSAGE = 'demo handler loaded'\n")
        out = self.path("out")
        metadata = worker.build(sources, out)
        bundle = os.path.join(out, "worker")
        _, files = worker.validate(bundle)
        entry = "acquisitions/demo/jail/demo.py"
        self.assertIn(entry, files)
        self.assertIn("acquisitions/demo/jail/message.py", files)
        self.assertIn(entry, metadata["entrypoints"])
        probe = subprocess.run([PYTHON, "-I", "-S", "-B", os.path.join(bundle, entry), "shim", "demo", "show", "{}"],
                               cwd="/", env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=60, check=False)
        self.assertEqual((probe.returncode, probe.stdout, probe.stderr), (0, b"demo handler loaded\n", b""))

    def test_a_ready_counterpart_joins_the_bundle(self):
        counterparts = os.path.join(REPO, "acquisitions", "testing", "memo", "jail")
        ctx, out, metadata = self.build("c", counterparts)
        self.assertEqual(os.listdir(os.path.join(ctx, "worker-counterparts")), ["memo.py"])
        bundle = os.path.join(out, "worker")
        release, files = worker.validate(bundle)
        memo = "acquisitions/memo/jail/memo.py"
        self.assertEqual(worker.measured(os.path.join(bundle, memo)),
                         worker.measured(os.path.join(counterparts, "memo.py")))
        self.assertIn(memo, metadata["entrypoints"])
        self.assertEqual(metadata["counterparts"], [{"path": memo, "size": files[memo][0],
                                                     "sha256": files[memo][1]}])
        worker.check_metadata(os.path.join(out, worker.METADATA["file"]), release)
        # It runs from the bundle alone: without a request context, a fixed local line.
        probe = subprocess.run([PYTHON, "-I", "-S", "-B", os.path.join(bundle, memo), "shim", "memo", "a", "b"],
                               cwd="/", env={"PATH": "/usr/bin:/bin"},
                               stdin=subprocess.DEVNULL, capture_output=True, timeout=60, check=False)
        self.assertEqual((probe.returncode, probe.stdout),
                         (3, b'memo: {"ok":false,"code":"request_unavailable","cleanup":"observed"}\n'),
                         probe.stderr)
        # A path the sources provide is refused.
        clash = self.path("clash")
        write(os.path.join(clash, "git.py"), "pass\n")
        self.refused("counterpart", worker.build, os.path.join(ctx, "worker-src"), self.path("c", "out2"), clash)

    def test_a_tampered_staged_source_is_refused(self):
        stage.stage_podman(REPO, self.path("s"))
        ctx = self.path("s", "context")
        for extra in ("guest/src/extra.txt", "acquisitions/git/host/worker.py", "acquisitions/x.py",
                      "guest/test/test_x.py"):
            write(os.path.join(ctx, "worker-src", extra), "x")
            with self.assertRaises(Refused):
                worker.build(os.path.join(ctx, "worker-src"), self.path("out1"))
            os.unlink(os.path.join(ctx, "worker-src", extra))
            shutil.rmtree(self.path("out1"), ignore_errors=True)


class Context(Temp):
    def fake_repo(self):
        repo = self.path("repo")
        guest = os.path.join(fake_guest(repo), "guest")
        write(os.path.join(guest, "home", "AGENTS.md"), "guidance\n")
        write(os.path.join(guest, "home", "CLAUDE.md"), "guidance\n")
        return repo

    def assert_clean(self, root):
        for rel, kind, _, _ in worker.scan(root):
            self.assertNotIn(".git", rel.split("/"))
            self.assertNotEqual(os.path.basename(rel).lower(), "human.md")
            if kind == "file":
                with open(os.path.join(root, rel), "rb") as stream:
                    self.assertNotIn(SECRET.encode(), stream.read(), rel)

    def test_podman_context_is_exactly_the_allowlist(self):
        repo = self.fake_repo()
        result = stage.stage_podman(repo, self.path("out"))
        ctx = self.path("out", "context")
        self.assertEqual(sorted(os.listdir(ctx)),
                         ["Dockerfile", "agents", "worker", "worker-counterparts", "worker-src"])
        self.assertEqual(os.listdir(os.path.join(ctx, "worker-counterparts")), [])
        self.assertEqual(result["worker"]["counterparts"], [])
        # The agents' tools, never the tracked locks (QEMU's): the build
        # resolves its own.
        self.assertEqual(sorted(e["path"] for e in result["context"]), sorted([
            "Dockerfile", "worker/layout.json", "worker/worker.py", "agents/resolve.sh", "agents/agentlock.py",
            *("worker-src/" + n for n in SOURCE_PY)]))
        for name, source in (("resolve.sh", "agents/resolve.sh"), ("agentlock.py", "worker/agentlock.py")):
            self.assertEqual(slurp(os.path.join(ctx, "agents", name)), slurp(os.path.join(IMAGES, source)))
            self.assertIn(source, [r["path"] for r in result["recipe"]])
        self.assert_clean(ctx)
        self.assertEqual(result["worker"]["sources"]["revision"],
                         worker.source_revision(worker.source_files(os.path.join(ctx, "worker-src"))))
        # Every canonical recipe is measured, one directory per preset; only
        # the default is the context's Dockerfile (a build reads its own copy).
        self.assertEqual([r["path"] for r in result["recipe"] if r["path"].startswith("podman/")],
                         ["podman/default/Dockerfile", "podman/dev/Dockerfile"])
        self.assertEqual(slurp(os.path.join(ctx, "Dockerfile")),
                         slurp(os.path.join(IMAGES, "podman", "default", "Dockerfile")))
        self.assertEqual({r["path"]: r["sha256"] for r in result["recipe"]}["podman/dev/Dockerfile"],
                         worker.measured(os.path.join(IMAGES, "podman", "dev", "Dockerfile"))[1])

    def fake_inputs(self, extras=False):
        inputs = self.path("inputs")
        files = {}
        for name, data in [("base.img", b"base"), ("node-v24.18.0-linux-x64.tar.xz", b"node"), ("git.deb", b"git"),
                           ("extra.deb", b"a")]:
            write(os.path.join(inputs, name), data)
            files[name] = {"file": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        source = {"url": "https://nodejs.test/dist/v24.18.0/node-v24.18.0-linux-x64.tar.xz", "signed": 1,
                  "signer": "A" * 40, "sums_sha256": "0" * 64}
        value = {"schema": stage.INPUTS_SCHEMA,
                 "base": dict(files["base.img"], source={"url": "https://images.test/base.img", "signed": 1}),
                 "node": dict(files["node-v24.18.0-linux-x64.tar.xz"], version="24.18.0", source=source)}
        if extras:
            value.update(git=files["git.deb"], packages=[dict(files["extra.deb"], name="extra", version="1.0")])
        write(os.path.join(inputs, "inputs.json"), json.dumps(value))
        return inputs, value

    def test_qemu_inputs_are_closed_and_exact(self):
        inputs, value = self.fake_inputs(extras=True)
        # A custom recipe's operator extras (git, packages) are still staged.
        loaded, paths = stage.load_inputs(os.path.join(inputs, "inputs.json"))
        self.assertEqual((loaded, paths["git"]), (value, os.path.join(inputs, "git.deb")))
        self.assertEqual(paths["deb:extra.deb"], os.path.join(inputs, "extra.deb"))
        # Without them: the built-in profile's own inputs, nothing for the
        # agents (the build resolves them); Node's provenance optional.
        plain = {k: value[k] for k in ("schema", "base", "node")}
        write(os.path.join(inputs, "plain.json"), json.dumps(plain))
        self.assertEqual(sorted(stage.load_inputs(os.path.join(inputs, "plain.json"))[1]), ["base", "node"])
        bare = dict(plain, node={k: v for k, v in plain["node"].items() if k != "source"})
        write(os.path.join(inputs, "bare.json"), json.dumps(bare))
        self.assertEqual(stage.load_inputs(os.path.join(inputs, "bare.json"))[0], bare)
        # Every file is exactly its declaration.
        write(os.path.join(inputs, "git.deb"), b"not the declared deb")
        self.refused("input_mismatch", stage.load_inputs, os.path.join(inputs, "inputs.json"))
        for name, change in [
            ("unknown key", lambda v: v.__setitem__("extra", 1)),
            ("git without packages", lambda v: v.pop("packages")),
            ("packages without git", lambda v: v.pop("git")),
            ("no node", lambda v: v.pop("node")),
            ("node name", lambda v: v["node"].__setitem__("version", "22.0.0")),
            ("bad file", lambda v: v["packages"][0].__setitem__("file", "../x.deb")),
            ("base source", lambda v: v["base"].__setitem__("source", "x")),
            ("node source", lambda v: v["node"].__setitem__("source", "x")),
            ("node key", lambda v: v["node"].__setitem__("urls", [])),
            ("base key", lambda v: v["base"].__setitem__("url", "x")),
        ]:
            with self.subTest(name):
                bad = json.loads(json.dumps(value))
                change(bad)
                write(os.path.join(inputs, "bad.json"), json.dumps(bad))
                self.refused("inputs", stage.load_inputs, os.path.join(inputs, "bad.json"))

    def test_the_base_has_its_own_2_gib_bound_and_the_rest_share_1_gib(self):
        """By declared size, before anything is read (no large file here):
        the base up to MAX_BASE_BYTES, apart from MAX_INPUT_BYTES; Node,
        extras and the agents' tarballs together up to MAX_INPUT_BYTES."""
        self.assertEqual((stage.MAX_BASE_BYTES, stage.MAX_INPUT_BYTES), (2 << 30, 1 << 30))
        inputs, value = self.fake_inputs()
        path = os.path.join(inputs, "sized.json")
        for declared, code in ((stage.MAX_BASE_BYTES + 1, "limit"), (stage.MAX_BASE_BYTES, "input_mismatch"),
                               (stage.MAX_INPUT_BYTES + 1, "input_mismatch")):
            with self.subTest(base=declared):
                write(path, json.dumps(dict(value, base=dict(value["base"], bytes=declared))))
                self.refused(code, stage.load_inputs, path)
        write(path, json.dumps(dict(value, node=dict(value["node"], bytes=stage.MAX_INPUT_BYTES + 1))))
        self.refused("limit", stage.load_inputs, path)
        # The shared total is exact at its bound; the base's own counter
        # never takes from it.
        node = dict(value["node"], file="node-v24.18.0-linux-x64.tar.xz")
        total = [stage.MAX_INPUT_BYTES - node["bytes"]]
        stage._asset(node, inputs, total)
        self.assertEqual(total, [stage.MAX_INPUT_BYTES])
        self.refused("limit", stage._asset, node, inputs, [stage.MAX_INPUT_BYTES - node["bytes"] + 1])
        base = [stage.MAX_BASE_BYTES - value["base"]["bytes"]]
        stage._asset(value["base"], inputs, base, stage.MAX_BASE_BYTES)
        self.assertEqual(base, [stage.MAX_BASE_BYTES])
        self.assertEqual(stage.load_inputs(os.path.join(inputs, "inputs.json"))[0], value)

    @unittest.skipIf(not os.access(stage.KEYGEN, os.X_OK), "no ssh-keygen")
    def test_qemu_context_seed_and_key_stay_apart(self):
        repo = self.fake_repo()
        inputs, value = self.fake_inputs()
        result = stage.stage_qemu(repo, os.path.join(inputs, "inputs.json"), self.path("q"))
        out = self.path("q")
        self.assertEqual(sorted(os.listdir(out)),
                         ["agentbox.pkrvars.hcl", "build-key", "context", "seed", "stage.json"])
        ctx = os.path.join(out, "context")
        self.assertEqual(sorted(os.listdir(ctx)), ["agents", "context.json", "home", "inputs", "inputs.json",
                                                  "qemu", "worker", "worker-counterparts", "worker-src"])
        # Node alone as input; the agents' tools, no lock or tarball: the
        # guest resolves the agents' latest releases.
        self.assertEqual(os.listdir(os.path.join(ctx, "inputs")), ["node-v24.18.0-linux-x64.tar.xz"])
        self.assertEqual(json.loads(slurp(os.path.join(ctx, "inputs.json"))),
                         {"schema": stage.INPUTS_SCHEMA, "node": value["node"]})
        self.assertEqual(sorted(os.listdir(os.path.join(ctx, "agents"))), ["agentlock.py", "resolve.sh"])
        for name, source in (("resolve.sh", "agents/resolve.sh"), ("agentlock.py", "worker/agentlock.py")):
            self.assertEqual(slurp(os.path.join(ctx, "agents", name)), slurp(os.path.join(IMAGES, source)))
        self.assertEqual(result["node"], value["node"])
        self.assert_clean(ctx)
        private = slurp(os.path.join(out, "build-key", "id_ed25519"))
        public = slurp(os.path.join(out, "build-key", "id_ed25519.pub")).strip()
        self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(out, "build-key")).st_mode), 0o700)
        for root in (ctx, os.path.join(out, "seed")):
            for rel, kind, _, _ in worker.scan(root):
                if kind == "file":
                    text = slurp(os.path.join(root, rel), "rb").decode("utf-8", "replace")
                    self.assertNotIn("PRIVATE KEY", text)
                    self.assertNotIn(private.strip().splitlines()[1], text)
        user_data = slurp(os.path.join(out, "seed", "user-data"))
        self.assertIn(public, user_data)
        self.assertTrue(user_data.startswith("#cloud-config\n"))
        variables = slurp(os.path.join(out, "agentbox.pkrvars.hcl"))
        self.assertIn('context = "%s"' % ctx, variables)
        self.assertIn(value["base"]["sha256"], variables)
        # context.json lists the uploaded tree exactly; the guest re-checks it.
        installer = load_guest_install(ctx)
        self.assertEqual(installer.check_context()["schema"], stage.INPUTS_SCHEMA)
        write(os.path.join(ctx, "worker-src", "guest", "src", "main.py"), "tampered")
        self.refused("context", installer.check_context)
        self.assertEqual(result["seed"], stage.measured_tree(os.path.join(out, "seed")))
        # The agents' resolution and lock rules are part of the recipe
        # identity, as the rest of the guest's scripts.
        measured = {e["path"]: e["sha256"] for e in result["recipe"]}
        self.assertEqual(measured["worker/agentlock.py"], worker.measured(os.path.join(HERE, "agentlock.py"))[1])
        self.assertEqual(measured["agents/resolve.sh"],
                         worker.measured(os.path.join(IMAGES, "agents", "resolve.sh"))[1])
        self.assertEqual([p for p in measured if p.startswith("worker/")],
                         ["worker/worker.py", "worker/layout.json", "worker/stage.py", "worker/agentlock.py"])
        self.assertFalse([p for p in measured if p.endswith("package-lock.json")])
        # The default preset's recipe and guest files, staged as the
        # context's qemu/ whatever their place in the tree.
        self.assertEqual([p for p in measured if p.startswith("qemu/")],
                         ["qemu/default/" + n for n in (stage.QEMU_RECIPE,) + stage.QEMU_GUEST])
        self.assertEqual(sorted(os.listdir(os.path.join(ctx, "qemu"))), ["finalize.sh", "guest-install.py", "profile"])


def integrity(data):
    import base64
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def fake_agents(root, registry=stage.REGISTRY, names=None, version="1.0.0"):
    """Stand-in images/agents at `root`/agents: each agent one registry
    package (`names`, else @fixture/AGENT; claude also a linux-x64 and a
    darwin optional one); their tarballs' bytes by file name."""
    tarballs = {}
    for agent in stage.AGENTS:
        name = names[agent] if names else f"@fixture/{agent}"
        base = name.rsplit("/", 1)[-1]
        data = f"{agent} tarball".encode()
        tarballs[f"{name.lstrip('@').replace('/', '-')}-{version}.tgz"] = data
        packages = {"": {"name": f"agentbox-agent-{agent}", "version": "0.0.0", "dependencies": {name: version}},
                    f"node_modules/{name}": {"version": version,
                                             "resolved": f"{registry}{name}/-/{base}-{version}.tgz",
                                             "integrity": integrity(data)}}
        if agent == "claude":
            for platform, os_name in (("linux-x64", "linux"), ("darwin-arm64", "darwin")):
                extra = f"{agent}-{platform}"
                body = extra.encode()
                packages[f"node_modules/@fixture/{extra}"] = {
                    "version": "1.0.0", "resolved": f"{registry}@fixture/{extra}/-/{extra}-1.0.0.tgz",
                    "integrity": integrity(body), "optional": True, "os": [os_name],
                    "cpu": ["x64" if "x64" in platform else "arm64"]}
                if os_name == "linux":
                    tarballs[f"fixture-{extra}-1.0.0.tgz"] = body
        write(os.path.join(root, "agents", agent, "package.json"),
              json.dumps({"name": f"agentbox-agent-{agent}", "version": "0.0.0", "private": True,
                          "dependencies": {name: version}}))
        write(os.path.join(root, "agents", agent, "package-lock.json"),
              json.dumps({"name": f"agentbox-agent-{agent}", "version": "0.0.0", "lockfileVersion": 3,
                          "requires": True, "packages": packages}))
    return os.path.join(root, "agents"), tarballs


def load_guest_install(ctx=None):
    """guest-install.py (staged in `ctx`, else the tree's) loaded in this
    process, without writing bytecode."""
    path = os.path.join(ctx, "qemu", "guest-install.py") if ctx else os.path.join(stage.QEMU, "guest-install.py")
    spec = importlib.util.spec_from_file_location("guest_install_" + str(abs(hash(path))), path)
    module = importlib.util.module_from_spec(spec)
    saved, flag = sys.modules.get("worker"), sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = flag
        if saved is not None:
            sys.modules["worker"] = saved
    return module


def minimal_context(root):
    """A context with the builder, guest-install.py and a matching
    context.json: enough for its import and check_context."""
    ctx = os.path.join(root, "context")
    for name in ("worker.py", "layout.json"):
        stage.copy_file(os.path.join(HERE, name), os.path.join(ctx, "worker", name))
    stage.stage_agent_tools(ctx)
    stage.copy_file(os.path.join(IMAGES, "qemu", "default", "guest-install.py"),
                    os.path.join(ctx, "qemu", "guest-install.py"))
    write(os.path.join(ctx, "inputs.json"), json.dumps({"schema": stage.INPUTS_SCHEMA}))
    stage.write_json(os.path.join(ctx, "context.json"), {"files": stage.measured_tree(ctx)})
    return ctx


class FakeSandbox:
    """guest-install's Sandbox for an unprivileged test: the same calls,
    run directly (PATH: `path` first), no account or namespace; what it was
    asked recorded."""

    def __init__(self, installer, root, path=None):
        self.installer, self.root, self.path = installer, root, path
        self.home = os.path.join(root, "home")
        os.makedirs(self.home, exist_ok=True)
        self.calls, self.owned, self.released, self.stops = [], [], [], 0
        self.evidence = {"isolated": True}

    def private(self, name):
        path = os.path.join(self.root, name)
        os.mkdir(path, 0o700)
        return path

    def run(self, argv, online=False, code="command", timeout=1800):
        self.calls.append((argv, online))
        env = dict(self.installer.ENV, HOME=self.home, TMPDIR=self.home)
        if self.path:
            env["PATH"] = f"{self.path}:/usr/bin:/bin"
        try:
            return self.installer.run(argv, env=env, cwd=self.home, code=code, timeout=timeout)
        finally:
            self.stops += 1

    def check_online(self):
        self.evidence["online"] = {"network": "build"}

    def own(self, path):
        self.owned.append(path)

    def release(self, path):
        self.released.append(path)


class GuestSandbox(Temp):
    """Check the sandbox command and probe verdict, not isolation itself."""

    def test_the_sandbox_command_drops_everything_before_the_program(self):
        installer = load_guest_install()
        box = installer.Sandbox.__new__(installer.Sandbox)
        box.uid, box.gid = 990, 991
        self.assertEqual(box.argv(["/usr/local/bin/npm", "ci"]), [
            "/usr/bin/unshare", "--net", "--mount", "--propagation", "private", "--",
            "/bin/sh", "-c", '/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run && exec "$@"', "sh",
            "/usr/bin/setpriv", "--reuid=990", "--regid=991", "--clear-groups", "--no-new-privs", "--inh-caps=-all",
            "--bounding-set=-all", "--", "/usr/local/bin/npm", "ci"])
        installer.SANDBOX = None
        self.refused("sandbox", installer.untrusted, ["/bin/true"])
        # Online: no new network namespace, the same private /run with the
        # guest's resolver copied in (root, before setpriv), then the same
        # privileges dropped.
        box.resolver = ("/run/systemd/resolve/stub-resolv.conf", "/var/tmp/agentbox-held-x/resolv.conf")
        self.assertEqual(box.argv(["/usr/local/bin/npm", "view"], online=True), [
            "/usr/bin/unshare", "--mount", "--propagation", "private", "--",
            "/bin/sh", "-c", "/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run "
            "&& /usr/bin/mkdir -p /run/systemd/resolve && /usr/bin/cp /var/tmp/agentbox-held-x/resolv.conf "
            "/run/systemd/resolve/stub-resolv.conf && /usr/bin/chmod 0644 /run/systemd/resolve/stub-resolv.conf "
            "&& exec \"$@\"", "sh",
            "/usr/bin/setpriv", "--reuid=990", "--regid=991", "--clear-groups", "--no-new-privs", "--inh-caps=-all",
            "--bounding-set=-all", "--", "/usr/local/bin/npm", "view"])
        box.resolver = None
        self.assertEqual(box.argv(["x"], online=True)[7], '/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev '
                                                          'tmpfs /run && exec "$@"')
        self.assertEqual(installer.run_entries("/run/systemd/resolve/stub-resolv.conf"),
                         ["systemd", "systemd/resolve", "systemd/resolve/stub-resolv.conf"])

    def test_only_an_isolated_observation_passes(self):
        installer = load_guest_install()
        good = {"uid": 990, "gid": 991, "groups": [], "netns": "net:[2]", "interfaces": ["lo"],
                "connect": {"10.0.2.2": 101, "10.0.2.3": 101, "1.1.1.1": 101}, "dns": "failed", "run": []}
        evidence = installer.isolated(good, 990, 991, "net:[1]")
        self.assertEqual(evidence["isolated"], True)
        self.assertEqual(evidence["connect"], {"1.1.1.1": "ENETUNREACH", "10.0.2.2": "ENETUNREACH",
                                               "10.0.2.3": "ENETUNREACH"})
        for name, change in [("root", {"uid": 0}), ("group", {"groups": [27]}), ("same netns", {"netns": "net:[1]"}),
                             ("an interface", {"interfaces": ["eth0", "lo"]}), ("dns", {"dns": "resolved"}),
                             ("run", {"run": ["dbus"]}), ("gateway", {"connect": dict(good["connect"], **{
                                 "10.0.2.2": 111})}), ("connected", {"connect": dict(good["connect"], **{
                                 "1.1.1.1": 0})}), ("probe missing", {"connect": {"1.1.1.1": 101}})]:
            with self.subTest(name):
                self.refused("sandbox", installer.isolated, dict(good, **change), 990, 991, "net:[1]")

    def test_only_the_expected_online_observation_passes(self):
        installer = load_guest_install()
        run = installer.run_entries("/run/systemd/resolve/stub-resolv.conf")
        good = {"uid": 990, "gid": 991, "groups": [], "netns": "net:[1]", "run": run, "dns": "resolved"}
        self.assertEqual(installer.online(good, 990, 991, "net:[1]", run),
                         {"network": "build", "run": run, "dns": "resolved", "scripts": "off"})
        for name, change in [("root", {"uid": 0}), ("group", {"groups": [27]}), ("other netns", {"netns": "net:[2]"}),
                             ("more of /run", {"run": run + ["dbus"]}), ("no resolver", {"run": []}),
                             ("no dns", {"dns": "failed"})]:
            with self.subTest(name):
                self.refused("sandbox", installer.online, dict(good, **change), 990, 991, "net:[1]", run)


class Bytecode(Temp):
    """Production entrypoints, run fresh with real interpreter flags, leave
    the staged or shipped trees unchanged."""

    def test_guest_install_import_keeps_its_context_exact(self):
        for flags in (["-I"], ["-I", "-B"]):
            with self.subTest(flags=flags):
                ctx = minimal_context(self.path("-".join(flags)))
                before = stage.measured_tree(ctx)
                # An argument is refused before any effect, but after the
                # module-level import of the staged builder.
                out = subprocess.run([PYTHON, *flags, os.path.join(ctx, "qemu", "guest-install.py"), "check"],
                                     capture_output=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
                self.assertEqual(out.returncode, 1)
                self.assertIn(b"refused: usage", out.stderr)
                self.assertEqual(stage.measured_tree(ctx), before)
                self.assertFalse([rel for rel, _, _, _ in worker.scan(ctx) if "__pycache__" in rel])
                check = ("import importlib.util, sys; sys.dont_write_bytecode = True; "
                         "spec = importlib.util.spec_from_file_location('g', sys.argv[1]); "
                         "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); "
                         "print(m.check_context()['schema'])")
                out = subprocess.run([PYTHON, *flags, "-c", check, os.path.join(ctx, "qemu", "guest-install.py")],
                                     capture_output=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
                self.assertEqual((out.returncode, out.stdout.strip()), (0, stage.INPUTS_SCHEMA.encode()),
                                 out.stderr)

    def test_stage_import_leaves_the_shipped_builder_unchanged(self):
        tools = self.path("images", "worker")
        for name in ("stage.py", "agentlock.py", "worker.py", "layout.json"):
            stage.copy_file(os.path.join(HERE, name), os.path.join(tools, name))
        before = sorted(os.listdir(tools))
        out = subprocess.run([PYTHON, "-I", os.path.join(tools, "stage.py")], capture_output=True, timeout=60,
                             env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(out.returncode, 1)
        self.assertIn(b"refused: usage", out.stderr)
        self.assertEqual(sorted(os.listdir(tools)), before)


class NodeMinimum(Temp):
    def test_the_images_node_check_is_npm_s_minimum_not_the_workers(self):
        installer = load_guest_install()
        installer.SANDBOX = FakeSandbox(installer, self.tmp)
        minimum = installer.NODE_MAJOR
        self.assertEqual((minimum, stage.NODE_MAJOR), (24, 24))
        self.assertNotIn("min_node_major", json.dumps(worker.LAYOUT))
        for major, ok in ((minimum, True), (minimum + 1, True), (minimum - 1, False), ("x", False)):
            with self.subTest(major=major):
                node = self.path(f"node-{major}")
                write(node, f"#!/bin/sh\necho {major}\n", 0o755)
                if ok:
                    installer.check_node(node)
                else:
                    self.refused("node_version", installer.check_node, node)
        self.assertTrue(stage.node_version_ok(f"{minimum + 1}.0.0"))
        self.assertFalse(stage.node_version_ok(f"{minimum - 1}.9.9"))
        for bad in (f"{minimum}.1.0-rc.1", f"0{minimum}.1.0", f"{minimum}.1", f"v{minimum}.1.0"):
            self.assertFalse(stage.node_version_ok(bad), bad)


def node_archive(path, version, top=tarfile.DIRTYPE, extra=()):
    """A tar.xz shaped as the official Node distribution: its own top
    directory entry first (`top` its type, None to omit), bin/node (a
    script answering the version), bin/npm as the official link, npm's
    entry points and a file outside the selection; then `extra` members
    [(name, type)]."""
    prefix = f"node-v{version}-linux-x64"
    members = [] if top is None else [(prefix, top, b"")]
    members += [(f"{prefix}/bin", tarfile.DIRTYPE, b""),
                (f"{prefix}/bin/node", tarfile.REGTYPE, f"#!/bin/sh\necho v{version}\n".encode()),
                (f"{prefix}/bin/npm", tarfile.SYMTYPE, b"../lib/node_modules/npm/bin/npm-cli.js"),
                (f"{prefix}/include/node/node.h", tarfile.REGTYPE, b"/* header */\n"),
                (f"{prefix}/lib/node_modules/npm", tarfile.DIRTYPE, b""),
                (f"{prefix}/lib/node_modules/npm/bin/npm-cli.js", tarfile.REGTYPE, b"// npm\n"),
                (f"{prefix}/lib/node_modules/npm/bin/npx-cli.js", tarfile.REGTYPE, b"// npx\n")]
    members += [(name, kind, b"x") for name, kind in extra]
    with tarfile.open(path, "w:xz") as archive:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            info.type, info.mode = kind, 0o755 if kind == tarfile.DIRTYPE or name.endswith("/node") else 0o644
            if kind == tarfile.SYMTYPE:
                info.linkname = data.decode()
                archive.addfile(info)
            elif kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)


class NodeArchive(Temp):
    """guest-install's Node installation from an official-shaped archive,
    into private stand-ins for /usr/local and /var/tmp."""

    VERSION = "24.22.1"

    def install(self, name, **shape):
        installer = load_guest_install()
        ctx, local = self.path(name, "context"), self.path(name, "local")
        os.makedirs(os.path.join(ctx, "inputs"))
        os.makedirs(os.path.join(local, "bin"))
        os.makedirs(self.path(name, "var-tmp"))
        archive = os.path.join(ctx, "inputs", f"node-v{self.VERSION}-linux-x64.tar.xz")
        node_archive(archive, self.VERSION, **shape)
        installer.CONTEXT, installer.LOCAL = ctx, local
        installer.NODE = os.path.join(local, "bin", "node")
        installer.NPM_ROOT = os.path.join(local, "lib", "node_modules", "npm")
        scratch = self.path(name, "var-tmp")
        installer.tempfile = type("Scratch", (), {"TemporaryDirectory": staticmethod(
            lambda prefix, dir: tempfile.TemporaryDirectory(prefix=prefix, dir=scratch))})
        installer.SANDBOX = FakeSandbox(installer, self.path(name, "sandbox"))
        inputs = {"node": {"file": os.path.basename(archive), "version": self.VERSION}}
        return installer, inputs, local

    def test_official_top_directory_is_accepted(self):
        installer, inputs, local = self.install("ok")
        installer.install_node(inputs)
        self.assertEqual(slurp(os.path.join(local, "bin", "node")), f"#!/bin/sh\necho v{self.VERSION}\n")
        self.assertEqual(os.readlink(os.path.join(local, "bin", "npm")), "../lib/node_modules/npm/bin/npm-cli.js")
        self.assertTrue(os.path.isfile(os.path.join(local, "lib", "node_modules", "npm", "bin", "npx-cli.js")))
        self.assertFalse(os.path.exists(os.path.join(local, "include")))
        self.assertEqual(os.listdir(self.path("ok", "var-tmp")), [])

    def test_archive_without_top_directory_is_accepted(self):
        installer, inputs, _ = self.install("bare", top=None)
        installer.install_node(inputs)

    def test_only_the_exact_top_directory_is_skipped(self):
        top = f"node-v{self.VERSION}-linux-x64"
        cases = {"top-file": dict(top=tarfile.REGTYPE), "top-link": dict(top=tarfile.SYMTYPE),
                 "top-fifo": dict(top=tarfile.FIFOTYPE),
                 "near": dict(extra=[(top + "-x", tarfile.DIRTYPE)]),
                 "other-version": dict(extra=[("node-v24.22.0-linux-x64", tarfile.DIRTYPE)]),
                 "foreign": dict(extra=[("etc/passwd", tarfile.REGTYPE)]),
                 "traversal": dict(extra=[(top + "/lib/node_modules/npm/../../../../x", tarfile.REGTYPE)]),
                 "npm-device": dict(extra=[(top + "/lib/node_modules/npm/dev", tarfile.CHRTYPE)])}
        for name, shape in cases.items():
            with self.subTest(name):
                installer, inputs, local = self.install(name, **shape)
                self.refused("node_archive", installer.install_node, inputs)
                self.assertFalse(os.path.lexists(os.path.join(local, "bin", "node")))


def download_provisioners(text):
    """The recipe's download provisioners: [(source, destination)]."""
    out = []
    for block in re.findall(r'provisioner "file" \{(.*?)\n  \}', text, re.S):
        if 'direction   = "download"' in block:
            out.append((re.search(r'source\s+=\s+"([^"]+)"', block).group(1),
                        re.search(r'destination\s+=\s+"([^"]+)"', block).group(1)))
    return out


def simulate_download(guest, source, destination, output):
    """Packer's file download, dispatched as Packer does: by the source's
    syntax, never the remote file type. A source ending in '/' or holding a
    glob is a directory download (recursive SCP into the destination
    directory, where it lands under its own name); any other source is a
    single-file download, which fails on a directory. A file goes to the
    destination path (under its name for a destination ending in '/')."""
    src = os.path.join(guest, source.strip("/"))
    dest = destination.replace("${var.output}", output)
    if source.endswith("/") or any(c in source for c in "*?["):
        if not os.path.isdir(src):
            raise OSError("download_dir: not a directory")
        shutil.copytree(src, os.path.join(dest, os.path.basename(src.rstrip("/"))))
    else:
        if not os.path.isfile(src):
            raise OSError("download: not a regular file")
        shutil.copyfile(src, os.path.join(dest, os.path.basename(src)) if dest.endswith("/") else dest)


def system_manifest():
    return {"schema": stage.SYSTEM_SCHEMA,
            "kernel": {"build": "7.0.0-43-generic", "intended": "7.0.0-44-generic",
                       "installed": ["7.0.0-43-generic", "7.0.0-44-generic"]},
            "packages": [["git", "amd64", "1:2.53.0-1ubuntu1.1"], ["python3-venv", "amd64", "3.14.3-0ubuntu2"]],
            "apt": {"phased_updates": "never", "recommends": False},
            "sandbox": {"isolated": True, "user": "agentbox-sandbox"},
            "agents": {agent: {"package": agentlock.PACKAGES[agent], "version": "1.0.0", "lock_sha256": "a" * 64}
                       for agent in agentlock.AGENTS}}


class Publication(Temp):
    """The recipe's downloads land where `stage.py publish` reads them."""

    def guest_output(self):
        guest = self.path("guest")
        out = os.path.join(guest, "var", "tmp", "agentbox-build", "out")
        data = synthetic_bundle(os.path.join(out, "worker"))
        release = hashlib.sha256(data).hexdigest()
        stage.write_json(os.path.join(out, worker.METADATA["file"]), {
            "schema": worker.METADATA["schema"], "release": release, "install_root": worker.INSTALL_ROOT,
            "manifest": data.decode(), "sources": {"revision": "b" * 64}})
        stage.write_json(os.path.join(out, stage.SYSTEM_MANIFEST), system_manifest())
        stage_dir = self.path("stage")
        os.mkdir(stage_dir)
        stage.write_json(os.path.join(stage_dir, "stage.json"), {
            "schema": stage.STAGE_SCHEMA, "target": "qemu", "base": {"file": "base.img"},
            "node": {"file": "node-v24.22.3-linux-x64.tar.xz", "version": "24.22.3"},
            "worker": {"sources": {"revision": "b" * 64}}, "recipe": []})
        return guest, stage_dir, release

    def output(self, name):
        output = self.path(name)
        os.mkdir(output)
        write(os.path.join(output, "agentbox.qcow2"), b"QFI\xfb" + bytes(60))
        return output

    def test_the_recipe_downloads_publish(self):
        guest, stage_dir, release = self.guest_output()
        output = self.output("output")
        text = slurp(os.path.join(IMAGES, "qemu", "default", "agentbox.pkr.hcl"))
        downloads = download_provisioners(text)
        self.assertEqual(downloads, [
            ("/var/tmp/agentbox-build/out/worker/", "${var.output}/"),
            ("/var/tmp/agentbox-build/out/worker-metadata.json", "${var.output}/worker-metadata.json"),
            ("/var/tmp/agentbox-build/out/image-manifest.json", "${var.output}/image-manifest.json")])
        for source, destination in downloads:
            simulate_download(guest, source, destination, output)
        self.assertEqual(sorted(os.listdir(output)), ["agentbox.qcow2", "image-manifest.json", "worker",
                                                      "worker-metadata.json"])
        image = stage.publish(stage_dir, output)
        self.assertEqual(image["worker"]["release"], release)
        self.assertEqual(image["system"], system_manifest())
        self.assertEqual(image["node"], {"file": "node-v24.22.3-linux-x64.tar.xz", "version": "24.22.3"})
        self.assertEqual(image["status"], "built_native_unvalidated")
        self.assertTrue(os.path.isfile(os.path.join(output, "image.json")))

    def test_the_system_record_is_closed_and_bounded(self):
        guest, stage_dir, _ = self.guest_output()
        for name, change in [
                ("schema", lambda v: v.__setitem__("schema", "x")),
                ("extra", lambda v: v.__setitem__("extra", 1)),
                ("intended not installed", lambda v: v["kernel"].__setitem__("intended", "9.9.9-generic")),
                ("kernel text", lambda v: v["kernel"].__setitem__("build", "7.0 ; rm")),
                ("no packages", lambda v: v.__setitem__("packages", [])),
                ("package", lambda v: v["packages"].append(["Bad Name", "amd64", "1"])),
                ("phasing", lambda v: v["apt"].__setitem__("phased_updates", "random")),
                ("not isolated", lambda v: v["sandbox"].__setitem__("isolated", False)),
                ("no agents", lambda v: v.pop("agents")),
                ("an agent missing", lambda v: v["agents"].pop("pi")),
                ("another agent", lambda v: v["agents"].__setitem__("x", v["agents"]["pi"])),
                ("another package", lambda v: v["agents"]["pi"].__setitem__("package", "@x/pi")),
                ("a range", lambda v: v["agents"]["codex"].__setitem__("version", "^1.0.0")),
                ("a lock digest", lambda v: v["agents"]["claude"].__setitem__("lock_sha256", "x")),
                ("an agent key", lambda v: v["agents"]["claude"].__setitem__("integrity", "x"))]:
            with self.subTest(name):
                output = self.output(name)
                value = system_manifest()
                change(value)
                write(os.path.join(output, stage.SYSTEM_MANIFEST), json.dumps(value))
                with self.assertRaises(Refused):
                    stage.check_system(os.path.join(output, stage.SYSTEM_MANIFEST))
        output = self.output("large")
        write(os.path.join(output, stage.SYSTEM_MANIFEST), b" " * (stage.MAX_SYSTEM_BYTES + 1))
        with self.assertRaises(Refused):
            stage.check_system(os.path.join(output, stage.SYSTEM_MANIFEST))
        # A custom recipe's output without one publishes without `system`.
        output = self.output("custom")
        simulate_download(guest, "/var/tmp/agentbox-build/out/worker/", "${var.output}/", output)
        simulate_download(guest, "/var/tmp/agentbox-build/out/worker-metadata.json",
                          "${var.output}/worker-metadata.json", output)
        self.assertNotIn("system", stage.publish(stage_dir, output))

    def test_a_whole_out_directory_download_does_not_publish(self):
        guest, stage_dir, _ = self.guest_output()
        output = self.output("output")
        simulate_download(guest, "/var/tmp/agentbox-build/out/", "${var.output}/", output)
        self.assertEqual(sorted(os.listdir(output)), ["agentbox.qcow2", "out"])
        with self.assertRaises(Refused):
            stage.publish(stage_dir, output)

    def test_a_directory_source_without_its_slash_fails(self):
        guest, _, _ = self.guest_output()
        output = self.output("output")
        with self.assertRaises(OSError):
            simulate_download(guest, "/var/tmp/agentbox-build/out/worker", "${var.output}/", output)
        self.assertEqual(sorted(os.listdir(output)), ["agentbox.qcow2"])


class AgentLocks(Temp):
    """agentlock's rules for one resolved lock (both recipes' builds)."""

    def edited(self, change, agent="codex"):
        root = self.path("images", str(len(os.listdir(self.tmp))))
        agents, _ = fake_agents(root)
        path = os.path.join(agents, agent, "package-lock.json")
        lock = json.loads(slurp(path))
        project = json.loads(slurp(os.path.join(agents, agent, "package.json")))
        change(lock, project)
        write(path, json.dumps(lock))
        write(os.path.join(agents, agent, "package.json"), json.dumps(project))
        return os.path.join(agents, agent)

    def lock_refused(self, path):
        with self.assertRaises(agentlock.Refused) as caught:
            agentlock.check_dir(path)
        self.assertEqual(str(caught.exception), "agent_lock")

    def test_anything_but_registry_tarballs_at_their_derived_url_refuses(self):
        key = "node_modules/@fixture/codex"
        self.assertEqual(agentlock.check_dir(self.edited(lambda lock, project: None))[0], ("@fixture/codex", "1.0.0"))

        def entry(field, value):
            return lambda lock, project: lock["packages"][key].__setitem__(field, value)

        def added(name, value):
            return lambda lock, project: lock["packages"].__setitem__(name, value)

        good = {"version": "1.0.0", "resolved": stage.REGISTRY + "x/-/x-1.0.0.tgz",
                "integrity": integrity(b"x")}
        for label, change in [
            ("other host", entry("resolved", "https://evil.example.org/@fixture/codex/-/codex-1.0.0.tgz")),
            ("other file", entry("resolved", stage.REGISTRY + "@fixture/codex/-/other-1.0.0.tgz")),
            ("http", entry("resolved", "http://registry.npmjs.org/@fixture/codex/-/codex-1.0.0.tgz")),
            ("git", entry("resolved", "git+https://github.com/x/y.git#abc")),
            ("sha1", entry("integrity", "sha1-" + "A" * 27 + "=")),
            ("no integrity", lambda lock, project: lock["packages"][key].pop("integrity")),
            ("range", entry("version", "^1.0.0")),
            ("link", entry("link", True)),
            ("dev", entry("dev", True)),
            ("bundled", entry("inBundle", True)),
            ("traversal", added("node_modules/../x", good)),
            ("absolute", added("/node_modules/x", good)),
            ("not a module", added("lib/x", good)),
            ("platform, not optional", added("node_modules/x", dict(good, os=["darwin"]))),
            ("bad platform", added("node_modules/x", dict(good, os="linux"))),
            ("v2", lambda lock, project: lock.__setitem__("lockfileVersion", 2)),
            ("two dependencies", lambda lock, project: project["dependencies"].__setitem__("y", "1.0.0")),
            ("not private", lambda lock, project: project.pop("private")),
            ("scripts", lambda lock, project: project.__setitem__("scripts", {"postinstall": "x"})),
            ("lock disagrees", lambda lock, project: project["dependencies"].__setitem__("@fixture/codex",
                                                                                        "2.0.0")),
        ]:
            with self.subTest(label):
                self.lock_refused(self.edited(change))
        # An optional package for another platform is left out; `!` excludes.
        path = self.edited(added("node_modules/x", dict(good, optional=True, os=["!linux"])))
        self.assertEqual([e["file"] for e in agentlock.check_dir(path)[1]], ["fixture-codex-1.0.0.tgz"])
        path = self.edited(added("node_modules/x", dict(good, optional=True, cpu=["x64", "arm64"])))
        self.assertEqual([e["file"] for e in agentlock.check_dir(path)[1]], ["fixture-codex-1.0.0.tgz", "x-1.0.0.tgz"])


class AgentResolution(Temp):
    """Podman's agent tools: resolve.sh, and agentlock.py checking the
    locks a build resolved (the tracked locks' rules, each agent's own
    package, nothing else in the tree)."""

    def tree(self, registry=stage.REGISTRY, names=agentlock.PACKAGES):
        root = self.path(f"r{len(os.listdir(self.tmp))}")
        fake_agents(root, registry, names, "2.0.0")
        return os.path.join(root, "agents")

    def test_resolve_locks_each_agents_own_latest_and_runs_no_package_code(self):
        text = slurp(os.path.join(IMAGES, "agents", "resolve.sh"))
        listed = text[text.index("<<EOF\n") + 6:text.rindex("EOF")].splitlines()
        self.assertEqual([tuple(line.split()) for line in listed], list(agentlock.PACKAGES.items()))
        self.assertEqual(tuple(agentlock.PACKAGES), agentlock.AGENTS)
        for agent, name in agentlock.PACKAGES.items():
            self.assertIn(f'PACKAGE = "{name}"', slurp(os.path.join(REPO, "agents", agent, "adapter.py")))
        code = "\n".join(line for line in text.splitlines() if not line.startswith("#"))
        command = " ".join(code[code.index("npm "):code.index("</dev/null")].replace("\\\n", " ").split())
        self.assertEqual(command, "npm install --package-lock-only --ignore-scripts --save-exact --no-audit "
                                  '--no-fund --no-update-notifier --registry="$registry" "$package@latest"')
        self.assertEqual(code.count("npm "), 1)
        self.assertIn("printf '{\"private\": true}\\n'", code)

    def test_check_takes_exactly_each_agents_own_lock(self):
        expected = {agent: "2.0.0" for agent in agentlock.AGENTS}
        self.assertEqual(agentlock.check_tree(self.tree()), expected)
        other = "https://registry.example.test/"
        self.assertEqual(agentlock.check_tree(self.tree(other), other), expected)

        def refused(root, registry=stage.REGISTRY):
            with self.assertRaises(agentlock.Refused) as caught:
                agentlock.check_tree(root, registry)
            self.assertEqual(str(caught.exception), "agent_lock")

        refused(self.tree(other))
        refused(self.tree(names={agent: f"@fixture/{agent}" for agent in agentlock.AGENTS}))
        swapped = dict(agentlock.PACKAGES, pi=agentlock.PACKAGES["codex"], codex=agentlock.PACKAGES["pi"])
        refused(self.tree(names=swapped))
        for change in (lambda root: write(os.path.join(root, "pi", "extra"), b""),
                       lambda root: os.mkdir(os.path.join(root, "node_modules")),
                       lambda root: shutil.rmtree(os.path.join(root, "claude")),
                       lambda root: os.unlink(os.path.join(root, "codex", "package-lock.json")),
                       lambda root: (os.rename(os.path.join(root, "pi"), os.path.join(root, "real")),
                                     os.symlink("real", os.path.join(root, "pi"))),
                       lambda root: (os.rename(os.path.join(root, "pi", "package.json"), os.path.join(root, "p")),
                                     os.symlink("../p", os.path.join(root, "pi", "package.json"))),
                       lambda root: write(os.path.join(root, "codex", "package-lock.json"),
                                          b" " * (agentlock.MAX_LOCK_BYTES + 1))):
            root = self.tree()
            change(root)
            refused(root)

    def test_the_check_command(self):
        script = os.path.join(HERE, "agentlock.py")
        good = self.tree()
        bad = self.tree(names={agent: f"@fixture/{agent}" for agent in agentlock.AGENTS})
        for argv, code, err in (
                (["check", "--registry", stage.REGISTRY, good], 0, b""),
                (["check", "--registry", stage.REGISTRY, bad], 1, b"agentlock refused: agent_lock\n"),
                (["check", "--registry", "https://registry.npmjs.org", good], 1, b"agentlock refused: usage\n"),
                (["check", good], 1, b"agentlock refused: usage\n")):
            out = subprocess.run([PYTHON, "-I", "-B", script, *argv], capture_output=True, timeout=60,
                                 env={"PATH": "/usr/bin:/bin"})
            self.assertEqual((out.returncode, out.stdout, out.stderr), (code, b"", err), argv)


class FixtureRegistry:
    """A local HTTP registry for one test: `files` {path: bytes} served,
    `redirects` {path: location} answered 302, anything else 404; every
    request path recorded."""

    def __init__(self, files, redirects=None):
        import http.server
        import threading
        registry = self
        self.files, self.redirects, self.requests = dict(files), dict(redirects or {}), []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                registry.requests.append(self.path)
                if self.path in registry.redirects:
                    self.send_response(302)
                    self.send_header("Location", registry.redirects[self.path])
                    self.end_headers()
                elif self.path in registry.files:
                    data = registry.files[self.path]
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_error(404)

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class GuestAgents(Temp):
    """guest-install's agents with a stand-in npm (absolute path, first on
    the sandbox's PATH, every call logged) and a local fixture registry:
    resolved online, downloaded by the script, installed offline, verified
    against the held locks."""

    NPM = """#!%s -I
import json, os, shutil, sys
args = sys.argv[1:]
with open(os.environ["NPM_LOG"], "a") as stream:
    stream.write(" ".join(args) + "\\n")
fixture = os.environ["NPM_FIXTURE"]
if args[:2] == ["install", "--package-lock-only"]:
    assert "--ignore-scripts" in args and args[-1].endswith("@latest")
    package = args[-1][:-len("@latest")]
    for agent in sorted(os.listdir(fixture)):
        with open(os.path.join(fixture, agent, "package.json")) as stream:
            if package in json.load(stream)["dependencies"]:
                for name in ("package.json", "package-lock.json"):
                    shutil.copyfile(os.path.join(fixture, agent, name), name)
elif args[0] == "ci":
    target = args[2]
    with open(os.path.join(target, "package.json")) as stream:
        (name, version), = json.load(stream)["dependencies"].items()
    os.makedirs(os.path.join(target, "node_modules", name))
    os.makedirs(os.path.join(target, "node_modules", ".bin"))
    with open(os.path.join(target, "node_modules", name, "package.json"), "w") as stream:
        json.dump({"name": name, "version": os.environ.get("FAKE_VERSION") or version}, stream)
    agent = os.path.basename(target)
    with open(os.path.join(target, "node_modules", ".bin", agent), "w") as stream:
        stream.write("#!/bin/sh\\necho started >> \\"$NPM_LOG\\"\\n")
    os.chmod(os.path.join(target, "node_modules", ".bin", agent), 0o755)
    if os.environ.get("NPM_TAMPER"):
        with open(os.path.join(target, "package-lock.json"), "a") as stream:
            stream.write(" ")
""" % PYTHON

    def setUp(self):
        super().setUp()
        self.addCleanup(os.umask, os.umask(0o022))

    def world(self, name, registry_files=None, redirects=None, change=None):
        """A fresh guest stand-in `name`: (installer, sandbox, registry,
        fixture tarballs by file name, tools, held)."""
        root = self.path(name)
        os.makedirs(root)
        stub = os.path.join(root, "stub")
        os.mkdir(stub)
        write(os.path.join(stub, "npm"), self.NPM, 0o755)
        registry = FixtureRegistry({})
        self.addCleanup(registry.close)
        fixture, tarballs = fake_agents(os.path.join(root, "fixture"), registry.url, agentlock.PACKAGES, "2.0.0")
        if change is not None:
            change(fixture)
        for agent in agentlock.AGENTS:
            lock = json.loads(slurp(os.path.join(fixture, agent, "package-lock.json")))
            for key, entry in lock["packages"].items():
                file = f"{key.rsplit('node_modules/', 1)[-1].lstrip('@').replace('/', '-')}-{entry.get('version')}.tgz"
                if key and file in tarballs:
                    registry.files["/" + entry["resolved"][len(registry.url):]] = tarballs[file]
        registry.files.update(registry_files or {})
        registry.redirects.update(redirects or {})
        installer = load_guest_install()
        local, tools, held = (os.path.join(root, n) for n in ("local", "tools", "held"))
        for path in (os.path.join(local, "bin"), tools, held):
            os.makedirs(path)
        shutil.copyfile(os.path.join(IMAGES, "agents", "resolve.sh"), os.path.join(tools, "resolve.sh"))
        installer.LOCAL, installer.NPM, installer.AGENTS_ROOT = local, os.path.join(stub, "npm"), \
            os.path.join(root, "opt")
        installer.REGISTRY, installer.OWNER, installer.DOWNLOAD_ATTEMPTS = registry.url, (os.getuid(), os.getgid()), 1
        installer.ENV = dict(installer.ENV, NPM_LOG=os.path.join(root, "npm.log"), NPM_FIXTURE=fixture)
        sandbox = installer.SANDBOX = FakeSandbox(installer, os.path.join(root, "sandbox"), stub)
        return installer, sandbox, registry, tarballs, tools, held

    def test_latest_resolved_online_fetched_installed_offline_and_verified(self):
        installer, sandbox, registry, tarballs, tools, held = self.world("ok")
        locks = installer.resolve_agents(tools)
        self.assertEqual({agent: locks[agent]["version"] for agent in locks}, dict.fromkeys(agentlock.AGENTS, "2.0.0"))
        files = installer.download(locks, held)
        # This platform's tarballs, once each, nothing else asked of the
        # registry (no metadata: that was npm's, online).
        self.assertEqual(files, sorted(tarballs))
        self.assertNotIn("fixture-claude-darwin-arm64-1.0.0.tgz", files)
        self.assertEqual(sorted(registry.requests), sorted(registry.files))
        installer.install_agents(locks, files, held)
        agents = installer.verify_agents(locks)
        root = self.path("ok")
        for agent in agentlock.AGENTS:
            lock = slurp(os.path.join(root, "fixture", "agents", agent, "package-lock.json"), "rb")
            self.assertEqual(agents[agent], {"package": agentlock.PACKAGES[agent], "version": "2.0.0",
                                             "lock_sha256": hashlib.sha256(lock).hexdigest()})
            self.assertEqual(slurp(os.path.join(root, "opt", agent, "package-lock.json"), "rb"), lock)
            self.assertEqual(os.readlink(os.path.join(root, "local", "bin", agent)),
                             os.path.join(root, "opt", agent, "node_modules", ".bin", agent))
        # Only the resolution (npm, metadata) online; everything else, the
        # agents' own start included, offline; each command's processes
        # stopped after it.
        online = [argv for argv, net in sandbox.calls if net]
        self.assertEqual(online, [["/bin/sh", os.path.join(tools, "resolve.sh"), registry.url,
                                   os.path.join(root, "sandbox", "resolve", "locks")]])
        offline = [argv for argv, net in sandbox.calls if not net]
        self.assertEqual([argv[1] for argv in offline[:4]], ["cache", "ci", "ci", "ci"])
        self.assertEqual(offline[4:], [[os.path.join(root, "local", "bin", a), "--version"] for a in agentlock.AGENTS])
        self.assertEqual(sandbox.stops, len(sandbox.calls))
        self.assertEqual(sandbox.owned, [os.path.join(root, "opt", a) for a in agentlock.AGENTS])
        self.assertEqual(sandbox.released, sandbox.owned)
        log = slurp(os.path.join(root, "npm.log")).splitlines()
        self.assertEqual(len([line for line in log if line.startswith("install --package-lock-only")]), 3)
        self.assertEqual(log.count("started"), 3)
        for line in log:
            if line.startswith(("cache", "ci")):
                self.assertIn("--offline", line)
        self.assertEqual(os.listdir(held), [])
        self.assertEqual(sorted(os.listdir(os.path.join(root, "sandbox"))), ["home"])
        # No sandbox: no third-party code runs.
        installer.SANDBOX = None
        self.refused("sandbox", installer.install_agents, locks, files, held)

    def test_a_tarball_other_than_its_lock_refuses(self):
        """Other bytes (`agent_integrity`), larger than the bound, more
        tarballs than allowed (`agent_bounds`), a redirect or a missing one
        (`agent_download`), one file for two tarballs (`agent_lock`)."""
        name = "codex-2.0.0.tgz"
        path = "/@openai/codex/-/codex-2.0.0.tgz"
        installer, _, _, _, tools, held = self.world("bad", registry_files={path: b"tampered"})
        locks = installer.resolve_agents(tools)
        self.refused("agent_integrity", installer.download, locks, held)
        for label, change in (("size", {"MAX_AGENT_TARBALL": 4}), ("total", {"MAX_AGENT_BYTES": 4}),
                              ("count", {"MAX_AGENT_TARBALLS": 1})):
            with self.subTest(label):
                installer, _, _, _, tools, held = self.world(label)
                locks = installer.resolve_agents(tools)
                for key, value in change.items():
                    setattr(installer, key, value)
                self.refused("agent_bounds", installer.download, locks, held)
        installer, _, registry, _, tools, held = self.world("redirect")
        registry.redirects[path] = registry.url + "elsewhere.tgz"
        registry.files["/elsewhere.tgz"] = registry.files[path]
        self.refused("agent_download", installer.download, installer.resolve_agents(tools), held)
        self.assertNotIn("/elsewhere.tgz", registry.requests)
        del registry.redirects[path], registry.files[path]
        self.refused("agent_download", installer.download, installer.resolve_agents(tools), held)
        locks = installer.resolve_agents(tools)
        locks["pi"]["tarballs"].append(dict(locks["codex"]["tarballs"][0], integrity=integrity(b"other")))
        self.refused("agent_lock", installer.download_plan, locks)
        self.assertNotIn(name, os.listdir(held))

    def test_a_lock_outside_the_rules_refuses_before_any_download(self):
        def git(fixture):
            path = os.path.join(fixture, "pi", "package-lock.json")
            lock = json.loads(slurp(path))
            lock["packages"]["node_modules/x"] = {"version": "1.0.0", "resolved": "git+https://github.com/x/y.git",
                                                  "integrity": integrity(b"x")}
            write(path, json.dumps(lock))
        installer, _, registry, _, tools, _ = self.world("git", change=git)
        self.refused("agent_lock", installer.resolve_agents, tools)
        self.assertEqual(registry.requests, [])

    def test_an_install_other_than_the_held_lock_refuses(self):
        for label, env in (("lock rewritten", {"NPM_TAMPER": "1"}), ("other version", {"FAKE_VERSION": "9.9.9"})):
            with self.subTest(label):
                installer, _, _, _, tools, held = self.world(label.replace(" ", "-"))
                installer.ENV = dict(installer.ENV, **env)
                locks = installer.resolve_agents(tools)
                installer.install_agents(locks, installer.download(locks, held), held)
                self.refused("agent", installer.verify_agents, locks)


def stages(text):
    """Dockerfile stages: [(FROM line, [instruction lines])], comments and
    continuations joined."""
    lines, current = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        current += (" " if current else "") + line.rstrip("\\").strip()
        if not line.endswith("\\"):
            lines.append(current)
            current = ""
    out = []
    for line in lines:
        if line.startswith("FROM "):
            out.append((line, []))
        elif out:
            out[-1][1].append(line)
    return out


class Recipes(unittest.TestCase):
    def test_podman_builds_the_worker_in_its_own_stage(self):
        text = slurp(os.path.join(IMAGES, "podman", "default", "Dockerfile"))
        parsed = stages(text)
        names = [line.split()[-1] if " AS " in line else None for line, _ in parsed]
        self.assertEqual(names, ["node", "worker", "agents-resolve", "agents-check", "agents",
                                 "worker-export", None])
        self.assertEqual([line.split()[1] for line, _ in parsed][2:5], ["${NODE}", "worker", "${NODE}"])
        bodies = dict(zip(names, [body for _, body in parsed]))
        worker_stage = bodies["worker"]
        context_copies = [line for _, body in parsed for line in body
                          if line.startswith("COPY ") and "--from=" not in line]
        self.assertEqual(context_copies, ["COPY worker/ /build/worker/", "COPY worker-src/ /build/worker-src/",
                                          "COPY worker-counterparts/ /build/worker-counterparts/",
                                          "COPY agents/resolve.sh /build/resolve.sh",
                                          "COPY agents/agentlock.py /build/agentlock.py"])
        self.assertTrue(all(line in worker_stage for line in context_copies[:3]))
        # The agents: resolved at every build from the one registry, checked
        # without network, then only the checked locks installed by `npm ci`
        # at the path the final stage keeps, each command linked on PATH.
        registry = "https://registry.npmjs.org/"
        self.assertEqual(text.count("https://"), 3)
        self.assertEqual(text.count(registry), 3)
        self.assertEqual(bodies["agents-resolve"], ["COPY agents/resolve.sh /build/resolve.sh",
                                                    f"RUN sh /build/resolve.sh {registry} /out"])
        self.assertEqual(bodies["agents-check"], [
            "COPY agents/agentlock.py /build/agentlock.py", "COPY --from=agents-resolve /out/ /checked/",
            f"RUN --network=none /usr/bin/python3 -I -B /build/agentlock.py check --registry {registry} "
            "/checked"])
        agents_stage = "\n".join(bodies["agents"])
        self.assertEqual(bodies["agents"][0], "COPY --from=agents-check /checked/ /opt/agentbox-agents/")
        self.assertEqual(len(bodies["agents"]), 2)
        self.assertIn('npm ci --prefix "/opt/agentbox-agents/$agent" --omit=dev', agents_stage)
        self.assertIn(f"--registry={registry}", agents_stage)
        self.assertNotIn("npm install", text)
        self.assertIn("for agent in pi codex claude", agents_stage)
        self.assertFalse([line for line in text.splitlines() if "agents-resolve" in line
                          and not line.startswith(("FROM ", "COPY --from=agents-resolve /out/ /checked/"))])
        # The context's modes follow the stager's umask (0700 under 077):
        # the agents leave readable by the workload, and the final stage
        # checks it (natively found unreadable, 2026-11-19).
        self.assertTrue(bodies["agents"][-1].endswith("done; chmod -R u=rwX,go=rX /opt/agentbox-agents"))
        # No Node, compiler or dependency reaches the worker's own stage.
        self.assertFalse([line for line in worker_stage if "node" in line.lower() or "deps" in line])
        assembly = [line for line in worker_stage if "worker.py build" in line]
        self.assertEqual(len(assembly), 1)
        self.assertTrue(assembly[0].startswith("RUN --network=none "))
        self.assertIn("--counterparts /build/worker-counterparts", assembly[0])
        final = parsed[-1][1]
        final_text = "\n".join(final)
        self.assertEqual([l for l in final if l.startswith("COPY --from=worker")], [
            "COPY --from=worker --chown=0:0 /out/worker/ /opt/agentbox/worker/",
            "COPY --from=worker --chown=0:0 /out/worker-metadata.json /opt/agentbox/worker-metadata.json"])
        for absent in ("worker-src", "worker-deps", "typescript", "tsc", "/build/", "COPY worker"):
            self.assertNotIn(absent, final_text.replace("source=/build/worker", ""))
        self.assertEqual(final[-1], "RUN --network=none --mount=type=bind,from=worker,source=/build/worker,"
                                    "target=/run/agentbox-worker /usr/bin/python3 -I -B "
                                    "/run/agentbox-worker/worker.py seal")
        # The worker's `python3` (the launcher's, on the fixed system PATH), and
        # Node and npm for npm and agents only.
        for needed in ("/usr/bin/python3 ", "/usr/local/bin/npm", "/usr/bin/git"):
            self.assertIn(needed, final_text)
        # The newest LTS by digest, never a floating tag; Ubuntu's own
        # packages only, none of the dev preset's toolchain, and no source
        # build of Git.
        args = [line for line in text.splitlines() if line.startswith("ARG ")]
        self.assertEqual(args[0], "ARG UBUNTU=docker.io/library/ubuntu:26.04@sha256:"
                                  "d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db")
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        for absent in ("python3.12", "GIT_SHA256", "GIT_VERSION", "kernel.org", "make -j", "ubuntu:latest",
                       "ubuntu:24.04"):
            self.assertNotIn(absent, code)
        install = [line for line in final if line.startswith("RUN apt-get")]
        self.assertEqual(len(install), 1)
        packages = install[0].split("--no-install-recommends", 1)[1].split("&&", 1)[0].split()
        self.assertEqual(packages, ["ca-certificates", "git", "libstdc++6", "openssh-server", "python3",
                                    "python3-minimal", "python3-venv", "tini", "zlib1g"])
        self.assertEqual(text.count("apt-get install"), 2)
        checks = next(line for line in final if "set -eu; if getent" in line)
        for needed in ("for tool in cc gcc g++ make gdb rustc cargo; do", "git-remote-https", "ca-certificates.crt",
                       "import ensurepip, sys, venv; assert sys.version_info >= (3, 12)",
                       # The SSH bootstrap's own forms (agentbox_controller/ssh.py), with this
                       # image's coreutils.
                       '[ "$(stat -c %u -- "$tmp")" = 0 ]', '[ $((0$(stat -c %a -- "$tmp") & 022)) -eq 0 ]',
                       'size=$(wc -c < "$tmp/f"); [ $size -eq 3 ]', "| sha256sum -c --status -",
                       "timeout 2 /usr/bin/sleep infinity", 'test "$2" -ge 53', "protocol.allow=never"):
            self.assertIn(needed, checks)
        probes = checks[checks.index('[ "$(uname -s)" = Linux ]'):]
        self.assertNotIn("&&", probes)
        self.assertNotIn("; !", probes)
        self.assertNotIn("ADD ", text)
        self.assertEqual(bodies["worker-export"], ["COPY --from=worker /out/ /"])
        # Each agent starts without network or a HOME of its own, before
        # the worker is copied and sealed.
        smoke = [l for l in final if '"/usr/local/bin/$agent" --version' in l]
        self.assertEqual(len(smoke), 1)
        self.assertTrue(smoke[0].startswith('RUN --network=none set -eu; scratch="$(mktemp -d)"; '
                                            'for agent in pi codex claude; do'))
        for needed in ('HOME="$scratch" TMPDIR="$scratch" timeout 120 "/usr/local/bin/$agent" --version '
                       '</dev/null >/dev/null', 'rm -rf "$scratch"'):
            self.assertIn(needed, smoke[0])
        self.assertLess(final.index(smoke[0]), final.index(
            "COPY --from=worker --chown=0:0 /out/worker/ /opt/agentbox/worker/"))
        self.assertIn("COPY --from=agents --chown=0:0 /opt/agentbox-agents/ /opt/agentbox-agents/", final)
        self.assertIn('test -z "$(find /opt/agentbox-agents ! -type l \\( ! -perm -o=r -o -type d ! -perm -o=x \\) '
                      '-print -quit)"', final_text)
        self.assertIn('ln -s "/opt/agentbox-agents/$agent/node_modules/.bin/$agent" "/usr/local/bin/$agent"',
                      final_text)
        # The builder's own install root is the runtime's.
        self.assertEqual(worker.INSTALL_ROOT, "/opt/agentbox/worker")

    def test_the_dev_preset_shares_the_runtime_contract_and_the_agents(self):
        default = slurp(os.path.join(IMAGES, "podman", "default", "Dockerfile"))
        text = slurp(os.path.join(IMAGES, "podman", "dev", "Dockerfile"))
        parsed, base = stages(text), stages(default)
        names = [line.split()[-1] if " AS " in line else None for line, _ in parsed]
        self.assertEqual(names, ["node", "worker", "agents-resolve", "agents-check", "agents", None])
        bodies, base_bodies = dict(zip(names, (b for _, b in parsed))), dict(
            zip([line.split()[-1] if " AS " in line else None for line, _ in base], (b for _, b in base)))
        # The worker and the agents exactly as the default recipe's.
        for stage_name in ("node", "worker", "agents-resolve", "agents-check", "agents"):
            self.assertEqual(bodies[stage_name], base_bodies[stage_name], stage_name)
        self.assertEqual([line for line, _ in parsed][:5], [line for line, _ in base][:5])
        # The default's base and Node, the same ARG lines.
        args = [line for line in text.splitlines() if line.startswith("ARG ")]
        self.assertEqual(args, [line for line in default.splitlines() if line.startswith("ARG ")])
        code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
        self.assertNotIn("ubuntu:latest", code)
        self.assertFalse("python3.12" in code, "python3.12 in the dev recipe")
        # The worker: built and sealed with the image's python3.
        self.assertIn("RUN --network=none /usr/bin/python3 -I -B /build/worker/worker.py build "
                      "--sources /build/worker-src --out /out --counterparts /build/worker-counterparts",
                      bodies["worker"])
        final = parsed[-1][1]
        self.assertEqual(final[-1], "RUN --network=none --mount=type=bind,from=worker,source=/build/worker,"
                                    "target=/run/agentbox-worker /usr/bin/python3 -I -B "
                                    "/run/agentbox-worker/worker.py seal")
        # The default's final stage, but its packages and checks: the same
        # copies, links, account removal and agent start.
        same = [line for line in base[-1][1] if not line.startswith("RUN apt-get") and "set -eu; if getent" not in line]
        mine = [line for line in final if not line.startswith("RUN apt-get") and "set -eu; if getent" not in line]
        self.assertEqual(mine, same)
        # Its packages: the default's and the toolchain's.
        default_install = next(line for line in base[-1][1] if line.startswith("RUN apt-get"))
        self.assertLessEqual(set(default_install.split("--no-install-recommends", 1)[1].split("&&", 1)[0].split()),
                             set(next(line for line in final if line.startswith("RUN apt-get"))
                                 .split("--no-install-recommends", 1)[1].split("&&", 1)[0].split()))
        install = [line for line in final if line.startswith("RUN apt-get")]
        self.assertEqual(len(install), 1)
        packages = install[0].split("--no-install-recommends", 1)[1].split("&&", 1)[0].split()
        self.assertEqual(packages, sorted(packages))
        for needed in ("build-essential", "ca-certificates", "cargo", "curl", "gdb", "git", "openssh-client",
                       "openssh-server", "pkg-config", "python3", "python3-dev", "python3-minimal", "python3-pip", "python3-venv",
                       "rustc", "tini"):
            self.assertIn(needed, packages)
        for absent in ("nodejs", "npm", "coreutils", "coreutils-from-gnu", "sudo"):
            self.assertNotIn(absent, packages)
        self.assertEqual(text.count("apt-get install"), 2)
        self.assertNotIn("--allow-remove-essential", text)
        checks = next(line for line in final if "set -eu; if getent" in line)
        for needed in ("/usr/bin/gdb", "/usr/bin/cargo", "/usr/bin/rustc", "/usr/bin/cc", "/usr/bin/pkg-config",
                       "/usr/bin/ssh", "/usr/bin/curl", "git-remote-https", "ca-certificates.crt",
                       "import ensurepip, sys, venv; assert sys.version_info >= (3, 12)",
                       # The SSH bootstrap's own forms (agentbox_controller/ssh.py), with this
                       # image's coreutils.
                       '[ "$(stat -c %u -- "$tmp")" = 0 ]', '[ $((0$(stat -c %a -- "$tmp") & 022)) -eq 0 ]',
                       'size=$(wc -c < "$tmp/f"); [ $size -eq 3 ]', "| sha256sum -c --status -",
                       "timeout 2 /usr/bin/sleep infinity", 'test "$2" -ge 53'):
            self.assertIn(needed, checks)
        bootstrap = slurp(os.path.join(REPO, "src", "agentbox_controller", "ssh.py"))
        for form in ('stat -c %u -- ', 'stat -c %a -- ', 'wc -c < ', 'sha256sum -c --status -'):
            self.assertIn(form, bootstrap)
        # `set -e` stops at each probe: no `&&` list or `!` pipeline hides one.
        probes = checks[checks.index('[ "$(uname -s)" = Linux ]'):]
        self.assertNotIn("&&", probes)
        self.assertNotIn("; !", probes)
        # The default's probes, the same coreutils.
        default_checks = next(line for line in base[-1][1] if "set -eu; if getent" in line)
        self.assertEqual(default_checks[default_checks.index('[ "$(uname -s)" = Linux ]'):], probes)

    def test_qemu_recipe_network_is_the_builds_alone(self):
        """The canonical build's network: user-mode NAT for APT (no host
        share, guestfwd or proxy), chosen apart from the provisioning; the
        runtime's restricted NIC is the provider's (qemu_argv)."""
        text = slurp(os.path.join(IMAGES, "qemu", "default", "agentbox.pkr.hcl"))
        code = "\n".join(l for l in text.splitlines() if not l.strip().startswith("#"))
        for needle in ('disk_image       = true', 'use_backing_file = false', 'format           = "qcow2"',
                       'cd_label = "cidata"', 'ssh_file_transfer_method     = "sftp"', 'headless         = true',
                       'vnc_bind_address = "127.0.0.1"', 'sensitive   = true',
                       'nat = "user,id=agentbox0,ipv4=on,ipv6=off,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"',
                       '["-netdev", local.netdev[var.build_network]]', 'contains(["nat"], var.build_network)',
                       '["-cpu", "host"]',
                       'ssh_agent_auth               = false', 'ssh_disable_agent_forwarding = true',
                       'shutdown_command = "sudo -n /bin/sh /var/tmp/agentbox-build/qemu/finalize.sh"',
                       'sudo -n /usr/bin/python3 -I -B /var/tmp/agentbox-build/qemu/guest-install.py',
                       'direction   = "download"'):
            self.assertIn(needle, code)
        self.assertNotIn("python3.12", code)
        # The jail's NIC stays restricted whatever the build's network; the
        # build's CPU model is the jail's.
        provider = slurp(os.path.join(REPO, "providers", "qemu.py"))
        self.assertIn("user,id=net0,restrict=on,ipv4=on,ipv6=off,", provider)
        self.assertIn('"-cpu", "host",', provider)
        for absent in ("http_directory", "http_content", "http_bind", "virtfs", "fsdev", "9p", "smb=",
                       "guestfwd", "ssh_password", "-net ", "floppy", "ansible", "curl", "wget", "apt-get",
                       "boot_command"):
            self.assertNotIn(absent, code)
        self.assertEqual(code.count("-netdev"), 1)
        self.assertEqual(re.findall(r'source\s+=\s+"([^"]+)"', code[code.index("build {"):]),
                         ["${var.context}/", "/var/tmp/agentbox-build/out/worker/",
                          "/var/tmp/agentbox-build/out/worker-metadata.json",
                          "/var/tmp/agentbox-build/out/image-manifest.json"])

    def test_qemu_guest_scripts_use_apt_alone_and_clean_up(self):
        install = slurp(os.path.join(IMAGES, "qemu", "default", "guest-install.py"))
        finalize = slurp(os.path.join(IMAGES, "qemu", "default", "finalize.sh"))
        for absent in ("curl", "wget", "npm install", "pip install", "http://", "https://", "import socket"):
            self.assertNotIn(absent, install)
            self.assertNotIn(absent, finalize)
        self.assertNotIn("urllib", finalize)
        self.assertNotIn("apt-get", finalize)
        # Stock APT, any update error fatal, phasing deterministic, the
        # base's shipped lists cleared first.
        for needed in ('"APT::Update::Error-Mode=any"', '"APT::Get::Never-Include-Phased-Updates=true"',
                       '"APT::Install-Recommends=false"', 'run([*APT, "update"])', 'run([*APT, "-y", "dist-upgrade"])',
                       'run([*APT, "-y", "install", *SYSTEM_PACKAGES])',
                       'SYSTEM_PACKAGES = ("git", "ca-certificates", "python3-venv")'):
            self.assertIn(needed, install)
        code = install[install.index('"""', 3) + 3:]
        self.assertLess(code.index("    clear_lists()\n    run([*APT, \"update\"])"), code.index('"dist-upgrade"'))
        for needed in ('rm -rf "$context"', "userdel --force --remove agentbox-build",
                       "rm -f /etc/sudoers.d/90-cloud-init-users", "cloud-init clean --logs --seed",
                       "rm -f /etc/ssh/ssh_host_*", ": > /etc/machine-id", "rm -rf /root/.ssh",
                       "/etc/ssh/sshd_config.d/00-agentbox.conf", "/etc/cloud/cloud.cfg.d/99-agentbox.cfg",
                       "ln -sfn /dev/null /etc/systemd/system/ssh.socket", "systemctl poweroff"):
            self.assertIn(needed, finalize)
        # Profile application is the finalize step, after every build session.
        self.assertLess(finalize.index("00-agentbox.conf"), finalize.index("userdel"))
        # Host private keys are overwritten before their removal.
        self.assertLess(finalize.index("\nscrub_host_keys /etc/ssh\n"),
                        finalize.index("rm -f /etc/ssh/ssh_host_*"))
        self.assertIn("worker.install(out)", install)
        self.assertIn("worker.build(", install)
        # The agents: every Node or npm process in the sandbox; online only
        # resolve.sh (npm, install scripts off) and the probe; the tarballs
        # from REGISTRY alone (agentlock's), no proxy, no redirect; npm
        # offline from the cache of exactly them.
        self.assertIn('flags = ["--offline", "--no-audit", "--no-fund", "--no-update-notifier"]', install)
        for unsandboxed in ("run([NPM", "run([NODE", "run([node", "subprocess.run([NPM"):
            self.assertNotIn(unsandboxed, install.replace("SANDBOX.run([NPM", ""))
        self.assertEqual(install.count("online=True"), 2)
        self.assertIn('SANDBOX.run(["/bin/sh", os.path.join(tools, "resolve.sh"), REGISTRY, out], online=True,',
                      install)
        self.assertIn("REGISTRY = agentlock.REGISTRY\n", install)
        self.assertIn("urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())", install)
        self.assertEqual(install.count(".urlopen("), 0)
        self.assertIn('SANDBOX.run([NPM, "cache", "add", "--cache", cache, *flags, ', install)
        self.assertIn('SANDBOX.run([NPM, "ci", "--prefix", target, "--cache", cache, "--omit=dev", *flags], ', install)
        main = install[install.index("def main(argv):"):]
        self.assertLess(main.index("SANDBOX = Sandbox(held)"), main.index("install_node(inputs)"))
        self.assertLess(main.index("install_node(inputs)"), main.index("resolve_agents(tools)"))
        # Verified only once the sandbox is gone.
        self.assertLess(main.index("sandbox.close()"), main.index("verify_agents(locks)"))
        self.assertLess(main.index("verify_agents(locks)"), main.index("write_system("))

    def test_qemu_profile_is_the_fixed_root_managed_profile(self):
        profile = os.path.join(IMAGES, "qemu", "default", "profile")
        self.assertEqual(sorted(os.listdir(profile)),
                         ["00-agentbox.conf", "10-agentbox-identity.conf", "99-agentbox-no-periodic",
                          "99-agentbox.cfg"])
        cloud = slurp(os.path.join(profile, "99-agentbox.cfg")).splitlines()
        self.assertEqual(cloud, ["datasource_list: [ NoCloud, None ]", "manual_cache_clean: false",
                                 "cloud_init_modules: [ seed_random, write_files, set_hostname, update_hostname,"
                                 " update_etc_hosts, users_groups ]",
                                 "cloud_config_modules: []", "cloud_final_modules: [ final_message ]"])
        sshd = [line.split(" ", 1) for line in slurp(os.path.join(profile, "00-agentbox.conf")).splitlines()]
        self.assertEqual(dict(sshd), {
            "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "PermitRootLogin": "no",
            "AllowUsers": "agentbox", "PubkeyAuthentication": "yes", "AuthenticationMethods": "publickey",
            "AuthorizedKeysFile": "/etc/ssh/agentbox_authorized_keys", "AuthorizedKeysCommand": "none",
            "TrustedUserCAKeys": "none", "HostbasedAuthentication": "no",
            "HostKey": "/etc/ssh/ssh_host_ed25519_key", "AllowAgentForwarding": "no",
            "AllowTcpForwarding": "remote", "PermitListen": "127.0.0.1:18080", "GatewayPorts": "no",
            "X11Forwarding": "no", "PermitTunnel": "no", "PermitUserEnvironment": "no", "UseDNS": "no",
            "PrintMotd": "no"})
        self.assertEqual(len(sshd), 20)
        service = slurp(os.path.join(profile, "10-agentbox-identity.conf"))
        # Ubuntu 26.04's cloud-init (24.3 on) runs the init stage, which
        # writes the seed's keys and accounts, as cloud-init-network.service;
        # sshd answers only once logins are allowed (no /run/nologin): its
        # banner is the start's readiness.
        self.assertEqual(service, "[Unit]\nRequires=cloud-init-local.service cloud-init-network.service\n"
                                  "After=cloud-init-local.service cloud-init-network.service "
                                  "systemd-user-sessions.service\n\n[Service]\n"
                                  "ExecStartPre=/usr/bin/test -s /etc/ssh/agentbox_authorized_keys\n"
                                  "ExecStartPre=/usr/bin/test -s /etc/ssh/ssh_host_ed25519_key\n"
                                  "ExecStartPre=/usr/bin/test -s /etc/ssh/ssh_host_ed25519_key.pub\n")
        periodic = slurp(os.path.join(profile, "99-agentbox-no-periodic")).splitlines()
        self.assertEqual(periodic, ['APT::Periodic::Enable "0";', 'APT::Periodic::Update-Package-Lists "0";',
                                    'APT::Periodic::Unattended-Upgrade "0";'])


class FinalizeHostKeys(Temp):
    """finalize.sh's own `scrub_host_keys`, run by /bin/sh on stand-in key
    files in a private directory (the host's shred; GNU's in the guest)."""

    def scrub(self, directory):
        text = slurp(os.path.join(IMAGES, "qemu", "default", "finalize.sh"))
        start = text.index("scrub_host_keys() {")
        function = text[start:text.index("\n}\n", start) + 3]
        return subprocess.run(["/bin/sh", "-euc", function + 'scrub_host_keys "$1"', "sh", directory],
                              capture_output=True, timeout=60)

    def test_private_keys_are_zeroed_in_place_and_others_kept(self):
        keys = self.path("ssh")
        os.mkdir(keys)
        self.assertEqual(self.scrub(keys).returncode, 0)
        names = ("ssh_host_ed25519_key", "ssh_host_rsa_key", "ssh_host_ecdsa_key")
        inodes = {}
        for name in names + ("ssh_host_ed25519_key.pub", "sshd_config"):
            with open(os.path.join(keys, name), "wb") as stream:
                stream.write(b"synthetic-not-a-key-" + name.encode() * 20)
            inodes[name] = os.stat(os.path.join(keys, name)).st_ino
        done = self.scrub(keys)
        self.assertEqual((done.returncode, done.stderr), (0, b""))
        for name, inode in inodes.items():
            path = os.path.join(keys, name)
            data = slurp(path, "rb")
            self.assertEqual(os.stat(path).st_ino, inode)
            if name in names:
                self.assertTrue(data and not data.strip(b"\0"), name)
            else:
                self.assertTrue(data.startswith(b"synthetic-not-a-key-"), name)

    def test_a_link_or_non_regular_key_refuses_untouched(self):
        target = self.path("target")
        with open(target, "wb") as stream:
            stream.write(b"synthetic-target")
        cases = (("symlink", lambda key: os.symlink(target, key)),
                 ("dangling", lambda key: os.symlink(self.path("absent"), key)),
                 ("hardlink", lambda key: os.link(target, key)),
                 ("directory", os.mkdir),
                 ("fifo", os.mkfifo))
        for label, make in cases:
            keys = self.path(label)
            os.mkdir(keys)
            make(os.path.join(keys, "ssh_host_ed25519_key"))
            done = self.scrub(keys)
            self.assertEqual((done.returncode, done.stderr),
                             (1, b"agentbox-finalize refused: host_key\n"), label)
            self.assertEqual(slurp(target, "rb"), b"synthetic-target", label)

if __name__ == "__main__":
    unittest.main()
