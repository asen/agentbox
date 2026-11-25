"""The pip distribution (agentbox_build.py), offline, in private scratch:
this checkout's sdist; a wheel pip builds from that sdist with a stand-in
`cargo` first on a fixed PATH (it writes a stand-in relay, nothing
compiled); that wheel installed by pip without an index into a venv and a
user prefix under umask 022, and into a venv under umask 002; then the
installed CLI run from `/` with an isolated environment.

AGENTBOX_TEST_PREFIX=PREFIX (CI: the real build from the sdist, installed)
runs the installed-tree checks on that install too.
"""
import base64
import csv
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

import agentbox_build  # noqa: E402
import package  # noqa: E402
import worker  # noqa: E402
from test_package import ELF, capabilities, tree  # noqa: E402

VERSION = "0.1.0"
BASE = f"agentbox-{VERSION}"
WHEEL = f"{BASE}-py3-none-linux_x86_64.whl"
SHEBANG = b"#!/usr/bin/python3 -IB\n"
FAKE_CARGO = """
import json, os, sys
args = sys.argv[1:]
with open(os.environ["FAKE_CARGO_LOG"], "a") as stream:
    stream.write(json.dumps({"args": args, "cwd": os.getcwd()}) + "\\n")
target = args[args.index("--target-dir") + 1]
os.makedirs(os.path.join(target, "release"), exist_ok=True)
path = os.path.join(target, "release", "agentbox-relay")
with open(path, "wb") as stream:
    stream.write(ELF)
os.chmod(path, 0o755)
"""


def run(argv, env, cwd="/", umask=0o022, timeout=300):
    return subprocess.run(argv, env=env, cwd=cwd, umask=umask, capture_output=True, timeout=timeout)


class Scratch:
    """The class's shared scratch: the stand-in cargo, the sdist, the
    wheel pip built from it, and the installs."""

    def __init__(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="abw-"))
        for name in ("bin", "home", "tmp", "dist", "empty"):
            os.mkdir(os.path.join(self.tmp, name), 0o700)
        self.cargo_log = os.path.join(self.tmp, "cargo.jsonl")
        with open(os.path.join(self.tmp, "bin", "cargo"), "w") as stream:
            stream.write(f"#!{sys.executable} -I\nELF = {ELF!r}\n{FAKE_CARGO}")
        os.chmod(os.path.join(self.tmp, "bin", "cargo"), 0o755)

    def env(self, **extra):
        env = {"PATH": f"{self.tmp}/bin:/usr/bin:/bin", "HOME": f"{self.tmp}/home", "TMPDIR": f"{self.tmp}/tmp",
               "LC_ALL": "C", "FAKE_CARGO_LOG": self.cargo_log}
        env.update(extra)
        return env

    def pip(self, *args, env=None, umask=0o022):
        done = run([sys.executable, "-m", "pip", "--isolated", "--disable-pip-version-check", "--no-cache-dir",
                    *args], env or self.env(), umask=umask)
        if done.returncode != 0:
            raise AssertionError(done.stdout.decode() + done.stderr.decode())
        return done

    def sdist(self):
        probe = (f"import sys; sys.path.insert(0, {HERE!r}); import agentbox_build; "
                 f"print(agentbox_build.build_sdist(sys.argv[1]))")
        done = run([sys.executable, "-I", "-B", "-c", probe, os.path.join(self.tmp, "dist")], self.env(), cwd=REPO)
        if done.returncode != 0:
            raise AssertionError(done.stderr.decode())
        return os.path.join(self.tmp, "dist", done.stdout.decode().strip())

    def wheel(self, sdist):
        self.pip("wheel", "--no-deps", "--no-index", "-w", os.path.join(self.tmp, "dist"), sdist)
        return os.path.join(self.tmp, "dist", WHEEL)

    def venv(self, name, wheel, umask=0o022):
        prefix = os.path.join(self.tmp, name)
        done = run([sys.executable, "-m", "venv", "--without-pip", prefix], self.env(), umask=umask)
        if done.returncode != 0:
            raise AssertionError(done.stderr.decode())
        self.pip("--python", os.path.join(prefix, "bin", "python"), "install", "--no-deps", "--no-index", wheel,
                 umask=umask)
        return prefix

    def user(self, name, wheel):
        prefix = os.path.join(self.tmp, name)
        self.pip("install", "--user", "--break-system-packages", "--no-deps", "--no-index", wheel,
                 env=self.env(PYTHONUSERBASE=prefix))
        return prefix

    def close(self):
        shutil.rmtree(self.tmp, True)


_SHARED = []


def shared():
    """The module's scratch, its sdist and wheel built once."""
    if not _SHARED:
        scratch = Scratch()
        _SHARED.append(scratch)
        scratch.sdist_path = scratch.sdist()
        scratch.wheel_path = scratch.wheel(scratch.sdist_path)
    return _SHARED[0]


def tearDownModule():
    for scratch in _SHARED:
        scratch.close()


class Distribution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = shared()

    def test_the_sdist_is_the_build_and_its_sources(self):
        with tarfile.open(self.scratch.sdist_path) as tar:
            members = tar.getmembers()
            data = {m.name[len(BASE) + 1:]: tar.extractfile(m).read() for m in members if m.isfile()}
        self.assertTrue(all(m.name == BASE or m.name.startswith(BASE + "/") for m in members))
        self.assertTrue(all(m.isfile() or m.isdir() for m in members))
        self.assertTrue(all((m.uid, m.gid, m.mode) == (0, 0, 0o755 if m.isdir() else 0o644) for m in members))
        crate = sorted(os.path.relpath(os.path.join(d, n), REPO)
                       for crate in ("agentbox-relay",)
                       for d, _, names in os.walk(os.path.join(REPO, "crates", crate, "src"))
                       for n in names if n.endswith(".rs"))
        expected = set(agentbox_build.SDIST) | {package.LAUNCHER_SOURCE, package.SERVER_SOURCE, "PKG-INFO"} \
            | set(package.allowlist(REPO)) | set(crate)
        self.assertEqual(set(data), expected)
        self.assertIn("crates/agentbox-relay/Cargo.toml", data)
        self.assertIn("crates/agentbox-relay/src/main.rs", data)
        for rel in data:
            self.assertFalse(rel.startswith((".git", "target/", "guest/node_modules", "guest/test/", "docs/")), rel)
            self.assertFalse(os.path.basename(rel).startswith("test_"), rel)
            if rel != "PKG-INFO":
                with open(os.path.join(REPO, rel), "rb") as stream:
                    self.assertEqual(data[rel], stream.read(), rel)
        self.assertIn(f"Version: {VERSION}\n".encode(), data["PKG-INFO"])
        # Reproducible: the same bytes again.
        again = os.path.join(self.scratch.tmp, "again")
        os.mkdir(again)
        probe = (f"import sys; sys.path.insert(0, {HERE!r}); import agentbox_build; "
                 f"agentbox_build.build_sdist(sys.argv[1])")
        done = run([sys.executable, "-I", "-B", "-c", probe, again], self.scratch.env(), cwd=REPO)
        self.assertEqual(done.returncode, 0, done.stderr)
        with open(self.scratch.sdist_path, "rb") as first, open(os.path.join(again, f"{BASE}.tar.gz"), "rb") as second:
            self.assertEqual(first.read(), second.read())

    def test_pip_builds_the_wheel_from_the_sdist_with_cargo(self):
        with open(self.scratch.cargo_log) as stream:
            calls = [json.loads(line) for line in stream]
        self.assertEqual(len(calls), 1)
        args, cwd = calls[0]["args"], calls[0]["cwd"]
        # pip's unpacked sdist, never this checkout.
        self.assertEqual(args, ["build", "--release", "--locked", "--target-dir", os.path.join(cwd, "target")])
        self.assertFalse(cwd.startswith(REPO + "/"))
        self.assertTrue(cwd.startswith(self.scratch.tmp + "/"))
        with zipfile.ZipFile(self.scratch.wheel_path) as archive:
            names = archive.namelist()
            info = f"{BASE}.dist-info"
            allow = package.allowlist(REPO)
            self.assertEqual(sorted(names), sorted(
                [f"{BASE}.data/scripts/{name}" for name in ("agentbox", "agentbox-server", "agentbox-relay")]
                + [f"{BASE}.data/data/share/agentbox-assets/{package.installed(rel)}" for rel in allow]
                + [f"{info}/METADATA", f"{info}/WHEEL", f"{info}/RECORD"]))
            self.assertEqual(archive.read(f"{BASE}.data/scripts/agentbox-relay"), ELF)
            with open(os.path.join(REPO, package.SERVER_SOURCE), "rb") as stream:
                self.assertEqual(archive.read(f"{BASE}.data/scripts/agentbox-server"), stream.read())
            launcher = archive.read(f"{BASE}.data/scripts/agentbox")
            with open(os.path.join(REPO, package.LAUNCHER_SOURCE), "rb") as stream:
                self.assertEqual(launcher, stream.read())
            self.assertTrue(launcher.startswith(SHEBANG))
            for item in archive.infolist():
                mode = 0o755 if "/scripts/" in item.filename else 0o644
                self.assertEqual(item.external_attr >> 16, stat.S_IFREG | mode, item.filename)
            wheel = archive.read(f"{info}/WHEEL").decode()
            self.assertIn("Root-Is-Purelib: false\n", wheel)
            self.assertIn("Tag: py3-none-linux_x86_64\n", wheel)
            self.assertIn(f"Version: {VERSION}\n", archive.read(f"{info}/METADATA").decode())
            rows = list(csv.reader(io.StringIO(archive.read(f"{info}/RECORD").decode())))
            self.assertEqual(sorted(r[0] for r in rows), sorted(names))
            for path, digest, size in rows:
                if path == f"{info}/RECORD":
                    self.assertEqual((digest, size), ("", ""))
                    continue
                data = archive.read(path)
                self.assertEqual(digest, "sha256=" + base64.urlsafe_b64encode(
                    hashlib.sha256(data).digest()).rstrip(b"=").decode(), path)
                self.assertEqual(int(size), len(data), path)

    def test_one_version_and_one_minimum_python(self):
        from_cargo = agentbox_build.version(REPO)
        with open(os.path.join(REPO, "src", "agentbox_controller", "cli.py")) as stream:
            self.assertIn(f'VERSION = "{from_cargo}"\n', stream.read())
        self.assertEqual(from_cargo, VERSION)
        # The host code's minimum (hashlib.file_digest, PEP 701 f-strings):
        # the metadata, doctor and the launcher say the same.
        self.assertEqual(agentbox_build.REQUIRES_PYTHON, ">=3.12")
        with zipfile.ZipFile(self.scratch.wheel_path) as archive:
            self.assertIn("Requires-Python: >=3.12\n", archive.read(f"{BASE}.dist-info/METADATA").decode())
        for rel in ("src/agentbox_controller/doctor.py", package.LAUNCHER_SOURCE):
            with open(os.path.join(REPO, rel)) as stream:
                self.assertIn("\nMIN_PYTHON = (3, 12)\n", stream.read(), rel)

    def test_without_cargo_the_build_is_refused(self):
        source = os.path.join(self.scratch.tmp, "unpacked")
        with tarfile.open(self.scratch.sdist_path) as tar:
            tar.extractall(source, filter="data")
        source = os.path.join(source, BASE)
        out = os.path.join(self.scratch.tmp, "nowheel")
        os.mkdir(out)
        probe = ("import sys; sys.path.insert(0, 'packaging'); import agentbox_build; "
                 "agentbox_build.build_wheel(sys.argv[1])")
        done = run([sys.executable, "-I", "-B", "-c", probe, out],
                   dict(self.scratch.env(), PATH=os.path.join(self.scratch.tmp, "empty")), cwd=source)
        self.assertEqual(done.returncode, 1, done.stderr)
        self.assertEqual(done.stderr.decode().splitlines()[0],
                         "agentbox build: cargo not found on PATH: the wheel builds agentbox-relay from source "
                         "(Rust, packaging/README.md)")
        self.assertEqual(os.listdir(out), [])
        self.assertFalse(os.path.lexists(os.path.join(source, "target")))


class InstalledChecks:
    """One install's checks; `prefix` (bin/ and share/), `relay` (the
    expected agentbox-relay bytes, or None for a real build)."""
    relay = ELF

    def env(self, **extra):
        env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(self.home, "h"), "LC_ALL": "C"}
        env.update(extra)
        return env

    def entry(self, *args, cwd="/", **extra):
        return run([os.path.join(self.prefix, "bin", "agentbox"), *args], self.env(**extra), cwd=cwd)

    def assets(self):
        return os.path.join(self.prefix, "share", "agentbox-assets")

    def test_the_launcher_and_server_are_the_packaged_ones(self):
        for name, rel in (("agentbox", package.LAUNCHER_SOURCE), ("agentbox-server", package.SERVER_SOURCE)):
            with open(os.path.join(self.prefix, "bin", name), "rb") as stream, \
                    open(os.path.join(REPO, rel), "rb") as source:
                self.assertEqual(stream.read(), source.read())
        for name in ("agentbox", "agentbox-server", "agentbox-relay"):
            st = os.lstat(os.path.join(self.prefix, "bin", name))
            self.assertTrue(stat.S_ISREG(st.st_mode))
            self.assertIn(stat.S_IMODE(st.st_mode), (0o755, 0o775), name)
        with open(os.path.join(self.prefix, "bin", "agentbox-relay"), "rb") as stream:
            head = stream.read()
        self.assertTrue(package.elf_x86_64(head[:20]))
        if self.relay is not None:
            self.assertEqual(head, self.relay)

    def test_the_installed_server_runs_from_its_prefix(self):
        """Its package found in the prefix's assets, not this checkout: at
        once the end of its input, a clean stop."""
        done = subprocess.run([os.path.join(self.prefix, "bin", "agentbox-server")], input=b"",
                              capture_output=True, cwd="/", env={"PATH": "/usr/bin:/bin"}, timeout=60)
        self.assertEqual((done.returncode, done.stderr), (0, b"agentbox-server: control_eof\n"))
        stopped = json.loads(done.stdout[4:])
        self.assertEqual((stopped["type"], stopped["reason"], stopped["clean"]), ("stopped", "control_eof", True))

    def test_the_assets_are_the_allowlist_and_trusted(self):
        found = tree(self.assets())
        files = {p for p, (kind, _) in found.items() if kind == "file" and "__pycache__" not in p.split("/")}
        self.assertEqual(files, {package.installed(rel) for rel in package.allowlist(REPO)})
        # pip's own bytecode is the only addition.
        self.assertTrue(all(kind in ("dir", "file") for kind, _ in found.values()))
        self.assertTrue(all("__pycache__" in p.split("/") for p in set(found) - files
                            if found[p][0] == "file"))
        for path in [self.assets()] + [os.path.join(self.assets(), p) for p in found]:
            st = os.lstat(path)
            self.assertEqual(st.st_uid, os.geteuid())
            self.assertFalse(st.st_mode & 0o002, path)
        for rel in package.allowlist(REPO):
            self.assertEqual(worker.measured(os.path.join(self.assets(), package.installed(rel))),
                             worker.measured(os.path.join(REPO, rel)), rel)
        self.assertEqual(worker.source_revision(worker.source_files(self.assets())),
                         worker.source_revision(worker.source_files(REPO)))
        # Never the old CLI's store root.
        self.assertFalse(os.path.lexists(os.path.join(self.prefix, "share", "agentbox")))

    def test_the_installed_cli_runs_isolated_outside_the_checkout(self):
        evil = os.path.join(self.home, "evil")
        os.makedirs(os.path.join(evil, "agentbox_controller"), exist_ok=True)
        for name in ("__init__.py", "cli.py"):
            with open(os.path.join(evil, "agentbox_controller", name), "w") as stream:
                stream.write("raise SystemExit('EVIL')\n")
        done = self.entry("--version", cwd=evil, PYTHONPATH=evil)
        self.assertEqual((done.returncode, done.stdout), (0, f"agentbox {VERSION} (Python controller; "
                                                             f"server protocol v1)\n".encode()), done.stderr)
        done = self.entry("no-such-command", cwd=evil, PYTHONPATH=evil)
        self.assertEqual(done.returncode, 2)
        self.assertIn(b"agentbox run AGENT", done.stderr)
        self.assertNotIn(b"EVIL", done.stdout + done.stderr)
        done = self.entry("doctor")
        self.assertIn(b"server: ok\n", done.stdout)
        for command in (("image", "list"), ("jail", "list")):
            done = self.entry(*command)
            self.assertEqual(done.returncode, 0, done.stderr)
        # The built-in profiles find this install's trusted providers.
        probe = ("import sys; sys.path[:0] = [sys.argv[1]]; from agentbox_controller import builtin; "
                 "builtin.check_tree(); print(builtin.ASSETS)")
        done = run(["/usr/bin/python3", "-I", "-B", "-c", probe, os.path.join(self.assets(), "controller")],
                   self.env())
        self.assertEqual((done.returncode, done.stdout.decode().strip()), (0, self.assets()), done.stderr)
        state = os.path.join(self.home, "state")
        os.makedirs(state, 0o700, exist_ok=True)
        for name, transport in (("qemu", "tcp"), ("podman", "stdio")):
            answer = capabilities(self.assets(), name, state)
            self.assertEqual((answer["type"], answer["provider"], answer["transport"]),
                             ("described", name, transport))


class Venv(InstalledChecks, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = shared()
        cls.prefix = cls.scratch.venv("venv", cls.scratch.wheel_path)
        cls.home = os.path.join(cls.scratch.tmp, "use-venv")
        os.makedirs(os.path.join(cls.home, "h"), 0o700)

    def test_uninstall_leaves_nothing_of_ours(self):
        prefix = self.scratch.venv("venv-gone", self.scratch.wheel_path)
        self.scratch.pip("--python", os.path.join(prefix, "bin", "python"), "uninstall", "-y", "agentbox")
        for rel in ("bin/agentbox", "bin/agentbox-server", "bin/agentbox-relay"):
            self.assertFalse(os.path.lexists(os.path.join(prefix, rel)), rel)
        # pip may leave empty directories; no file.
        self.assertEqual([p for p, (kind, _) in tree(os.path.join(prefix, "share")).items() if kind != "dir"], [])

    def test_install_under_umask_0002_works(self):
        prefix = self.scratch.venv("venv-002", self.scratch.wheel_path, umask=0o002)
        assets = os.path.join(prefix, "share", "agentbox-assets")
        self.assertEqual(stat.S_IMODE(os.lstat(os.path.join(prefix, "bin", "agentbox-server")).st_mode), 0o775)
        self.assertTrue(os.lstat(os.path.join(assets, "providers", "podman.py")).st_mode & 0o020)
        env = self.env()
        done = run([os.path.join(prefix, "bin", "agentbox"), "doctor"], env)
        self.assertIn(b"server: ok\n", done.stdout)
        probe = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from agentbox_controller import agent, builtin, config, handlers; "
            "builtin.check_tree(); agent.tools({}, builtin.ASSETS, 'pi'); "
            "config.input_tools({}, builtin.ASSETS); "
            "handlers.packaged('/usr/bin/python3', builtin.ASSETS, 'npm', 'agents/npm-registry.json'); "
            # The packaged default policies, from the installed tree.
            "chosen = handlers.select({'schema': handlers.CONFIG_SCHEMA, 'interpreter': '/usr/bin/python3', "
            "'handlers': {'npm': {}, 'pip': {}}}, None); "
            "assert sorted(chosen.handlers) == ['npm', 'pip'] and chosen.assets == builtin.ASSETS"
        )
        done = run(["/usr/bin/python3", "-I", "-B", "-c", probe, os.path.join(assets, "controller")], env)
        self.assertEqual(done.returncode, 0, done.stderr)
        done = subprocess.run([os.path.join(prefix, "bin", "agentbox-server")], input=b"",
                              capture_output=True, cwd="/", env=env, timeout=60)
        self.assertEqual((done.returncode, done.stderr), (0, b"agentbox-server: control_eof\n"))


class UserPrefix(InstalledChecks, unittest.TestCase):
    """`pip install --user` (PYTHONUSERBASE): bin/ and share/ under it."""

    @classmethod
    def setUpClass(cls):
        cls.scratch = shared()
        cls.prefix = cls.scratch.user("userbase", cls.scratch.wheel_path)
        cls.home = os.path.join(cls.scratch.tmp, "use-user")
        os.makedirs(os.path.join(cls.home, "h"), 0o700)


@unittest.skipUnless(os.environ.get("AGENTBOX_TEST_PREFIX"), "AGENTBOX_TEST_PREFIX: an install to check")
class GivenInstall(InstalledChecks, unittest.TestCase):
    """The operator's (CI's) install, its real relay."""
    relay = None

    @classmethod
    def setUpClass(cls):
        cls.prefix = os.environ["AGENTBOX_TEST_PREFIX"]
        cls.home = os.path.realpath(tempfile.mkdtemp(prefix="abg-"))
        os.makedirs(os.path.join(cls.home, "h"), 0o700)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.home, True)


if __name__ == "__main__":
    unittest.main()
