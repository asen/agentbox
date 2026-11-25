"""package.py on this repository and on synthetic copies, in private
scratch. Runs only the staged providers' `capabilities` (no custody, tool or
engine) as owned subprocesses."""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO, "providers"))

import package  # noqa: E402
import protocol  # noqa: E402
import worker  # noqa: E402

ELF = b"\x7fELF\x02\x01\x01\x00" + bytes(10) + b"\x3e\x00" + bytes(44)
# The Rust asset-tree bounds (provider_config.rs).
MAX_ASSET_ENTRIES, MAX_ASSET_DEPTH = 4096, 16


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), 0o700, exist_ok=True)
    with open(path, "wb") as stream:
        stream.write(data)
    os.chmod(path, mode)


def tree(root):
    """{relative path: (kind, mode)} of everything below `root`, by lstat."""
    out = {}
    for parent, dirs, files in os.walk(root):
        for name in dirs + files:
            path = os.path.join(parent, name)
            st = os.lstat(path)
            kind = "dir" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other"
            out[os.path.relpath(path, root)] = (kind, stat.S_IMODE(st.st_mode))
    return out


def capabilities(assets, name, state):
    """The staged provider `name`'s `capabilities` answer, run from `/` with
    an isolated interpreter and a fixed environment."""
    request = {"type": "capabilities", "operation": "op-1", "timeout_ms": 1000}
    # stdin stays open until the answer: its EOF is host loss.
    proc = subprocess.Popen([sys.executable, "-I", "-B", os.path.join(assets, "providers", f"{name}.py"),
                             "control", state], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd="/", env={"PATH": "/usr/bin:/bin"})
    try:
        proc.stdin.write(protocol.encode(request) + b"\n")
        proc.stdin.flush()
        line = proc.stdout.readline()
        proc.stdin.close()
        if proc.wait(60) != 0:
            raise AssertionError(proc.stderr.read())
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
        proc.stderr.close()
    return protocol.decode_response(line.rstrip(b"\n"))


class Package(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="abp-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.relay = os.path.join(self.tmp, "agentbox-relay")
        write(self.relay, ELF + b"relay", 0o755)

    def run_package(self, source, out, relay=None):
        return package.package(source, relay or self.relay, out)

    def source_copy(self):
        """The allowlisted files of this repository, copied (0700/0600)."""
        source = os.path.join(self.tmp, "src")
        for rel in package.allowlist(REPO) + [package.LAUNCHER_SOURCE, package.SERVER_SOURCE]:
            with open(os.path.join(REPO, rel), "rb") as stream:
                write(os.path.join(source, rel), stream.read(), 0o600)
        return source

    def refused(self, code, source, out=None, relay=None):
        out = out or os.path.join(self.tmp, "out")
        with self.assertRaises(package.Refused) as caught:
            self.run_package(source, out, relay)
        self.assertEqual(str(caught.exception), code)
        return out

    def test_the_package_is_exactly_the_allowlist_with_fixed_modes(self):
        out = os.path.join(self.tmp, "out")
        assets = self.run_package(REPO, out)
        self.assertEqual(assets, os.path.join(out, "share", "agentbox-assets"))
        allow = package.allowlist(REPO)
        files = {f"share/agentbox-assets/{package.installed(rel)}" for rel in allow} | {
            "bin/agentbox", "bin/agentbox-server", "bin/agentbox-relay"}
        found = tree(out)
        self.assertEqual({p for p, (k, _) in found.items() if k == "file"}, files)
        self.assertTrue(all(kind in ("dir", "file") for kind, _ in found.values()))
        for path, (kind, mode) in found.items():
            expected = 0o755 if kind == "dir" or path.startswith("bin/") else 0o644
            self.assertEqual(mode, expected, path)
        self.assertEqual(stat.S_IMODE(os.lstat(out).st_mode), 0o755)
        # Nothing else of the checkout: no tests, build output, docs or HUMAN.md.
        for absent in ("HUMAN.md", "providers/test_qemu.py", "images/worker/test_worker.py",
                       "acquisitions/test_git_handler.py", "acquisitions/git_fixture_server.py",
                       "acquisitions/test_package_handlers.py", "acquisitions/package_fixture_server.py",
                       "acquisitions/handler_testing.py", "acquisitions/testing",
                       "acquisitions/handlers", "acquisitions/lib/__pycache__",
                       "acquisitions/git/__pycache__", "acquisitions/git/host/__pycache__",
                       "guest/dist", "inputs/test_stage.py", "inputs/__pycache__",
                       "guest/node_modules", "guest/test", "packaging", "crates", "contracts",
                       "acquisitions/contracts", "acquisitions/git/contract",
                       "acquisitions/npm/contract", "acquisitions/pip/contract",
                       "agents/test_pi_adapter.py", "agents/test_codex_adapter.py",
                       "agents/test_claude_adapter.py", "agents/test_jail.py",
                       "agents/pi/__pycache__", "agents/codex/__pycache__"):
            self.assertFalse(os.path.lexists(os.path.join(assets, absent)), absent)
        self.assertIn("images/qemu/default/profile/00-agentbox.conf", allow)
        self.assertIn("guest/home/AGENTS.md", allow)
        for handler in ("git", "npm", "pip"):
            self.assertIn(f"acquisitions/{handler}/manifest.json", allow)
            # Its packaged default policy (handlers.PACKAGED).
            self.assertIn(f"acquisitions/{handler}/policy.json", allow)
            self.assertIn(f"acquisitions/{handler}/host/worker.py", allow)
            # Its jail package beside it, the module its manifest names
            # among them.
            self.assertIn(f"acquisitions/{handler}/__init__.py", allow)
            self.assertIn(f"acquisitions/{handler}/jail/__init__.py", allow)
            self.assertIn(f"acquisitions/{handler}/jail/{handler}.py", allow)
        self.assertIn("acquisitions/__init__.py", allow)
        self.assertIn("guest/__init__.py", allow)
        self.assertIn("acquisitions/lib/agentbox_handler.py", allow)
        # The host's own input worker, alone in its directory.
        self.assertEqual([rel for rel in allow if rel.startswith("inputs/")], ["inputs/stage.py"])
        # Each agent: its adapter, the common runner once, the installer's
        # registry policy; no agent-package handler.
        self.assertEqual([rel for rel in allow if rel.startswith("agents/")],
                         ["agents/claude/adapter.py", "agents/codex/adapter.py",
                          "agents/jail/run.py", "agents/npm-registry.json", "agents/pi/adapter.py"])
        self.assertFalse([rel for rel in allow if rel.startswith("acquisitions/agent-package/")])
        # Both recipes' agent resolution and lock check; no lock.
        self.assertEqual([rel for rel in allow if rel.startswith("images/agents/")], ["images/agents/resolve.sh"])
        self.assertIn("images/worker/agentlock.py", allow)
        # QEMU's one preset: its recipe, guest files, inputs' pins and both
        # keyrings, together; no README.
        self.assertEqual([rel for rel in allow if rel.startswith("images/qemu/")], sorted(
            f"images/qemu/default/{name}" for name in (
                "agentbox.pkr.hcl", "guest-install.py", "finalize.sh", "inputs.lock.json",
                "ubuntu-cloudimage-keyring.gpg", "nodejs-release-keyring.gpg", "profile/00-agentbox.conf",
                "profile/10-agentbox-identity.conf", "profile/99-agentbox-no-periodic", "profile/99-agentbox.cfg")))
        # Every canonical Podman recipe, one directory per preset.
        self.assertEqual([rel for rel in allow if rel.startswith("images/podman/")],
                         ["images/podman/default/Dockerfile", "images/podman/dev/Dockerfile"])
        # Every file each shipped manifest lists is shipped; its jail entry
        # is the bundle path of a shipped jail source.
        for handler in ("git", "npm", "pip"):
            with open(os.path.join(REPO, "acquisitions", handler, "manifest.json")) as stream:
                manifest = json.load(stream)
            for listed in manifest["files"]:
                self.assertIn(f"acquisitions/{listed}", allow, listed)
            entry = manifest["jail"]["entry"]
            self.assertEqual(entry, f"acquisitions/{handler}/jail/{handler}.py")
            self.assertIn(entry, allow)
        # Within the Rust tree bounds, every object ours and not group or world writable.
        self.assertLess(len(tree(assets)), MAX_ASSET_ENTRIES)
        self.assertLess(max(p.count("/") for p in tree(assets)) + 1, MAX_ASSET_DEPTH)
        for path in [assets] + [os.path.join(assets, p) for p in tree(assets)]:
            st = os.lstat(path)
            self.assertEqual(st.st_uid, os.geteuid())
            self.assertFalse(st.st_mode & 0o022, path)
        # The entry and the server are the Python launchers; beside them
        # the relay child.
        for name, rel in (("agentbox", package.LAUNCHER_SOURCE), ("agentbox-server", package.SERVER_SOURCE)):
            with open(os.path.join(out, "bin", name), "rb") as stream, \
                    open(os.path.join(REPO, rel), "rb") as source:
                self.assertEqual(stream.read(), source.read())
        with open(os.path.join(out, "bin", "agentbox-relay"), "rb") as stream:
            self.assertEqual(stream.read(), ELF + b"relay")
        # The controller: its entry and every module of its packages, from
        # SRC/src to ASSETS/controller; never tests/ (fakes, stand-ins,
        # launch seams).
        modules = sorted(f"src/{package_dir}/{name}"
                         for package_dir in ("agentbox_controller", "agentbox_server")
                         for name in os.listdir(os.path.join(REPO, "src", package_dir))
                         if name.endswith(".py"))
        self.assertEqual([rel for rel in allow if rel.startswith("src/")],
                         sorted(["src/main.py"] + modules))
        self.assertEqual(sorted(os.listdir(os.path.join(assets, "controller"))),
                         ["agentbox_controller", "agentbox_server", "main.py"])
        for absent in ("src", "tests"):
            self.assertFalse(os.path.lexists(os.path.join(assets, absent)), absent)

    def test_the_staged_worker_sources_have_the_source_revision(self):
        out = os.path.join(self.tmp, "out")
        assets = self.run_package(REPO, out)
        source = worker.source_files(REPO)
        staged = worker.source_files(assets)
        self.assertEqual(staged, source)
        # Every handler's jail tree, beside its host worker.
        self.assertEqual({e["path"].split("/")[1] for e in staged if e["path"].startswith("acquisitions/")
                          and e["path"].count("/") > 1}, {"git", "npm", "pip"})
        self.assertEqual(worker.source_revision(staged), worker.source_revision(source))
        for rel in package.allowlist(REPO):
            self.assertEqual(worker.measured(os.path.join(assets, package.installed(rel))),
                             worker.measured(os.path.join(REPO, rel)), rel)

    def test_staged_providers_answer_from_root_with_isolated_python(self):
        assets = self.run_package(REPO, os.path.join(self.tmp, "out"))
        before = tree(assets)
        for name, transport in (("qemu", "tcp"), ("podman", "stdio")):
            state = os.path.join(self.tmp, f"state-{name}")
            os.mkdir(state, 0o700)
            answer = capabilities(assets, name, state)
            self.assertEqual((answer["type"], answer["provider"], answer["transport"]),
                             ("described", name, transport))
            self.assertEqual(os.listdir(state), [])
        # Nothing written into the assets (no bytecode).
        self.assertEqual(tree(assets), before)

    def test_the_packaged_controller_runs_from_its_assets(self):
        """`python3 -I -B ASSETS/controller/main.py`: its own asset tree's
        shared modules (providers, guest codecs, worker layout) only."""
        assets = self.run_package(REPO, os.path.join(self.tmp, "out"))
        before = tree(assets)
        done = subprocess.run([sys.executable, "-I", "-B", os.path.join(assets, "controller", "main.py")],
                              capture_output=True, cwd="/", env={"PATH": "/usr/bin:/bin"}, timeout=60)
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertIn(b"agentbox jail stop        [--config FILE] JAIL [--assert-local-ended ID]", done.stderr)
        probe = ("import sys; sys.path[:0] = [sys.argv[1]]; "
                 "from agentbox_controller import cli, assets; print(assets.ASSETS)")
        done = subprocess.run([sys.executable, "-I", "-B", "-c", probe, os.path.join(assets, "controller")],
                              capture_output=True, cwd="/", env={"PATH": "/usr/bin:/bin"}, timeout=60)
        self.assertEqual((done.returncode, done.stdout.decode().strip()), (0, assets), done.stderr)
        self.assertEqual(tree(assets), before)

    def entry(self, prefix, *args, env=None, cwd="/"):
        return subprocess.run([os.path.join(prefix, "bin", "agentbox"), *args], capture_output=True, cwd=cwd,
                              env=env or {"PATH": "/usr/bin:/bin", "HOME": os.path.join(self.tmp, "home")},
                              timeout=60)

    def test_the_entry_is_the_python_controller_through_any_link(self):
        """PREFIX/bin/agentbox runs as `/usr/bin/python3 -IB`, finds
        PREFIX through its real location (a symlinked launcher too), never
        the working directory or PYTHONPATH."""
        prefix = os.path.join(self.tmp, "out")
        assets = self.run_package(REPO, prefix)
        before = tree(assets)
        os.mkdir(os.path.join(self.tmp, "home"), 0o700)
        with open(os.path.join(prefix, "bin", "agentbox"), "rb") as stream:
            self.assertEqual(stream.readline(), b"#!/usr/bin/python3 -IB\n")
        evil = os.path.join(self.tmp, "evil")
        write(os.path.join(evil, "agentbox_controller", "__init__.py"), b"raise SystemExit('EVIL')\n", 0o644)
        write(os.path.join(evil, "agentbox_controller", "cli.py"), b"raise SystemExit('EVIL')\n", 0o644)
        links = os.path.join(self.tmp, "links")
        os.mkdir(links)
        os.symlink(os.path.join(prefix, "bin", "agentbox"), os.path.join(links, "agentbox"))
        env = {"PATH": "/usr/bin:/bin", "HOME": os.path.join(self.tmp, "home"), "PYTHONPATH": evil}
        for launcher in (os.path.join(prefix, "bin", "agentbox"), os.path.join(links, "agentbox")):
            done = subprocess.run([launcher, "no-such-command"], capture_output=True, cwd=evil, env=env, timeout=60)
            # The Python usage.
            self.assertEqual(done.returncode, 2, done.stderr)
            self.assertIn(b"agentbox run AGENT", done.stderr)
            self.assertNotIn(b"EVIL", done.stdout + done.stderr)
        # Every command reaches the Python CLI (no fallback, no traceback).
        probe = ("import json, sys; sys.path[:0] = [sys.argv[1]]; from agentbox_controller import cli; "
                 "print(json.dumps(sorted(cli.COMMANDS)))")
        done = subprocess.run([sys.executable, "-I", "-B", "-c", probe, os.path.join(assets, "controller")],
                              capture_output=True, cwd="/", env={"PATH": "/usr/bin:/bin"}, timeout=60)
        commands = json.loads(done.stdout)
        for expected in (["run"], ["doctor"], ["shell"], ["jail", "serve"], ["jail", "export"],
                         ["jail", "exec"], ["checkpoint", "restore"]):
            self.assertIn(expected, commands)
        for command in commands:
            done = self.entry(prefix, *[c for c in command if c], "--no-such-option", "x")
            self.assertEqual(done.returncode, 2, (command, done.stderr))
            self.assertIn(b"usage:", done.stderr)
            self.assertNotIn(b"Traceback", done.stderr)
        self.assertEqual(tree(assets), before)
        # No data root was made for a refused command.
        self.assertFalse(os.path.lexists(os.path.join(self.tmp, "home", ".local")))

    def test_the_entry_refuses_an_older_python_first(self):
        """The launcher's own check, before any import: an older
        /usr/bin/python3 (its version faked here) is told so, nothing runs."""
        prefix = os.path.join(self.tmp, "out")
        self.run_package(REPO, prefix)
        launcher = os.path.join(prefix, "bin", "agentbox")
        probe = ("import sys; sys.version_info = (3, 11, 9, 'final', 0); path = sys.argv[1]; "
                 "sys.argv = [path, '--version']; "
                 "exec(compile(open(path).read(), path, 'exec'), {'__name__': '__main__', '__file__': path})")
        done = subprocess.run([sys.executable, "-I", "-B", "-c", probe, launcher], capture_output=True, cwd="/",
                              env={"PATH": "/usr/bin:/bin"}, timeout=60)
        self.assertEqual((done.returncode, done.stdout), (1, b""), done.stderr)
        self.assertTrue(done.stderr.endswith(b" is Python 3.11; agentbox needs 3.12 or later as /usr/bin/python3\n"),
                        done.stderr)
        self.assertNotIn(b"Traceback", done.stderr)

    def test_the_entry_defaults_and_overrides(self):
        """Configuration: --config, else XDG_CONFIG_HOME, else HOME; data
        and server defaults; the packaged server unless configured."""
        prefix = os.path.join(self.tmp, "out")
        self.run_package(REPO, prefix)
        home = os.path.join(self.tmp, "home")
        os.mkdir(home, 0o700)
        env = {"PATH": "/usr/bin:/bin", "HOME": home}
        done = self.entry(prefix, "doctor", env=env)
        self.assertIn(b"server: ok\n", done.stdout)
        # Reading commands never make it; one that may write makes it private.
        done = self.entry(prefix, "checkpoint", "list", env=env)
        self.assertEqual((done.returncode, done.stderr), (1, b"agentbox: checkpoint list refused: store_unavailable\n"))
        done = self.entry(prefix, "jail", "stop", "r-" + "0" * 32, env=env)
        self.assertEqual((done.returncode, done.stderr), (1, b"agentbox: jail stop refused: run_unknown\n"))
        done = self.entry(prefix, "checkpoint", "list", env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        data = os.path.join(home, ".local", "share", "agentbox-controller")
        self.assertEqual(stat.S_IMODE(os.stat(data).st_mode), 0o700)
        self.assertFalse(os.path.exists(os.path.join(data, "run-limits.json")))
        # A default configuration file, then an explicit one, each wins.
        xdg = os.path.join(self.tmp, "xdg")
        write(os.path.join(xdg, "agentbox", "controller.json"),
              json.dumps({"schema": "agentbox.controller-config.v1",
                          "server": os.path.join(self.tmp, "missing-server")}).encode(), 0o600)
        done = self.entry(prefix, "doctor", env=dict(env, XDG_CONFIG_HOME=xdg))
        self.assertIn(b"server: missing\n", done.stdout)
        explicit = os.path.join(self.tmp, "explicit.json")
        write(explicit, json.dumps({"schema": "agentbox.controller-config.v1", "server": self.relay}).encode(), 0o600)
        done = self.entry(prefix, "doctor", "--config", explicit, env=dict(env, XDG_CONFIG_HOME=xdg))
        self.assertIn(b"server: ok\n", done.stdout)
        # An explicit file must exist; a group-writable one is refused.
        done = self.entry(prefix, "checkpoint", "list", "--config", os.path.join(self.tmp, "none.json"), env=env)
        self.assertEqual((done.returncode, done.stderr), (1, b"agentbox: checkpoint list refused: config_unreadable\n"))
        os.chmod(explicit, 0o620)
        done = self.entry(prefix, "checkpoint", "list", "--config", explicit, env=env)
        self.assertEqual(done.returncode, 1)
        # A source tree's entry has no packaged server: said so, never guessed.
        done = subprocess.run([sys.executable, "-I", "-B", os.path.join(REPO, "src", "main.py"), "doctor"],
                              capture_output=True, cwd="/", env=env, timeout=60)
        self.assertIn(b"server: unconfigured\n", done.stdout)

    def test_a_moved_package_is_a_whole_asset_tree_at_its_new_place(self):
        """Relocation of the tree itself: moved, its providers still answer
        from the new place and its worker sources are unchanged. This says
        nothing of existing runs, which keep the paths they recorded."""
        first = os.path.join(self.tmp, "first")
        assets = self.run_package(REPO, first)
        before = tree(first)
        moved = os.path.join(self.tmp, "moved")
        os.rename(first, moved)
        assets = os.path.join(moved, "share", "agentbox-assets")
        self.assertEqual(tree(moved), before)
        self.assertEqual(worker.source_files(assets), worker.source_files(REPO))
        state = os.path.join(self.tmp, "state-moved")
        os.mkdir(state, 0o700)
        self.assertEqual(capabilities(assets, "qemu", state)["type"], "described")
        self.assertEqual(tree(moved), before)

    def test_an_existing_output_is_never_touched(self):
        out = os.path.join(self.tmp, "out")
        os.mkdir(out, 0o700)
        write(os.path.join(out, "keep"), b"user data")
        self.refused("exists", REPO, out)
        self.assertEqual(tree(out), {"keep": ("file", 0o644)})
        os.symlink(out, os.path.join(self.tmp, "link"))
        self.refused("exists", REPO, os.path.join(self.tmp, "link"))
        self.assertEqual(tree(out), {"keep": ("file", 0o644)})

    def refused_left(self, code, source, out):
        """Refused after OUT was made: OUT is left, private and incomplete."""
        with self.assertRaises(package.Refused) as caught:
            self.run_package(source, out)
        self.assertEqual((str(caught.exception), caught.exception.left), (code, out))
        self.assertEqual(stat.S_IMODE(os.lstat(out).st_mode), 0o700)
        self.assertFalse(os.path.lexists(os.path.join(out, "share", "agentbox-assets", "images", "podman",
                                                      "default", "Dockerfile")))

    def test_links_special_and_missing_sources_are_refused(self):
        source = self.source_copy()
        self.run_package(source, os.path.join(self.tmp, "ok"))
        outs = iter(os.path.join(self.tmp, f"out-{n}") for n in range(10))
        dockerfile = os.path.join(source, "images", "podman", "default", "Dockerfile")
        # A final link, even to an identical file.
        os.rename(dockerfile, dockerfile + ".real")
        os.symlink("Dockerfile.real", dockerfile)
        self.refused_left("source", source, next(outs))
        os.unlink(dockerfile)
        # A hard link (several links).
        os.link(dockerfile + ".real", dockerfile)
        self.refused_left("source", source, next(outs))
        os.unlink(dockerfile)
        # A linked directory below SRC.
        podman = os.path.join(source, "images", "podman")
        os.rename(dockerfile + ".real", os.path.join(self.tmp, "Dockerfile"))
        os.rename(podman, podman + ".real")
        os.symlink("podman.real", podman)
        self.refused_left("source", source, next(outs))
        os.unlink(podman)
        os.rename(podman + ".real", podman)
        # A special file.
        os.mkfifo(dockerfile, 0o600)
        self.refused_left("source", source, next(outs))
        os.unlink(dockerfile)
        # Missing.
        self.refused_left("source", source, next(outs))
        # Refused before any output: SRC itself a link, a linked guest source.
        os.rename(os.path.join(self.tmp, "Dockerfile"), dockerfile)
        os.symlink(source, os.path.join(self.tmp, "src-link"))
        out = next(outs)
        self.refused("source", os.path.join(self.tmp, "src-link"), out)
        marker = os.path.join(source, "guest", "__init__.py")
        os.rename(marker, marker + ".real")
        os.symlink("__init__.py.real", marker)
        self.refused("source", source, out)
        self.assertFalse(os.path.lexists(out))
        os.unlink(marker)
        os.rename(marker + ".real", marker)
        self.assertEqual(os.path.basename(self.run_package(source, out)), "agentbox-assets")

    def test_a_failure_deletes_nothing_and_the_output_is_never_reused(self):
        source = self.source_copy()
        os.unlink(os.path.join(source, "images", "podman", "default", "Dockerfile"))
        out = os.path.join(self.tmp, "out")
        self.refused_left("source", source, out)
        left = tree(out)
        self.assertEqual(left["bin/agentbox"], ("file", 0o755))
        self.assertIn("share/agentbox-assets/guest/__init__.py", left)
        write(os.path.join(source, "images", "podman", "default", "Dockerfile"), b"FROM scratch\n", 0o600)
        self.refused("exists", source, out)
        self.assertEqual(tree(out), left)

    def test_a_replaced_output_name_is_refused_and_left_alone(self):
        """Between mkdir and reopening, the name is made to point elsewhere:
        a nonempty directory, then a link. Neither is used or changed."""
        real_open = os.open
        out = os.path.join(self.tmp, "out")
        for replacement in ("dir", "link"):
            moved = os.path.join(self.tmp, f"moved-{replacement}")
            other = os.path.join(self.tmp, f"other-{replacement}")
            os.mkdir(other, 0o700)
            write(os.path.join(other, "theirs"), b"keep", 0o600)

            def swapped(path, flags, *args, dir_fd=None, **kw):
                if path == "out" and dir_fd is not None and flags & os.O_DIRECTORY and not os.path.lexists(moved):
                    os.rename(out, moved)
                    if replacement == "dir":
                        os.rename(other, out)
                    else:
                        os.symlink(other, out)
                return real_open(path, flags, *args, dir_fd=dir_fd, **kw)
            with mock.patch.object(package.os, "open", swapped):
                self.refused("out", REPO, out)
            self.assertEqual(tree(moved), {})
            target = out if replacement == "dir" else other
            self.assertEqual(tree(target), {"theirs": ("file", 0o600)})
            if replacement == "dir":
                os.rename(out, other)
            else:
                os.unlink(out)

    def test_an_untrusted_parent_is_refused_before_anything_is_made(self):
        parent = os.path.join(self.tmp, "parent")
        os.mkdir(parent, 0o700)
        for mode in (0o770, 0o777, 0o1777, 0o720):
            os.chmod(parent, mode)
            self.refused("out", REPO, os.path.join(parent, "out"))
            os.chmod(parent, 0o700)
            self.assertEqual(os.listdir(parent), [])
        self.refused("out", REPO, os.path.join(self.tmp, "missing", "out"))
        self.run_package(REPO, os.path.join(parent, "out"))

    def test_paths_and_relay_are_explicit(self):
        out = os.path.join(self.tmp, "out")
        for source, relay, target in ((".", self.relay, out), (REPO, "agentbox-relay", out),
                                      (REPO, self.relay, "out"), (REPO + "/", self.relay, out),
                                      (REPO, self.relay, out + "/../out")):
            with self.assertRaises(package.Refused) as caught:
                package.package(source, relay, target)
            self.assertEqual(str(caught.exception), "path")
        self.assertFalse(os.path.lexists(out))
        # The relay: a regular x86-64 executable, not through a final link.
        not_elf = os.path.join(self.tmp, "script")
        write(not_elf, b"#!/bin/sh\n" + bytes(20), 0o755)
        self.refused("relay", REPO, out, relay=not_elf)
        not_exec = os.path.join(self.tmp, "plain")
        write(not_exec, ELF, 0o644)
        self.refused("relay", REPO, out, relay=not_exec)
        os.symlink(self.relay, os.path.join(self.tmp, "relay-link"))
        self.refused("relay", REPO, out, relay=os.path.join(self.tmp, "relay-link"))
        self.refused("relay", REPO, out, relay=os.path.join(self.tmp, "missing"))
        self.assertFalse(os.path.lexists(out))
        # Several links are fine (cargo links target/*/agentbox-relay into deps/).
        os.link(self.relay, os.path.join(self.tmp, "relay-hard"))
        self.run_package(REPO, out, os.path.join(self.tmp, "relay-hard"))

    def test_the_command_line(self):
        script = os.path.join(HERE, "package.py")
        out = os.path.join(self.tmp, "out")
        run = lambda *args: subprocess.run([sys.executable, "-I", "-B", script, *args], capture_output=True,
                                           cwd="/", env={"PATH": "/usr/bin:/bin"}, timeout=120)
        done = run("--source", REPO, "--server-binary", self.relay, "--out", out)
        self.assertEqual((done.returncode, done.stdout), (2, b""))
        done = run("--source", REPO, "--out", out)
        self.assertEqual((done.returncode, done.stdout), (2, b""))
        done = run("--source", REPO, "--relay-binary", self.relay, "--out", out)
        self.assertEqual((done.returncode, done.stdout, done.stderr),
                         (0, os.path.join(out, "share", "agentbox-assets").encode() + b"\n", b""))
        done = run("--source", REPO, "--relay-binary", self.relay, "--out", out)
        self.assertEqual((done.returncode, done.stderr), (1, b"package: refused: exists\n"))
        source = self.source_copy()
        os.unlink(os.path.join(source, "providers", "qemu.py"))
        partial = os.path.join(self.tmp, "partial")
        done = run("--source", source, "--relay-binary", self.relay, "--out", partial)
        self.assertEqual((done.returncode, done.stdout, done.stderr),
                         (1, b"", f"package: refused: source\npackage: incomplete output left: {partial}\n".encode()))
        self.assertTrue(os.path.isdir(partial))
        # No bytecode of package.py (pip's own import of the build backend
        # may leave agentbox_build's).
        cache = os.path.join(HERE, "__pycache__")
        self.assertEqual([n for n in (os.listdir(cache) if os.path.isdir(cache) else [])
                          if not n.startswith("agentbox_build.")], [])


if __name__ == "__main__":
    unittest.main()
