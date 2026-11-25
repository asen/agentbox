"""`dev AGENT` and `dev setup` offline (dev.py): a fake packaged tree whose
built-in podman is the stand-in provider (the `builtin.ASSETS` seam), its
capabilities a shared store's; a synthetic host HOME with synthetic agent
directories; stand-in agents, ssh and provider; local PTY pairs. No
native provider, credential, model, npm or real HOME.
"""
import json
import os
import shutil
import time
import unittest

from agentbox_controller import dev, images, store as store_mod
from agentbox_controller.host import HostError
from tests.controller.harness import HERE, REPO, World, write_file
from tests.controller.test_c2b import Terminal, kill_strays
from tests.controller.test_execution import QUICK

SHARED = {"retention": ["none", "home"], "features": ["select_user", "project_layout", "host_mounts",
                                                      "explicit_retention"], "volume": "agentbox-home-test"}


class Units(unittest.TestCase):
    def test_default_name(self):
        name = dev.default_name("/home/u/My Project.v2")
        self.assertRegex(name, r"^dev-my-project-v2-[0-9a-f]{12}$")
        self.assertTrue(store_mod.is_name(name))
        self.assertNotEqual(name, dev.default_name("/other/My Project.v2"))
        self.assertRegex(dev.default_name("/srv/" + "x" * 300), r"^dev-x{40}-[0-9a-f]{12}$")
        self.assertRegex(dev.default_name("/srv/..."), r"^dev-project-[0-9a-f]{12}$")

    def test_config_shape(self):
        dirs = {"pi": "/h/.pi", "codex": "/h/.codex", "claude": "/h/.claude"}
        for good in ({"schema": dev.SCHEMA}, {"schema": dev.SCHEMA, "agent_dirs": dirs},
                     {"schema": dev.SCHEMA, "acquisition_config": "/a.json", "acquisition_stage_root": "/s"}):
            self.assertEqual(dev.check(good), good)
        for bad in ({}, {"schema": "x"}, {"schema": dev.SCHEMA, "other": 1},
                    {"schema": dev.SCHEMA, "agent_dirs": dict(dirs, extra="/x")},
                    {"schema": dev.SCHEMA, "agent_dirs": {"pi": "/h/.pi"}},
                    {"schema": dev.SCHEMA, "agent_dirs": dict(dirs, pi="rel")},
                    {"schema": dev.SCHEMA, "acquisition_stage_root": "/s"},
                    {"schema": dev.SCHEMA, "acquisition_config": "a.json"}, []):
            with self.assertRaises(HostError, msg=bad) as caught:
                dev.check(bad)
            self.assertEqual(caught.exception.code, "dev_config_invalid")


class Dev(unittest.TestCase):
    def setUp(self):
        self.world = World()
        self.addCleanup(self.world.close)
        tmp = self.world.tmp
        self.addCleanup(kill_strays, tmp)
        self.world.set_behavior(**SHARED)
        # The packaged tree: the stand-in as the built-in providers.
        self.tree = f"{tmp}/pkg"
        os.makedirs(f"{self.tree}/providers")
        for name in ("podman", "qemu"):
            shutil.copyfile(f"{HERE}/provider_standin.py", f"{self.tree}/providers/{name}.py")
        shutil.copyfile(f"{REPO}/providers/protocol.py", f"{self.tree}/providers/protocol.py")
        for directory, _, names in os.walk(self.tree):
            os.chmod(directory, 0o755)
            for name in names:
                os.chmod(os.path.join(directory, name), 0o644)
        self.overrides = dict(QUICK, **{"builtin.ASSETS": self.tree})
        images.publish(self.world.data, "dev", {"builtin": "podman", "state": self.world.state},
                       self.world.image_id, self.world.release, "images/podman/dev/Dockerfile", "builtin")
        # The synthetic host HOME, its projects and agent directories.
        self.host = f"{tmp}/hosthome"
        os.mkdir(self.host, 0o700)
        self.project = self.make_project("app")
        self.dev_json = f"{self.world.xdg_config}/agentbox/dev.json"

    def make_project(self, name):
        # The stand-in binds nothing: the guest's mount, as a provider makes it.
        for root in (self.host, self.world.home):
            for at in (f"{root}/projects", f"{root}/projects/{name}"):
                os.makedirs(at, exist_ok=True)
                os.chmod(at, 0o755)
        return f"{self.host}/projects/{name}"

    def agent_dirs(self, names=("pi", "codex", "claude")):
        for name in names:
            os.mkdir(f"{self.host}/.{name}", 0o700)

    def env(self, extra=None):
        return dict({"HOME": self.host}, **(extra or {}))

    def dev(self, args, cwd=None, umask=None):
        """A non-interactive `dev` command: (code, out, err)."""
        import subprocess
        argv = self.world.argv(("dev",), args, overrides=self.overrides, command_args=False)
        old = os.umask(umask) if umask is not None else None
        try:
            done = subprocess.run(argv, env=self.world.env(self.env()), cwd=cwd or self.project,
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=60)
        finally:
            if old is not None:
                os.umask(old)
        return done.returncode, done.stdout.decode(), done.stderr.decode()

    def terminal(self, args, cwd=None):
        terminal = Terminal(self.world, args, self.env(), overrides=self.overrides, command=("dev",),
                            cwd=cwd or self.project)
        self.addCleanup(terminal.close)
        return terminal

    def session(self, args, cwd=None):
        """`dev AGENT` on a PTY, the agent ended at once: (code, text)."""
        terminal = self.terminal(args, cwd)
        terminal.expect(b"agent-ready")
        terminal.send(b"\x04")
        return terminal.finish()

    def refused(self, args, cwd=None):
        """`dev AGENT` on a PTY that never reaches the agent: (code, text)."""
        code, text = self.terminal(args, cwd).finish()
        self.assertNotIn("agent-ready", text)
        return code, text

    def runs(self):
        return sorted(n for n in os.listdir(f"{self.world.data}/controller-runs") if n.startswith("r-"))

    def creates(self):
        return [e for e in self.world.provider_log() if e.get("type") == "create"]

    def created(self, text):
        return text.split("dev: created ", 1)[1].split()[:2]

    def test_first_use_creates_then_every_agent_reuses(self):
        code, text = self.session(["pi", "--model", "openai/m", "--", "--continue"])
        self.assertEqual(code, 0, text)
        name, ident = self.created(text)
        run_id = ident.split("=", 1)[1]
        self.assertEqual(name, dev.default_name(self.project))
        record = self.world.record(run_id)
        self.assertEqual((record["name"], record["phase"], record["retention"], record["provider"],
                          record["project"], record["mounts"], record["volume"]),
                         (name, "ready", "home", {"builtin": "podman", "state": self.world.state}, "projects/app",
                          [{"source": self.project, "destination": "projects/app", "access": "rw"}],
                          "agentbox-home-test"))
        entry = self.world.agent_log()[-1]
        self.assertEqual((entry["name"], entry["argv"], entry["cwd"]),
                         ("pi", ["--offline", "--model", "openai/m", "--continue"],
                          f"{self.world.home}/projects/app"))
        self.assertEqual(len(self.creates()), 1)
        # Another agent, the same directory: the same jail, kept.
        code, text = self.session(["codex"])
        self.assertEqual(code, 0, text)
        self.assertIn(f"dev: jail {name} id={run_id} project={self.project}", text)
        self.assertEqual(self.world.agent_log()[-1]["name"], "codex")
        self.assertEqual((len(self.creates()), self.world.record(run_id)["phase"]), (1, "ready"))
        # A symlinked path to it is the same project.
        link = f"{self.world.tmp}/link"
        os.symlink(self.project, link)
        code, text = self.session(["claude"], cwd=link)
        self.assertEqual(code, 0, text)
        self.assertIn(f"dev: jail {name} id={run_id}", text)
        # Another directory: another jail.
        other = self.make_project("other")
        code, text = self.session(["pi"], cwd=other)
        self.assertEqual(code, 0, text)
        self.assertEqual(self.created(text)[0], dev.default_name(other))
        # A second jail of one project by name; reused by it.
        code, text = self.session(["pi", "--jail", "second"])
        self.assertEqual(code, 0, text)
        self.assertEqual(self.created(text)[0], "second")
        code, text = self.session(["pi", "--jail", "second"])
        self.assertEqual(code, 0, text)
        self.assertIn("dev: jail second ", text)
        self.assertEqual(len(self.creates()), 3)
        # The tag moved: an existing jail keeps its recorded image.
        images.publish(self.world.data, "dev", {"builtin": "podman", "state": self.world.state}, "ab" * 32,
                       self.world.release, "images/podman/dev/Dockerfile", "builtin")
        code, text = self.session(["pi"])
        self.assertEqual(code, 0, text)
        self.assertIn(f"dev: jail {name} id={run_id}", text)
        self.assertEqual(self.world.record(run_id)["image"], self.world.image_id)

    def test_setup_opt_in_dirs_and_config(self):
        code, out, err = self.dev(["setup"])
        self.assertEqual(code, 1, err)
        self.assertIn("refused: dev_setup_opt_in_required", err)
        self.agent_dirs(("pi", "claude"))
        code, out, err = self.dev(["setup", "--share-agent-dirs"])
        self.assertEqual(code, 1, err)
        self.assertIn("refused: agent_dirs_missing", err)
        self.assertIn("~/.codex", err)
        self.assertNotIn("warning:", err)
        self.assertFalse(os.path.lexists(f"{self.host}/.codex"))
        self.assertFalse(os.path.lexists(self.dev_json))
        os.mkdir(f"{self.host}/.codex", 0o700)
        # The lane's settings are kept; the file replaced privately even
        # under umask 0002.
        acquisition = self.world.acquisition()
        write_file(self.dev_json, {"schema": dev.SCHEMA, "acquisition_config": acquisition})
        code, out, err = self.dev(["setup", "--share-agent-dirs"], umask=0o002)
        self.assertEqual(code, 0, err)
        self.assertIn("refresh tokens", err)
        self.assertIn(f"dev setup: {self.dev_json} agent_dirs=pi,codex,claude", out)
        self.assertEqual(os.stat(self.dev_json).st_mode & 0o777, 0o600)
        with open(self.dev_json) as stream:
            self.assertEqual(json.load(stream), {
                "schema": dev.SCHEMA, "acquisition_config": acquisition,
                "agent_dirs": {name: f"{self.host}/.{name}" for name in ("pi", "codex", "claude")}})
        self.assertEqual(sorted(n for n in os.listdir(os.path.dirname(self.dev_json)) if n.startswith(".")), [])
        # Malformed or unknown: refused, never replaced.
        for bad in ("{", json.dumps({"schema": dev.SCHEMA, "extra": True})):
            write_file(self.dev_json, bad)
            code, out, err = self.dev(["setup", "--share-agent-dirs"])
            self.assertEqual(code, 1, err)
            self.assertIn("refused: dev_config_invalid", err)
            with open(self.dev_json) as stream:
                self.assertEqual(stream.read(), bad)
        # Usage: setup's own options only.
        for args in (["setup", "--share-agent-dirs", "--jail", "x"], ["pi", "--share-agent-dirs"],
                     ["setup", "--share-agent-dirs", "--"]):
            self.assertEqual(self.dev(args)[0], 2, args)

    def test_sharing_reaches_new_jails_only_and_mounts_are_exact(self):
        code, text = self.session(["pi"])
        self.assertEqual(code, 0, text)
        name = self.created(text)[0]
        self.agent_dirs()
        self.assertEqual(self.dev(["setup", "--share-agent-dirs"])[0], 0)
        # The jail made before setup: never changed, refused with the
        # difference until reused without the agent directories.
        code, text = self.refused(["pi"])
        self.assertEqual(code, 1, text)
        self.assertIn("refused: dev_jail_mismatch", text)
        self.assertIn(f"requested only: rw {self.host}/.pi -> .pi", text)
        self.assertIn(f"agentbox jail discard {name}", text)
        code, text = self.session(["pi", "--no-harness-mount"])
        self.assertEqual(code, 0, text)
        self.assertIn(f"dev: jail {name} ", text)
        # A new jail gets them, read-write at the hidden destinations.
        other = self.make_project("other")
        extra = f"{self.world.tmp}/docs"
        os.mkdir(extra, 0o755)
        code, text = self.session(["pi", "--mount-ro", f"{extra}=docs"], cwd=other)
        self.assertEqual(code, 0, text)
        run_id = self.created(text)[1].split("=", 1)[1]
        self.assertEqual(sorted((m["source"], m["destination"], m["access"])
                                for m in self.world.record(run_id)["mounts"]),
                         sorted([(other, "projects/other", "rw"), (extra, "docs", "ro")]
                                + [(f"{self.host}/.{n}", f".{n}", "rw") for n in ("pi", "codex", "claude")]))
        # Reused only with exactly that set, in any order.
        code, text = self.refused(["pi"], cwd=other)
        self.assertIn(f"jail only:      ro {extra} -> docs", text)
        code, text = self.refused(["pi", "--no-harness-mount", "--mount-ro", f"{extra}=docs"], cwd=other)
        self.assertIn(f"jail only:      rw {self.host}/.codex -> .codex", text)
        code, text = self.refused(["pi", "--mount-rw", f"{extra}=docs"], cwd=other)
        self.assertIn("refused: dev_jail_mismatch", text)
        code, text = self.session(["pi", "--mount-ro", f"{extra}=docs"], cwd=other)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(self.creates()), 2)
        # An explicit bind colliding with a shared directory: refused, not undone.
        code, text = self.refused(["pi", "--mount-rw", f"{extra}=.pi"])
        self.assertIn("refused: mount_destination_overlap", text)

    def test_refusals_before_any_jail(self):
        before, creates = self.runs(), len(self.creates())

        def refused(args, expected, cwd=None):
            code, text = self.refused(args, cwd)
            self.assertEqual(code, 1, text)
            self.assertIn(f"refused: {expected}", text)
            self.assertEqual((self.runs(), len(self.creates())), (before, creates))
            return text

        refused(["bogus"], "agent_unknown")
        refused(["pi", "--env", "C2B_MISSING"], "env_invalid")
        refused(["pi", "--jail", "r-" + "0" * 32], "run_name_invalid")
        refused(["pi"], "dev_project_invalid", cwd=self.host)
        refused(["pi"], "dev_project_invalid", cwd="/")
        refused(["pi"], "dev_project_invalid", cwd=os.path.dirname(self.host))
        # A private store's capabilities: nothing recorded.
        self.world.set_behavior(features=["select_user", "project_layout", "host_mounts"],
                                retention=["none", "home", "home_tmp"])
        text = refused(["pi"], "dev_store_not_shared")
        self.assertIn("agentbox image prepare podman --store shared --preset dev -t dev", text)
        self.world.set_behavior(**SHARED)
        # A custom provider's tag.
        images.publish(self.world.data, "dev", self.world.provider, self.world.image_id, self.world.release,
                       f"{self.world.state}/inputs/recipe.json", "custom")
        refused(["pi"], "dev_image_unsupported")
        os.unlink(f"{self.world.data}/images/dev")
        text = refused(["pi"], "dev_image_missing")
        self.assertIn("agentbox image prepare podman --store shared --preset dev -t dev", text)
        # Not a terminal.
        self.assertIn("interactive_terminal_required", self.dev(["pi"])[2])
        # A name held by another kind of jail.
        self.world.create(["-t", "plain", "--retention", "home"])
        before, creates = self.runs(), len(self.creates())
        refused(["pi", "--jail", "plain"], "dev_jail_unsuitable")

    def test_busy_partial_and_failures_keep_the_jail(self):
        code, text = self.session(["pi"])
        self.assertEqual(code, 0, text)
        name, ident = self.created(text)
        run_id = ident.split("=", 1)[1]
        store = store_mod.Store(self.world.data)
        self.addCleanup(store.close)
        lease = store.claim(run_id)
        try:
            # Checked even when busy: a mismatch says so first.
            extra = f"{self.world.tmp}/docs"
            os.mkdir(extra, 0o755)
            code, text = self.refused(["pi", "--mount-ro", f"{extra}=docs"])
            self.assertIn("refused: dev_jail_mismatch", text)
            self.assertIn(f"requested only: ro {extra} -> docs", text)
            code, text = self.refused(["pi"])
            self.assertEqual(code, 1, text)
            self.assertIn("refused: dev_jail_busy", text)
            # No serving session: no shell suggested.
            self.assertIn(f"agentbox jail status {name}", text)
            self.assertNotIn("agentbox shell", text)
            # Busy only once its lease is taken (after the checks): the
            # same refusal, nothing discarded.
            with self.assertRaises(HostError) as caught:
                self.in_process().claim(run_id, name, "pi")
            self.assertEqual(caught.exception.code, "dev_jail_busy")
            self.assertIn(f"agentbox jail status {name}", caught.exception.hint)
            self.assertNotIn("agentbox shell", caught.exception.hint)
        finally:
            lease.release()
        self.in_process().claim(run_id, name, "pi").release()
        self.assertEqual(self.world.record(run_id)["phase"], "ready")
        # A failed start: the jail stays as it was.
        self.world.set_behavior(start="fail")
        code, text = self.refused(["pi"])
        self.assertEqual(code, 1, text)
        self.assertEqual(self.world.record(run_id)["phase"], "ready")
        self.world.set_behavior(start="ok")
        # A failed create: the partial run keeps its name, never discarded here.
        other = self.make_project("other")
        self.world.set_behavior(create="fail")
        code, text = self.refused(["pi"], cwd=other)
        self.assertEqual(code, 1, text)
        self.assertIn("jail create failed", text)
        self.assertIn(f"agentbox jail discard {dev.default_name(other)}", text)
        self.world.set_behavior(create="ok")
        partial = [r for r in self.runs() if self.world.record(r).get("name") == dev.default_name(other)]
        self.assertEqual([self.world.record(r)["phase"] for r in partial], ["partial"])
        code, text = self.refused(["pi"], cwd=other)
        self.assertIn("refused: dev_jail_partial", text)
        self.assertEqual(self.world.record(partial[0])["phase"], "partial")
        self.assertEqual(len([e for e in self.world.provider_log() if e.get("type") == "discard"]), 0)

    def in_process(self):
        import io
        store = store_mod.Store(self.world.data)
        self.addCleanup(store.close)
        return dev.Dev(None, None, store, {}, {}, io.StringIO(), io.StringIO())

    def test_a_serving_session_is_suggested_for_a_login(self):
        terminal = self.terminal(["pi"])
        terminal.expect(b"agent-ready")
        name, ident = self.created(terminal.buffer.decode(errors="replace"))
        run_id = ident.split("=", 1)[1]
        profile = f"{self.world.data}/controller-runs/{run_id}/owner/shell.json"
        deadline = time.monotonic() + 30
        while not os.path.exists(profile) and time.monotonic() < deadline:
            terminal.read(0.1)
        code, text = self.refused(["codex"])
        self.assertEqual(code, 1, text)
        self.assertIn("refused: dev_jail_busy", text)
        self.assertIn(f"agentbox shell {name} opens a login there", text)
        with self.assertRaises(HostError) as caught:
            self.in_process().claim(run_id, name, "codex")
        self.assertIn(f"agentbox shell {name}", caught.exception.hint)
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.world.record(run_id)["phase"], "ready")

    def test_setup_never_writes_past_the_read_bound(self):
        self.agent_dirs()
        dirs = {n: os.path.realpath(f"{self.host}/.{n}") for n in ("pi", "codex", "claude")}

        def long_path(size):
            # An absolute path of exactly `size` bytes, plain components.
            parts, left = [], size - 1
            while left > 0:
                take = min(left, 200)
                if 0 < left - take < 2:
                    take -= 2
                parts.append("a" * take)
                left -= take + 1
            return "/" + "/".join(parts)

        def value(total):
            # acquisition_config and stage root sized so setup's output is
            # `total` bytes.
            base = dict(schema=dev.SCHEMA, agent_dirs=dirs, acquisition_config="/x", acquisition_stage_root="/y")
            spare = total - len(dev._dump(base)) + 4
            first = min(spare - 2, 4000)
            return {"schema": dev.SCHEMA, "acquisition_config": long_path(first),
                    "acquisition_stage_root": long_path(spare - first)}

        exact = value(dev.MAX_BYTES)
        self.assertEqual(len(dev._dump(dict(exact, agent_dirs=dirs))), dev.MAX_BYTES)
        write_file(self.dev_json, exact)
        code, out, err = self.dev(["setup", "--share-agent-dirs"])
        self.assertEqual(code, 0, err)
        self.assertEqual(os.path.getsize(self.dev_json), dev.MAX_BYTES)
        self.assertEqual(dev.load(self.dev_json), dict(exact, agent_dirs=dirs))
        # One byte more: refused before the warning, the old file kept.
        over = value(dev.MAX_BYTES + 1)
        write_file(self.dev_json, over)
        with open(self.dev_json, "rb") as stream:
            before = stream.read()
        code, out, err = self.dev(["setup", "--share-agent-dirs"])
        self.assertEqual(code, 1, err)
        self.assertIn("refused: dev_config_too_large", err)
        self.assertNotIn("warning:", err)
        with open(self.dev_json, "rb") as stream:
            self.assertEqual(stream.read(), before)
        self.assertEqual(sorted(n for n in os.listdir(os.path.dirname(self.dev_json)) if n.startswith(".")), [])

    def test_acquisition_lane_from_dev_json(self):
        # The persistent acquisition.json, unreadable: dev.json's lane wins.
        write_file(self.world.acquisition_default, "{", 0o666)
        acquisition = self.world.acquisition()
        write_file(self.dev_json, {"schema": dev.SCHEMA, "acquisition_config": acquisition})
        terminal = self.terminal(["pi"])
        terminal.expect(b"agent-ready")
        terminal.send(b"r")
        terminal.expect(b"request ok")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        # Unreadable: refused before anything.
        before = self.runs()
        write_file(self.dev_json, {"schema": dev.SCHEMA, "acquisition_config": acquisition}, 0o620)
        code, text = self.refused(["pi"], cwd=self.make_project("other"))
        self.assertIn("refused: dev_config_unreadable", text)
        self.assertEqual(self.runs(), before)
        # Without dev.json's lane: acquisition.json's, refused (never the
        # packaged defaults) before anything.
        write_file(self.dev_json, {"schema": dev.SCHEMA})
        code, text = self.refused(["pi"], cwd=self.make_project("other"))
        self.assertIn("refused: acquisition_config_unreadable", text)
        self.assertEqual(self.runs(), before)


if __name__ == "__main__":
    unittest.main()
