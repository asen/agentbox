"""Run names, offline: `jail create -t NAME`, a name in place of a run id
(resolved once, live runs only) for every public run selector, `jail list
[--all]` read only; the binding check under the store lock against real
concurrent creators (threads and processes), through the production CLI
with the stand-in provider and FakeCgroups.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t . -p test_names.py
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from agentbox_controller import config, store as store_mod
from agentbox_controller.host import HostError
from tests.controller import harness
from tests.controller.harness import SRC, World, server, write_file
from tests.controller.test_execution import QUICK

# A process creating one named record on a signal: (data, provider,
# manifest file, name, go file).
CREATOR = r"""
import json, os, sys, time
sys.path.insert(0, sys.argv[1])
from agentbox_controller import store
from agentbox_controller.host import HostError
data, provider, manifest, name, go = sys.argv[2:]
with open(manifest, "rb") as stream:
    manifest = stream.read()
fields = {"provider": json.loads(provider), "resource": store.new_id("res"), "image": "b" * 64, "limits": {},
          "described": {"operations": ["create"], "transport": "tcp", "retention": ["none"], "limits": [],
                        "features": []},
          "user": "agentbox", "retention": "none", "phase": "ready", "home": "/home/agentbox", "name": name}
opened = store.Store(data)
while not os.path.exists(go):
    time.sleep(0.001)
try:
    print(opened.create_managed(fields, manifest))
except HostError as error:
    print(error.code)
"""


def rows(out):
    return [line.split() for line in out.splitlines()]


def tree(path):
    return sorted(os.path.relpath(os.path.join(d, n), path) for d, ds, fs in os.walk(path) for n in ds + fs)


class Units(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abn-")
        os.chmod(self.tmp, 0o700)
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = f"{self.tmp}/data"
        os.mkdir(self.data, 0o700)
        os.mkdir(f"{self.tmp}/a")
        self.provider = {"schema": config.PROVIDER_SCHEMA, "provider": "p", "interpreter": "/usr/bin/python3",
                         "entry": f"{self.tmp}/a/e.py", "state": f"{self.tmp}/s", "assets": f"{self.tmp}/a"}
        self.manifest = harness.payload()["manifest"]

    def opened(self):
        opened = store_mod.Store(self.data)
        self.addCleanup(opened.close)
        return opened

    def make(self, opened, **fields):
        return harness.fixture_run(opened, self.provider, self.manifest, **fields)

    def refused(self, code, fn, *args, **kwargs):
        with self.assertRaises(HostError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def edit(self, opened, run_id, **changes):
        lease = opened.claim(run_id)
        try:
            lease.save(dict(lease.record, **changes))
        finally:
            lease.release()

    def path(self, run_id):
        return f"{self.data}/controller-runs/{run_id}/run.json"

    def test_names(self):
        for good in ("a", "my-run", "v1.2_x", "r-" + "0" * 31, "r-" + "0" * 33, "0" * 64):
            self.assertEqual(store_mod.check_name(good), good)
        for bad in ("", ".x", "-x", "A", "a/b", "a b", "x" * 65, "r-" + "0" * 32, "r-" + "a" * 32, None):
            self.refused("run_name_invalid", store_mod.check_name, bad)

    def test_unnamed_and_old_records_stay_valid(self):
        opened = self.opened()
        run_id = self.make(opened)
        self.assertIsNone(opened.status(run_id)["record"]["name"])
        # A record written before names: no key at all.
        with open(self.path(run_id)) as stream:
            record = json.load(stream)
        del record["name"]
        write_file(self.path(run_id), record)
        self.assertNotIn("name", opened.status(run_id)["record"])
        self.assertEqual(opened.resolve(run_id), run_id)
        self.refused("run_unknown", opened.resolve, "x")
        self.assertEqual(self.make(opened, name="x"), opened.resolve("x"))
        for bad in ("r-" + "1" * 32, "Bad", 7):
            write_file(self.path(run_id), dict(record, name=bad))
            self.refused("run_invalid", opened.status, run_id)

    def test_resolve_live_runs_only(self):
        opened = self.opened()
        first = self.make(opened, name="x")
        self.assertEqual(opened.resolve("x"), first)
        # An id as is: its use checks it.
        self.assertEqual(opened.resolve("r-" + "0" * 32), "r-" + "0" * 32)
        self.refused("run_invalid", opened.resolve, "Bad!")
        self.refused("run_unknown", opened.resolve, "nope")
        self.refused("run_name_taken", self.make, opened, name="x")
        self.refused("run_name_taken", opened.name_free, "x")
        self.edit(opened, first, phase="discarded")
        self.refused("run_unknown", opened.resolve, "x")
        opened.name_free("x")
        second = self.make(opened, name="x")
        self.assertEqual(opened.resolve("x"), second)
        self.assertEqual(opened.status(first)["record"]["name"], "x")
        # Two live holders (never made by a creation): every use refuses.
        other = self.make(opened)
        self.edit(opened, other, name="x")
        self.refused("run_name_ambiguous", opened.resolve, "x")
        self.refused("run_name_taken", opened.name_free, "x")

    def test_an_unreadable_record_fails_closed(self):
        opened = self.opened()
        self.make(opened, name="x")
        broken = self.make(opened)
        write_file(self.path(broken), "{")
        self.refused("run_invalid", opened.resolve, "x")
        self.refused("run_invalid", self.make, opened, name="y")
        self.assertEqual(opened.resolve(broken), broken)
        listed = dict(store_mod.listing(self.data))
        self.assertIsNone(listed[broken])
        self.assertEqual(sorted(r["name"] for r in listed.values() if r), ["x"])

    def test_concurrent_threads_one_name_one_run(self):
        """The binding check alone (no early check): each thread its own
        Store, so its own lock descriptor."""
        barrier = threading.Barrier(16)
        results = []

        def create():
            opened = store_mod.Store(self.data)
            try:
                barrier.wait()
                results.append(self.make(opened, name="race"))
            except HostError as error:
                results.append(error.code)
            finally:
                opened.close()

        threads = [threading.Thread(target=create) for _ in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        won = [r for r in results if r.startswith("r-")]
        self.assertEqual((len(won), sorted(set(results) - set(won))), (1, ["run_name_taken"]))
        opened = self.opened()
        with opened.lock():
            self.assertEqual(opened.named("race"), won)
        self.assertEqual(opened.run_ids(), won)

    def test_concurrent_processes_one_name_one_run(self):
        manifest = f"{self.tmp}/manifest"
        with open(manifest, "wb") as stream:
            stream.write(self.manifest.encode() if isinstance(self.manifest, str) else self.manifest)
        go = f"{self.tmp}/go"
        store_mod.Store(self.data).close()
        children = [subprocess.Popen([sys.executable, "-I", "-B", "-c", CREATOR, SRC, self.data,
                                      json.dumps(self.provider), manifest, "race", go],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(12)]
        # Every child at its spin, then all released at once.
        time.sleep(1.0)
        write_file(go, "")
        results = []
        for child in children:
            out, err = child.communicate(timeout=60)
            self.assertEqual(child.returncode, 0, err)
            results.append(out.decode().strip())
        won = [r for r in results if r.startswith("r-")]
        self.assertEqual((len(won), sorted(set(results) - set(won))), (1, ["run_name_taken"]))
        self.assertEqual(self.opened().run_ids(), won)

    def test_lookups_never_see_a_half_made_record(self):
        opened = self.opened()
        stable = self.make(opened, name="stable")
        done = threading.Event()
        errors = []

        def creator(index):
            mine = store_mod.Store(self.data)
            try:
                for count in range(25):
                    self.make(mine, **({"name": f"n-{index}-{count}"} if count % 2 else {}))
            except BaseException as error:
                errors.append(repr(error))
            finally:
                mine.close()

        def reader():
            mine = store_mod.Store(self.data)
            try:
                while not done.is_set():
                    if mine.resolve("stable") != stable:
                        errors.append("resolved elsewhere")
                    if any(record is None for _, record in store_mod.listing(self.data)):
                        errors.append("listed invalid")
            except BaseException as error:
                errors.append(repr(error))
            finally:
                mine.close()

        readers = [threading.Thread(target=reader) for _ in range(3)]
        creators = [threading.Thread(target=creator, args=(i,)) for i in range(4)]
        for thread in readers + creators:
            thread.start()
        for thread in creators:
            thread.join()
        done.set()
        for thread in readers:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(store_mod.listing(self.data)), 101)

    def test_listing_makes_nothing(self):
        absent = f"{self.tmp}/absent"
        self.assertEqual(store_mod.listing(absent), [])
        self.assertFalse(os.path.lexists(absent))
        # An empty root, then a store no creation has touched (no lock).
        self.assertEqual(store_mod.listing(self.data), [])
        self.assertEqual(os.listdir(self.data), [])
        store_mod.Store(self.data).close()
        before = tree(self.data)
        self.assertEqual(store_mod.listing(self.data), [])
        self.assertEqual(tree(self.data), before)
        self.assertNotIn("controller-runs/.lock", before)
        foreign = f"{self.tmp}/foreign"
        os.makedirs(f"{foreign}/controller-runs", 0o700)
        os.chmod(foreign, 0o700)
        self.refused("store_version_unsupported", store_mod.listing, foreign)
        os.chmod(self.data, 0o755)
        self.refused("store_invalid", store_mod.listing, self.data)

    def test_listing_waits_for_a_first_creation_begun_after_its_lock_probe(self):
        """The first creation interleaved: listing's probe finds no lock;
        then a creator makes the lock and, holding it, a half-written run;
        listing must wait for it, never read it half made."""
        os.mkdir(f"{self.tmp}/other", 0o700)
        other = store_mod.Store(f"{self.tmp}/other")
        self.addCleanup(other.close)
        run_id = self.make(other)
        with open(f"{self.tmp}/other/controller-runs/{run_id}/run.json", "rb") as stream:
            whole = stream.read()
        opened = self.opened()
        runs = f"{self.data}/controller-runs"
        made, probed = threading.Event(), []
        real = os.open

        def creator():
            with opened.lock():
                os.mkdir(f"{runs}/{run_id}", 0o700)
                write_file(f"{runs}/{run_id}/run.json", "{")
                made.set()
                time.sleep(0.5)
                with open(f"{runs}/{run_id}/run.json", "wb") as stream:
                    stream.write(whole)

        def hooked(path, flags, *args, **kwargs):
            if path == store_mod.LOCK and not flags & os.O_CREAT and not probed:
                probed.append(True)
                threading.Thread(target=creator).start()
                made.wait(10)
                raise FileNotFoundError(path)
            return real(path, flags, *args, **kwargs)

        with mock.patch.object(store_mod.os, "open", hooked):
            listed = store_mod.listing(self.data)
        self.assertEqual(probed, [True])
        self.assertEqual(len(listed), 1)
        self.assertEqual(listed[0][0], run_id)
        self.assertEqual(listed[0][1], json.loads(whole))

    def test_run_directories_without_the_lock_refuse(self):
        store_mod.Store(self.data).close()
        os.mkdir(f"{self.data}/controller-runs/r-{'a' * 32}", 0o700)
        before = tree(self.data)
        self.refused("store_invalid", store_mod.listing, self.data)
        self.assertEqual(tree(self.data), before)


class Cli(unittest.TestCase):
    behavior = {"checkpoints": True}
    kind = "managed"

    def setUp(self):
        self.world = World(kind=self.kind, behavior=dict(self.behavior))
        self.addCleanup(self.world.close)

    def run_(self, command, extra=(), **kwargs):
        kwargs.setdefault("overrides", QUICK)
        return self.world.run(command, list(extra), **kwargs)

    def create(self, *args):
        return self.run_(("jail", "create"), list(args), command_args=False)

    def list_(self, *args):
        code, out, err = self.run_(("jail", "list"), list(args), command_args=False)
        self.assertEqual(code, 0, err)
        return rows(out)


class Managed(Cli):
    def test_named_lifecycle(self):
        code, out, err = self.create("-t", "my-run", "--retention", "disk")
        self.assertEqual(code, 0, err)
        run_id = out.split()[1]
        self.assertEqual(out, f"created: {run_id} kind=managed name=my-run\n")
        self.assertEqual(self.world.record(run_id)["name"], "my-run")
        by_name = self.run_("status", run_id="my-run")
        self.assertEqual(by_name, self.run_("status", run_id=run_id))
        self.assertTrue(by_name[1].startswith(f"run: {run_id} name=my-run state=idle "), by_name)
        # Taken: refused before any provider work.
        log = len(self.world.provider_log())
        self.assertEqual(self.create("-t", "my-run")[::2], (1, "agentbox: jail create refused: run_name_taken\n"))
        self.assertEqual(len(self.world.provider_log()), log)
        for bad in ("r-" + "0" * 32, "My"):
            self.assertEqual(self.create("-t", bad)[::2], (1, "agentbox: jail create refused: run_name_invalid\n"))
        self.assertEqual(len(self.world.provider_log()), log)
        code, _, err = self.world.exec(["/bin/sh", "-c", "true"], run_id="my-run", overrides=QUICK)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.list_(), [["NAME", "JAIL", "ID", "PROVIDER", "PHASE"],
                                        ["my-run", run_id, "standin", "ready"],
                                        ["-", self.world.run_id, "standin", "ready"]])
        self.assertEqual(self.run_("discard", run_id="my-run")[:2], (0, f"discard: {run_id} discarded\n"))
        self.assertEqual(self.run_("status", run_id="my-run")[::2],
                         (1, "agentbox: jail status refused: run_unknown\n"))
        code, out, _ = self.run_("status", run_id=run_id)
        self.assertIn(" name=my-run state=idle kind=managed phase=discarded ", out)
        self.assertEqual(self.list_()[1:], [["-", self.world.run_id, "standin", "ready"]])
        self.assertIn(["my-run", run_id, "standin", "discarded"], self.list_("--all"))
        # Free again: a new run, the old one by id only.
        code, out, err = self.create("-t", "my-run")
        self.assertEqual(code, 0, err)
        again = out.split()[1]
        self.assertNotEqual(again, run_id)
        self.assertTrue(self.run_("status", run_id="my-run")[1].startswith(f"run: {again} name=my-run "))
        self.assertEqual(self.list_("--all")[1:], sorted([["my-run", again, "standin", "ready"],
                                                          ["my-run", run_id, "standin", "discarded"]])
                         + [["-", self.world.run_id, "standin", "ready"]])

    def test_a_failed_create_keeps_its_name_until_discarded(self):
        self.world.set_behavior(create="user_conflict")
        self.assertEqual(self.create("-t", "held")[::2],
                         (1, "agentbox: jail create refused: provider_failed provider_code=user_conflict\n"))
        self.world.set_behavior(create="ok")
        [held] = [row[1] for row in self.list_() if row[0] == "held"]
        self.assertIn(["held", held, "standin", "partial"], self.list_())
        self.assertEqual(self.create("-t", "held")[::2], (1, "agentbox: jail create refused: run_name_taken\n"))
        self.assertEqual(self.run_("discard", run_id="held")[:2], (0, f"discard: {held} retired\n"))
        code, out, err = self.create("-t", "held")
        self.assertEqual(code, 0, err)
        self.assertNotEqual(out.split()[1], held)

    def test_every_selector_resolves_to_the_same_run(self):
        code, out, err = self.create("-t", "sel", "--retention", "disk")
        self.assertEqual(code, 0, err)
        run_id = out.split()[1]
        missing = f"{self.world.tmp}/missing"
        cases = [("status", []), ("stop", []),
                 (("jail", "inputs"), ["--copy", f"{missing}=x"]),
                 (("jail", "export"), ["--to", f"{self.world.tmp}/out.tar"]),
                 (("jail", "serve"), ["--acquisition-config", "x", "--acquisition-stage-root", "rel"]),
                 (("shell",), [])]
        for command, extra in cases:
            by_id = self.run_(command, extra, run_id=run_id)
            self.assertEqual(self.run_(command, extra, run_id="sel"), by_id, command)
            self.assertNotIn("run_unknown", by_id[2], command)
            self.assertNotIn("run_invalid", by_id[2], command)
        code, _, err = self.world.exec(["/bin/sh", "-c", "true"], run_id="sel", overrides=QUICK)
        self.assertEqual(code, 0, err)
        code, out, err = self.run_(("checkpoint", "create"), run_id="sel")
        self.assertEqual((code, out.split()[2]), (0, f"source={run_id}"), err)
        # A busy run: the owner's signal by its id (none here: run_busy).
        held = store_mod.Store(self.world.data)
        lease = held.claim(run_id)
        try:
            self.assertEqual(self.run_("stop", run_id="sel"), self.run_("stop", run_id=run_id))
            self.assertEqual(self.run_("stop", run_id="sel")[2], "agentbox: jail stop refused: run_busy\n")
        finally:
            lease.release()
            held.close()
        # run AGENT --jail: the run's id in its own refusal.
        self.world.edit_record(run_id, storage="unclean", generation=1)
        jail = ["pi", "--prompt", "p", "--jail"]
        by_id = self.run_(("run",), jail + [run_id], command_args=False)
        self.assertEqual(self.run_(("run",), jail + ["sel"], command_args=False), by_id)
        self.assertIn(f"agentbox jail status {run_id}", by_id[2])
        self.assertIn("agent_jail_unclean", by_id[2])
        # Unknown names, everywhere; the hidden transport takes ids only.
        for command, extra in cases + [("exec", ["--", "true"]), ("discard", []), (("checkpoint", "create"), [])]:
            words = " ".join(self.world.LEGACY.get(command, command))
            self.assertEqual(self.run_(command, extra, run_id="nope")[::2],
                             (1, f"agentbox: {words} refused: run_unknown\n"), command)
        self.assertEqual(self.run_(("run",), jail + ["nope"], command_args=False)[::2],
                         (1, "agentbox: run refused: run_unknown\n"))
        self.assertEqual(self.run_(("jail", "shell-transport"), ["e-" + "0" * 32], run_id="sel")[::2],
                         (1, "agentbox: jail shell-transport refused: run_invalid\n"))
        # Only an explicit jail create names.
        for command, extra in ((("run",), ["pi", "-t", "x"]), (("checkpoint", "restore"), ["-t", "x", "c"])):
            self.assertEqual(self.run_(command, extra, command_args=False)[0], 2)

    def test_list_shows_invalid_records_and_creation_fails_closed(self):
        broken = "r-" + "f" * 32
        os.mkdir(f"{self.world.data}/controller-runs/{broken}", 0o700)
        write_file(f"{self.world.data}/controller-runs/{broken}/run.json", "{}")
        self.assertIn(["-", broken, "-", "invalid"], self.list_())
        self.assertIn(["-", broken, "-", "invalid"], self.list_("--all"))
        log = len(self.world.provider_log())
        self.assertEqual(self.create("-t", "z")[::2], (1, "agentbox: jail create refused: run_invalid\n"))
        self.assertEqual(self.run_("status", run_id="z")[::2], (1, "agentbox: jail status refused: run_invalid\n"))
        self.assertEqual(len(self.world.provider_log()), log)
        self.assertEqual(self.run_("status")[0], 0)

    def test_list_never_creates_data(self):
        fresh = f"{self.world.tmp}/fresh"
        path = f"{self.world.tmp}/fresh.json"
        write_file(path, {"schema": "agentbox.controller-config.v1", "data": fresh, "server": server()})

        def listed():
            argv = self.world.argv(("jail", "list"), command_args=False)
            argv[argv.index("--config") + 1] = path
            done = subprocess.run(argv, env=self.world.env(), capture_output=True, timeout=60)
            return done.returncode, rows(done.stdout.decode())

        self.assertEqual(listed(), (0, [["NAME", "JAIL", "ID", "PROVIDER", "PHASE"]]))
        self.assertFalse(os.path.lexists(fresh))
        os.mkdir(fresh, 0o700)
        self.assertEqual(listed(), (0, [["NAME", "JAIL", "ID", "PROVIDER", "PHASE"]]))
        self.assertEqual(os.listdir(fresh), [])


class Attached(Cli):
    kind = "attached"
    behavior = {}

    def test_concurrent_cli_creates_one_wins(self):
        """Real processes through the CLI, queued behind the held store
        lock, then released together."""
        held = store_mod.Store(self.world.data)
        try:
            with held.lock():
                children = [self.world.start(("jail", "create"), ["-t", "race", "--ssh-target",
                                                                 self.world.target_file], command_args=False)
                            for _ in range(8)]
                time.sleep(1.5)
        finally:
            held.close()
        results = []
        for child in children:
            out, err = child.communicate(timeout=60)
            results.append((child.returncode, out.decode(), err.decode()))
        won = [out for code, out, _ in results if code == 0]
        self.assertEqual(len(won), 1, results)
        self.assertEqual(sorted({(code, err) for code, _, err in results if code != 0}),
                         [(1, "agentbox: jail create refused: run_name_taken\n")])
        run_id = won[0].split()[1]
        self.assertEqual(won[0], f"created: {run_id} kind=attached name=race\n")
        code, out, err = self.run_(("jail", "list"), command_args=False)
        self.assertEqual(rows(out)[1:], [["race", run_id, "attached", "ready"],
                                         ["-", self.world.run_id, "attached", "ready"]])
        for detail in (self.world.target["host"], self.world.identity, self.world.remote, self.world.bundle):
            self.assertNotIn(detail, out)
        self.assertEqual(self.run_("discard", run_id="race")[:2], (0, f"discard: {run_id} discarded\n"))
        code, out, err = self.create("-t", "race", "--ssh-target", self.world.target_file)
        self.assertEqual(code, 0, err)
        self.assertTrue(self.run_("status", run_id="race")[1].startswith(f"run: {out.split()[1]} name=race "))


if __name__ == "__main__":
    unittest.main()
