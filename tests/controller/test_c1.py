"""C1 end to end, offline: the managed lifecycle (image prepare and
recover, jail create, stop, discard, checkpoints) through the production
CLI with the stand-in provider and FakeCgroups, mounts and project
routing, STATE claims, unclean storage, the acquisition stage root, and
the operator's assertion (the user's choice for attached runs and input
staging).

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t .
"""
import json
import os
import shutil
import signal
import subprocess
import tempfile
import unittest

from agentbox_controller import inputs as inputs_mod, lifecycle, states, store as store_mod
from tests.controller import test_b2
from tests.controller.harness import World, server, write_file
from tests.controller.test_execution import QUICK, fields, final, until

request = test_b2.request
FEATURES = ["select_user", "project_layout", "host_mounts"]


class C1(test_b2.B2):
    kind = "managed"
    behavior = {}

    def setUp(self):
        self.world = World(kind=self.kind, retention=self.retention, behavior=dict(self.behavior))
        self.addCleanup(self.world.close)

    def run_(self, command, extra=(), **kwargs):
        kwargs.setdefault("overrides", QUICK)
        return self.world.run(command, list(extra), **kwargs)

    def status_of(self, run_id):
        code, out, err = self.world.run("status", run_id=run_id)
        self.assertEqual(code, 0, err)
        return dict(word.split("=", 1) for word in out.split()[2:])

    def creates(self, *args):
        code, out, err = self.world.run(("jail", "create"), ["--image", self.world.image] + list(args),
                                        command_args=False)
        return code, out, err

    def provider(self, kind):
        return [e for e in self.world.provider_log() if e.get("type") == kind]

    def directory(self, mode=0o700):
        path = tempfile.mkdtemp(prefix="c1-", dir=os.environ.get("TMPDIR"))
        os.chmod(path, mode)
        self.addCleanup(shutil.rmtree, path, True)
        return path


class Lifecycle(C1):
    def test_create_exec_stop_discard(self):
        run_id = self.world.create(["--retention", "home", "--cpus", "2"])
        record = self.world.record(run_id)
        self.assertEqual((record["phase"], record["retention"], record["limits"], record["home"], record["pending"]),
                         ("ready", "home", {"cpus": 2}, self.world.home, None))
        self.assertEqual([(e["user"], e["retention"]) for e in self.provider("create")], [("agentbox", "home")])
        code, out, err = self.world.exec(request("echo hi"), run_id=run_id, overrides=QUICK)
        self.assertEqual(code, 0, err)
        code, out, err = self.run_("stop", run_id=run_id)
        self.assertEqual((code, out), (0, f"stop: {run_id} idle\n"), err)
        code, out, err = self.run_("discard", run_id=run_id)
        self.assertEqual((code, out), (0, f"discard: {run_id} discarded\n"), err)
        self.assertEqual(self.world.record(run_id)["phase"], "discarded")
        self.assertEqual(len(self.provider("discard")), 1)
        code, _, err = self.world.exec(request("true"), run_id=run_id, overrides=QUICK)
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: run_discarded\n"))
        code, out, _ = self.run_("discard", run_id=run_id)
        self.assertEqual((code, out), (0, f"discard: {run_id} already_discarded\n"))
        self.assertEqual(self.world.domains(), [])

    def test_capability_refusals_record_nothing(self):
        runs = set(os.listdir(f"{self.world.data}/controller-runs"))
        self.world.set_behavior(retention=["none"], features=[])
        for args, reason in ((["--retention", "disk"], "retention_unsupported"),
                             (["--disk-mib", "10"], "limit_unsupported"),
                             (["--user", "bob"], "user_unsupported"),
                             (["--mount-ro", self.directory()], "mounts_unsupported"),
                             (["--cpus", "0"], "limit_invalid"),
                             (["--user", "Bad"], "user_invalid")):
            code, _, err = self.creates(*args)
            # A provider that keeps nothing (a shared Podman store) says so.
            hint = f"agentbox: hint: {lifecycle.NO_RETENTION_HINT}\n" if reason == "retention_unsupported" else ""
            self.assertEqual((code, err), (1, f"agentbox: jail create refused: {reason}\n" + hint), args)
        self.assertEqual(set(os.listdir(f"{self.world.data}/controller-runs")), runs)
        # A tag whose image left STATE.
        with open(f"{self.world.data}/images/default") as stream:
            tag = json.load(stream)
        write_file(f"{self.world.data}/images/gone", dict(tag, name="gone", image="c" * 64))
        code, _, err = self.world.run(("jail", "create"), ["--image", "gone"], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: jail create refused: worker_invalid\n"))

    def test_user_conflict_is_retired(self):
        self.world.set_behavior(create="user_conflict")
        code, _, err = self.creates()
        self.assertEqual((code, err),
                         (1, "agentbox: jail create refused: provider_failed provider_code=user_conflict\n"))
        run_id = [r for r in os.listdir(f"{self.world.data}/controller-runs")
                  if r.startswith("r-") and r != self.world.run_id][0]
        status = self.status_of(run_id)
        self.assertEqual((status["phase"], status["create"]), ("partial", "refused"))
        code, _, err = self.world.exec(request("true"), run_id=run_id, overrides=QUICK)
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: run_not_ready\n"))
        code, out, err = self.run_("discard", run_id=run_id)
        self.assertEqual((code, out), (0, f"discard: {run_id} retired\n"), err)

    def test_mount_refusals_are_retired_and_free_their_name(self):
        for code in ("mount_source_unavailable", "mount_source_unsupported", "mount_source_protected",
                     "mount_source_overlap"):
            before = set(os.listdir(f"{self.world.data}/controller-runs"))
            self.world.set_behavior(create=code)
            got, _, err = self.creates("-t", "held")
            self.assertEqual((got, err), (1, f"agentbox: jail create refused: provider_failed provider_code={code}\n"))
            [run_id] = set(os.listdir(f"{self.world.data}/controller-runs")) - before
            status = self.status_of(run_id)
            self.assertEqual((status["phase"], status["create"]), ("partial", "refused"), code)
            self.world.set_behavior(create="ok")
            self.assertEqual(self.creates("-t", "held")[::2], (1, "agentbox: jail create refused: run_name_taken\n"))
            got, out, err = self.run_("discard", run_id=run_id)
            self.assertEqual((got, out), (0, f"discard: {run_id} retired\n"), err)
        # The name is free again.
        got, out, err = self.creates("-t", "held")
        self.assertEqual(got, 0, err)

    def test_other_or_uncertain_create_failures_stay_partial(self):
        for behavior in ({"create": "mount_source_protected", "failed_durability": "uncertain"},
                         {"create": "user_conflict", "failed_durability": "uncertain"},
                         {"create": "mount_destination_unsafe"}, {"create": "fail"}):
            before = set(os.listdir(f"{self.world.data}/controller-runs"))
            self.world.set_behavior(**behavior)
            got, _, err = self.creates()
            self.assertEqual(got, 1, err)
            [run_id] = set(os.listdir(f"{self.world.data}/controller-runs")) - before
            status = self.status_of(run_id)
            self.assertEqual(status["phase"], "partial", behavior)
            self.assertNotIn("create", status, behavior)
            self.world.set_behavior(create="ok", failed_durability="unchanged")
            # The provider's not_found never retires it.
            got, _, err = self.run_("discard", run_id=run_id)
            self.assertEqual((got, err),
                             (1, "agentbox: jail discard refused: provider_failed provider_code=not_found\n"), behavior)
            self.assertEqual(self.status_of(run_id)["phase"], "partial")

    def test_unclean_storage_needs_the_exact_generation(self):
        self.world.set_behavior(stop_storage="unclean")
        code, out, err = self.exec(request("true"))
        self.assertEqual(code, 0, err)
        status = self.status()
        self.assertEqual((status["storage"], status["generation"]), ("unclean", "1"))
        code, _, err = self.exec(request("true"))
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: storage_unclean\n"))
        for value, reason in (("0", "generation_mismatch"), ("x", "allow_unclean_invalid")):
            code, _, err = self.exec(request("true"), ["--allow-unclean", value])
            self.assertEqual((code, err), (1, f"agentbox: jail exec refused: {reason}\n"))
        code, _, err = self.exec(request("true"), ["--allow-unclean", "1"])
        self.assertEqual(code, 0, err)
        self.assertEqual([e["accept_unclean"] for e in self.provider("start")], [False, True])

    def test_storage_limit_records_nothing(self):
        runs = set(os.listdir(f"{self.world.data}/controller-runs"))
        limits = f"{self.world.data}/run-limits.json"
        with open(limits) as stream:
            value = json.load(stream)
        write_file(limits, dict(value, max_reserved_bytes=1024))
        code, _, err = self.creates()
        self.assertEqual((code, err), (1, "agentbox: jail create refused: storage_limit\n"))
        self.assertEqual(set(os.listdir(f"{self.world.data}/controller-runs")), runs)
        self.assertEqual(self.provider("create"), [])


class Crashes(C1):
    def kill_when(self, process, kind):
        until(lambda: self.provider(kind))
        process.kill()
        process.communicate(timeout=30)

    def test_create_cancelled_then_discarded(self):
        self.world.set_behavior(create="hang")
        process = self.world.start(("jail", "create"), ["--image", self.world.image], command_args=False,
                                   overrides=QUICK)
        until(lambda: self.provider("create"))
        process.send_signal(signal.SIGTERM)
        _, err = process.communicate(timeout=60)
        self.assertEqual(err.decode(), "agentbox: jail create refused: cancelled\n")
        run_id = self.newest()
        self.assertEqual(self.status_of(run_id)["phase"], "partial")
        code, out, err = self.run_("discard", run_id=run_id)
        self.assertEqual((code, out), (0, f"discard: {run_id} discarded\n"), err)
        self.assertEqual(self.world.domains(), [])

    def newest(self):
        runs = [r for r in os.listdir(f"{self.world.data}/controller-runs") if r.startswith("r-")
                and r != self.world.run_id]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def test_controller_killed_during_create(self):
        self.world.set_behavior(create="hang")
        process = self.world.start(("jail", "create"), ["--image", self.world.image], command_args=False,
                                   overrides=QUICK)
        self.kill_when(process, "create")
        run_id = self.newest()
        status = self.status_of(run_id)
        self.assertEqual((status["state"], status["phase"], status["pending"], status["processes"]),
                         ("abandoned", "creating", "create", "unknown"))
        self.assertTrue(self.world.domains())
        code, _, err = self.run_("discard", run_id=run_id)
        self.assertEqual((code, err), (1, "agentbox: jail discard refused: processes_unsettled\n"))
        code, out, err = self.run_("stop", run_id=run_id)
        self.assertEqual((code, out), (0, f"stop: {run_id} partial\n"), err)
        self.assertEqual(self.world.domains(), [])
        self.assertEqual([p for p in self.world.listed_pids() if self.world.ours(p)], [])
        code, out, err = self.run_("discard", run_id=run_id)
        self.assertEqual((code, out), (0, f"discard: {run_id} discarded\n"), err)

    def test_controller_killed_during_prepare(self):
        self.world.set_behavior(prepare="hang")
        recipe = f"{self.world.state}/inputs/other.json"
        write_file(recipe, "{}")
        args = ["standin", "--provider-config", self.world.provider_file, "--recipe", recipe]
        process = self.world.start(("image", "prepare"), args, command_args=False, overrides=QUICK)
        self.kill_when(process, "prepare")
        key = states.key(self.world.state)
        with open(f"{self.world.data}/controller-states/{key}/state.json") as stream:
            pending = json.load(stream)["pending"]
        self.assertEqual((pending["op"], pending["processes"]), ("prepare", "unknown"))
        self.world.set_behavior(prepare="ok")
        code, _, err = self.run_(("image", "prepare"), args, command_args=False)
        self.assertEqual((code, err), (1, "agentbox: image prepare refused: prepare_unsettled\n"))
        code, _, err = self.run_(("image", "recover"), ["standin", "--provider-config", self.world.provider_file,
                                                        "o-" + "0" * 32], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: image recover refused: operation_unknown\n"))
        code, out, err = self.run_(("image", "recover"), ["standin", "--provider-config", self.world.provider_file,
                                                          pending["operation"]], command_args=False)
        self.assertEqual((code, out), (0, f"image recover: {pending['operation']} recovered\n"), err)
        self.assertEqual(self.world.domains(), [])
        code, out, err = self.run_(("image", "prepare"), args, command_args=False)
        self.assertEqual(code, 0, err)


    def test_prepare_failure_clears_its_record(self):
        self.world.set_behavior(prepare="fail")
        recipe = f"{self.world.state}/inputs/recipe.json"
        code, _, err = self.run_(("image", "prepare"), ["standin", "--provider-config", self.world.provider_file,
                                                        "--recipe", recipe], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: image prepare refused: provider_failed provider_code=failed\n"))
        with open(f"{self.world.data}/controller-states/{states.key(self.world.state)}/state.json") as stream:
            self.assertIsNone(json.load(stream)["pending"])
        self.assertEqual(self.world.domains(), [])


class States(C1):
    def test_one_store_per_state(self):
        other = self.directory()
        write_file(f"{other}/run-limits.json", {"max_reserved_bytes": 1 << 40,
                                                "storage_scopes": [{"path": self.world.state, "measure": "tree"}]})
        # The same tag in the other store: the same provider and image.
        os.mkdir(f"{other}/images", 0o700)
        shutil.copyfile(f"{self.world.data}/images/default", f"{other}/images/default")
        os.chmod(f"{other}/images/default", 0o600)
        config = f"{self.world.tmp}/other.json"
        write_file(config, {"schema": "agentbox.controller-config.v1", "data": other,
                            "server": server()})
        argv = self.world.argv(("jail", "create"), ["--image", self.world.image], command_args=False)
        argv[argv.index("--config") + 1] = config
        done = subprocess.run(argv, env=self.world.env(), capture_output=True, timeout=60)
        self.assertEqual((done.returncode, done.stderr.decode()),
                         (1, "agentbox: jail create refused: state_owned_elsewhere\n"))
        # A STATE already used by another (no claim, allocations present).
        os.unlink(f"{self.world.state}/.agentbox-controller.json")
        code, _, err = self.creates()
        self.assertEqual((code, err), (1, "agentbox: jail create refused: state_unclaimed\n"))

    def test_state_lease_excludes(self):
        opened = store_mod.Store(self.world.data)
        held = states.StateLease(opened, self.world.state)
        try:
            code, _, err = self.creates()
            self.assertEqual((code, err), (1, "agentbox: jail create refused: state_busy\n"))
        finally:
            held.release()
            opened.close()


class Mounts(C1):
    retention = "home"
    behavior = {"features": FEATURES}

    def source(self):
        source = self.directory(0o755)
        os.makedirs(f"{source}/app", 0o755)
        return source

    def test_refusals_before_anything(self):
        source = self.source()
        other = self.source()
        runs = set(os.listdir(f"{self.world.data}/controller-runs"))
        for args, reason in (
                (["--mount-rw", self.world.data], "mount_source_protected"),
                (["--mount-rw", self.world.state + "/inputs"], "mount_source_protected"),
                (["--mount-ro", os.path.dirname(self.world.data)], "mount_source_protected"),
                (["--mount-ro", f"{source}=a", "--mount-ro", f"{source}/app=b"], "mount_source_overlap"),
                (["--mount-ro", f"{source}=a", "--mount-ro", f"{other}=a/b"], "mount_destination_overlap"),
                (["--mount-ro", f"{source}=work"], "mount_work_overlap"),
                (["--mount-ro", f"{source}/missing=m"], "mount_source_unavailable"),
                (["--mount-ro", "/proc=p"], "mount_source_unsupported"),
                (["--mount-ro", f"{source}=.agentbox"], "mount_destination_invalid"),
                (["--mount-ro", f"{source}=.agentbox-inputs-x"], "mount_destination_invalid"),
                (["--mount-ro", f"{source}=.agentbox-root"], "mount_destination_invalid"),
                # A hidden destination only when explicit (lexical: nothing there is looked at).
                (["--mount-ro", os.environ["HOME"] + "/.agentbox-test-absent"], "mount_destination_unmapped"),
                (["--mount-ro", f"{source}=.pi", "--project", f"{source}/app"], "project_invalid"),
                (["--mount-ro", f"{source}=a", "--project", other], "project_invalid"),
                (["--project", other], "project_invalid"),
                ([w for i in range(9) for w in ("--mount-ro", f"{source}=m{i}")], "mount_limit"),
                (["--retention", "none", "--mount-ro", f"{source}=a"], "mounts_need_retention")):
            code, _, err = self.creates(*(["--retention", "home"] if "--retention" not in args else []), *args)
            self.assertEqual((code, err), (1, f"agentbox: jail create refused: {reason}\n"), args)
        self.assertEqual(set(os.listdir(f"{self.world.data}/controller-runs")), runs)

    def test_mounted_project_routes_cwd_and_delivery(self):
        source = self.source()
        run_id = self.world.create(["--retention", "home", "--mount-rw", f"{source}=proj", "--project",
                                    f"{source}/app"])
        record = self.world.record(run_id)
        self.assertEqual((record["project"], record["mounts"]),
                         ("proj/app", [{"source": source, "destination": "proj", "access": "rw"}]))
        self.assertEqual(self.provider("create")[-1]["mounts"], record["mounts"])
        # A workspace never replaces a mounted project; copies never meet a mount.
        note = f"{self.world.tmp}/n.txt"
        write_file(note, "n\n", 0o644)
        for args, reason in ((["--workspace", source], "input_project_mounted"),
                             (["--copy", f"{note}=proj/x"], "input_mount_conflict")):
            code, _, err = self.world.run("inputs", args, run_id=run_id)
            self.assertEqual((code, err), (1, f"agentbox: jail inputs refused: {reason}\n"))
        # The stand-in binds nothing: the guest's mount, as a provider makes it.
        os.makedirs(f"{self.world.home}/proj/app", 0o755)
        code, out, err = self.world.exec(request("pwd; agentbox-request echo say '{\"text\":\"m\"}'"),
                                         ["--acquisition-config", self.world.acquisition()], run_id=run_id,
                                         overrides=QUICK)
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith(f"{self.world.home}/proj/app\n"), out)
        delivered = [t for t in self.world.transfers() if t["program"] == "scp"]
        self.assertTrue(delivered[-1]["operands"][-1].split(":", 1)[1].startswith(
            f"{self.world.home}/proj/app/.agentbox-requests/"))
        code, _, err = self.run_(("checkpoint", "create"), [], run_id=run_id)
        self.assertEqual((code, err), (1, "agentbox: checkpoint create refused: checkpoint_unsupported\n"))

    def test_an_explicit_hidden_destination_is_recorded(self):
        source, other = self.source(), self.source()
        run_id = self.world.create(["--retention", "home", "--mount-rw", f"{source}=.pi", "--mount-ro",
                                    f"{other}=.agentbox-root/app"])
        mounts = [{"source": other, "destination": ".agentbox-root/app", "access": "ro"},
                  {"source": source, "destination": ".pi", "access": "rw"}]
        self.assertEqual((self.world.record(run_id)["mounts"], self.provider("create")[-1]["mounts"]),
                         (mounts, mounts))

    def test_start_refusal_code_is_shown(self):
        source = self.source()
        run_id = self.world.create(["--retention", "home", "--memory-mib", "1024", "--mount-ro", f"{source}=ref"])
        self.world.set_behavior(start="mounts_need_memory")
        code, _, err = self.world.exec(request("true"), run_id=run_id, overrides=QUICK)
        line = fields(final(err))
        self.assertEqual((code, line["reason"], line["provider_code"]), (1, "provider_failed", "mounts_need_memory"))

    def test_a_retained_home_volume_is_recorded_and_shown(self):
        self.world.set_behavior(volume="agentbox-home-res-x")
        run_id = self.world.create(["--retention", "home"])
        self.assertEqual(self.world.record(run_id)["volume"], "agentbox-home-res-x")
        status = self.status_of(run_id)
        self.assertEqual((status["retention"], status["volume"]), ("home", "agentbox-home-res-x"))
        # None kept: no name, never one from the provider for it.
        run_id = self.world.create(["--retention", "none"])
        self.assertNotIn("volume", self.world.record(run_id))
        status = self.status_of(run_id)
        self.assertEqual(status["retention"], "none")
        self.assertNotIn("volume", status)

    def test_a_shared_store_refusal_is_shown_with_its_hint(self):
        run_id = self.world.create([])
        for code_name in lifecycle.PROVIDER_HINTS:
            self.world.set_behavior(start=code_name)
            code, _, err = self.world.exec(request("true"), run_id=run_id, overrides=QUICK)
            line = fields(final(err))
            self.assertEqual((code, line["reason"], line["provider_code"]), (1, "provider_failed", code_name))
            self.assertEqual(err.splitlines()[-1], f"agentbox: hint: {lifecycle.PROVIDER_HINTS[code_name]}")

    def test_workspace_goes_to_its_project_location(self):
        project = f"{self.world.tmp}/project"
        os.makedirs(f"{project}/sub")
        write_file(f"{project}/sub/a.txt", "alpha\n", 0o644)
        location = inputs_mod.project(project, os.environ["HOME"])
        code, out, err = self.world.run("inputs", ["--workspace", project])
        self.assertEqual(code, 0, err)
        self.assertIn(f"project={location}", out)
        code, out, err = self.exec(request("pwd; cat sub/a.txt"))
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith(f"{self.world.home}/{location}\nalpha\n"), out)

    def test_current_user(self):
        import pwd
        name = pwd.getpwuid(os.getuid()).pw_name
        run_id = self.world.create(["--user", "current"])
        self.assertEqual((self.world.record(run_id)["user"], self.provider("create")[-1]["user"]), (name, name))


class Checkpoints(C1):
    behavior = {"checkpoints": True}

    def test_checkpoint_restore_discard(self):
        run_id = self.world.create(["--retention", "disk"])
        code, _, err = self.world.exec(request("true"), run_id=run_id, overrides=QUICK)
        self.assertEqual(code, 0, err)
        code, out, err = self.run_(("checkpoint", "create"), [], run_id=run_id)
        self.assertEqual(code, 0, err)
        ident = out.split()[1]
        code, out, err = self.run_(("checkpoint", "list"), [], command_args=False)
        self.assertEqual(out, f"checkpoint: {ident} state=ready source={run_id} generation=0 storage=clean "
                              "processes=settled\n")
        code, out, err = self.run_(("checkpoint", "restore"), [ident], command_args=False)
        self.assertEqual(code, 0, err)
        restored = out.split()[1]
        record = self.world.record(restored)
        self.assertEqual((record["phase"], record["generation"], record["origin"]),
                         ("ready", 1, {"checkpoint": ident, "source_run": run_id}))
        code, _, err = self.world.exec(request("true"), run_id=restored, overrides=QUICK)
        self.assertEqual(code, 0, err)
        note = f"{self.world.tmp}/n.txt"
        write_file(note, "n\n", 0o644)
        code, _, err = self.world.run("inputs", ["--copy", f"{note}=n"], run_id=restored)
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: inputs_run_restored\n"))
        code, out, err = self.run_(("checkpoint", "discard"), [ident], command_args=False)
        self.assertEqual((code, out), (0, f"checkpoint discard: {ident} discarded\n"), err)
        code, out, _ = self.run_(("checkpoint", "discard"), [ident], command_args=False)
        self.assertEqual(out, f"checkpoint discard: {ident} already_discarded\n")
        self.assertEqual(self.world.domains(), [])

    def test_unclean_needs_acknowledgement(self):
        self.world.set_behavior(stop_storage="unclean")
        run_id = self.world.create(["--retention", "disk"])
        code, _, err = self.world.exec(request("true"), run_id=run_id, overrides=QUICK)
        self.assertEqual(code, 0, err)
        code, _, err = self.run_(("checkpoint", "create"), [], run_id=run_id)
        self.assertEqual((code, err), (1, "agentbox: checkpoint create refused: storage_unclean\n"))
        code, out, err = self.run_(("checkpoint", "create"), ["--allow-unclean", "1"], run_id=run_id)
        self.assertEqual(code, 0, err)
        self.assertIn("storage=unclean", self.run_(("checkpoint", "status"), [out.split()[1]],
                                                   command_args=False)[1])

    def test_controller_killed_during_checkpoint(self):
        run_id = self.world.create(["--retention", "disk"])
        self.world.set_behavior(checkpoint="hang")
        process = self.world.start(("checkpoint", "create"), [], run_id=run_id, overrides=QUICK)
        until(lambda: any(e.get("type") == "checkpoint" for e in self.world.provider_log()))
        process.kill()
        process.communicate(timeout=30)
        status = self.status_of(run_id)
        self.assertEqual((status["pending"], status["processes"]), ("checkpoint", "unknown"))
        ident = [e for e in self.world.provider_log() if e.get("type") == "checkpoint"][0]["checkpoint"]
        code, out, err = self.run_("stop", run_id=run_id)
        self.assertEqual((code, out), (0, f"stop: {run_id} recovered\n"), err)
        # Lost, not failed: its outcome unknown, a not_found retires nothing.
        code, out, _ = self.run_(("checkpoint", "status"), [ident], command_args=False)
        self.assertIn("state=lost", out)
        code, out, err = self.run_(("checkpoint", "discard"), [ident], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: checkpoint discard refused: provider_failed "
                                          "provider_code=not_found\n"))
        code, out, _ = self.run_(("checkpoint", "status"), [ident], command_args=False)
        self.assertIn("state=lost", out)
        self.assertIn("processes=settled", out)
        self.assertEqual(self.world.domains(), [])

    def test_affirmatively_refused_checkpoint_is_retired(self):
        run_id = self.world.create(["--retention", "disk"])
        self.world.set_behavior(checkpoint="fail")
        code, _, err = self.run_(("checkpoint", "create"), [], run_id=run_id)
        self.assertEqual((code, err),
                         (1, "agentbox: checkpoint create refused: provider_failed provider_code=failed\n"))
        ident = [e for e in self.world.provider_log() if e.get("type") == "checkpoint"][0]["checkpoint"]
        self.assertIn("state=failed", self.run_(("checkpoint", "status"), [ident], command_args=False)[1])
        self.assertNotIn("pending", self.status_of(run_id))
        code, out, err = self.run_(("checkpoint", "discard"), [ident], command_args=False)
        self.assertEqual((code, out), (0, f"checkpoint discard: {ident} retired\n"), err)


    def test_controller_killed_during_restore(self):
        run_id = self.world.create(["--retention", "disk"])
        code, out, err = self.run_(("checkpoint", "create"), [], run_id=run_id)
        ident = out.split()[1]
        self.world.set_behavior(restore="hang")
        process = self.world.start(("checkpoint", "restore"), [ident], command_args=False, overrides=QUICK)
        until(lambda: any(e.get("type") == "restore" for e in self.world.provider_log()))
        process.kill()
        process.communicate(timeout=30)
        code, out, _ = self.run_(("checkpoint", "status"), [ident], command_args=False)
        self.assertIn("processes=unknown holder=", out)
        restored = out.split("holder=")[1].split()[0]
        code, _, err = self.run_(("checkpoint", "discard"), [ident], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: checkpoint discard refused: checkpoint_unsettled\n"))
        code, out, err = self.run_("stop", run_id=restored)
        self.assertEqual((code, out), (0, f"stop: {restored} partial\n"), err)
        code, out, _ = self.run_(("checkpoint", "status"), [ident], command_args=False)
        self.assertIn("state=ready", out)
        self.assertIn("processes=settled", out)
        self.assertEqual(self.world.domains(), [])
        code, out, err = self.run_("discard", run_id=restored)
        self.assertEqual((code, out), (0, f"discard: {restored} discarded\n"), err)


    def test_restore_binds_the_run_before_the_checkpoint(self):
        """A failure between the new run's binding and C's holder (here C's
        write refused as too large): `jail stop` of that run settles it and
        C was never stranded."""
        run_id = self.world.create(["--retention", "disk"])
        code, out, err = self.run_(("checkpoint", "create"), [], run_id=run_id)
        ident = out.split()[1]
        entry = f"{self.world.data}/controller-checkpoints/{ident}.json"
        with open(entry) as stream:
            before = stream.read()
        creates = len(self.provider("create"))
        code, _, err = self.run_(("checkpoint", "restore"), [ident], command_args=False,
                                 overrides=dict(QUICK, **{"checkpoints.MAX_RECORD_BYTES": len(before) + 16}))
        self.assertEqual((code, err), (1, "agentbox: checkpoint restore refused: record_too_large\n"))
        with open(entry) as stream:
            self.assertEqual(stream.read(), before)
        self.assertEqual(len(self.provider("create")), creates)
        restored = [r for r in os.listdir(f"{self.world.data}/controller-runs")
                    if r.startswith("r-") and r not in (run_id, self.world.run_id)][0]
        status = self.status_of(restored)
        self.assertEqual((status["pending"], status["processes"]), ("create", "unknown"))
        code, out, err = self.run_("stop", run_id=restored)
        self.assertEqual((code, out), (0, f"stop: {restored} partial\n"), err)
        self.assertEqual(self.world.domains(), [])
        code, out, err = self.run_(("checkpoint", "restore"), [ident], command_args=False)
        self.assertEqual(code, 0, err)


class Assertions(C1):
    def stage_abandoned(self):
        opened = store_mod.Store(self.world.data)
        lease = opened.claim(self.world.run_id)
        attempt = "s-" + "cd" * 16
        lease.save(dict(lease.record, inputs={"state": "staging", "attempt": attempt, "copies": 1,
                                              "settings": dict(inputs_mod.DEFAULT_SETTINGS)}))
        directory = f"{self.world.data}/controller-runs/{self.world.run_id}/inputs"
        os.makedirs(directory, 0o700, exist_ok=True)
        write_file(f"{directory}/spool-{attempt}", "x")
        lease.release()
        opened.close()
        return attempt, directory

    def test_staging_assertion(self):
        attempt, directory = self.stage_abandoned()
        before = self.charges()
        code, out, err = self.run_("stop")
        self.assertEqual(code, 1)
        self.assertIn(f"unproven local work: {attempt} staging", err)
        code, out, err = self.run_("stop", ["--assert-local-ended", attempt])
        self.assertEqual((code, out), (0, f"stop: {self.world.run_id} asserted {attempt}\n"), err)
        self.assertIn(f"input staging {attempt} ended", err)
        self.assertEqual(os.listdir(directory), [])
        self.assertEqual(before - self.charges(), inputs_mod.DEFAULT_SETTINGS["archive_bytes"])
        status = self.status()
        self.assertEqual((status["inputs"], status["asserted"]), ("none", attempt))
        code, _, err = self.run_("stop", ["--assert-local-ended", attempt])
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: assertion_id_unknown\n"))

    def test_inaccessible_inputs_are_not_absent(self):
        attempt, directory = self.stage_abandoned()
        before = self.charges()
        os.chmod(directory, 0)
        self.addCleanup(os.chmod, directory, 0o700)
        code, _, err = self.run_("stop", ["--assert-local-ended", attempt])
        self.assertEqual(code, 1)
        self.assertTrue(err.endswith("agentbox: jail stop refused: spool_unremoved\n"), err)
        os.chmod(directory, 0o700)
        record = self.world.record()
        self.assertEqual((record["inputs"]["state"], record["inputs"]["local_end"], record["asserted"]),
                         ("staging", "asserted", [attempt]))
        self.assertEqual(self.charges(), before)
        self.assertEqual(os.listdir(directory), [f"spool-{attempt}"])
        code, _, err = self.run_("stop", ["--assert-local-ended", attempt])
        self.assertEqual(code, 0, err)
        self.assertEqual(os.listdir(directory), [])

    def test_publication_stopped_after_the_rename(self):
        """The archive renamed, its record never saved (here refused): the
        attempt's own archive is what an assertion removes; nothing else."""
        project = f"{self.world.tmp}/project"
        os.makedirs(project)
        write_file(f"{project}/a.txt", "a\n", 0o644)
        code, _, err = self.run_("inputs", ["--workspace", project], overrides={"store.DELIVERIES": ["x"]})
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: run_invalid\n"))
        record = self.world.record()
        attempt = record["inputs"]["attempt"]
        directory = f"{self.world.data}/controller-runs/{self.world.run_id}/inputs"
        self.assertEqual((record["inputs"]["state"], os.listdir(directory)), ("staging", [f"archive-{attempt}"]))
        write_file(f"{directory}/archive-s-{'ef' * 16}", "unrelated")
        before = self.charges()
        os.chmod(directory, 0o500)
        self.addCleanup(os.chmod, directory, 0o700)
        code, _, err = self.run_("stop", ["--assert-local-ended", attempt])
        self.assertTrue(err.endswith("agentbox: jail stop refused: spool_unremoved\n"), err)
        self.assertEqual(self.charges(), before)
        os.chmod(directory, 0o700)
        code, _, err = self.run_("stop", ["--assert-local-ended", attempt])
        self.assertEqual(code, 0, err)
        self.assertEqual(os.listdir(directory), [f"archive-s-{'ef' * 16}"])
        self.assertEqual(before - self.charges(), inputs_mod.DEFAULT_SETTINGS["archive_bytes"])

    def test_discard_keeps_inputs_charged_until_removed(self):
        discard_keeps_inputs(self)

    def test_managed_execution_needs_the_domain(self):
        opened = store_mod.Store(self.world.data)
        lease = opened.claim(self.world.run_id)
        execution = store_mod.new_id("e")
        lease.write_execution(execution, {"state": "begun", "spool": 2 << 30}, first=True)
        lease.release()
        opened.close()
        os.makedirs(f"{self.world.spool}/{self.world.run_id}-{execution}/stage", 0o700)
        code, _, err = self.run_("stop", ["--assert-local-ended", execution])
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: assertion_not_applicable\n"))
        # Nothing pending: every domain was read empty, `jail stop` alone.
        code, out, err = self.run_("stop")
        self.assertEqual((code, out), (0, f"stop: {self.world.run_id} recovered\n"), err)
        self.assertEqual(os.listdir(self.world.spool), [])


class AttachedAssertions(C1):
    kind = "attached"

    def test_assertion_never_grants_remote_inputs(self):
        note = f"{self.world.tmp}/n.txt"
        write_file(note, "n\n", 0o644)
        code, _, err = self.world.run("inputs", ["--copy", f"{note}=n"])
        self.assertEqual(code, 0, err)
        record = self.world.record()
        self.world.edit_record(inputs=dict(record["inputs"], delivery="attempted"))
        opened = store_mod.Store(self.world.data)
        lease = opened.claim(self.world.run_id)
        execution = store_mod.new_id("e")
        lease.write_execution(execution, {"state": "begun", "spool": 2 << 30}, first=True)
        lease.release()
        opened.close()
        os.makedirs(f"{self.world.spool}/{self.world.run_id}-{execution}", 0o700)
        code, out, err = self.run_("stop", ["--assert-local-ended", execution])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.record()["inputs"]["delivery"], "attempted")
        code, _, err = self.exec(request("true"))
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: inputs_setup_uncertain\n"))
        code, out, err = self.run_("discard")
        self.assertEqual((code, out), (0, f"discard: {self.world.run_id} discarded\n"), err)

    def test_discard_is_terminal_and_waits_for_unproven_work(self):
        opened = store_mod.Store(self.world.data)
        lease = opened.claim(self.world.run_id)
        execution = store_mod.new_id("e")
        # Finished, its spool not confirmed removed: still reserved.
        lease.write_execution(execution, {"state": "finished", "outcome": "failed", "spool": 2 << 30}, first=True)
        lease.release()
        opened.close()
        spool = f"{self.world.spool}/{self.world.run_id}-{execution}"
        os.makedirs(spool, 0o700)
        session = f"{self.world.data}/controller-runs/{self.world.run_id}/session/{execution}"
        os.makedirs(session, 0o700)
        code, _, err = self.run_("discard")
        self.assertEqual((code, err), (1, "agentbox: jail discard refused: local_work_unproven\n"))
        self.assertTrue(os.path.isdir(session))
        self.assertEqual(self.world.record()["phase"], "ready")
        code, _, err = self.run_("stop", ["--assert-local-ended", execution])
        self.assertEqual(code, 0, err)
        code, out, err = self.run_("discard")
        self.assertEqual((code, out), (0, f"discard: {self.world.run_id} discarded\n"), err)
        self.assertEqual(self.world.record()["phase"], "discarded")
        self.assertFalse(os.path.lexists(session))
        code, out, _ = self.run_("discard")
        self.assertEqual(out, f"discard: {self.world.run_id} already_discarded\n")
        code, _, err = self.exec(request("true"))
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: run_discarded\n"))
        self.assertEqual(self.status()["phase"], "discarded")
        # Local only: nothing reached the operator's jail.
        self.assertEqual(self.world.ssh_entries(), [])

    def test_discard_keeps_inputs_charged_until_removed(self):
        discard_keeps_inputs(self)

    def test_no_delegation_needed(self):
        project = f"{self.world.tmp}/project"
        os.makedirs(project)
        write_file(f"{project}/a.txt", "a\n", 0o644)
        faults = {"fail_start": True}
        code, _, err = self.world.run("inputs", ["--workspace", project], faults=faults)
        self.assertEqual(code, 0, err)
        code, out, err = self.exec(request("cat a.txt"), faults=faults)
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("a\n"))


class InputSettings(C1):
    def test_overrides_and_host_config(self):
        project = f"{self.world.tmp}/project"
        os.makedirs(project)
        write_file(f"{project}/big", "x" * 4096, 0o644)
        code, _, err = self.world.run("inputs", ["--workspace", project, "--max-archive-bytes", "1"])
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: input_settings_invalid\n"))
        code, _, err = self.world.run("inputs", ["--workspace", project, "--host-config", f"{self.world.tmp}/none"])
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: host_config_unreadable\n"))
        code, _, err = self.world.run("inputs", ["--workspace", project, "--max-entries", "1"])
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: input_entry_limit\n"))
        self.assertEqual(self.status()["inputs"], "none")
        code, _, err = self.world.run("inputs", ["--workspace", project, "--max-entries", "2"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.record()["inputs"]["settings"]["entries"], 2)


def discard_keeps_inputs(case):
    """A discard whose input removal fails: the terminal phase stands, the
    inputs stay recorded and charged; a retry that removes them releases
    the charge then only."""
    note = f"{case.world.tmp}/n.txt"
    write_file(note, "n\n", 0o644)
    code, _, err = case.world.run("inputs", ["--copy", f"{note}=n"])
    case.assertEqual(code, 0, err)
    directory = f"{case.world.data}/controller-runs/{case.world.run_id}/inputs"
    archive = case.world.record()["inputs"]["archive_bytes"]
    before = case.charges()
    os.chmod(directory, 0o500)
    case.addCleanup(os.chmod, directory, 0o700)
    code, _, err = case.run_("discard")
    case.assertEqual((code, err), (1, "agentbox: jail discard refused: inputs_unremoved\n"))
    record = case.world.record()
    case.assertEqual((record["phase"], record["inputs"]["state"]), ("discarded", "staged"))
    case.assertEqual(case.charges(), before)
    os.chmod(directory, 0o700)
    code, out, err = case.run_("discard")
    case.assertEqual((code, out), (0, f"discard: {case.world.run_id} already_discarded\n"), err)
    case.assertEqual((case.world.record()["inputs"], os.listdir(directory)), (None, []))
    case.assertEqual(before - case.charges(), archive)


class Units(unittest.TestCase):
    def test_only_enoent_is_absence(self):
        tmp = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        self.addCleanup(shutil.rmtree, tmp, True)
        locked = f"{tmp}/locked"
        os.mkdir(locked, 0o700)
        os.mkdir(f"{locked}/inner")
        write_file(f"{tmp}/file", "x")
        os.symlink(f"{tmp}/missing", f"{tmp}/broken")
        os.chmod(locked, 0)
        self.addCleanup(os.chmod, locked, 0o700)
        self.assertTrue(store_mod.absent(f"{tmp}/missing"))
        for path in (f"{locked}/inner", f"{tmp}/file/below", f"{tmp}/broken", f"{tmp}/file"):
            self.assertFalse(store_mod.absent(path), path)

    def test_mount_selection_is_lexical(self):
        from agentbox_controller import mounts
        from agentbox_controller.host import HostError
        selected, project, host = mounts.select([("/home/u/src", None, "rw"), ("/srv/ref", "ref", "ro")],
                                                "/home/u/src/app", None, "/home/u")
        self.assertEqual((selected[0]["destination"], project, host), ("src", "src/app", "/home/u/src/app"))
        for args, project_dir, code in (([("/home/u/.ssh", None, "ro")], None, "mount_destination_unmapped"),
                                        ([("/home/u", None, "ro")], None, "mount_destination_unmapped"),
                                        ([("rel", "x", "ro")], None, "mount_source_invalid")):
            with self.assertRaises(HostError) as caught:
                mounts.select(args, project_dir, None, "/home/u")
            self.assertEqual(caught.exception.code, code)

    def test_unclean_acknowledgement(self):
        from agentbox_controller.host import HostError
        from agentbox_controller.lifecycle import accept_unclean
        self.assertFalse(accept_unclean({"storage": "clean", "generation": 3}, None))
        self.assertTrue(accept_unclean({"storage": "unclean", "generation": 3}, "3"))
        for allow, code in ((None, "storage_unclean"), ("2", "generation_mismatch"), ("03", "allow_unclean_invalid")):
            with self.assertRaises(HostError) as caught:
                accept_unclean({"storage": "unclean", "generation": 3}, allow)
            self.assertEqual(caught.exception.code, code)


class StageRoot(C1):
    def test_explicit_stage_root(self):
        root = f"{self.world.tmp}/stage-root"
        os.mkdir(root, 0o700)
        args = ["--acquisition-config", self.world.acquisition(), "--acquisition-stage-root", root]
        code, _, err = self.lane_args(args)
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: storage_scope_undeclared\n"))
        limits = f"{self.world.data}/run-limits.json"
        with open(limits) as stream:
            value = json.load(stream)
        value["storage_scopes"].append({"path": root, "measure": "tree"})
        write_file(limits, value)
        code, out, err = self.lane_args(args)
        self.assertEqual(code, 0, err)
        self.assertIn('"ok":true', out)
        self.assertEqual(os.listdir(root), [])
        os.chmod(root, 0o755)
        code, _, err = self.lane_args(args)
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: acquisition_stage_root_invalid\n"))

    def lane_args(self, args):
        return self.exec(request("agentbox-request echo say '{\"text\":\"r\"}'"), args)

    def declared_root(self):
        root = f"{self.world.tmp}/stage-root"
        os.mkdir(root, 0o700)
        limits = f"{self.world.data}/run-limits.json"
        with open(limits) as stream:
            value = json.load(stream)
        value["storage_scopes"].append({"path": root, "measure": "tree"})
        write_file(limits, value)
        return root

    def pinned(self):
        """An execution whose stage under the custom root cannot be
        removed: finished, its reservation kept with that exact root."""
        root = self.declared_root()
        code, out, err = self.exec(request("agentbox-request fake fetch '{\"mode\":\"pinned\"}'; true"),
                                   ["--acquisition-config", self.world.acquisition(), "--acquisition-stage-root", root])
        self.assertEqual(fields(final(err))["acquisition_cleanup"], "unconfirmed")
        execution = self.executions()[-1]
        self.assertEqual((execution["state"], execution["spool"], execution["spool_root"]), ("finished", 2 << 30, root))
        spool = f"{root}/{self.world.run_id}-{execution['execution_id']}"
        stage = f"{spool}/{os.listdir(spool)[0]}"
        self.addCleanup(lambda: os.path.isdir(stage) and os.chmod(stage, 0o700))
        # The store's default spool never held it: no false proof there.
        self.assertFalse(os.path.lexists(f"{self.world.spool}/{self.world.run_id}-{execution['execution_id']}"))
        return execution["execution_id"], spool, stage

    def test_failed_cleanup_keeps_the_custom_root_managed(self):
        _, spool, stage = self.pinned()
        before = self.charges()
        code, _, err = self.run_("stop")
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: spool_unremoved\n"))
        self.assertEqual(self.charges(), before)
        self.assertEqual(self.executions()[-1]["spool_root"], f"{self.world.tmp}/stage-root")
        os.chmod(stage, 0o700)
        code, out, err = self.run_("stop")
        self.assertEqual((code, out), (0, f"stop: {self.world.run_id} recovered\n"), err)
        self.assertFalse(os.path.lexists(spool))
        self.assertEqual(before - self.charges(), 2 << 30)


    def settle(self, execution):
        if self.kind == "attached":
            return self.run_("stop", ["--assert-local-ended", execution])
        return self.run_("stop")

    def test_inaccessible_root_is_not_absent(self):
        """The custom root unreadable (EACCES): its spool's absence is
        unproven, the reservation stays; access back, cleanup works."""
        execution, spool, stage = self.pinned()
        os.chmod(stage, 0o700)
        root = f"{self.world.tmp}/stage-root"
        os.chmod(root, 0)
        self.addCleanup(os.chmod, root, 0o700)
        before = self.charges()
        code, _, err = self.settle(execution)
        self.assertEqual(code, 1)
        self.assertTrue(err.endswith("agentbox: jail stop refused: spool_unremoved\n"), err)
        self.assertEqual(self.charges(), before)
        os.chmod(root, 0o700)
        self.assertTrue(os.path.isdir(spool))
        code, _, err = self.settle(execution)
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.lexists(spool))
        self.assertEqual(before - self.charges(), 2 << 30)


class AttachedStageRoot(StageRoot):
    kind = "attached"

    def test_failed_cleanup_keeps_the_custom_root_managed(self):
        execution, spool, stage = self.pinned()
        before = self.charges()
        code, _, err = self.run_("stop", ["--assert-local-ended", execution])
        self.assertEqual(code, 1)
        self.assertTrue(err.endswith("agentbox: jail stop refused: spool_unremoved\n"), err)
        self.assertEqual(self.charges(), before)
        record = self.executions()[-1]
        self.assertEqual((record["local_end"], record["spool"], record["spool_root"]),
                         ("asserted", 2 << 30, f"{self.world.tmp}/stage-root"))
        os.chmod(stage, 0o700)
        code, _, err = self.run_("stop", ["--assert-local-ended", execution])
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.lexists(spool))
        self.assertEqual(before - self.charges(), 2 << 30)


if __name__ == "__main__":
    unittest.main()
