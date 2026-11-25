"""B2 end to end, offline: attached records, copied inputs and the
mediated acquisition lane through the production controller CLI, the real
agentbox-server (POST ingress and delivery), the real guest helper and its
request client, the real input stage worker, authored test handlers (echo,
memo, fake), stand-in ssh/scp/sftp and FakeCgroups.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t .
"""
import json
import os
import signal
import subprocess
import time
import unittest

from agentbox_controller import inputs as inputs_mod, store as store_mod
from tests.controller.harness import HERE, REPO, World, copy_tree, write_file
from tests.controller.test_execution import QUICK, fields, final, until

POSTER = f"/usr/bin/python3 {HERE}/jail_poster.py"


def request(text):
    return ["/bin/sh", "-c", text]


class B2(unittest.TestCase):
    kind = "attached"
    retention = "none"
    log_bytes = 64 << 20
    transport = "tcp"

    def setUp(self):
        self.world = World(kind=self.kind, retention=self.retention, log_bytes=self.log_bytes,
                           transport=self.transport, behavior={"engine": True})
        self.addCleanup(self.world.close)

    def exec(self, argv, extra=(), **kwargs):
        kwargs.setdefault("overrides", QUICK)
        return self.world.exec(argv, extra, **kwargs)

    def lane(self, argv, handlers=None, **kwargs):
        return self.exec(argv, ["--acquisition-config", self.world.acquisition(handlers)], **kwargs)

    def events(self, prefix):
        return [e for e in self.world.events() if e["event_type"].startswith(prefix)]

    def requests(self):
        return [e["attributes"] for e in self.events("host.handler.request")]

    def closed(self):
        return [e["attributes"] for e in self.events("host.handler.lane_closed")][-1]

    def status(self):
        code, out, err = self.world.run("status")
        self.assertEqual(code, 0, err)
        return dict(word.split("=", 1) for word in out.split()[2:])

    def assertClean(self):
        self.assertEqual(self.world.domains(), [])
        self.assertEqual([p for p in self.world.listed_pids() if self.world.ours(p)], [])
        self.assertEqual(os.listdir(self.world.spool), [])

    def charges(self):
        opened = store_mod.Store(self.world.data)
        try:
            return opened.charges()
        finally:
            opened.close()

    def executions(self):
        directory = f"{self.world.data}/controller-runs/{self.world.run_id}/executions"
        out = []
        for name in sorted(os.listdir(directory)):
            with open(f"{directory}/{name}") as stream:
                out.append(json.load(stream))
        return out

    def poster(self, scenario, **kwargs):
        code, out, err = self.lane(request(f"{POSTER} {scenario}"), **kwargs)
        replies = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
        return code, replies, err


class Attached(B2):
    def test_attach_is_local_and_exec_claims_no_jail(self):
        self.assertEqual(self.world.ssh_entries(), [])
        self.assertEqual(self.status(), {"state": "idle", "kind": "attached", "phase": "ready", "inputs": "none",
                                         "jail": "unobserved"})
        code, out, err = self.exec(request("echo hi"))
        self.assertEqual(code, 0, err)
        self.assertEqual(final(out), "execution: outcome=completed reason=completed exit=0 host_cleanup=confirmed "
                                     "provider=attached output=complete")
        entries = self.world.ssh_entries()
        self.assertEqual([e["mode"] for e in entries], ["bootstrap", "bootstrap", "session"])
        alias = f"agentbox-{self.world.run_id}-"
        self.assertTrue(all(e["pinned"].startswith(alias) and e["pinned"].endswith(self.world.host_key + "\n")
                            for e in entries))
        self.assertTrue(all(e["options"]["IdentityFile"] == self.world.identity for e in entries))
        sftp = [t for t in self.world.transfers() if t["program"] == "sftp"]
        self.assertEqual(len(sftp), 1)
        self.assertTrue(sftp[0]["profile_ok"])
        self.assertEqual(self.world.provider_log(), [])
        # Nothing local left to settle; the operator's jail untouched.
        code, out, err = self.world.run("stop")
        self.assertEqual((code, out, err), (0, f"stop: {self.world.run_id} idle\n", ""))
        self.assertEqual(len(self.world.ssh_entries()), 3)
        self.assertClean()

    def test_bundle_changed_after_attach_is_refused(self):
        target = f"{self.world.bundle}/guest/src/protocol.py"
        os.chmod(target, 0o644)
        with open(target, "a") as stream:
            stream.write("#")
        code, _, err = self.exec(request("true"))
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: ssh_target_bundle_invalid\n"))
        self.assertEqual(self.world.ssh_entries(), [])

    def test_attach_refusals(self):
        bad = dict(self.world.target, revision="0" * 40)
        path = f"{self.world.tmp}/bad.json"
        write_file(path, bad)
        code, _, err = self.world.run("attach", ["--ssh-target", path], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: jail create refused: ssh_target_revision_invalid\n"))
        for change, reason in (({"host": "Bad_Host"}, "ssh_target_host_invalid"),
                               ({"port": 0}, "ssh_target_port_invalid"),
                               ({"host_key": "ssh-rsa AAAA"}, "ssh_target_host_key_invalid"),
                               ({"remote_root": "/"}, "ssh_target_remote_root_invalid"),
                               ({"extra": 1}, "ssh_target_invalid")):
            write_file(path, dict(self.world.target, **change))
            code, _, err = self.world.run("attach", ["--ssh-target", path], command_args=False)
            self.assertEqual((code, err), (1, f"agentbox: jail create refused: {reason}\n"))
        os.chmod(path, 0o666)
        code, _, err = self.world.run("attach", ["--ssh-target", path], command_args=False)
        self.assertEqual((code, err), (1, "agentbox: jail create refused: ssh_target_unreadable\n"))

    def test_bootstrap_upload_failure(self):
        self.world.set_ssh(fail="sftp")
        code, _, err = self.exec(request("true"))
        line = fields(final(err))
        self.assertEqual((code, line["reason"], line["provider"], line["host_cleanup"]),
                         (1, "bootstrap_failed", "attached", "confirmed"))
        self.assertClean()


class Inputs(B2):
    kind = "managed"

    def sources(self):
        project = f"{self.world.tmp}/project"
        os.makedirs(f"{project}/sub")
        write_file(f"{project}/sub/a.txt", "alpha\n", 0o644)
        note = f"{self.world.tmp}/note.txt"
        write_file(note, "note\n", 0o644)
        return project, note

    def stage(self, *args):
        return self.world.run("inputs", list(args))

    def uploads(self):
        return [t for t in self.world.transfers() if t["program"] == "scp"
                and ".agentbox-inputs-" in t["operands"][-1]]

    def test_fresh_storage_gets_them_every_execution(self):
        project, note = self.sources()
        code, out, err = self.stage("--workspace", project, "--copy", f"{note}=notes/n.txt")
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"staged archive_bytes=\d+ entries=4")
        self.assertEqual(self.status()["inputs"], "staged")
        for _ in range(2):
            code, out, err = self.exec(request("cat sub/a.txt ../notes/n.txt"))
            self.assertEqual(code, 0, err)
            self.assertTrue(out.startswith("alpha\nnote\n"))
            # Fresh storage: the next execution sees an empty home again.
            for name in os.listdir(self.world.home):
                subprocess.run(["rm", "-rf", f"{self.world.home}/{name}"], check=True)
        self.assertEqual(len(self.uploads()), 2)
        self.assertTrue(all(u["profile_ok"] for u in self.uploads()))
        self.assertNotIn("delivery", self.status())

    def test_selection_rules(self):
        project, note = self.sources()
        for args, reason in ((["--workspace", project, "--copy", f"{note}=work/x"], "input_destination_conflict"),
                             (["--copy", f"{note}=.agentbox-inputs-x"], "input_destination_invalid"),
                             (["--copy", f"{note}=a/../b"], "input_destination_invalid"),
                             (["--copy", note], "inputs_selection_invalid"),
                             (["--copy", f"{self.world.tmp}/missing=m"], "input_source_unavailable")):
            code, _, err = self.stage(*args)
            self.assertEqual((code, err), (1, f"agentbox: jail inputs refused: {reason}\n"), args)
            self.assertEqual(self.status()["inputs"], "none")
        self.assertEqual(os.listdir(f"{self.world.data}/controller-runs/{self.world.run_id}/inputs"), [])
        code, _, err = self.stage("--copy", f"{note}=n")
        self.assertEqual(code, 0, err)
        code, _, err = self.stage("--copy", f"{note}=m")
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: inputs_already_configured\n"))

    def test_abandoned_staging_keeps_its_spool(self):
        """A controller gone mid-staging, its worker's end unknown (here a
        process still holding the spool open): no second worker, nothing
        unlinked, the reservation kept; exec refused too."""
        _, note = self.sources()
        opened = store_mod.Store(self.world.data)
        lease = opened.claim(self.world.run_id)
        attempt = "s-" + "ab" * 16
        lease.save(dict(lease.record, inputs={"state": "staging", "attempt": attempt, "copies": 1,
                                              "settings": dict(inputs_mod.DEFAULT_SETTINGS)}))
        directory = f"{self.world.data}/controller-runs/{self.world.run_id}/inputs"
        os.mkdir(directory, 0o700)
        spool = f"{directory}/spool-{attempt}"
        with open(spool, "wb") as stream:
            holder = subprocess.Popen(["sleep", "1000"], stdout=stream)
        self.addCleanup(holder.wait)
        self.addCleanup(holder.kill)
        lease.release()
        opened.close()
        before, inode, record = self.charges(), os.stat(spool).st_ino, self.world.record()
        code, _, err = self.stage("--copy", f"{note}=n")
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: inputs_staging_unsettled\n"))
        code, _, err = self.exec(request("true"))
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: inputs_staging_unsettled\n"))
        self.assertEqual(os.listdir(directory), [f"spool-{attempt}"])
        self.assertEqual(os.stat(spool).st_ino, inode)
        self.assertEqual((self.charges(), self.world.record()), (before, record))
        self.assertGreaterEqual(before, inputs_mod.DEFAULT_SETTINGS["archive_bytes"])
        self.assertEqual(self.status()["inputs"], "staging")

    def test_after_an_execution_refused(self):
        _, note = self.sources()
        code, _, err = self.exec(request("true"))
        self.assertEqual(code, 0, err)
        code, _, err = self.stage("--copy", f"{note}=n")
        self.assertEqual((code, err), (1, "agentbox: jail inputs refused: inputs_run_has_history\n"))


class RetainedInputs(Inputs):
    retention = "disk"

    def test_fresh_storage_gets_them_every_execution(self):
        """Retained: delivered once, recorded attempted then ready."""
        project, note = self.sources()
        code, _, err = self.stage("--workspace", project, "--copy", f"{note}=notes/n.txt")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.status()["delivery"], "none")
        code, out, err = self.exec(request("cat sub/a.txt"))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.status()["delivery"], "ready")
        code, out, err = self.exec(request("cat sub/a.txt"))
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.uploads()), 1)

    def test_failed_upload_blocks_until_settled(self):
        _, note = self.sources()
        code, _, err = self.stage("--copy", f"{note}=n")
        self.assertEqual(code, 0, err)
        self.world.set_ssh(fail="scp")
        code, _, err = self.exec(request("true"))
        self.assertEqual(fields(final(err))["reason"], "inputs_upload_failed")
        self.assertEqual(self.status()["delivery"], "attempted")
        self.world.set_ssh(fail=None)
        code, _, err = self.exec(request("true"))
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: inputs_setup_uncertain\n"))


class AttachedInputs(Inputs):
    kind = "attached"

    def test_fresh_storage_gets_them_every_execution(self):
        project, _ = self.sources()
        code, _, err = self.stage("--workspace", project)
        self.assertEqual(code, 0, err)
        for _ in range(2):
            code, out, err = self.exec(request("cat sub/a.txt"))
            self.assertEqual(code, 0, err)
            self.assertTrue(out.startswith("alpha\n"))
        self.assertEqual(len(self.uploads()), 1)
        self.assertEqual(self.status()["delivery"], "ready")


class Lane(B2):
    def test_two_acquisitions_in_one_command(self):
        code, out, err = self.lane(request(
            "agentbox-request echo say '{\"text\":\"one\"}' && agentbox-request echo say '{\"text\":\"two\"}'"))
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count('"ok":true'), 2)
        records = self.requests()
        self.assertEqual([(r["request"], r["end"], r.get("guest_claim"), r["uploaded"]) for r in records],
                         [("req-1", "recorded", "applied", True), ("req-2", "recorded", "applied", True)])
        summary = self.closed()
        self.assertEqual((summary["requests"], summary["uploads"], summary["cleanup_confirmed"]), (2, 2, True))
        executions = f"{self.world.data}/controller-runs/{self.world.run_id}/executions"
        with open(f"{executions}/{os.listdir(executions)[0]}") as stream:
            self.assertEqual(json.load(stream)["state"], "finished")
        self.assertClean()

    def test_metering_settles_and_keeps_unreported(self):
        code, out, err = self.lane(request(
            "agentbox-request fake fetch '{\"size\":3,\"acquired\":1000}';"
            "agentbox-request fake fetch '{\"mode\":\"error\",\"acquired\":500}';"
            "agentbox-request fake fetch '{\"mode\":\"crash\"}';"
            "agentbox-request fake fetch '{\"size\":3}'; true"))
        self.assertEqual(code, 0, err)
        records = self.requests()
        self.assertEqual([(r["end"], r.get("reason"), r["acquired"]) for r in records],
                         [("recorded", None, 1000), ("denied", "fake_denied", 500),
                          ("denied", "worker_failed", 0), ("denied", "byte_limit", 0)])
        # The crashed worker reported nothing: its whole reservation stays.
        self.assertEqual(self.closed()["acquired"], 2 << 30)

    def test_overclaim_and_artifact_checks(self):
        code, out, err = self.lane(request(
            "for m in perms linked wrongsize; do agentbox-request fake fetch \"{\\\"mode\\\":\\\"$m\\\"}\"; done;"
            "agentbox-request fake fetch '{\"mode\":\"metadata\",\"size\":600}';"
            "agentbox-request fake fetch '{\"mode\":\"overclaim\"}';"
            "agentbox-request fake fetch '{\"size\":1}'; true"))
        self.assertEqual(code, 0, err)
        # An invalid line keeps the whole reservation: nothing is left.
        self.assertEqual([r.get("reason") for r in self.requests()],
                         ["artifact_invalid", "artifact_invalid", "artifact_invalid", "metadata_too_large",
                          "worker_failed", "byte_limit"])
        self.assertClean()

    def test_worker_inherits_no_descriptor(self):
        code, out, err = self.lane(request("agentbox-request fake fetch '{\"mode\":\"fds\"}'"))
        self.assertEqual(code, 0, err)
        self.assertIn('"metadata":{"fds":0}', out.replace(" ", ""))

    def test_grant_replay_and_answers(self):
        code, replies, err = self.poster("limit 257 nope")
        self.assertEqual(code, 0, err)
        self.assertEqual(replies, [{"closed:handler_unknown": 256, "rejected:submission_limit": 1}])
        self.assertEqual(self.closed()["requests"], 256)
        code, replies, _ = self.poster("replay")
        self.assertEqual([r["type"] for r in replies], ["ready", "rejected"])
        self.assertEqual(replies[1]["code"], "busy")
        code, replies, _ = self.poster("binding")
        self.assertEqual([r.get("code") for r in replies], [None, "binding_mismatch"])
        code, replies, _ = self.poster("early_result")
        self.assertEqual(replies, [{"status": "409", "v": 1, "type": "error", "code": "not_active"}])

    def test_cancel_and_peer_loss_end_the_worker(self):
        began = time.monotonic()
        code, replies, err = self.poster("busy")
        self.assertLess(time.monotonic() - began, 20)
        self.assertEqual([(r["type"], r.get("code") or r.get("outcome")) for r in replies],
                         [("rejected", "busy"), ("closed", "cancelled"), ("closed", "cancelled")])
        code, replies, err = self.poster("peer_eof")
        self.assertEqual(replies, [{"status": "none"}])
        self.assertEqual([r["end"] for r in self.requests()][-1], "cancelled")
        self.assertClean()

    def test_request_deadline(self):
        code, replies, err = self.poster("sleep", overrides=dict(QUICK, **{"acquisition.REQUEST_TIMEOUT": 2.0}))
        self.assertEqual((replies[0]["type"], replies[0]["outcome"]), ("closed", "expired"))
        self.assertClean()

    def test_signal_during_acquisition(self):
        process = self.world.start("exec", ["--acquisition-config", self.world.acquisition(), "--",
                                            "/bin/sh", "-c", f"{POSTER} sleep"], overrides=QUICK)
        until(lambda: self.events("host.handler.started"))
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=60)
        line = fields(final(err.decode()))
        self.assertEqual((line["reason"], line["host_cleanup"]), ("cancelled", "confirmed"))
        self.assertEqual([r["end"] for r in self.requests()], ["cancelled"])
        self.assertTrue(self.closed()["cleanup_confirmed"])
        self.assertClean()

    def test_no_ready_after_revoke(self):
        self.world.set_ssh(scp_sleep=3)
        process = self.world.start("exec", ["--acquisition-config", self.world.acquisition(), "--",
                                            "/bin/sh", "-c", "agentbox-request echo say '{\"text\":\"x\"}'"],
                                   overrides=QUICK)
        until(lambda: any(t["program"] == "scp" for t in self.world.transfers()))
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=60)
        self.assertNotIn(b'"ok":true', out)
        self.assertEqual([(r["end"], r["uploaded"]) for r in self.requests()], [("cancelled", False)])
        self.assertClean()

    def test_configuration_refused_before_effects(self):
        path = self.world.acquisition()
        os.chmod(f"{self.world.tmp}/policy-echo.json", 0o666)
        code, _, err = self.exec(request("true"), ["--acquisition-config", path])
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: handler_policy_unreadable\n"))
        os.chmod(f"{self.world.tmp}/policy-echo.json", 0o600)
        lib = f"{self.world.handlers}/acquisitions/lib/agentbox_handler.py"
        os.chmod(lib, 0o666)
        code, _, err = self.exec(request("true"), ["--acquisition-config", path])
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: acquisition_worker_untrusted\n"))
        os.chmod(lib, 0o644)
        code, _, err = self.lane(request("true"), handlers={"echo": ["nope"]})
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: handler_operation_unknown\n"))
        self.assertEqual(self.world.ssh_entries(), [])
        self.assertFalse(os.path.isdir(f"{self.world.data}/controller-logs/{self.world.run_id}"))

    def test_storage_admission_says_its_bound(self):
        """The spool reservation is a lower bound, said at run time: an
        unmetered handler (Git) makes it unbounded."""
        expected = []
        for handlers, bound, unmetered in (({"fake": None, "git": None}, "unbounded", "git"),
                                           ({"fake": None}, "lower_bound", "")):
            code, out, err = self.lane(request("true"), handlers=handlers)
            self.assertEqual(code, 0, err)
            self.assertEqual(fields(final(out))["storage"], bound)
            expected.append(("WARN", {"code": f"acquisition_storage_{bound}", "spool_reserved": 2 << 30,
                                      "unmetered": unmetered}))
        warnings = [(w["severity_text"], w["attributes"]) for w in self.events("host.storage.warning")]
        self.assertEqual(sorted(warnings, key=str), sorted(expected, key=str))
        self.assertEqual(["spool" in e for e in self.executions()], [False, False])

    def packaged(self, git=True):
        """No acquisition.json; a packaged tree of the shipped git, npm and
        pip, their own policies (launch.py's seam); PATH with a stand-in
        host git, or without git. Nothing here reaches a registry."""
        root = f"{self.world.tmp}/packaged"
        copy_tree(f"{REPO}/acquisitions/lib", f"{root}/acquisitions/lib")
        for ident in ("git", "npm", "pip"):
            copy_tree(f"{REPO}/acquisitions/{ident}", f"{root}/acquisitions/{ident}")
        os.chmod(root, 0o755)
        os.chmod(f"{root}/acquisitions", 0o755)
        if os.path.lexists(self.world.acquisition_default):
            os.unlink(self.world.acquisition_default)
        tools = f"{self.world.tmp}/host-tools"
        if not os.path.isdir(tools):
            os.mkdir(tools, 0o700)
            write_file(f"{tools}/git", "#!/bin/sh\nexit 1\n", 0o755)
        # The stand-in ssh/scp/sftp only (no git) when git is absent.
        path = f"{tools}:{self.world.bin}:/usr/bin:/bin" if git else self.world.bin
        return dict(QUICK, **{"handlers.PACKAGED_ASSETS": root}), {"PATH": path}

    def test_default_lane_without_configuration(self):
        """No --acquisition-config and no acquisition.json: the packaged
        git, npm and pip lane, its shims and session wrapper."""
        overrides, env = self.packaged()
        code, out, err = self.exec(request('for n in git npm npx; do command -v $n; done; echo "$PIP_INDEX_URL"'),
                                   overrides=overrides, env=env)
        self.assertEqual(code, 0, err)
        lines = out.splitlines()
        for line, name in zip(lines, ("git", "npm", "npx")):
            self.assertRegex(line, rf"/releases/[0-9a-f-]+/bin/{name}$")
        self.assertRegex(lines[3], r"^http://127\.0\.0\.1:[0-9]+/simple/$")
        # Git is unmetered: the spool's bound is said unbounded.
        self.assertEqual(fields(final(out))["storage"], "unbounded")
        self.assertEqual([w["attributes"]["unmetered"] for w in self.events("host.storage.warning")], ["git"])
        self.assertTrue(self.closed()["cleanup_confirmed"])
        # `"handlers": {}`: no lane, no shims, no wrapper.
        write_file(self.world.acquisition_default, {"schema": "agentbox.acquisition-config.v2", "handlers": {}})
        code, out, err = self.exec(request('command -v npm; echo "pip=$PIP_INDEX_URL"; true'),
                                   overrides=overrides, env=env)
        self.assertEqual(code, 0, err)
        self.assertNotIn("/releases/", out)
        self.assertIn("pip=\n", out)
        self.assertNotIn("storage", fields(final(out)))

    def test_git_missing_refuses_the_session_only(self):
        overrides, env = self.packaged(git=False)
        for command in ("exec", ("jail", "serve")):
            extra = ["--", "true"] if command == "exec" else []
            code, _, err = self.world.run(command, extra, overrides=overrides, env=env)
            name = "jail exec" if command == "exec" else "jail serve"
            self.assertEqual(err.splitlines()[0], f"agentbox: {name} refused: acquisition_git_missing")
            self.assertIn("agentbox: hint: Git acquisition is enabled, but git was not found on the host PATH",
                          err)
            self.assertEqual(code, 1)
        self.assertEqual(self.world.ssh_entries(), [])
        self.assertFalse(os.path.isdir(f"{self.world.data}/controller-logs/{self.world.run_id}"))
        # Management needs neither git nor a readable acquisition.json.
        write_file(self.world.acquisition_default, "{", 0o666)
        for command, args in ((("image", "list"), []), (("jail", "list"), []), ("status", None),
                              ("stop", None)):
            code, _, err = self.world.run(command, args or [], overrides=overrides, env=env,
                                          command_args=args is None)
            self.assertEqual(code, 0, err)
        # The hint's example: Git left out (its shim too; the server's own
        # tools need the usual PATH, git there or not).
        env = {"PATH": f"{self.world.bin}:/usr/bin:/bin"}
        write_file(self.world.acquisition_default,
                   {"schema": "agentbox.acquisition-config.v2", "handlers": {"npm": {}, "pip": {}}})
        code, out, err = self.exec(request('case "$(command -v git)" in */releases/*) ;; *) echo no-shim;; esac'),
                                   overrides=overrides, env=env)
        self.assertEqual(code, 0, err)
        self.assertIn("no-shim", out)
        self.assertEqual(fields(final(out))["storage"], "lower_bound")

    def test_operations_denied_and_shims(self):
        code, out, err = self.lane(request(
            "agentbox-request fake denied-op '{}'; command -v memo; agentbox-request memo nope '{}'; true"),
            handlers={"fake": ["fetch"], "memo": None})
        self.assertEqual(code, 0, err)
        self.assertEqual([r.get("reason") for r in self.requests()], ["operation_denied", "operation_unknown"])
        self.assertRegex(out, r"/releases/[0-9a-f-]+/bin/memo\n")

class Crash(B2):
    """A controller SIGKILLed during an acquisition: its worker lives on."""

    def crash(self):
        process = self.world.start("exec", ["--acquisition-config", self.world.acquisition(), "--",
                                            "/bin/sh", "-c", f"{POSTER} sleep"], overrides=QUICK)
        until(lambda: self.events("host.handler.started"))
        process.kill()
        process.communicate(timeout=30)
        self.addCleanup(self.kill_workers)
        spools = os.listdir(self.world.spool)
        self.assertEqual(len(spools), 1)
        return f"{self.world.spool}/{spools[0]}"

    def workers(self):
        """Live processes started for this world's spool (the workers)."""
        found = []
        for name in os.listdir("/proc"):
            try:
                with open(f"/proc/{name}/cmdline", "rb") as stream:
                    if self.world.spool.encode() in stream.read():
                        found.append(int(name))
            except (OSError, ValueError):
                continue
        return found

    def kill_workers(self):
        for pid in self.workers():
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass



class AttachedCrash(Crash):
    def test_orphan_keeps_its_spool_and_blocks(self):
        spool = self.crash()
        self.assertTrue(self.workers())
        stage = os.listdir(spool)
        before = self.charges()
        status = self.status()
        self.assertEqual((status["state"], status["spool_reserved"]), ("interrupted", str(2 << 30)))
        for extra in (["--acquisition-config", self.world.acquisition()], []):
            code, _, err = self.exec(request("true"), extra)
            self.assertEqual((code, err), (1, "agentbox: jail exec refused: run_interrupted\n"))
        # `jail stop` proves nothing here: it lists the exact work.
        execution = self.executions()[0]["execution_id"]
        code, out, err = self.world.run("stop")
        self.assertEqual(code, 1)
        self.assertIn(f"unproven local work: {execution} execution state=begun", err)
        self.assertTrue(self.workers())
        self.assertEqual(os.listdir(spool), stage)
        self.assertEqual(self.charges(), before)
        self.assertEqual([e["state"] for e in self.executions()], ["begun"])

    def assertion(self, ident):
        return self.world.run("stop", ["--assert-local-ended", ident])

    def test_assertion_of_the_exact_execution(self):
        """The operator's word, unverified, for one exact id: only that
        execution's own spool removed, its reservation released once
        removed; recorded as asserted, never as a kill."""
        spool = self.crash()
        execution = self.executions()[0]["execution_id"]
        before = self.charges()
        for ident, reason in (("e-" + "0" * 32, "assertion_id_unknown"), ("s-" + "0" * 32, "assertion_id_unknown"),
                              ("x", "assertion_id_invalid")):
            code, _, err = self.assertion(ident)
            self.assertEqual((code, err), (1, f"agentbox: jail stop refused: {reason}\n"))
        self.assertTrue(os.path.isdir(spool))
        self.kill_workers()
        code, out, err = self.assertion(execution)
        self.assertEqual((code, out), (0, f"stop: {self.world.run_id} asserted {execution}\n"), err)
        self.assertIn(f"warning: asserting, unverified, that local work of {execution} ended (state=begun "
                      f"spool_reserved={2 << 30})", err)
        self.assertFalse(os.path.lexists(spool))
        self.assertEqual(before - self.charges(), 2 << 30)
        self.assertEqual([(e["state"], e["outcome"], e["local_end"], "spool" in e) for e in self.executions()],
                         [("finished", "interrupted", "asserted", False)])
        status = self.status()
        self.assertEqual((status["state"], status["asserted"]), ("idle", execution))
        self.assertNotIn("spool_reserved", status)
        code, _, err = self.assertion(execution)
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: assertion_id_stale\n"))
        code, _, err = self.exec(request("true"))
        self.assertEqual(code, 0, err)

    def test_failed_removal_keeps_the_reservation(self):
        spool = self.crash()
        execution = self.executions()[0]["execution_id"]
        self.kill_workers()
        stage = f"{spool}/{os.listdir(spool)[0]}"
        os.chmod(stage, 0o500)
        self.addCleanup(lambda: os.path.isdir(stage) and os.chmod(stage, 0o700))
        code, _, err = self.assertion(execution)
        self.assertEqual(code, 1)
        self.assertTrue(err.endswith("agentbox: jail stop refused: spool_unremoved\n"), err)
        self.assertEqual([(e["state"], e.get("local_end"), e.get("spool")) for e in self.executions()],
                         [("finished", "asserted", 2 << 30)])
        self.assertEqual(self.status()["spool_reserved"], str(2 << 30))
        os.chmod(stage, 0o700)
        code, _, err = self.assertion(execution)
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.lexists(spool))


class ManagedCrash(Crash):
    kind = "managed"

    def recover(self):
        code, out, err = self.world.run("stop", overrides=QUICK)
        return code, out, err

    def test_recover_releases_the_spool_after_the_domain(self):
        spool = self.crash()
        status = self.status()
        self.assertEqual((status["state"], status["spool_reserved"]), ("abandoned", str(2 << 30)))
        before = self.charges()
        code, out, err = self.recover()
        self.assertEqual((code, out), (0, f"stop: {self.world.run_id} recovered\n"), err)
        self.assertEqual(self.workers(), [])
        self.assertFalse(os.path.lexists(spool))
        self.assertEqual(self.status(), {"state": "idle", "kind": "managed", "phase": "ready", "generation": "0",
                                         "storage": "clean", "retention": "none", "inputs": "none"})
        self.assertEqual(before - self.charges(), 2 << 30)
        self.assertEqual([(e["state"], e.get("outcome"), "spool" in e) for e in self.executions()],
                         [("finished", "interrupted", False)])

    def test_failed_removal_keeps_the_reservation(self):
        spool = self.crash()
        stage = f"{spool}/{os.listdir(spool)[0]}"
        os.chmod(stage, 0o500)
        self.addCleanup(lambda: os.path.isdir(stage) and os.chmod(stage, 0o700))
        code, _, err = self.recover()
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: spool_unremoved\n"))
        self.assertEqual(self.workers(), [])
        status = self.status()
        self.assertEqual((status["state"], status["spool_reserved"]), ("idle", str(2 << 30)))
        self.assertEqual([(e["state"], e.get("spool")) for e in self.executions()], [("finished", 2 << 30)])
        # Settled now (nothing pending): a later execution retries, and
        # keeps the reservation while the removal fails.
        code, _, err = self.exec(request("true"))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.status()["spool_reserved"], str(2 << 30))
        os.chmod(stage, 0o700)
        code, out, err = self.recover()
        self.assertEqual((code, out), (0, f"stop: {self.world.run_id} recovered\n"), err)
        self.assertFalse(os.path.lexists(spool))
        self.assertNotIn("spool_reserved", self.status())


class SmallLog(B2):
    # The smallest log budget (a managed fixture run: `attach` keeps the
    # default).
    kind = "managed"
    log_bytes = 1 << 20

    def test_lane_keeps_its_reserve(self):
        """Ordinary records stop short of the lane's reserve: the request
        and the lane's closing summary still land."""
        code, out, err = self.lane(request(
            "head -c 900000 /dev/zero | tr '\\0' x; echo; agentbox-request echo say '{\"text\":\"late\"}'"))
        self.assertIn('"ok":true', out)
        self.assertEqual([r["end"] for r in self.requests()], ["recorded"])
        self.assertTrue(self.closed()["cleanup_confirmed"])


class ManagedLane(B2):
    kind = "managed"

    def test_echo_through_the_domain(self):
        code, out, err = self.lane(request("agentbox-request echo say '{\"text\":\"m\"}'"))
        self.assertEqual(code, 0, err)
        self.assertIn("provider=settled", final(out))
        self.assertEqual([r["end"] for r in self.requests()], ["recorded"])
        delivered = [t for t in self.world.transfers() if t["program"] == "scp"]
        self.assertEqual(len(delivered), 1)
        self.assertTrue(delivered[0]["profile_ok"])
        self.assertClean()


class StdioLane(ManagedLane):
    transport = "stdio"

    def test_echo_through_the_domain(self):
        super().test_echo_through_the_domain()
        scp = [t for t in self.world.transfers() if t["program"] == "scp"][0]
        self.assertTrue(any(word.startswith("ProxyCommand=") and "connect" in word for word in scp["argv"]))


if __name__ == "__main__":
    unittest.main()
