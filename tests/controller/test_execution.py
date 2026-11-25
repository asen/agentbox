"""Headless executions end to end, offline: the controller CLI (launch.py,
FakeCgroups), the real agentbox-server on loopback, the real ssh-keygen,
the stand-in provider and ssh, the real guest helper from a built bundle.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t .
"""
import base64
import json
import os
import signal
import subprocess
import sys
import time
import unittest

from tests.controller.harness import World, write_file

QUICK = {"provider.CANCEL_GRACE": 2.0, "provider.STOP_TIMEOUT_MS": 3000, "execute.KILL_TIMEOUT": 1.0,
         "lifecycle.KILL_TIMEOUT": 1.0, "execute.CANCEL_GRACE": 3.0}

DYING_SERVER = """
import json, os, struct, sys, time
def frame():
    n = struct.unpack(">I", sys.stdin.buffer.read(4))[0]
    return json.loads(sys.stdin.buffer.read(n))
m = frame()
body = json.dumps({"type": "ready", "v": 1, "id": m["id"], "session": m["session"],
                   "broker": {"host": "127.0.0.1", "port": 40001}, "post": False, "delivery": False}).encode()
sys.stdout.buffer.write(struct.pack(">I", len(body)) + body)
sys.stdout.buffer.flush()
time.sleep(1.5)
os._exit(1)
"""


def until(condition, timeout=30):
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() >= deadline:
            raise AssertionError("condition not reached")
        time.sleep(0.05)


def final(text):
    return [line for line in text.splitlines() if line.startswith("execution: ")][-1]


def fields(line):
    return dict(word.split("=", 1) for word in line.split()[1:])


class Execution(unittest.TestCase):
    behavior = None
    transport = "tcp"
    log_bytes = 64 << 20

    def setUp(self):
        self.world = World(behavior=self.behavior, transport=self.transport, log_bytes=self.log_bytes)
        self.addCleanup(self.world.close)

    def exec(self, argv, extra=(), **kwargs):
        kwargs.setdefault("overrides", QUICK)
        code, out, err = self.world.exec(argv, extra, **kwargs)
        return code, out, err

    def assertClean(self):
        """Nothing of the execution left: no domain, no listed process."""
        self.assertEqual(self.world.domains(), [])
        self.assertEqual([p for p in self.world.listed_pids() if self.world.ours(p)], [])

    def pending(self):
        return self.world.record()["pending"]

    def status(self):
        code, out, err = self.world.run("status")
        self.assertEqual(code, 0, f"status stdout={out!r} stderr={err!r}")
        return out.split()[2].split("=")[1]


class Success(Execution):
    behavior = {"engine": True}

    def test_output_and_exit(self):
        code, out, err = self.exec(["/bin/sh", "-c", "printf 'out\\033[2J\\n'; printf err >&2; exit 0"])
        self.assertEqual(code, 0, err)
        line = final(out)
        self.assertEqual(line, "execution: outcome=completed reason=completed exit=0 host_cleanup=confirmed "
                               "provider=settled durability=unchanged output=complete")
        self.assertTrue(out.startswith("out\\x1b[2J\n"))
        self.assertEqual(err, "err")
        self.assertIsNone(self.pending())
        self.assertClean()
        log = self.world.provider_log()
        start = [e for e in log if e.get("type") == "start"][0]
        self.assertEqual(start["leaf"], "h-1")
        self.assertTrue(start["custody"].startswith(self.world.cgroup + "/cg/"))
        self.assertEqual(start["scopes"], f"{self.world.data}/run-limits.json")
        self.assertIsNone([e for e in log if e.get("type") == "capabilities"][0]["custody"])
        self.assertIn({"frame": "stop"}, log)
        entries = self.world.ssh_entries()
        self.assertEqual([e["mode"] for e in entries], ["bootstrap", "bootstrap", "session"])
        self.assertTrue(all(e["profile_ok"] for e in entries))
        self.assertEqual(set(entries[0]["env"]), {"PATH", "LC_ALL"})
        self.assertRegex(entries[2]["forward"], r"^127\.0\.0\.1:18080:127\.0\.0\.1:\d+$")
        self.assertEqual(entries[2]["port"], "2222")
        events = self.world.events()
        self.assertEqual([e["seq"] for e in events], list(range(1, len(events) + 1)))
        kinds = [e["event_type"] for e in events]
        for kind in ("host.storage.admitted", "broker.started", "guest.hello", "guest.exit",
                     "broker.stopped", "host.execution.finished"):
            self.assertIn(kind, kinds)
        body = b"".join(base64.b64decode(e["body"]) for e in events if e["event_type"] == "guest.output")
        self.assertEqual(sorted(body), sorted(b"out\x1b[2J\nerr"))
        execution = os.listdir(f"{self.world.data}/controller-runs/{self.world.run_id}/executions")[0]
        with open(f"{self.world.data}/controller-runs/{self.world.run_id}/executions/{execution}") as stream:
            record = json.load(stream)
        self.assertEqual((record["state"], record["outcome"], record["exit"]), ("finished", "completed", 0))
        self.assertEqual(os.listdir(f"{self.world.data}/controller-runs/{self.world.run_id}/session"), [])

    def test_connect_grants_are_this_invocations_only(self):
        """`--allow-connect`: the broker's effective policy for this
        invocation's session (duplicates merged), never the next one's."""
        code, _, err = self.exec(["/bin/true"], ["--allow-connect", "192.168.1.20:8080", "--allow-connect",
                                                 "NAS.lan.:445", "--allow-connect", "nas.lan:445"])
        self.assertEqual(code, 0, err)
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)
        started = sorted((e for e in self.world.events() if e["event_type"] == "broker.started"),
                         key=lambda e: int(e["time_unix_nano"]))
        self.assertEqual([e["attributes"]["grants"] for e in started], [2, 0])
        self.assertEqual({e["attributes"]["mode"] for e in started}, {"model_only"})
        self.assertNotEqual(started[0]["attributes"]["policy"], started[1]["attributes"]["policy"])
        # Refused before anything starts: a usage error, no execution.
        for value in ("0.0.0.0:22", "[::]:22", "[::ffff:0.0.0.0]:80", "*.lan:445", "nas.lan", "fd00::1:22"):
            code, _, err = self.exec(["/bin/true"], ["--allow-connect", value])
            self.assertEqual(code, 2, value)
            self.assertIn("usage:", err)
        self.assertEqual(len([e for e in self.world.events() if e["event_type"] == "broker.started"]), 2)
        self.assertClean()

    def test_insecure_open_overrides_this_invocation_only(self):
        """`--insecure-open`: Open for this invocation's session, the very
        identity a configured `"mode": "open"` has; grants still checked,
        then ignored; the configuration and the next run unchanged."""
        def started():
            return sorted((e for e in self.world.events() if e["event_type"] == "broker.started"),
                          key=lambda e: int(e["time_unix_nano"]))
        code, _, err = self.exec(["/bin/true"], ["--insecure-open", "--allow-connect", "127.0.0.1:8080"])
        self.assertEqual(code, 0, err)
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)
        flagged, plain = [e["attributes"] for e in started()]
        self.assertEqual((flagged["mode"], flagged["grants"], plain["mode"], plain["grants"]),
                         ("open", 0, "model_only", 0))
        policy_file = f"{self.world.tmp}/open-policy.json"
        write_file(policy_file, {"schema": "agentbox.network-policy.v1", "mode": "open"})
        with open(self.world.config) as stream:
            config = json.load(stream)
        write_file(self.world.config, dict(config, network_policy=policy_file))
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)
        configured = started()[2]["attributes"]
        self.assertEqual((configured["mode"], configured["policy"]), ("open", flagged["policy"]))
        code, _, err = self.exec(["/bin/true"], ["--insecure-open", "--allow-connect", "0.0.0.0:80"])
        self.assertEqual(code, 2)
        self.assertIn("usage:", err)
        self.assertEqual(len(started()), 3)
        self.assertClean()

    def test_a_configured_connect_proxy_reaches_every_session_broker(self):
        """`connect_proxy`: the configuration's, normalized, routes each
        session's broker through it; without it, direct."""
        def routes():
            return [e["attributes"]["route"] for e in sorted(
                (e for e in self.world.events() if e["event_type"] == "broker.started"),
                key=lambda e: int(e["time_unix_nano"]))]
        with open(self.world.config) as stream:
            config = json.load(stream)
        write_file(self.world.config, dict(config, connect_proxy="Proxy.Corp.:3128"))
        code, _, err = self.exec(["/bin/true"], ["--allow-connect", "nas.lan:445"])
        self.assertEqual(code, 0, err)
        write_file(self.world.config, config)
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)
        self.assertEqual(routes(), ["proxy", "direct"])
        write_file(self.world.config, dict(config, connect_proxy="0.0.0.0:3128"))
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual(code, 1)
        self.assertEqual(len(routes()), 2)
        write_file(self.world.config, config)
        self.assertClean()

    def test_exit_code_and_repeat(self):
        code, out, err = self.exec(["/bin/sh", "-c", "exit 3"])
        self.assertEqual(code, 1)
        self.assertIn("reason=completed exit=3 host_cleanup=confirmed provider=settled", final(err))
        code, out, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)
        self.assertClean()

    def test_stdin(self):
        data = os.urandom(3000) .hex().encode() + b"\n"
        code, out, err = self.exec(["/bin/cat"], ["--stdin"], input=data)
        self.assertEqual(code, 0, err)
        self.assertEqual(out[:len(data)].encode(), data)

    def test_env_selection(self):
        code, out, err = self.exec(["/bin/sh", "-c", 'printf "%s|%s" "$PICKED" "$OTHER"'], ["--env", "PICKED"],
                                   env={"PICKED": "yes", "OTHER": "no"})
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("yes|"))
        code, out, err = self.exec(["/bin/true"], ["--env", "MISSING"])
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: env_invalid\n"))

    def test_lease_exclusion(self):
        first = self.world.start("exec", ["--", "/bin/sleep", "5"], overrides=QUICK)
        try:
            deadline = time.monotonic() + 20
            while self.status() != "active" and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertEqual(self.status(), "active")
            code, _, err = self.exec(["/bin/true"])
            self.assertEqual((code, err), (1, "agentbox: jail exec refused: run_busy\n"))
            # C2a: a busy owner is signalled to stop (its published identity).
            until(lambda: os.path.exists(f"{self.world.data}/controller-runs/{self.world.run_id}/owner/owner.json"))
            code, out, err = self.world.run("stop")
            self.assertEqual((code, out), (0, f"stop: {self.world.run_id} requested\n"), err)
        finally:
            out, err = first.communicate(timeout=60)
        self.assertEqual((first.returncode, fields(final(err.decode()))["reason"]), (1, "cancelled"))
        self.assertEqual(self.status(), "idle")


class Cancellation(Execution):
    behavior = {"engine": True}

    def started(self, extra=(), overrides=QUICK):
        process = self.world.start("exec", list(extra) + ["--", "/bin/sh", "-c", "echo started; exec sleep 30"],
                                   overrides=overrides)
        self.assertEqual(process.stdout.readline(), b"started\n")
        return process

    def test_sigterm_and_sigint(self):
        for number in (signal.SIGTERM, signal.SIGINT):
            process = self.started()
            process.send_signal(number)
            out, err = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 1)
            self.assertEqual(fields(final(err.decode()))["reason"], "cancelled")
            self.assertIn("host_cleanup=confirmed provider=settled", final(err.decode()))
            self.assertIsNone(self.pending())
            self.assertClean()

    def test_timeout(self):
        code, out, err = self.exec(["/bin/sleep", "30"], ["--timeout", "2"])
        self.assertEqual(code, 1)
        self.assertEqual(fields(final(err))["reason"], "timeout")
        self.assertEqual(fields(final(err))["outcome"], "cancelled")
        self.assertIsNone(self.pending())
        self.assertClean()

    def test_second_signal_forces(self):
        self.world.set_behavior(stop="hang")
        overrides = dict(QUICK, **{"provider.STOP_TIMEOUT_MS": 60000, "execute.CANCEL_GRACE": 60.0})
        process = self.world.start("exec", ["--", "/bin/sh", "-c", "trap '' TERM INT; echo started; "
                                            "while :; do sleep 1; done"], overrides=overrides)
        self.assertEqual(process.stdout.readline(), b"started\n")
        began = time.monotonic()
        process.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        process.send_signal(signal.SIGTERM)
        out, err = process.communicate(timeout=30)
        self.assertLess(time.monotonic() - began, 15)
        line = fields(final(err.decode()))
        # The server was not given its clean stop: cleanup unconfirmed,
        # though the domain was killed and read empty.
        self.assertEqual((line["reason"], line["host_cleanup"], line["provider"]),
                         ("cancelled", "unconfirmed", "unknown"))
        pending = self.pending()
        self.assertEqual((pending["processes"], pending["provider"], pending["settlement"]),
                         ("settled", "lost", "unknown"))
        self.assertEqual(self.status(), "abandoned")
        self.assertClean()
        self.world.set_behavior(stop="settled")
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)
        self.assertEqual(self.status(), "idle")
        stops = [e for e in self.world.provider_log() if e.get("type") == "stop"]
        self.assertEqual(len(stops), 1)
        self.assertTrue(stops[0]["custody"] and stops[0]["leaf"] == "h-1")
        self.assertClean()

    def test_controller_killed_then_recovered(self):
        process = self.started()
        process.send_signal(signal.SIGKILL)
        process.communicate(timeout=30)
        self.assertEqual(self.status(), "abandoned")
        pending = self.pending()
        self.assertEqual((pending["op"], pending["processes"], pending["provider"]),
                         ("start", "unknown", "started"))
        self.assertNotEqual([p for p in self.world.listed_pids() if self.world.ours(p)], [])
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)
        self.assertEqual(self.status(), "idle")
        self.assertClean()
        code, out, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)


class Failures(Execution):
    log_bytes = 1 << 20

    def check(self, argv, reason, pending=None, extra=(), **kwargs):
        code, out, err = self.exec(argv, extra, **kwargs)
        self.assertEqual(code, 1, out)
        line = fields(final(err))
        self.assertEqual(line["reason"], reason, err)
        if pending is None:
            self.assertIsNone(self.pending())
        else:
            self.assertEqual({k: self.pending()[k] for k in pending}, pending)
        return line

    def test_provider_start_failed(self):
        self.world.set_behavior(start="fail")
        line = self.check(["/bin/true"], "provider_failed")
        self.assertEqual((line["provider"], line["provider_code"], line["host_cleanup"]),
                         ("settled", "failed", "confirmed"))
        self.assertEqual(self.world.ssh_entries(), [])
        self.assertClean()

    def test_start_cancelled_at_timeout(self):
        self.world.set_behavior(start="hang")
        line = self.check(["/bin/true"], "timeout", extra=["--timeout", "2"])
        self.assertEqual((line["provider"], line["provider_code"], line["host_cleanup"]),
                         ("settled", "cancelled", "confirmed"))
        self.assertEqual(self.world.ssh_entries(), [])
        self.assertClean()

    def test_worker_mismatch(self):
        self.world.set_behavior(worker_sha256="0" * 64)
        line = self.check(["/bin/true"], "provider_protocol", {"processes": "settled", "settlement": "unknown"})
        self.assertEqual(line["provider"], "unknown")
        self.assertEqual(self.world.ssh_entries(), [])
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)
        self.assertClean()

    def test_binding_mismatch(self):
        self.world.set_behavior(user="other")
        line = self.check(["/bin/true"], "binding_mismatch")
        self.assertEqual(line["provider"], "settled")
        self.assertEqual(self.world.ssh_entries(), [])
        self.assertClean()

    def test_owner_lost(self):
        self.world.set_behavior(start="die", die_after=2.0)
        line = self.check(["/bin/sleep", "30"], "provider_lost", {"processes": "settled", "provider": "lost"})
        self.assertEqual(line["host_cleanup"], "confirmed")
        self.assertEqual(self.status(), "abandoned")
        self.assertClean()

    def test_server_lost(self):
        server = f"{self.world.tmp}/dying-server"
        write_file(server, f"#!{sys.executable} -I\n{DYING_SERVER}", 0o755)
        write_file(self.world.config, {"schema": "agentbox.controller-config.v1", "data": self.world.data,
                                   "server": server})
        line = self.check(["/bin/sleep", "30"], "server_lost")
        self.assertEqual((line["host_cleanup"], line["provider"]), ("unconfirmed", "settled"))
        self.assertClean()

    def test_failed_stop_stays_pending(self):
        self.world.set_behavior(stop="unsettled")
        line = self.check(["/bin/true"], "completed", {"processes": "settled", "provider": "failed",
                                                      "settlement": "unsettled", "code": "failed"})
        self.assertEqual((line["exit"], line["provider"]), ("0", "unsettled"))
        self.assertEqual(self.status(), "abandoned")
        code, _, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: provider_unsettled\n"))
        self.world.set_behavior(stop="settled")
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual(code, 0, err)

    def test_kill_unconfirmed(self):
        self.world.set_behavior(engine=True)
        line = self.check(["/bin/true"], "completed", {"processes": "unknown", "provider": "stopped"},
                          faults={"stuck": True})
        self.assertEqual(line["host_cleanup"], "unconfirmed")
        self.assertNotEqual(self.world.domains(), [])
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: run_unsettled\n"))
        code, out, err = self.world.run("stop", overrides=QUICK, faults={"stuck": True})
        self.assertEqual((code, err), (1, "agentbox: jail stop refused: processes_unsettled\n"))
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)
        self.assertIsNone(self.pending())
        self.assertClean()
        stops = [e for e in self.world.provider_log() if e.get("type") == "stop"]
        self.assertEqual(stops, [])

    def test_delegation_refused_before_effects(self):
        for faults, reason in (({"fail_start": True}, "delegation_missing"),
                               ({"mismatch": "memory.max"}, "limit_mismatch"),
                               ({"deny_controllers": True}, "delegation_missing")):
            self.check(["/bin/true"], reason, faults=faults)
            self.assertEqual([e.get("type") for e in self.world.provider_log()][-1], "capabilities")
            self.assertEqual(self.world.domains(), [])
        self.assertEqual(self.world.ssh_entries(), [])

    def test_bootstrap_and_session_failures(self):
        self.world.set_ssh(fail="bootstrap")
        line = self.check(["/bin/true"], "bootstrap_failed")
        self.assertEqual((line["host_cleanup"], line["provider"]), ("confirmed", "settled"))
        self.world.set_ssh(fail="session")
        self.check(["/bin/true"], "transport_lost")
        self.world.set_ssh(fail=None)
        self.assertClean()

    def test_capture_full(self):
        script = "head -c 3000000 /dev/zero | tr '\\0' x"
        code, out, err = self.exec(["/bin/sh", "-c", script])
        self.assertEqual(code, 1)
        line = fields(final(err))
        self.assertEqual((line["reason"], line["exit"], line["capture"]), ("completed", "0", "incomplete"))
        self.assertEqual(len(out), 3000000)
        gap = self.world.events()[-1]
        self.assertEqual(gap["event_type"], "host.capture.gap")
        self.assertLessEqual(os.path.getsize(self._log()), 1 << 20)

    def _log(self):
        logs = f"{self.world.data}/controller-logs/{self.world.run_id}"
        return f"{logs}/{os.listdir(logs)[0]}/events.jsonl"

    def test_store_refusals(self):
        write_file(f"{self.world.data}/run-limits.json", {"max_reserved_bytes": 1000, "storage_scopes": [
            {"path": self.world.state, "measure": "tree"}]})
        code, _, err = self.exec(["/bin/true"])
        self.assertEqual((code, err), (1, "agentbox: jail exec refused: storage_limit\n"))
        self.assertEqual(self.world.provider_log(), [])


class Interruption(Execution):
    """Signals and the cutoff end each active wait promptly; nothing
    renews a cancel grace; the record says what was not observed."""
    behavior = {"engine": True}

    def finished(self, process, limit):
        began = time.monotonic()
        out, err = process.communicate(timeout=60)
        self.assertLess(time.monotonic() - began, limit)
        return fields(final(err.decode()))

    def test_signal_during_bootstrap(self):
        self.world.set_ssh(fail="hang_bootstrap")
        process = self.world.start("exec", ["--", "/bin/true"], overrides=QUICK)
        until(lambda: self.world.ssh_entries())
        process.send_signal(signal.SIGTERM)
        line = self.finished(process, 15)
        self.assertEqual((line["reason"], line["host_cleanup"], line["provider"]),
                         ("cancelled", "confirmed", "settled"))
        self.assertIsNone(self.pending())
        self.assertClean()

    def test_cutoff_during_bootstrap(self):
        self.world.set_ssh(fail="hang_bootstrap")
        began = time.monotonic()
        code, out, err = self.exec(["/bin/true"], ["--timeout", "3"])
        self.assertLess(time.monotonic() - began, 20)
        line = fields(final(err))
        self.assertEqual((code, line["reason"], line["provider"]), (1, "timeout", "settled"))
        self.assertClean()

    def stop_hangs(self, grace):
        self.world.set_behavior(stop="hang")
        overrides = dict(QUICK, **{"provider.STOP_TIMEOUT_MS": 120000, "provider.CANCEL_GRACE": grace})
        process = self.world.start("exec", ["--", "/bin/true"], overrides=overrides)
        until(lambda: {"frame": "stop"} in self.world.provider_log())
        return process

    def after_unanswered_stop(self, line):
        self.assertEqual((line["reason"], line["exit"], line["provider"]), ("completed", "0", "unknown"))
        pending = self.pending()
        self.assertEqual((pending["processes"], pending["provider"], pending["settlement"]),
                         ("settled", "lost", "unknown"))
        self.assertEqual(self.status(), "abandoned")
        self.assertClean()
        self.world.set_behavior(stop="settled")
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)

    def test_first_signal_during_teardown_cancels_stop(self):
        process = self.stop_hangs(2.0)
        process.send_signal(signal.SIGTERM)
        line = self.finished(process, 15)
        self.assertIn({"frame": "cancel"}, self.world.provider_log())
        self.after_unanswered_stop(line)

    def test_second_signal_during_teardown_forces(self):
        process = self.stop_hangs(60.0)
        process.send_signal(signal.SIGTERM)
        until(lambda: {"frame": "cancel"} in self.world.provider_log())
        process.send_signal(signal.SIGTERM)
        line = self.finished(process, 15)
        # The server had already stopped clean; D was killed and read empty.
        self.assertEqual(line["host_cleanup"], "confirmed")
        self.after_unanswered_stop(line)

    def test_second_signal_during_start_forces(self):
        self.world.set_behavior(start="hang_ignore")
        overrides = dict(QUICK, **{"provider.CANCEL_GRACE": 60.0})
        process = self.world.start("exec", ["--", "/bin/true"], overrides=overrides)
        until(lambda: any(e.get("type") == "start" for e in self.world.provider_log()))
        process.send_signal(signal.SIGTERM)
        until(lambda: {"frame": "cancel"} in self.world.provider_log())
        process.send_signal(signal.SIGTERM)
        line = self.finished(process, 15)
        self.assertEqual((line["reason"], line["provider"]), ("cancelled", "unknown"))
        pending = self.pending()
        self.assertEqual((pending["processes"], pending["provider"]), ("settled", "lost"))
        self.assertClean()
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (0, "recovered"), err)

    def test_undrained_stderr(self):
        """A reader that stops reading loses the final line, never holds the
        controller or the lease."""
        process = subprocess.Popen(self.world.argv("exec", ["--", "/bin/sh", "-c", "head -c 3000000 /dev/zero >&2"],
                                                   overrides=QUICK),
                                   env=self.world.env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE)
        try:
            self.assertEqual(process.wait(timeout=30), 1)
        finally:
            process.stderr.close()
        self.assertEqual(self.status(), "idle")
        self.assertIsNone(self.pending())
        directory = f"{self.world.data}/controller-runs/{self.world.run_id}/executions"
        with open(f"{directory}/{os.listdir(directory)[0]}") as stream:
            record = json.load(stream)
        self.assertEqual((record["outcome"], record["exit"], record["host_cleanup"]), ("completed", 0, True))
        self.assertClean()


class Stdio(Execution):
    transport = "stdio"
    behavior = {"engine": True}

    def test_proxy_route(self):
        code, out, err = self.exec(["/bin/sh", "-c", "echo via-proxy"])
        self.assertEqual(code, 0, err)
        self.assertTrue(out.startswith("via-proxy\n"))
        entries = self.world.ssh_entries()
        self.assertTrue(all(e["proxy_exit"] == 0 and e["destination"].startswith("agentbox-r-") for e in entries))
        self.assertNotIn("SHELL", entries[0]["env"])
        connects = [e for e in self.world.provider_log() if e.get("argv") == "connect"]
        self.assertEqual(len(connects), 3)
        # Spawned by ssh in its leaf: the fake lists only joined pids.
        self.assertTrue(all(c["custody"] == connects[0]["custody"] for c in connects))
        self.assertClean()


if __name__ == "__main__":
    unittest.main()
