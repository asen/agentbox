"""C2b offline: `run AGENT` through the Python controller (headless and
interactive, existing, attached and owned runs), the packaged entry and
configuration defaults. Stand-in agents (tests/controller/agents/standin_agent.py),
the trusted adapters and common runner unchanged (the runner's /dev/shm
moved to a scratch root, its npm a stand-in), a network-free npm worker,
stand-in ssh and provider, FakeCgroups, local PTY pairs: no native SSH, systemd,
provider, credential, model, npm or node.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t .
"""
import fcntl
import io
import json
import os
import select
import shutil
import signal
import stat
import struct
import sys
import subprocess
import tarfile
import tempfile
import termios
import time
import unittest
import unittest.mock

from agentbox_controller import agent as agent_mod
from agentbox_controller import agentrun
from agentbox_controller import config as config_mod
from agentbox_controller import host
from agentbox_controller import inputs as inputs_mod
from agentbox_controller import interactive
from agentbox_controller import lifecycle
from agentbox_controller.host import HostError
from tests.controller.harness import World, write_file
from tests.controller.test_execution import QUICK, fields, until


def selected(entry):
    """The agent's --env selection as it logged it (its request context
    aside)."""
    return {k: v for k, v in entry["env"].items() if k.startswith("C2B_")}


def credential(world, name="auth.json"):
    """A fake API-key credential (never a real one): pi's `openai` entry."""
    path = f"{world.tmp}/{name}"
    write_file(path, {"openai": {"type": "api_key", "key": "test-not-a-secret"}}, 0o600)
    return path


class Agents(unittest.TestCase):
    kind = "managed"
    retention = "home"
    transport = "tcp"

    def setUp(self):
        self.world = World(kind=self.kind, retention=self.retention, transport=self.transport)
        self.addCleanup(self.world.close)

    def agent(self, name, extra, env=None, timeout=120, **kwargs):
        args = [name] + list(extra)
        kwargs.setdefault("overrides", QUICK)
        return self.world.run(("run",), args, command_args=False, env=env, timeout=timeout, **kwargs)

    def jail(self, name, extra, **kwargs):
        return self.agent(name, ["--jail", self.world.run_id] + list(extra), **kwargs)

    def owned(self, name, extra, **kwargs):
        return self.agent(name, ["--image", self.world.image] + list(extra), **kwargs)

    def runs(self):
        return sorted(os.listdir(f"{self.world.data}/controller-runs"))

    def record(self, run_id):
        return self.world.record(run_id)

    def execution_line(self, text):
        return fields([l for l in text.splitlines() if l.startswith("execution: ")][-1])


class Headless(Agents):
    def test_pi_literal_argv_prompt_model_env(self):
        code, out, err = self.jail("pi", ["--prompt", "say hi -x @file", "--model", "openai/gpt-test",
                                          "--env", "C2B_ONE"], env={"C2B_ONE": "value one", "C2B_TWO": "no"})
        self.assertEqual(code, 0, err)
        self.assertIn("agent pi got: say hi -x @file", out)
        entry = self.world.agent_log()[-1]
        self.assertEqual((entry["name"], entry["argv"], entry["prompt"], selected(entry), entry["auth"]),
                         ("pi", ["--offline", "-p", "--model", "openai/gpt-test"], "say hi -x @file",
                          {"C2B_ONE": "value one"}, None))
        # Never in argv, a record or the capture.
        for entry in self.world.ssh_entries():
            self.assertNotIn("say hi", json.dumps(entry["argv"]))
        captured = json.dumps(self.world.events())
        for secret in ("say hi -x @file", "openai/gpt-test", "value one"):
            self.assertNotIn(secret, captured)
        self.assertEqual(self.record(self.world.run_id)["phase"], "ready")

    def test_codex_and_claude_profiles(self):
        code, out, err = self.jail("codex", ["--prompt", "p", "--model", "gpt-x"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.agent_log()[-1]["argv"],
                         ["exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check",
                          "--color", "never", "-m", "gpt-x", "-"])
        code, out, err = self.jail("claude", ["--prompt", "p"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.agent_log()[-1]["name"], "claude")

    def test_refusals_before_any_effect(self):
        before = self.runs()
        for extra, env, expected in ((["--prompt", "p", "--env", "PATH"], None, "env_invalid"),
                                     (["--prompt", "p", "--env", "C2B_MISSING"], None, "env_invalid"),
                                     (["--prompt", "p", "--discard"], None, "headless_unexpected_argument"),
                                     (["--install-agent"], None, "interactive_install_unsupported"),
                                     (["--prompt", "p", "--model", "-x"], None, "invalid_model"),
                                     (["--prompt", "p", "--keep-auth"], None, "keep_auth_requires_copy_auth"),
                                     (["--prompt", "p", "--copy-auth", "/nonexistent/auth.json"], None,
                                      "credential_unreadable")):
            code, out, err = self.jail("pi", extra, env=env)
            self.assertEqual((code, err.strip().splitlines()[-1]), (1, f"agentbox: run refused: {expected}"))
        code, _, err = self.agent("bogus", ["--jail", self.world.run_id, "--prompt", "p"])
        self.assertEqual(err, "agentbox: run refused: agent_unknown\n"
                              "agentbox: hint: agents: pi, codex, claude; a command: agentbox run -- ARG...\n")
        self.assertEqual(self.runs(), before)
        self.assertEqual(self.world.agent_log(), [])
        self.assertFalse(os.path.isdir(f"{self.world.data}/controller-runs/{self.world.run_id}/executions")
                         and os.listdir(f"{self.world.data}/controller-runs/{self.world.run_id}/executions"))

    def test_credential_copied_and_removed_or_kept(self):
        auth = credential(self.world)
        code, out, err = self.jail("pi", ["--prompt", "p", "--model", "openai/m", "--copy-auth", auth])
        self.assertEqual(code, 0, err)
        self.assertGreater(self.world.agent_log()[-1]["auth"], 0)
        self.assertFalse(os.path.exists(f"{self.world.home}/.pi/agent/auth.json"))
        code, out, err = self.jail("pi", ["--prompt", "p", "--copy-auth", auth, "--keep-auth"])
        self.assertEqual(code, 0, err)
        self.assertIn("--keep-auth: the copied credential stays in the jail", err)
        self.assertTrue(os.path.exists(f"{self.world.home}/.pi/agent/auth.json"))
        # Never in any record, argv or the capture.
        self.assertNotIn("test-not-a-secret", json.dumps(self.world.events()) + json.dumps(self.world.ssh_entries()))

    def test_owned_without_export_is_discarded(self):
        code, out, err = self.owned("pi", ["--prompt", "p"])
        self.assertEqual(code, 0, err)
        self.assertIn("no --export-to: the owned run's jail-local storage is discarded", err)
        created = [l for l in out.splitlines() if l.startswith("run: created")][0].split()[2].split("=")[1]
        self.assertIn(f"discard: {created} discarded", out)
        self.assertEqual(self.record(created)["phase"], "discarded")
        self.assertEqual(self.record(created)["retention"], "none")
        self.assertEqual(self.world.domains(), [])

    def test_owned_export_published_then_discarded(self):
        out_dir = f"{self.world.tmp}/out"
        os.mkdir(out_dir, 0o700)
        code, out, err = self.owned("pi", ["--prompt", "p", "--export-to", f"{out_dir}/w.tar"])
        self.assertEqual(code, 0, err)
        created = [l for l in out.splitlines() if l.startswith("run: created")][0].split()[2].split("=")[1]
        self.assertIn("retention=home", out)
        self.assertIn("outcome=published", out)
        self.assertEqual(self.record(created)["phase"], "discarded")
        with tarfile.open(f"{out_dir}/w.tar") as archive:
            self.assertTrue(archive.getnames())

    def test_owned_failure_keeps_an_export_run(self):
        out_dir = f"{self.world.tmp}/out"
        os.mkdir(out_dir, 0o700)
        self.world.set_ssh(export="exit7")
        code, out, err = self.owned("pi", ["--prompt", "p", "--export-to", f"{out_dir}/w.tar"])
        self.assertEqual(code, 1)
        created = [l for l in out.splitlines() if l.startswith("run: created")][0].split()[2].split("=")[1]
        self.assertIn(f"the owned run {created} is kept (its export was not published)", err)
        self.assertEqual(self.record(created)["phase"], "ready")

    def test_install_through_the_lane(self):
        installs = f"{self.world.home}/.local/share/agentbox-agents/codex"
        log = f"{self.world.home}/npm-log.jsonl"
        # A headless run's lane is its installer's: acquisition.json unread.
        write_file(self.world.acquisition_default, "{", 0o666)
        code, out, err = self.jail("codex", ["--prompt", "p", "--install-agent"])
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isfile(f"{installs}/9.9.9/.agentbox-installed"), err)
        self.assertEqual(os.readlink(f"{installs}/current"), "9.9.9")
        self.assertEqual(_lines_json(log), [
            ["view", "--json", "@openai/codex@latest", "version"],
            ["install", "--global", "--prefix", f"{installs}/9.9.9", "--no-audit", "--no-fund",
             "@openai/codex@9.9.9"]])
        requests = [e["attributes"] for e in self.world.events() if e["event_type"] == "host.handler.request"]
        self.assertEqual([(r["handler"], r["end"]) for r in requests], [("npm", "recorded")])
        # An exact version; then no flag: the installed one, npm never run.
        code, _, err = self.jail("codex", ["--prompt", "p", "--install-agent", "--agent-version", "1.2.3"])
        self.assertEqual(code, 0, err)
        self.assertEqual(os.readlink(f"{installs}/current"), "1.2.3")
        os.unlink(log)
        code, _, err = self.jail("codex", ["--prompt", "p"])
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.exists(log))
        code, _, err = self.jail("codex", ["--prompt", "p", "--install-agent", "--agent-version", "latest"])
        self.assertEqual(err.strip().splitlines()[-1], "agentbox: run refused: agent_version_invalid")


def _lines_json(path):
    with open(path) as stream:
        return [json.loads(line) for line in stream]


class Owned(Agents):
    behavior = {"features": ["select_user", "project_layout", "host_mounts"]}

    def setUp(self):
        self.world = World(kind=self.kind, retention=self.retention, transport=self.transport,
                           behavior=self.behavior)
        self.addCleanup(self.world.close)

    def units(self):
        found = []
        for directory, names, _ in os.walk(f"{self.world.cgroup}/cg"):
            found += [n for n in names if n.startswith("agentbox-launch-")]
        return sorted(found)

    def test_one_process_one_delegated_scope_and_mounts_stay(self):
        source = f"{self.world.tmp}/src"
        os.mkdir(source, 0o755)
        write_file(f"{source}/kept.txt", "host", 0o644)
        before = self.units()
        # The stand-in binds nothing: the guest's mount, as a provider makes it.
        os.makedirs(f"{self.world.home}/proj", 0o755)
        code, out, err = self.owned("pi", ["--prompt", "p", "--mount-rw", f"{source}=proj", "--project", source])
        self.assertEqual(code, 0, err)
        # create, exec and discard in one process: one delegated scope.
        self.assertEqual(len(self.units()) - len(before), 1)
        created = out.split("run: created id=", 1)[1].split()[0]
        self.assertIn("retention=home", out)
        self.assertIn("changes to writable host mounts remain", err)
        self.assertEqual(self.record(created)["phase"], "discarded")
        self.assertEqual(self.world.agent_log()[-1]["cwd"], f"{self.world.home}/proj")
        create = [e for e in self.world.provider_log() if e.get("type") == "create"][-1]
        self.assertEqual(create["mounts"], [{"source": source, "destination": "proj", "access": "rw"}])
        # Nothing of a host source is ever removed.
        self.assertTrue(os.path.exists(f"{source}/kept.txt"))
        self.assertEqual(self.world.domains(), [])

    def test_no_credential_or_managed_install_reaches_a_host_mount(self):
        source = f"{self.world.tmp}/src"
        os.mkdir(source, 0o755)
        write_file(f"{source}/kept.txt", "host", 0o644)
        auth = credential(self.world)
        runs, creates = self.runs(), len([e for e in self.world.provider_log() if e.get("type") == "create"])
        for extra, reason in (
                (["--copy-auth", auth, "--mount-ro", f"{source}=.pi"], "auth_location_mounted"),
                (["--copy-auth", auth, "--keep-auth", "--mount-rw", f"{source}=.pi/agent"], "auth_location_mounted"),
                (["--copy-auth", auth, "--mount-rw", f"{source}=.pi/agent/auth.json"], "auth_location_mounted"),
                (["--install-agent", "--mount-rw", f"{source}=.local"], "install_location_mounted"),
                (["--install-agent", "--mount-ro", f"{source}=.local/share/agentbox-agents/pi/x"],
                 "install_location_mounted")):
            code, _, err = self.owned("pi", ["--prompt", "p"] + extra)
            self.assertEqual((code, err.strip().splitlines()[-1]), (1, f"agentbox: run refused: {reason}"), extra)
        # Refused before creation: no run, no provider create, no agent.
        self.assertEqual(self.runs(), runs)
        self.assertEqual(len([e for e in self.world.provider_log() if e.get("type") == "create"]), creates)
        self.assertEqual(self.world.agent_log(), [])
        # An existing run's mounts, under its lease: refused before any SSH.
        run_id = self.world.create(["--retention", "home", "--mount-rw", f"{source}=.pi"])
        ssh = len(self.world.ssh_entries())
        code, _, err = self.agent("pi", ["--jail", run_id, "--prompt", "p", "--copy-auth", auth])
        self.assertEqual((code, err.strip().splitlines()[-1]), (1, "agentbox: run refused: auth_location_mounted"))
        self.assertEqual((len(self.world.ssh_entries()), self.world.agent_log()), (ssh, []))
        # Without a copied credential, or with one beside another mount: as before.
        code, _, err = self.agent("pi", ["--jail", run_id, "--prompt", "p"])
        self.assertEqual(code, 0, err)
        code, out, err = self.owned("pi", ["--prompt", "p", "--copy-auth", auth, "--mount-rw", f"{source}=.claude"])
        self.assertEqual(code, 0, err)
        self.assertIsNotNone(self.world.agent_log()[-1]["auth"])
        with open(f"{source}/kept.txt") as stream:
            self.assertEqual((sorted(os.listdir(source)), stream.read()), (["kept.txt"], "host"))

    def test_an_interrupt_still_cleans_the_owned_run(self):
        auth = credential(self.world)
        proc = self.world.start(("run",), ["pi", "--image", self.world.image,
                                                   "--prompt", "sleep:30", "--copy-auth", auth],
                                command_args=False, overrides=QUICK)
        until(lambda: any(e.get("prompt") == "sleep:30" for e in self.world.agent_log()), 60)
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=60)
        out, err = out.decode(), err.decode()
        self.assertEqual(proc.returncode, 1, err)
        self.assertEqual(self.execution_line(err)["reason"], "cancelled")
        created = out.split("run: created id=", 1)[1].split()[0]
        # Discarded, the credential with it: no warning of one left behind.
        self.assertNotIn("copied credential may remain", err)
        self.assertIn(f"discard: {created} discarded", out)
        self.assertEqual(self.world.domains(), [])


class Staging(Agents):
    def test_a_replaced_staging_is_refused_and_left(self):
        self.world.set_ssh(tamper=self.world.shm)
        terminal = Terminal(self.world, ["pi", "--jail",
                                         self.world.run_id])
        self.addCleanup(terminal.close)
        self.addCleanup(kill_strays, self.world.tmp)
        code, text = terminal.finish()
        self.assertEqual(code, 1, text)
        self.assertIn("agentbox: agent: exit=95", text)
        self.assertIn("(staging_left)", text)
        # Never deleted without its receipt: the replacement stays.
        self.assertEqual(len([f for _, _, files in os.walk(self.world.shm) for f in files]), 1)
        self.assertEqual(self.world.agent_log(), [])


class Attached(Agents):
    kind = "attached"

    def test_ssh_target_is_registered_and_never_discarded(self):
        code, out, err = self.agent("pi", ["--ssh-target", self.world.target_file, "--prompt", "p"])
        self.assertEqual(code, 0, err)
        created = [l for l in out.splitlines() if l.startswith("run: created")][0].split()[2].split("=")[1]
        self.assertIn("kind=attached", out)
        self.assertEqual(self.record(created)["phase"], "ready")
        self.assertNotIn("discard:", out)


class Terminal:
    """The CLI on a local PTY pair: its session leader, the slave its
    controlling terminal and stdin/stdout/stderr, this process its foreground
    group's owner (as a shell starts a job)."""

    def __init__(self, world, args, env=None, rows=24, cols=80, overrides=QUICK, command=("run",), cwd=None):
        self.master, self.slave = os.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        argv = world.argv(command, args, overrides=overrides, command_args=False)
        self.proc = subprocess.Popen(argv, env=world.env(env), stdin=self.slave, stdout=self.slave,
                                     stderr=self.slave, start_new_session=True, cwd=cwd,
                                     preexec_fn=lambda: fcntl.ioctl(0, termios.TIOCSCTTY, 0))
        self.buffer = b""

    def read(self, wait):
        ready, _, _ = select.select([self.master], [], [], wait)
        if ready:
            try:
                self.buffer += os.read(self.master, 65536)
            except OSError:
                pass

    def expect(self, data, timeout=60):
        deadline = time.monotonic() + timeout
        while data not in self.buffer:
            if time.monotonic() >= deadline or self.proc.poll() is not None:
                self.read(0.2)
                if data in self.buffer:
                    break
                raise AssertionError(f"{data!r} not seen: {self.buffer[-2000:]!r}")
            self.read(0.1)

    def send(self, data):
        os.write(self.master, data)

    def resize(self, rows, cols):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def finish(self, timeout=60):
        deadline = time.monotonic() + timeout
        while self.proc.poll() is None and time.monotonic() < deadline:
            self.read(0.1)
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        self.read(0.2)
        return self.proc.returncode, self.buffer.decode(errors="replace")

    def close(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        for fd in (self.master, self.slave):
            os.close(fd)


def kill_strays(tmp):
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as stream:
                if tmp.encode() in stream.read():
                    os.kill(int(name), signal.SIGKILL)
        except OSError:
            pass


class Interactive(Agents):
    def terminal(self, args, env=None, overrides=QUICK):
        terminal = Terminal(self.world, args, env, overrides=overrides)
        self.addCleanup(terminal.close)
        self.addCleanup(kill_strays, self.world.tmp)
        return terminal

    def assertQuietUntil(self, text, marker):
        """Nothing of this command's own before the agent's session ended."""
        head = text.split(marker, 1)[0]
        for own in ("agentbox:", "serve:", "agent: exit", "run: retained"):
            self.assertNotIn(own, head)

    def test_terminal_session_raw_resize_ctrl_c_eot(self):
        auth = credential(self.world)
        terminal = self.terminal(["pi", "--jail", self.world.run_id,
                                  "--model", "openai/m", "--copy-auth", auth, "--env", "C2B_X", "--",
                                  "--continue"], env={"C2B_X": "x1", "TERM": "xterm-256color"})
        terminal.expect(b"agent-ready")
        terminal.send(b"t")
        terminal.expect(b"tty raw")
        terminal.resize(40, 100)
        terminal.expect(b"winch 40x100")
        terminal.send(b"\x03")
        terminal.expect(b"ctrl-c")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        self.assertQuietUntil(text, "agent-eot")
        self.assertLess(text.index("agent: exit=0"), text.index("serve: "))
        # Set back exactly, once.
        self.assertEqual(termios.tcgetattr(terminal.slave), terminal.original)
        entry = self.world.agent_log()[-1]
        self.assertEqual((entry["argv"], selected(entry), entry["tty"], entry["term"]),
                         (["--offline", "--model", "openai/m", "--continue"], {"C2B_X": "x1"}, True,
                          "xterm-256color"))
        # The serving owner's request context (no lane: its POST unconfigured).
        self.assertRegex(entry["env"]["AGENTBOX_REQUEST_SESSION"], "^[0-9a-f]{32}$")
        self.assertEqual(entry["env"]["AGENTBOX_WORK_ROOT"], f"{self.world.home}/work")
        self.assertGreater(entry["auth"], 0)
        self.assertFalse(os.path.exists(f"{self.world.home}/.pi/agent/auth.json"))
        # Staged, consumed, nothing left; no secret in any record.
        self.assertEqual([f for _, _, files in os.walk(self.world.shm) for f in files], [])
        modes = [e["mode"] for e in self.world.ssh_entries()]
        self.assertEqual([m for m in modes if m in ("staging", "shell")], ["staging", "shell", "staging"])
        for entry in self.world.ssh_entries():
            self.assertNotIn("x1", json.dumps(entry["argv"]))
        self.assertNotIn("test-not-a-secret", json.dumps(self.world.events()))
        serve = fields([l for l in text.splitlines() if l.startswith("serve: ")][-1])
        self.assertEqual((serve["reason"], serve["host_cleanup"]), ("cancelled", "confirmed"))

    def test_run_stop_ends_the_session(self):
        terminal = self.terminal(["pi", "--jail", self.world.run_id])
        terminal.expect(b"agent-ready")
        code, out, err = self.world.run(("jail", "stop"))
        self.assertEqual(out.strip(), f"stop: {self.world.run_id} requested", err)
        code, text = terminal.finish()
        self.assertEqual(code, 1, text)
        self.assertIn("code=agent_session_stopped", text)
        self.assertEqual(termios.tcgetattr(terminal.slave), terminal.original)

    def test_kill_after_ignored_term_restores_the_terminal(self):
        self.world.set_ssh(term="ignore")
        terminal = self.terminal(["pi", "--jail", self.world.run_id])
        terminal.expect(b"agent-ready")
        self.world.run(("jail", "stop"))
        code, text = terminal.finish()
        self.assertEqual(code, 1, text)
        self.assertIn("code=agent_session_killed", text)
        # The killed ssh never restored it: this command did.
        self.assertEqual(termios.tcgetattr(terminal.slave), terminal.original)

    def test_owned_interactive_retained_or_discarded(self):
        terminal = self.terminal(["pi"])
        terminal.expect(b"agent-ready")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        run_id = text.split("run: created id=", 1)[1].split()[0]
        self.assertIn(f"run: retained id={run_id}", text)
        self.assertEqual((self.record(run_id)["phase"], self.record(run_id)["retention"]), ("ready", "home"))
        terminal = self.terminal(["pi", "--image", self.world.image, "--discard"])
        terminal.expect(b"agent-ready")
        terminal.send(b"q")
        code, text = terminal.finish()
        self.assertEqual(code, 1, text)
        self.assertIn("agentbox: agent: exit=3", text)
        run_id = text.split("run: created id=", 1)[1].split()[0]
        self.assertEqual((self.record(run_id)["phase"], self.record(run_id)["retention"]), ("discarded", "none"))

    def test_an_explicit_retention_provider_keeps_nothing_unasked(self):
        # A shared Podman store: HOME only by jail create --retention.
        self.world.set_behavior(retention=["none", "home"], features=["explicit_retention"])
        terminal = self.terminal(["pi"])
        terminal.expect(b"agent-ready")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        run_id = text.split("run: created id=", 1)[1].split()[0]
        self.assertIn(f"run: created id={run_id} kind=managed owned=true retention=none", text)
        self.assertNotIn("run: retained", text)
        self.assertIn(f"discard: {run_id} discarded", text)
        self.assertEqual((self.record(run_id)["phase"], self.record(run_id)["retention"]), ("discarded", "none"))
        # --discard: the same, still accepted.
        terminal = self.terminal(["pi", "--discard"])
        terminal.expect(b"agent-ready")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        self.assertIn("retention=none", text)
        # Storage an option needs is never made unasked: refused, no run.
        before = self.runs()
        code, _, err = self.owned("pi", ["--prompt", "p", "--export-to", f"{self.world.tmp}/w.tar"])
        self.assertEqual(code, 1, err)
        self.assertIn("agentbox: run refused: retention_explicit\n"
                      f"agentbox: hint: {lifecycle.EXPLICIT_RETENTION_HINT}\n", err)
        self.assertEqual(self.runs(), before)
        # The run asked for by name keeps its HOME and is never discarded.
        terminal = self.terminal(["pi", "--jail", self.world.run_id])
        terminal.expect(b"agent-ready")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        self.assertEqual(self.record(self.world.run_id)["phase"], "ready")

    def test_terminal_required_and_no_export_or_install(self):
        code, _, err = self.jail("pi", [])
        self.assertEqual(err.strip(), "agentbox: run refused: interactive_terminal_required")
        code, _, err = self.jail("pi", ["--export-to", f"{self.world.tmp}/x.tar"])
        self.assertEqual(err.strip(), "agentbox: run refused: interactive_export_unsupported")
        # Always untimed: a timeout is refused, never ignored.
        code, _, err = self.jail("pi", ["--timeout", "60"])
        self.assertEqual((code, err.strip()), (1, "agentbox: run refused: interactive_timeout_unsupported"))
        # A headless run's lane is its installer's alone.
        code, _, err = self.jail("pi", ["--prompt", "x", "--acquisition-config", self.world.acquisition()])
        self.assertEqual((code, err.strip()), (1, "agentbox: run refused: headless_acquisition_unsupported"))
        for extra in (["--acquisition-stage-root", self.world.tmp], ["--prompt", "x", "--timeout", "0"],
                      ["--prompt", "x", "--timeout", str(7 * 24 * 3600 + 1)]):
            code, _, err = self.jail("pi", extra)
            self.assertEqual(code, 2, err)
        self.assertEqual(self.world.agent_log(), [])

    def test_the_persistent_acquisition_file_is_read_before_anything(self):
        """No --acquisition-config: acquisition.json's lane, refused when
        unreadable (never the packaged defaults) before any guest step."""
        write_file(self.world.acquisition_default, "{", 0o666)
        code, text = self.terminal(["pi", "--jail", self.world.run_id]).finish()
        self.assertEqual(code, 1, text)
        self.assertIn("agentbox: run refused: acquisition_config_unreadable", text)
        self.assertNotIn("serve:", text)
        self.assertEqual(self.world.agent_log(), [])

    def test_the_session_shares_its_lane_with_shell_logins(self):
        """--acquisition-config: the agent and `shell` logins in the owner's
        one request context, one grant (2 here) for the whole session."""
        terminal = self.terminal(["pi", "--jail", self.world.run_id,
                                  "--acquisition-config", self.world.acquisition()],
                                 overrides=dict(QUICK, **{"acquisition.MAX_REQUESTS": 2}))
        terminal.expect(b"agent-ready")
        with open(f"{self.world.data}/controller-runs/{self.world.run_id}/owner/shell.json") as stream:
            session = json.load(stream)["profile"]["session"]
        terminal.send(b"r")
        terminal.expect(b"request ok")
        code, out, err = self.world.run(("shell",), ["--", "/bin/sh", "-c", "echo $AGENTBOX_REQUEST_SESSION; "
                                                     "agentbox-request echo say '{\"text\":\"s\"}'"],
                                        overrides=QUICK)
        self.assertEqual(code, 0, err)
        self.assertEqual(out.splitlines()[0], session)
        self.assertIn('"ok":true', out)
        # The grant is spent: the agent's next request is refused.
        terminal.send(b"r")
        terminal.expect(b"request failed")
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        serve = fields([l for l in text.splitlines() if l.startswith("serve: ")][-1])
        self.assertEqual((serve["reason"], serve["host_cleanup"]), ("cancelled", "confirmed"), text)
        self.assertNotIn("acquisition_cleanup", serve)
        entry = self.world.agent_log()[-1]
        self.assertEqual((entry["env"]["AGENTBOX_REQUEST_SESSION"], entry["env"]["AGENTBOX_WORK_ROOT"]),
                         (session, f"{self.world.home}/work"))
        closed = [e for e in self.world.events() if e["event_type"] == "host.handler.lane_closed"][-1]
        self.assertEqual((closed["attributes"]["requests"], closed["attributes"]["uploads"],
                          closed["attributes"]["cleanup_confirmed"]), (2, 2, True))
        scp = [t["operands"][-1].split(":", 1)[1] for t in self.world.transfers() if t["program"] == "scp"]
        self.assertEqual(scp[-2:], [f"{self.world.home}/work/.agentbox-requests/{session}-req-{n}.artifact"
                                    for n in (1, 2)])


class SetupDeadline(Interactive):
    """An untimed owner's setup has one fixed deadline until its guest is
    ready (execute.SETUP_TIMEOUT, shortened here); only then untimed."""
    SETUP = 6.0

    def quick(self, **more):
        return dict(QUICK, **{"execute.SETUP_TIMEOUT": self.SETUP}, **more)

    def expired(self, args, overrides):
        started = time.monotonic()
        terminal = self.terminal(args, overrides=overrides)
        code, text = terminal.finish(120)
        elapsed = time.monotonic() - started
        self.assertEqual(code, 1, text)
        self.assertGreaterEqual(elapsed, self.SETUP)
        self.assertLess(elapsed, self.SETUP + 30)
        serve = fields([l for l in text.splitlines() if l.startswith("serve: ")][-1])
        self.assertEqual((serve["reason"], serve["host_cleanup"]), ("timeout", "confirmed"), text)
        self.assertIn("code=agent_not_started", text)
        # No staging, no PTY: the session never began.
        self.assertEqual([e for e in self.world.ssh_entries() if e["mode"] in ("staging", "shell")], [])
        self.assertEqual(self.world.agent_log(), [])
        self.assertIsNone(self.record(self.world.run_id)["pending"])
        self.assertEqual(self.world.domains(), [])
        self.assertEqual(termios.tcgetattr(terminal.slave), terminal.original)
        return text

    def test_no_hello_ends_at_the_setup_deadline(self):
        self.world.set_ssh(fail="hang")
        self.expired(["pi", "--jail", self.world.run_id], self.quick())

    def test_no_inputs_ready_ends_at_the_setup_deadline_despite_output(self):
        self.world.set_ssh(fail="hang_inputs")
        source = f"{self.world.tmp}/ws"
        os.mkdir(source, 0o755)
        write_file(f"{source}/a.txt", "a", 0o644)
        # The upload allowance (1 s) extends it once; stderr noise never does.
        settings = dict(inputs_mod.DEFAULT_SETTINGS, upload_timeout_ms=1000)
        self.expired(["pi", "--jail", self.world.run_id,
                      "--workspace", source], self.quick(**{"inputs.DEFAULT_SETTINGS": settings}))
        session = [e for e in self.world.ssh_entries() if e["mode"] == "session"]
        self.assertTrue(session)

    def test_a_ready_session_outlives_the_setup_deadline(self):
        started = time.monotonic()
        terminal = self.terminal(["pi", "--jail", self.world.run_id],
                                 overrides=self.quick())
        terminal.expect(b"agent-ready")
        self.assertLess(time.monotonic() - started, self.SETUP)
        while time.monotonic() < started + self.SETUP + 3:
            terminal.read(0.2)
        self.assertIsNone(terminal.proc.poll())
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        serve = fields([l for l in text.splitlines() if l.startswith("serve: ")][-1])
        self.assertEqual(serve["reason"], "cancelled")
        self.assertEqual(termios.tcgetattr(terminal.slave), terminal.original)

    test_terminal_session_raw_resize_ctrl_c_eot = None
    test_run_stop_ends_the_session = None
    test_kill_after_ignored_term_restores_the_terminal = None
    test_owned_interactive_retained_or_discarded = None
    test_terminal_required_and_no_export_or_install = None
    test_the_session_shares_its_lane_with_shell_logins = None


class TimedSetup(Agents):
    kind = "managed"

    def test_untimed_owners_setup_is_bounded_and_timed_ones_keep_their_own(self):
        # Untimed (serve; exec without --timeout): setup ends at the fixed
        # setup bound (shortened), never later.
        self.world.set_ssh(fail="hang")
        short = dict(QUICK, **{"execute.SETUP_TIMEOUT": 3.0})
        for command, extra, prefix in ((("jail", "serve"), [], "serve: "),
                                       (("jail", "exec"), ["--", "/bin/true"], "execution: ")):
            started = time.monotonic()
            code, out, err = self.world.run(command, extra, overrides=short, timeout=60)
            self.assertLess(time.monotonic() - started, 30)
            self.assertEqual(code, 1, err)
            line = fields([l for l in (out + err).splitlines() if l.startswith(prefix)][-1])
            self.assertEqual((line["reason"], line["host_cleanup"]), ("timeout", "confirmed"), err)
        # The untimed setup bound never applies to a timed execution.
        self.world.set_ssh(fail=None)
        code, out, err = self.world.run(("jail", "exec"), ["--timeout", "60", "--", "/bin/sleep", "1"],
                                        overrides=dict(QUICK, **{"execute.SETUP_TIMEOUT": 0.001}), timeout=60)
        self.assertEqual(code, 0, err)
        # Untimed once ready: past the (shortened) setup bound, completed.
        code, out, err = self.world.run(("jail", "exec"), ["--", "/bin/sleep", "4"], overrides=short, timeout=60)
        self.assertEqual(code, 0, err)

    def test_a_headless_agent_is_untimed_unless_given_a_timeout(self):
        code, out, err = self.jail("pi", ["--prompt", "sleep:4"],
                                   overrides=dict(QUICK, **{"execute.SETUP_TIMEOUT": 3.0}))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.execution_line(out)["reason"], "completed")
        started = time.monotonic()
        code, out, err = self.jail("pi", ["--prompt", "sleep:60", "--timeout", "3"])
        self.assertLess(time.monotonic() - started, 45)
        self.assertEqual(code, 1, err)
        self.assertEqual(self.execution_line(err)["reason"], "timeout")


class StdioInteractive(Interactive):
    transport = "stdio"

    def test_terminal_session_raw_resize_ctrl_c_eot(self):
        super().test_terminal_session_raw_resize_ctrl_c_eot()
        shells = [e for e in self.world.ssh_entries() if e["mode"] in ("staging", "shell")]
        self.assertTrue(shells)
        self.assertTrue(all("ProxyUseFdpass" not in e["options"] and e["bridge"] == "standin-connect"
                            and e["echoed"] == "ping" and e["proxy_exit"] == 0
                            and " jail shell-transport " in e["proxy_command"] for e in shells), shells)
        # Each became the provider's connect itself (exec all the way), in
        # its own slot of the owner's domain (the owner's own ssh's connects
        # are their ssh's children in its leaf).
        pids = {e["proxy_pid"]: e for e in shells}
        connects = [e for e in self.world.provider_log() if e.get("argv") == "connect" and e["pid"] in pids]
        self.assertEqual(len(connects), len(shells))
        self.assertEqual(sorted(e["leaf"] for e in connects), sorted(f"s-{n}" for n in range(1, len(shells) + 1)))

    def test_caller_environment_reaches_the_transport_only(self):
        """The agent command's own environment reaches each SSH's transport
        and so the provider's connect, sanitized (never SHELL, never its
        AGENTBOX_* over the owner's), and is never published."""
        records = f"{self.world.data}/controller-runs/{self.world.run_id}/owner"
        terminal = self.terminal(["pi", "--jail", self.world.run_id],
                                 env={"AB_CALLER_ONLY": "harmless-agent", "SHELL": "/bin/false",
                                      "AGENTBOX_CUSTODY": "/bogus",
                                      "AGENTBOX_STORAGE_SCOPES": "/bogus/run-limits.json"})
        terminal.expect(b"agent-ready")
        for name in ("owner.json", "shell.json"):
            with open(f"{records}/{name}") as stream:
                self.assertNotIn("harmless", stream.read())
        terminal.send(b"\x04")
        code, text = terminal.finish()
        self.assertEqual(code, 0, text)
        shells = [e for e in self.world.ssh_entries() if e["mode"] in ("staging", "shell")]
        pids = {e["proxy_pid"] for e in shells}
        connects = [e for e in self.world.provider_log() if e.get("argv") == "connect" and e["pid"] in pids]
        self.assertEqual(len(connects), len(shells))
        for entry in shells:
            self.assertEqual(entry["env"]["AB_CALLER_ONLY"], "harmless-agent")
            self.assertFalse([k for k in entry["env"] if k == "SHELL" or k.startswith("AGENTBOX_")])
        for connect in connects:
            self.assertIn("AB_CALLER_ONLY", connect["env"])
            self.assertNotIn("SHELL", connect["env"])
            self.assertEqual(connect["scopes"], f"{self.world.data}/run-limits.json")
            self.assertTrue(connect["custody"].startswith(f"{self.world.cgroup}/cg/"))

    test_run_stop_ends_the_session = None
    test_kill_after_ignored_term_restores_the_terminal = None
    test_owned_interactive_retained_or_discarded = None
    test_terminal_required_and_no_export_or_install = None


class Units(unittest.TestCase):
    def test_framing_and_receipt(self):
        plan = agent_mod.Plan({"schema": agent_mod.PLAN_SCHEMA, "argv": ["-c", "x"], "python": True,
                               "settings": {"argv": ["pi"], "auth": {"path": ".pi/agent/auth.json", "keep": False}},
                               "credential": "secret", "not_after_ms": None, "install": False})
        self.assertEqual(plan.credential_path, ".pi/agent/auth.json")
        data = agent_mod.framed(plan, "prompt")
        header, _, rest = data.partition(b"\n")
        self.assertEqual(json.loads(header)["prompt_bytes"], 6)
        self.assertEqual(rest, b"promptsecret")
        self.assertNotIn("secret", repr(plan))
        staged = agent_mod.framed(plan, "", ("a" * 32, {"X": "1"}))
        self.assertEqual(json.loads(staged.partition(b"\n")[0])["env"], {"X": "1"})
        with self.assertRaises(HostError) as caught:
            agent_mod.framed(plan, "", ("a" * 32, {"X": "v" * agent_mod.MAX_INPUT_BYTES}))
        self.assertEqual(caught.exception.code, "env_limit_exceeded")
        self.assertEqual(agent_mod.receipt(b"1:2:3:4\n"), "1:2:3:4")
        for bad in (b"1:2:3\n", b"1:2:3:4", b"1:2:3:4\nx", b"a:2:3:4\n", b"1:2:3:99999999999999999999\n"):
            self.assertIsNone(agent_mod.receipt(bad))
        for install in (None, "yes", 0):
            with self.assertRaises(HostError):
                agent_mod.Plan({"schema": agent_mod.PLAN_SCHEMA, "argv": ["x"], "settings": {},
                                "credential": None, "not_after_ms": None, "install": install})
        self.assertFalse(agent_mod.is_model("-m"))
        self.assertFalse(agent_mod.is_model("a b"))

    def test_credential_and_install_locations_keep_off_mounts(self):
        def plan(auth, install=False, credential="secret"):
            return agent_mod.Plan({"schema": agent_mod.PLAN_SCHEMA, "argv": ["x"],
                                   "settings": {"argv": ["pi"], "auth": auth, "package": None},
                                   "credential": credential, "not_after_ms": None, "install": install})
        # A credential's destination: a plain relative path, else no plan.
        for auth in (None, {}, {"path": None}, {"path": ""}, {"path": "/abs"}, {"path": "a//b"},
                     {"path": "a/../b"}, {"path": "./a"}, {"path": "a/"}, {"path": "a\0"}):
            with self.assertRaises(HostError) as caught:
                plan(auth)
            self.assertEqual(caught.exception.code, "adapter_plan_invalid", auth)
        self.assertIsNone(plan(None, credential=None).credential_path)
        auth = {"path": ".pi/agent/auth.json", "keep": True}

        def mounts(*destinations):
            return [{"source": "/s/" + d, "destination": d, "access": "ro"} for d in destinations]
        for destination in (".pi", ".pi/agent", ".pi/agent/auth.json"):
            with self.assertRaises(HostError) as caught:
                agentrun.check_mounted(plan(auth), "pi", mounts("work", destination))
            self.assertEqual(caught.exception.code, "auth_location_mounted", destination)
        for destination in (".local", ".local/share/agentbox-agents", ".local/share/agentbox-agents/pi/1.0.0"):
            with self.assertRaises(HostError) as caught:
                agentrun.check_mounted(plan(None, True, None), "pi", mounts(destination))
            self.assertEqual(caught.exception.code, "install_location_mounted", destination)
        # Beside them, or nothing copied or installed: no refusal.
        agentrun.check_mounted(plan(auth, True), "pi", mounts(".pi-other", ".piano", ".local/bin", ".claude",
                                                               ".local/share/agentbox-agents/codex"))
        agentrun.check_mounted(plan(None, credential=None), "pi", mounts(".pi", ".local"))

    def test_the_install_root_is_the_runners(self):
        from agentbox_controller.assets import ASSETS
        with open(os.path.join(ASSETS, "agents", "jail", "run.py")) as stream:
            text = stream.read()
        self.assertIn('AGENTS = os.path.join(HOME, %s)' % ", ".join(
            '"%s"' % part for part in agent_mod.INSTALL_ROOT.split("/")), text)

    def test_the_lane_only_when_asked(self):
        """An adapter whose plan's `install` differs from the request's:
        refused, whichever way."""
        assets = tempfile.mkdtemp(prefix="abt-")
        self.addCleanup(shutil.rmtree, assets, True)
        os.makedirs(f"{assets}/agents/pi")
        for asked, planned in ((False, True), (None, False), ("1.2.3", False)):
            with open(f"{assets}/agents/pi/adapter.py", "w") as stream:
                stream.write("import json, os, sys\nsys.stdin.read()\n"
                             "sys.stdout.write(json.dumps({'schema': 'agentbox.agent-plan.v1', 'argv': ['x'], "
                             "'settings': {}, 'credential': None, 'not_after_ms': None, 'install': %r}))\n"
                             "os.write(3, b'{\"schema\":\"agentbox.agent-result.v1\",\"outcome\":\"ok\"}\\n')\n"
                             % planned)
            value = agent_mod.request("pi", None, asked, None, None)
            with self.assertRaises(HostError) as caught:
                agent_mod.prepare(sys.executable, assets, value, lambda line: None)
            self.assertEqual(caught.exception.code, "adapter_plan_invalid", asked)
        value = agent_mod.request("pi", None, False, None, None)
        self.assertIs(agent_mod.prepare(sys.executable, assets, value, lambda line: None).install, False)

    def test_expiry(self):
        plan = agent_mod.Plan({"schema": agent_mod.PLAN_SCHEMA, "argv": ["x"], "settings": {},
                               "credential": None, "not_after_ms": 1000, "install": False})
        with self.assertRaises(HostError):
            plan.check_expiry(0)

    def test_server_trust_accepts_user_group_write_but_refuses_world_write(self):
        directory = tempfile.mkdtemp(prefix="abt-")
        self.addCleanup(shutil.rmtree, directory, True)
        path = f"{directory}/agentbox-server"
        with open(path, "wb") as stream:
            stream.write(b"#!/bin/false\n")
        os.chown(path, -1, os.getegid())
        for mode, trusted in ((0o755, True), (0o775, True), (0o757, False), (0o777, False), (0o644, False)):
            os.chmod(path, mode)
            if trusted:
                self.assertEqual(config_mod.check_server(path), path)
                continue
            with self.assertRaises(HostError) as caught:
                config_mod.check_server(path)
            self.assertEqual(caught.exception.code, "server_untrusted", oct(mode))
        # A root-owned install may only be group-writable if we are root.
        real = os.lstat(path)
        fake = os.stat_result((stat.S_IFREG | 0o775, real.st_ino, real.st_dev, 1, 0, 0, 1, 0, 0, 0))
        with unittest.mock.patch.object(config_mod.os, "lstat", return_value=fake), \
                unittest.mock.patch.object(config_mod.os, "geteuid", return_value=1000):
            with self.assertRaises(HostError) as caught:
                config_mod.check_server(path)
        self.assertEqual(caught.exception.code, "server_untrusted")

    def test_restoration_failure_fails_the_command(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        self.addCleanup(os.close, w)
        session = interactive.Session(None, "a" * 32, b"", "/bin/false", "dumb", None, {}, tty=r)
        session.saved = [0, 0, 0, 0, 0, 0, [b"\0"] * 32]
        session.agent = ("ended", 0)
        session._restore_terminal()
        lines = []
        self.assertEqual(session.report(lines.append, lines.append), 1)
        self.assertIn("code=terminal_restore_failed", "".join(lines))


class SharedSignals(unittest.TestCase):
    """host.share_signals: every interrupt counted once, in the handler,
    across loops and between them."""

    def setUp(self):
        previous = {n: signal.getsignal(n) for n in host.TERMINATING}
        shared = host.SHARED

        def restore():
            for number, handler in previous.items():
                signal.signal(number, handler)
            host.SHARED = shared
        self.addCleanup(restore)
        host.share_signals()

    def test_a_signal_after_the_last_step_survives_close(self):
        loop = host.Loop()
        loop.install_signals()
        loop.step(0)
        os.kill(os.getpid(), signal.SIGINT)
        # No step drains the wakeup byte: close loses it, not the count.
        loop.close()
        self.assertEqual(host.SHARED, [signal.SIGINT])
        following = host.Loop()
        try:
            self.assertIs(following.signals, host.SHARED)
            self.assertTrue(following.signals)
        finally:
            following.close()

    def test_counted_once_second_forces_and_between_loops_retained(self):
        loop = host.Loop()
        loop.install_signals()
        os.kill(os.getpid(), signal.SIGTERM)
        loop.step(0.2)
        loop.step(0)
        self.assertEqual(len(loop.signals), 1)
        os.kill(os.getpid(), signal.SIGINT)
        loop.step(0.2)
        self.assertEqual(len(loop.signals), 2)
        loop.close()
        os.kill(os.getpid(), signal.SIGHUP)
        self.assertEqual(host.SHARED, [signal.SIGTERM, signal.SIGINT, signal.SIGHUP])
        # A cleanup's start: a fresh budget, only later interrupts count.
        fresh = host.share_signals()
        self.assertEqual(fresh, [])
        nxt = host.Loop()
        try:
            self.assertIs(nxt.signals, fresh)
        finally:
            nxt.close()

    def test_an_interrupt_during_one_step_stops_the_next(self):
        calls = []
        out, err = io.StringIO(), io.StringIO()
        run = agentrun.AgentRun(None, None, None, {}, {}, out, err)
        run.chosen = object()

        def stage_inputs(_run_id):
            loop = host.Loop()
            loop.install_signals()
            loop.step(0)
            os.kill(os.getpid(), signal.SIGINT)
            loop.close()

        run.stage_inputs = stage_inputs
        run.headless = lambda run_id: calls.append(run_id)
        self.assertEqual(run.task("r-1", False, True), 1)
        self.assertEqual(calls, [])
        self.assertIn("code=interrupted", err.getvalue())


if __name__ == "__main__":
    unittest.main()
