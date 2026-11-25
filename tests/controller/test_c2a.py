"""C2a offline: the owner's published records (owner.py: strict private
files, stop identity by pidfd, the process-lifetime stop handler), timed
`jail serve`, `jail stop` on a busy owner, `shell` with its stdio transport
(slots of the owner's domain, EOF/SIGHUP, the cap, `%` escaping), D's
removal retried and an unconfirmed one kept pending, `jail export`, `jail
exec --export-to` with the operator's export assertion (the user's
decision), and `doctor`. Stand-in ssh, provider and FakeCgroups only: no
native SSH, systemd, Podman, QEMU, agent or model; nothing here proves
OpenSSH's own ProxyCommand handling or a real cross-unit cgroup move.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests -t .
"""
import json
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from agentbox_controller import cgroups, doctor, execute, export, host as host_mod, lifecycle, owner as owner_mod, \
    shell
from agentbox_controller import store as store_mod
from agentbox_controller.host import HostError
from tests.controller import fakes, harness
from tests.controller.harness import World, write_file
from tests.controller.test_execution import QUICK, fields, until


def reap(proc):
    if proc.poll() is None:
        proc.kill()
    if any(p is not None and not p.closed for p in (proc.stdout, proc.stderr)):
        proc.communicate()


def kill_strays(tmp):
    """Every process still running from this world (an attached export's
    ssh outlives a SIGKILLed controller: a plain process group, choice B)."""
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) == os.getpid():
            continue
        try:
            with open(f"/proc/{name}/cmdline", "rb") as stream:
                if tmp.encode() in stream.read():
                    os.kill(int(name), signal.SIGKILL)
        except OSError:
            pass


def read_text(path):
    try:
        with open(path) as stream:
            return stream.read()
    except OSError:
        return ""


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.01)
    return predicate()


class Private(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abu-")
        os.chmod(self.tmp, 0o700)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def refused(self, code, fn, *args, **kwargs):
        with self.assertRaises(HostError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


PROFILE = {"user": "agentbox", "identity": "/s/id_ed25519", "known_hosts": "/s/known_hosts",
           "alias": "agentbox-r-e", "launcher": "/c/launcher", "endpoint": None,
           "session": "0123456789abcdef0123456789abcdef"}


class Records(Private):
    """owner.py in one process: a fixture run's lease, its records."""

    def setUp(self):
        super().setUp()
        data = f"{self.tmp}/data"
        os.makedirs(data, 0o700)
        self.store = store_mod.Store(data)
        self.addCleanup(self.store.close)
        provider = {"schema": "agentbox.provider-config.v1", "provider": "p", "interpreter": "/usr/bin/python3",
                    "entry": f"{self.tmp}/a/e.py", "state": f"{self.tmp}/s", "assets": f"{self.tmp}/a"}
        self.run_id = harness.fixture_run(self.store, provider, harness.payload()["manifest"], retention="disk")
        self.lease = self.store.claim(self.run_id)
        self.addCleanup(self.lease.release)
        self.dir = f"{data}/controller-runs/{self.run_id}/owner"

    def publish(self, serve=True):
        execution = store_mod.new_id("e")
        publication = owner_mod.Publication(self.lease, execution, serve)
        self.addCleanup(publication.close)
        return publication, execution

    def write(self, name, value, mode=0o600):
        os.makedirs(self.dir, 0o700, exist_ok=True)
        data = value if isinstance(value, bytes) else json.dumps(value).encode()
        path = f"{self.dir}/{name}"
        with open(path, "wb") as stream:
            stream.write(data)
        os.chmod(path, mode)

    def record(self, pid, **changes):
        value = {"schema": owner_mod.OWNER_SCHEMA, "execution": store_mod.new_id("e"), "serve": True, "pid": pid,
                 "boot": owner_mod.boot_id(), "start": owner_mod.start_time(pid)}
        value.update(changes)
        return value

    def sleeper(self):
        proc = subprocess.Popen(["sleep", "30"])
        self.addCleanup(reap, proc)
        return proc

    def test_published_private_and_withdrawn(self):
        publication, execution = self.publish()
        self.assertEqual(os.stat(self.dir).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(f"{self.dir}/owner.json").st_mode & 0o777, 0o600)
        owner, shell_record = owner_mod.records(self.store, self.run_id)
        self.assertEqual((owner["execution"], owner["pid"], owner["serve"], shell_record),
                         (execution, os.getpid(), True, None))
        self.refused("shell_not_ready", owner_mod.serving, self.store, self.run_id)
        publication.serving(PROFILE, "/usr/bin:/bin")
        self.assertEqual(owner_mod.serving(self.store, self.run_id), (execution, PROFILE, "/usr/bin:/bin"))
        self.refused("invocation_stale", owner_mod.serving, self.store, self.run_id, store_mod.new_id("e"))
        self.assertTrue(publication.withdraw())
        self.refused("shell_not_ready", owner_mod.serving, self.store, self.run_id)
        # Only a bounded PATH: never another value, never a relative entry.
        for path in ("relative:/bin", "/bin:" + "/x" * 3000, ""):
            self.refused("shell_unpublished", publication.serving, PROFILE, path)
        publication.close()
        self.assertEqual(os.listdir(self.dir), [])
        self.assertEqual(owner_mod.records(self.store, self.run_id), (None, None))

    def test_exec_owner_has_no_shell(self):
        self.publish(serve=False)
        self.refused("shell_unsupported", owner_mod.serving, self.store, self.run_id)

    def test_a_gone_owners_records_replaced(self):
        dead = subprocess.Popen(["true"])
        dead.wait()
        self.write("owner.json", self.record(dead.pid, start=0))
        self.write("shell.json", {"schema": owner_mod.SHELL_SCHEMA, "execution": store_mod.new_id("e"),
                                  "profile": PROFILE, "path": None})
        self.refused("owner_unreachable", owner_mod.serving, self.store, self.run_id)
        self.refused("run_busy", owner_mod.request_stop, self.store, self.run_id)
        _, execution = self.publish()
        owner, shell_record = owner_mod.records(self.store, self.run_id)
        self.assertEqual((owner["execution"], shell_record), (execution, None))

    def test_strict_records(self):
        good = self.record(os.getpid())
        text = json.dumps(good)
        for data, mode in ((text.replace('"serve": true', '"serve": true, "serve": true').encode(), 0o600),
                           (json.dumps(dict(good, extra=1)).encode(), 0o600),
                           (json.dumps(dict(good, schema="x")).encode(), 0o600),
                           (json.dumps(dict(good, pid=True)).encode(), 0o600),
                           (json.dumps(dict(good, boot="b")).encode(), 0o600),
                           (json.dumps(dict(good, execution="e-x")).encode(), 0o600),
                           ((text + " " * owner_mod.MAX_RECORD).encode(), 0o600),
                           (b"\xff", 0o600), (b"[]", 0o600),
                           (text.encode(), 0o644)):
            self.write("owner.json", data, mode)
            self.refused("owner_record_invalid", owner_mod.records, self.store, self.run_id)
            self.refused("owner_record_invalid", owner_mod.request_stop, self.store, self.run_id)
        self.write("owner.json", text.encode())
        os.chmod(self.dir, 0o755)
        self.refused("owner_record_invalid", owner_mod.records, self.store, self.run_id)
        os.chmod(self.dir, 0o700)
        os.unlink(f"{self.dir}/owner.json")
        os.symlink("/etc/hostname", f"{self.dir}/owner.json")
        self.refused("owner_record_invalid", owner_mod.records, self.store, self.run_id)
        os.unlink(f"{self.dir}/owner.json")
        shell_good = {"schema": owner_mod.SHELL_SCHEMA, "execution": good["execution"], "profile": PROFILE,
                      "path": None}
        self.write("owner.json", text.encode())
        for bad in (dict(shell_good, profile=dict(PROFILE, extra=1)), dict(shell_good, path="a:b"),
                    dict(shell_good, env={"X": "1"})):
            self.write("shell.json", bad)
            self.refused("owner_record_invalid", owner_mod.records, self.store, self.run_id)

    def test_no_signal_to_another_process(self):
        """A record naming a live process that is not the one it recorded
        (another start time: a reused pid; another boot) refuses; the
        process is untouched. The right identity reaches it."""
        victim = self.sleeper()
        for record in (self.record(victim.pid, start=owner_mod.start_time(victim.pid) + 1),
                       self.record(victim.pid, boot="0" * 8 + "-0000-0000-0000-" + "0" * 12)):
            self.write("owner.json", record)
            self.refused("run_busy", owner_mod.request_stop, self.store, self.run_id)
            self.refused("owner_unreachable", owner_mod.serving, self.store, self.run_id)
        time.sleep(0.2)
        self.assertIsNone(victim.poll())
        # Control: its exact identity is signalled (sleep has no handler).
        self.write("owner.json", self.record(victim.pid))
        owner_mod.request_stop(self.store, self.run_id)
        self.assertEqual(victim.wait(timeout=10), -signal.SIGUSR1)
        self.refused("run_busy", owner_mod.request_stop, self.store, self.run_id)

    def test_handler_inactive_ignores_and_active_requests(self):
        owner_mod.install()
        os.kill(os.getpid(), signal.SIGUSR1)
        time.sleep(0.05)
        self.assertFalse(owner_mod.stop_requested())
        publication, _ = self.publish()
        self.assertFalse(owner_mod.stop_requested())
        owner_mod.request_stop(self.store, self.run_id)
        self.assertTrue(wait_for(owner_mod.stop_requested))
        # Repeated: still one request, never anything more.
        owner_mod.request_stop(self.store, self.run_id)
        self.assertTrue(owner_mod.stop_requested())
        self.assertEqual(signal.getsignal(signal.SIGUSR1), owner_mod._on_stop)
        publication.close()
        self.assertFalse(owner_mod.stop_requested())
        # Late: after the withdrawal the handler stays and ignores it.
        os.kill(os.getpid(), signal.SIGUSR1)
        time.sleep(0.05)
        self.assertFalse(owner_mod.stop_requested())
        self.assertEqual(signal.getsignal(signal.SIGUSR1), owner_mod._on_stop)
        # A later execution of this process starts without that request.
        self.publish()
        self.assertFalse(owner_mod.stop_requested())


class Slots(Private):
    """cgroups.Domain.join_slot over FakeCgroups."""

    def domain(self, host=None):
        host = host or fakes.FakeCgroups(self.tmp)
        cgroups.enter(host)
        domain = cgroups.Domain.create(host, cgroups.envelope({}))
        self.addCleanup(domain.close)
        return host, domain

    def test_cumulative_cap(self):
        host, domain = self.domain()
        names = [domain.join_slot() for _ in range(cgroups.MAX_SLOTS)]
        self.assertEqual(names, [f"s-{n}" for n in range(1, 33)])
        self.assertEqual(host.self_names()[-2:], [domain.name, "s-32"])
        with self.assertRaises(HostError) as caught:
            domain.join_slot()
        self.assertEqual(caught.exception.code, "shell_limit")
        # The owner's own leaves never collide with them.
        self.assertEqual(domain.named_leaf()[1], "h-1")

    def test_concurrent_claims_never_share(self):
        local = threading.local()

        class Host(fakes.FakeCgroups):
            def move_self(self, leaf_fd):
                super().move_self(leaf_fd)
                local.names = os.path.relpath(self._path(leaf_fd), self.root).split("/")

            def self_names(self):
                return getattr(local, "names", None) or super().self_names()

        _, domain = self.domain(Host(self.tmp))
        results = []

        def claim():
            try:
                results.append(domain.join_slot())
            except HostError as error:
                results.append(error.code)

        threads = [threading.Thread(target=claim) for _ in range(40)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        slots = [r for r in results if r.startswith("s-")]
        self.assertEqual(len(slots), 32)
        self.assertEqual(len(set(slots)), 32)
        self.assertEqual(sorted(r for r in results if not r.startswith("s-")), ["shell_limit"] * 8)

    def test_an_existing_slot_is_anothers(self):
        host, domain = self.domain()
        host.make(domain.fd, "s-1")
        self.assertEqual(domain.join_slot(), "s-2")
        self.assertEqual(host.self_names()[-1], "s-2")


class KillDomain(Private):
    """execute.Execution._kill_domain: a transport joining between D's
    kill and its removal is killed again, the removal retried within
    KILL_TIMEOUT; an unconfirmed removal is never settled."""

    def owner(self, host):
        cgroups.enter(host)
        domain = cgroups.Domain.create(host, cgroups.envelope({}))
        self.addCleanup(domain.close)
        events = []
        stub = types.SimpleNamespace(domain=domain, idle=time.sleep,
                                     event=lambda kind, *a, **k: events.append(kind))
        return stub, domain, events

    def late(self, join):
        tmp = self.tmp

        class Host(fakes.FakeCgroups):
            joined = False

            def remove(self, dir_fd, name):
                if name.startswith("agentbox-") and not Host.joined:
                    Host.joined = True
                    join(self, self.open_sub(dir_fd, name))
                return super().remove(dir_fd, name)

        return Host(tmp)

    def test_late_empty_slot_removed(self):
        def join(host, fd):
            host.make(fd, "s-1")
            os.close(fd)

        stub, domain, events = self.owner(self.late(join))
        self.assertTrue(execute.Execution._kill_domain(stub))
        self.assertTrue(domain.removed)
        self.assertEqual(events, [])

    def test_late_member_killed_then_removed(self):
        procs = []

        def join(host, fd):
            host.make(fd, "s-1")
            proc = subprocess.Popen(["sleep", "30"])
            procs.append(proc)
            self.addCleanup(reap, proc)
            with open(os.path.join(host._path(fd), "s-1", "cgroup.procs"), "w") as stream:
                stream.write(f"{proc.pid}\n")
            os.close(fd)

        stub, domain, events = self.owner(self.late(join))
        self.assertTrue(execute.Execution._kill_domain(stub))
        self.assertEqual(procs[0].wait(timeout=10), -signal.SIGKILL)
        self.assertTrue(domain.removed)

    def test_recovery_requires_the_removal(self):
        """lifecycle.kill_recorded (`jail stop`): the same retry and bound."""
        def join(host, fd):
            host.make(fd, "s-1")
            os.close(fd)

        host = self.late(join)
        stub, domain, _ = self.owner(host)
        record = domain.record()
        self.assertTrue(lifecycle.kill_recorded(types.SimpleNamespace(cgroups=host), record))
        self.assertFalse(os.path.exists(record["path"]))
        stuck = fakes.FakeCgroups(self.tmp)
        stub, domain, _ = self.owner(stuck)
        stuck.stuck_remove = True
        before = len(os.listdir("/proc/self/fd"))
        with mock.patch.object(lifecycle, "KILL_TIMEOUT", 0.3):
            self.assertFalse(lifecycle.kill_recorded(types.SimpleNamespace(cgroups=stuck), domain.record()))
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertTrue(os.path.exists(domain.path))

    def test_permanent_failure_not_settled(self):
        host = fakes.FakeCgroups(self.tmp)
        stub, domain, events = self.owner(host)
        host.stuck_remove = True
        with mock.patch.object(execute, "KILL_TIMEOUT", 0.3):
            self.assertFalse(execute.Execution._kill_domain(stub))
        self.assertFalse(domain.removed)
        self.assertEqual(events, ["host.domain.residue"])


class ExportUnits(Private):
    def test_destination(self):
        self.assertEqual(export.destination("out.tar", "/srv/here"), ("/srv/here", "out.tar"))
        self.assertEqual(export.destination("/a/./b/../c.tar", None), ("/a", "c.tar"))
        self.assertEqual(export.destination("/c.tar", None), ("/", "c.tar"))
        for bad in ("", "/", "a/", "a/.", "..", "/x/" + "y" * 5000):
            self.refused("export_destination_invalid", export.destination, bad, "/srv")
        self.refused("export_cwd_unavailable", export.destination, "x", None)

    def test_pin(self):
        store = f"{self.tmp}/store"
        os.mkdir(store, 0o700)
        out = f"{self.tmp}/out"
        os.mkdir(out, 0o700)
        fd = export.pin(out, "a.tar", store)
        os.close(fd)
        os.symlink(out, f"{self.tmp}/link")
        self.refused("export_destination_symlink_ancestor", export.pin, f"{self.tmp}/link", "a.tar", store)
        self.refused("export_destination_in_store", export.pin, store, "a.tar", store)
        self.refused("export_destination_in_store", export.pin, store + "/x", "a.tar", store)
        write_file(f"{out}/a.tar", "x")
        self.refused("export_destination_exists", export.pin, out, "a.tar", store)
        os.symlink("/nonexistent", f"{out}/dangling")
        self.refused("export_destination_exists", export.pin, out, "dangling", store)
        self.refused("export_destination_unavailable", export.pin, f"{out}/missing", "a.tar", store)
        shared = f"{self.tmp}/shared"
        os.mkdir(shared)
        os.chmod(shared, 0o777)
        self.refused("export_destination_untrusted", export.pin, shared, "a.tar", store)

    def output(self, limit=10240):
        out = f"{self.tmp}/out"
        os.makedirs(out, 0o700, exist_ok=True)
        parent = os.open(out, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, parent)
        output = export.Output(parent, export.new_export_id(), limit)
        self.addCleanup(output.close)
        return out, output

    def pumped(self, output, data):
        r, w = os.pipe()
        os.set_blocking(r, False)
        os.write(w, data)
        os.close(w)
        result = "open"
        while result == "open":
            result = output.pump(r)
        os.close(r)
        return result

    def test_output_publish_and_exact_removal(self):
        out, output = self.output()
        self.assertEqual(oct(os.stat(f"{out}/{output.name}").st_mode & 0o777), "0o600")
        self.assertEqual(self.pumped(output, b"abc"), "eof")
        write_file(f"{out}/taken", "x")
        self.refused("export_destination_exists", output.publish, "taken")
        output.publish("fresh")
        with open(f"{out}/fresh", "rb") as stream:
            self.assertEqual(stream.read(), b"abc")
        self.assertIsNone(output.partial)
        _, other = self.output(limit=4)
        self.assertEqual(self.pumped(other, b"12345"), "stopped")
        self.assertEqual((other.sink, other.bytes), ("overflow", 0))
        # Its name replaced: never unlinked; left, the other file kept.
        os.rename(f"{out}/{other.name}", f"{out}/moved")
        write_file(f"{out}/{other.name}", "not ours")
        self.assertEqual(other.remove(), "left")
        self.assertTrue(os.path.exists(f"{out}/{other.name}"))
        _, third = self.output()
        self.assertEqual(third.remove(), "removed")
        self.assertFalse(os.path.exists(f"{out}/{third.name}"))

    def test_script_and_codes(self):
        text = export.script("/h", "/h/work")
        self.assertIn("--directory='/h/work' .", text)
        self.assertIn("/usr/bin/env -i LC_ALL=C /usr/bin/tar --create", text)
        self.refused("export_layout_invalid", export.script, "/h", "/other")
        self.assertIsNone(export.failure(0, "complete"))
        self.assertEqual(export.failure(0, "open"), "export_incomplete")
        self.assertEqual(export.failure(7, "complete"), "export_remote_failed")
        self.assertEqual(export.failure("timeout", "open"), "export_timeout")
        self.assertEqual(export.failure(0, "overflow"), "export_limit")
        self.assertEqual(export.task_seconds(3600, 600000), 3600 - 600 - 120)
        self.assertIsNone(export.task_seconds(700, 600000))
        self.refused("export_settings_invalid", export.settings, {}, 100, None)
        self.assertEqual(export.settings({"export_timeout_ms": 5000}),
                         {"max_bytes": export.DEFAULT_MAX_BYTES, "timeout_ms": 5000})


class ShellUnits(Private):
    PROFILE = PROFILE

    def test_argv(self):
        words = shell.transport_words("/etc/agentbox/c.json", "r-" + "a" * 32, "e-" + "b" * 32,
                                      executable="/usr/bin/python3", entry=("/opt/c/main.py",))
        self.assertEqual(words[3:6], ["/opt/c/main.py", "jail", "shell-transport"])
        argv = shell.argv("/usr/bin/ssh", self.PROFILE, "xterm-256color", ["echo", "it's"], words)
        self.assertEqual(argv[:5], ["/usr/bin/ssh", "-F", "/dev/null", "-l", "agentbox"])
        options = [argv[i + 1] for i, w in enumerate(argv) if w == "-o"]
        self.assertIn("RequestTTY=force", options)
        self.assertNotIn("RequestTTY=no", options)
        self.assertIn("ClearAllForwardings=yes", options)
        self.assertIn("ProxyCommand=" + " ".join(words), options)
        self.assertFalse(any(o.startswith("ProxyUseFdpass") for o in options))
        self.assertEqual(argv[-7:], ["agentbox-r-e", "/c/launcher", "shell", "xterm-256color", PROFILE["session"],
                                     "'echo'", "'it'\\''s'"])
        direct = shell.argv("/usr/bin/ssh", dict(self.PROFILE, endpoint=["127.0.0.1", 2222]), "dumb", [])
        self.assertIn("-p", direct)
        self.assertIn("ProxyCommand=none", direct)
        self.assertEqual(direct[-5:], ["127.0.0.1", "/c/launcher", "shell", "dumb", PROFILE["session"]])

    def test_literal_percent(self):
        # No path word may hold `%` (provider_protocol.is_path): refused.
        for config, entry in (("/etc/a%h/c.json", "/opt/main.py"), ("/etc/c.json", "/opt/%r/main.py")):
            self.refused("shell_transport_unavailable", shell.transport_words, config, "r-x", "e-x",
                         executable="/usr/bin/python3", entry=(entry,))
        # Escaped all the same: ssh's own expansion gives the words back.
        words = ["/usr/bin/python3", "/a%h/b%%c", "x%"]
        command = shell.proxy_command(words)
        self.assertEqual(command, "/usr/bin/python3 /a%%h/b%%%%c x%%")
        from tests.controller import ssh_standin
        self.assertEqual(ssh_standin.expand(command), " ".join(words))
        self.assertIsNone(ssh_standin.expand("/a/%h"))

    def test_inert_words_and_term(self):
        for config in ("/a b/c.json", "/a/$(x).json", "/a/;x", "relative.json", "/a/`x`", "/a/'x", "/a/\"x",
                       "/a/x|y", "/a/x&y", "/a/~x", "/a/x\ny"):
            self.refused("shell_transport_unavailable", shell.transport_words, config, "r-x", "e-x",
                         executable="/usr/bin/python3", entry=("/opt/main.py",))
        self.refused("shell_transport_unavailable", shell.transport_words, "/c.json", "r-x", "e-x",
                     executable="/usr/bin/python 3", entry=("/opt/main.py",))
        self.refused("shell_transport_unavailable", shell.transport_words, "/c.json", "r-x", "e-x",
                     executable="/usr/bin/python3", entry=("relative/main.py",))
        self.assertEqual(shell.term({"TERM": "xterm;rm"}), "dumb")
        self.assertEqual(shell.term({}), "dumb")
        self.assertEqual(shell.term({"TERM": "screen.xterm-256color"}), "screen.xterm-256color")

    def test_profile_checked(self):
        shell.check_profile(dict(self.PROFILE), False)
        for bad in ({"identity": "rel"}, {"launcher": "/a b"}, {"endpoint": ["8.8.8.8", 22]}, {"user": "Root!"},
                    {"endpoint": [1, 2, 3]}, {"session": None}, {"session": "0" * 31}, {"session": "A" * 32},
                    {"session": "0" * 32 + " x"}):
            self.refused("owner_record_invalid", shell.check_profile, dict(self.PROFILE, **bad), False)
        # An attached run's profile is an endpoint's: never a transport.
        self.refused("owner_record_invalid", shell.check_profile, dict(self.PROFILE), True)

    def test_environment(self):
        captured = [("SHELL", "/bin/evil"), ("HOME", "/h"), ("XDG_DATA_HOME", "rel"), ("CALLER", "x"),
                    ("AGENTBOX_CUSTODY", "/bogus"), ("LC_ALL", "en_US.UTF-8"), ("TERM", "vt100"),
                    ("PATH", "/usr/bin")]
        with mock.patch.object(host_mod, "_CAPTURED", captured):
            env = shell.environment("dumb", True)
            direct = shell.environment("dumb", False)
            self.assertEqual(host_mod.capture_host(), captured)
        # The caller's, sanitized: never SHELL, AGENTBOX_* or a relative HOME/XDG.
        self.assertEqual(env, {"HOME": "/h", "CALLER": "x", "LC_ALL": "C", "TERM": "dumb", "PATH": "/usr/bin"})
        # A direct route's: the tool's alone, as before.
        self.assertEqual(direct, {"LC_ALL": "C", "TERM": "dumb", "PATH": "/usr/bin"})


class Doctor(unittest.TestCase):
    def test_checks(self):
        def find(name):
            if name == "sftp":
                raise HostError("tool_missing")
            return "/usr/bin/" + name

        checks = {name: (status, required) for name, status, required in
                  doctor.facts(find=find, controllers="/nonexistent")}
        self.assertEqual(checks["sftp"], ("missing", True))
        self.assertEqual(checks["ssh_keygen"], ("ok", True))
        self.assertEqual(checks["cgroup2"], ("missing", False))
        self.assertNotIn("server", checks)


# -- end to end ------------------------------------------------------------

class Owner(unittest.TestCase):
    kind = "managed"
    transport = "tcp"
    retention = "home"

    def setUp(self):
        self.world = World(kind=self.kind, transport=self.transport, retention=self.retention)
        self.addCleanup(self.world.close)

    @property
    def records_dir(self):
        return f"{self.world.data}/controller-runs/{self.world.run_id}/owner"

    def published(self, name="shell.json"):
        return os.path.exists(f"{self.records_dir}/{name}")

    def serve(self, extra=(), env=None, overrides=None, faults=None):
        before = self.count("host.shell.published")
        proc = self.world.start(("jail", "serve"), list(extra),
                                overrides=overrides or QUICK, env=env, faults=faults)
        self.addCleanup(reap, proc)
        until(lambda: self.count("host.shell.published") > before or proc.poll() is not None)
        self.assertIsNone(proc.poll(), proc.stderr.read() if proc.poll() is not None else "")
        return proc

    def count(self, kind):
        return len([e for e in self.world.events() if e["event_type"] == kind])

    def stop(self):
        code, out, err = self.world.run(("jail", "stop"))
        self.assertEqual((code, out.strip()), (0, f"stop: {self.world.run_id} requested"), err)

    def ended(self, proc, timeout=60):
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out.decode(), err.decode()

    def serve_line(self, text):
        return fields([line for line in text.splitlines() if line.startswith("serve: ")][-1])

    def executions(self):
        directory = f"{self.world.data}/controller-runs/{self.world.run_id}/executions"
        out = []
        for name in sorted(os.listdir(directory)):
            with open(f"{directory}/{name}") as stream:
                out.append(json.load(stream))
        return out

    def assertNoRecords(self):
        self.assertEqual(os.listdir(self.records_dir) if os.path.isdir(self.records_dir) else [], [])

    def shell(self, args, env=None):
        return self.world.run(("shell",), ["--"] + list(args) if args else [], env=env, overrides=QUICK)

    def units(self):
        return sorted(n for _, names, _ in os.walk(f"{self.world.cgroup}/cg") for n in names
                      if n.startswith("agentbox-launch-"))

    def execution(self):
        with open(f"{self.records_dir}/owner.json") as stream:
            return json.load(stream)["execution"]


class Serve(Owner):
    def test_stop_ends_it_cancelled(self):
        proc = self.serve()
        with open(f"{self.records_dir}/owner.json") as stream:
            owner = json.load(stream)
        self.assertEqual((owner["pid"], owner["serve"]), (proc.pid, True))
        self.stop()
        code, out, err = self.ended(proc)
        line = self.serve_line(out)
        self.assertEqual((code, line["outcome"], line["reason"], line["exit"], line["host_cleanup"],
                          line["provider"]), (0, "cancelled", "cancelled", "none", "confirmed", "settled"), err)
        self.assertEqual([(e["state"], e["outcome"], e["reason"]) for e in self.executions()],
                         [("finished", "cancelled", "cancelled")])
        self.assertEqual([e["event_type"] for e in self.world.events() if e["event_type"] == "host.stop.requested"],
                         ["host.stop.requested"])
        self.assertNoRecords()
        self.assertEqual(self.world.domains(), [])
        self.assertIsNone(self.world.record()["pending"])
        # Ended and idle: `jail stop` is the run's own, no owner signalled.
        code, out, err = self.world.run(("jail", "stop"))
        self.assertEqual(code, 0, err)
        self.assertNotIn("requested", out)

    def test_repeated_stops_stay_graceful(self):
        """Every `jail stop` is one request: the provider's stop is still
        sent and awaited for its whole timeout (a second SIGINT would end
        that wait at once)."""
        self.world.set_behavior(stop="hang")
        proc = self.serve()
        self.stop()
        until(lambda: any(e["event_type"] == "host.execution.stopping" for e in self.world.events()))
        began = time.monotonic()
        self.stop()
        self.stop()
        code, out, err = self.ended(proc)
        self.assertGreater(time.monotonic() - began, 1.5)
        line = fields([l for l in (out + err).splitlines() if l.startswith("serve: ")][-1])
        self.assertEqual((line["reason"], line["provider"]), ("cancelled", "unknown"))
        self.assertEqual(len([e for e in self.world.events() if e["event_type"] == "host.stop.requested"]), 1)
        self.assertNoRecords()

    def test_signal_ends_it_and_it_is_untimed(self):
        proc = self.serve()
        proc.send_signal(signal.SIGINT)
        code, out, err = self.ended(proc)
        self.assertEqual((code, self.serve_line(out)["reason"]), (0, "cancelled"), err)
        # No timeout form: refused as usage, nothing started.
        for extra in (["--timeout", "3"], ["--timeout", "0"]):
            code, _, err = self.world.run(("jail", "serve"), list(extra))
            self.assertEqual(code, 2, err)
            self.assertTrue(err.startswith("usage:"), err)
        # Untimed: well past a short session (the setup bound, shortened,
        # no longer applies once ready), until a stop.
        proc = self.serve(overrides=dict(QUICK, **{"execute.SETUP_TIMEOUT": 2.0}))
        time.sleep(4)
        self.assertIsNone(proc.poll())
        self.stop()
        code, out, err = self.ended(proc)
        self.assertEqual((code, self.serve_line(out)["reason"]), (0, "cancelled"), err)

    def test_stop_without_owner_is_busy(self):
        opened = store_mod.Store(self.world.data)
        self.addCleanup(opened.close)
        lease = opened.claim(self.world.run_id)
        self.addCleanup(lease.release)
        code, _, err = self.world.run(("jail", "stop"))
        self.assertEqual((code, err.strip()), (1, "agentbox: jail stop refused: run_busy"))

    def test_shell_direct(self):
        code, _, err = self.shell(["/bin/echo", "x"])
        self.assertEqual((code, err.strip()), (1, "agentbox: shell refused: run_not_serving"))
        proc = self.serve(env={"AB_HOST_SECRET": "s3cret-value"})
        for name in ("owner.json", "shell.json"):
            self.assertEqual(os.stat(f"{self.records_dir}/{name}").st_mode & 0o777, 0o600)
            self.assertNotIn("s3cret", read_text(f"{self.records_dir}/{name}"))
        with open(f"{self.records_dir}/shell.json") as stream:
            self.assertIsNone(json.load(stream)["path"])
        units = self.units()
        with open(f"{self.records_dir}/shell.json") as stream:
            session = json.load(stream)["profile"]["session"]
        self.assertRegex(session, "^[0-9a-f]{32}$")
        code, out, err = self.shell(["/bin/sh", "-c", "pwd; echo $TERM; echo \"$1\"; echo $AGENTBOX_REQUEST_SESSION; "
                                     "echo $AGENTBOX_WORK_ROOT; echo ${AGENTBOX_WORK_MOUNT-unset}", "sh", "it's a $x"],
                                    env={"TERM": "xterm;bad", "AGENTBOX_REQUEST_SESSION": "f" * 32})
        self.assertEqual(code, 0, err)
        # The owner's own session context, never the caller's.
        self.assertEqual(out.splitlines(), [f"{self.world.home}/work", "dumb", "it's a $x", session,
                                            f"{self.world.home}/work", "unset"])
        entry = [e for e in self.world.ssh_entries() if e["mode"] == "shell"][-1]
        self.assertTrue(entry["profile_ok"])
        self.assertEqual((entry["options"]["RequestTTY"], entry["options"]["ProxyCommand"],
                          entry["options"]["ClearAllForwardings"]), ("force", "none", "yes"))
        self.assertNotIn("ProxyUseFdpass", entry["options"])
        # A direct route needs no delegation: no unit entered for it.
        self.assertEqual(self.units(), units)
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)
        code, _, err = self.shell(["/bin/true"])
        self.assertEqual((code, err.strip()), (1, "agentbox: shell refused: run_not_serving"))

    def test_exec_owner_refuses_shell_and_accepts_stop(self):
        proc = self.world.start("exec", ["--", "/bin/sleep", "30"], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: any(e["event_type"] == "host.execution.ssh_started" for e in self.world.events()))
        until(lambda: self.published("owner.json"))
        code, _, err = self.shell(["/bin/true"])
        self.assertEqual((code, err.strip()), (1, "agentbox: shell refused: shell_unsupported"))
        self.assertFalse(self.published("shell.json"))
        self.stop()
        code, out, err = self.ended(proc)
        line = fields([l for l in err.splitlines() if l.startswith("execution: ")][-1])
        self.assertEqual((code, line["reason"], line["host_cleanup"]), (1, "cancelled", "confirmed"))
        self.assertNoRecords()

    def test_stale_records_never_serve(self):
        """A killed owner's records: shell refuses, stop never signals; the
        next owner replaces both."""
        proc = self.serve()
        stale = self.execution()
        proc.kill()
        proc.wait()
        self.assertTrue(self.published("shell.json"))
        code, _, err = self.shell(["/bin/true"])
        self.assertEqual((code, err.strip()), (1, "agentbox: shell refused: run_not_serving"))
        opened = store_mod.Store(self.world.data)
        self.addCleanup(opened.close)
        # Even with the lease held (another operation): the record's
        # process is gone, nothing is signalled or served.
        lease = opened.claim(self.world.run_id)
        try:
            with self.assertRaises(HostError) as caught:
                owner_mod.serving(opened, self.world.run_id)
            self.assertEqual(caught.exception.code, "owner_unreachable")
            code, _, err = self.world.run(("jail", "stop"))
            self.assertEqual((code, err.strip()), (1, "agentbox: jail stop refused: run_busy"))
        finally:
            lease.release()
        code, _, err = self.world.run(("jail", "stop"), overrides=QUICK)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.world.domains(), [])
        proc = self.serve()
        self.assertNotEqual(self.execution(), stale)
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)


class ServeLane(Owner):
    """`jail serve --acquisition-config`: one lane for the untimed session,
    shared by every `shell` login (each in the owner's exact request
    context); one grant, never reset by a reconnect; one active request."""

    def serve_lane(self, overrides=None, run_id=None, extra=()):
        before = self.count("host.shell.published")
        args = ["--acquisition-config", self.world.acquisition()] + list(extra)
        proc = self.world.start(("jail", "serve"), args, overrides=dict(QUICK, **(overrides or {})), run_id=run_id)
        self.addCleanup(reap, proc)
        until(lambda: self.count("host.shell.published") > before or proc.poll() is not None)
        self.assertIsNone(proc.poll(), proc.stderr.read() if proc.poll() is not None else "")
        return proc

    def session(self, run_id=None):
        with open(f"{self.world.data}/controller-runs/{run_id or self.world.run_id}/owner/shell.json") as stream:
            return json.load(stream)["profile"]["session"]

    def tally(self, out):
        return [json.loads(line) for line in out.splitlines() if line.startswith("{")]

    def shell_on(self, run_id, args):
        return self.world.run(("shell",), ["--"] + list(args), overrides=QUICK, run_id=run_id)

    def lane_closed(self):
        return [e for e in self.world.events() if e["event_type"] == "host.handler.lane_closed"][-1]

    def test_shells_share_one_grant_and_reconnects_never_reset_it(self):
        from tests.controller.test_b2 import POSTER
        proc = self.serve_lane({"acquisition.MAX_REQUESTS": 3})
        session = self.session()
        # A real request and delivery from the first login.
        code, out, err = self.shell(["/bin/sh", "-c", "agentbox-request echo say '{\"text\":\"s\"}'"])
        self.assertEqual(code, 0, err)
        self.assertIn('"ok":true', out)
        delivered = [t for t in self.world.transfers() if t["program"] == "scp"]
        self.assertEqual(delivered[-1]["operands"][-1].split(":", 1)[1],
                         f"{self.world.home}/work/.agentbox-requests/{session}-req-1.artifact")
        # A second login (a reconnect): the same grant, two left of three.
        code, out, err = self.shell(["/bin/sh", "-c", f"{POSTER} limit 3 nope"])
        self.assertEqual(code, 0, err)
        self.assertEqual(self.tally(out), [{"closed:handler_unknown": 2, "rejected:submission_limit": 1}])
        code, out, err = self.shell(["/bin/sh", "-c", f"{POSTER} limit 1 nope"])
        self.assertEqual(self.tally(out), [{"rejected:submission_limit": 1}])
        self.assertIsNone(proc.poll())
        self.stop()
        code, out, err = self.ended(proc)
        line = self.serve_line(out)
        self.assertEqual((code, line["reason"], line["host_cleanup"], line["storage"]),
                         (0, "cancelled", "confirmed", "unbounded"), err)
        self.assertNotIn("acquisition_cleanup", line)
        closed = self.lane_closed()["attributes"]
        self.assertEqual((closed["requests"], closed["cleanup_confirmed"], closed["max_requests"]), (3, True, 3))
        self.assertEqual([(e["state"], e.get("spool")) for e in self.executions()], [("finished", None)])

    def test_concurrent_logins_get_busy_and_a_stop_cancels_the_active_request(self):
        from tests.controller.test_b2 import POSTER
        proc = self.serve_lane()
        sleeper = self.world.start(("shell",), ["--", "/bin/sh", "-c", f"{POSTER} sleep"], overrides=QUICK)
        self.addCleanup(reap, sleeper)
        until(lambda: self.count("host.handler.started") >= 1)
        code, out, err = self.shell(["/bin/sh", "-c", f"{POSTER} limit 1 echo"])
        self.assertEqual((code, self.tally(out)), (0, [{"rejected:busy": 1}]), err)
        # A stop mid-acquisition: the worker killed, the request cancelled,
        # the spool removed, nothing reserved; the login's own end follows.
        self.stop()
        code, out, err = self.ended(proc)
        line = self.serve_line(out)
        self.assertEqual((code, line["reason"], line["host_cleanup"]), (0, "cancelled", "confirmed"), err)
        self.assertNotIn("acquisition_cleanup", line)
        ends = [e["attributes"]["end"] for e in self.world.events() if e["event_type"] == "host.handler.request"]
        self.assertEqual(ends[0], "cancelled")
        self.assertTrue(self.lane_closed()["attributes"]["spool_released"])
        self.assertEqual([(e["state"], e.get("spool")) for e in self.executions()], [("finished", None)])
        self.assertEqual(os.listdir(self.world.spool), [])
        sleeper.communicate(timeout=60)
        code, out, err = self.world.run(("jail", "status"))
        self.assertNotIn("spool_reserved", out)

    def test_an_earlier_sessions_context_authorizes_nothing_later(self):
        from tests.controller.test_b2 import POSTER
        proc = self.serve_lane()
        stale = self.session()
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)
        proc = self.serve_lane()
        self.assertNotEqual(self.session(), stale)
        code, out, err = self.shell(["/bin/sh", "-c", f"AGENTBOX_REQUEST_SESSION={stale} {POSTER} early_result"])
        self.assertEqual(code, 0, err)
        self.assertEqual([(r["status"], r.get("code")) for r in self.tally(out)], [("403", "session_mismatch")])
        # Its own context is the current one.
        code, out, err = self.shell(["/bin/sh", "-c", f"{POSTER} early_result"])
        self.assertEqual([(r["status"], r.get("code")) for r in self.tally(out)], [("409", "not_active")])
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)

    def test_a_mounted_project_is_the_logins_work_root(self):
        from tests.controller.test_c1 import FEATURES
        self.world.set_behavior(features=FEATURES)
        source = tempfile.mkdtemp(dir=self.world.tmp)
        os.chmod(source, 0o755)
        os.makedirs(f"{source}/app", 0o755)
        run_id = self.world.create(["--retention", "home", "--mount-rw", f"{source}=proj", "--project",
                                    f"{source}/app"])
        # The stand-in binds nothing: the guest's mount, as a provider makes it.
        os.makedirs(f"{self.world.home}/proj/app", 0o755)
        proc = self.world.start(("jail", "serve"), ["--acquisition-config",
                                                   self.world.acquisition()], overrides=QUICK, run_id=run_id)
        self.addCleanup(reap, proc)
        profile = f"{self.world.data}/controller-runs/{run_id}/owner/shell.json"
        until(lambda: os.path.exists(profile) or proc.poll() is not None)
        self.assertIsNone(proc.poll())
        script = "pwd; echo $AGENTBOX_WORK_ROOT; echo $AGENTBOX_WORK_MOUNT; agentbox-request echo say '{\"text\":\"m\"}'"
        code, out, err = self.shell_on(run_id, ["/bin/sh", "-c", script])
        self.assertEqual(code, 0, err)
        lines = out.splitlines()
        self.assertEqual(lines[:3], [f"{self.world.home}/proj/app"] * 2 + [f"{self.world.home}/proj"])
        self.assertIn('"ok":true', out)
        delivered = [t for t in self.world.transfers() if t["program"] == "scp"]
        self.assertTrue(delivered[-1]["operands"][-1].split(":", 1)[1].startswith(
            f"{self.world.home}/proj/app/.agentbox-requests/{self.session(run_id)}-"))
        code, _, err = self.world.run(("jail", "stop"), run_id=run_id)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.ended(proc)[0], 0)


class StdioShell(Owner):
    transport = "stdio"

    def connects(self):
        return [e for e in self.world.provider_log() if e.get("argv") == "connect"]

    def slots(self):
        return sorted(n for d in self.world.domains() for n in os.listdir(d) if n.startswith("s-"))

    def transport_cmd(self, execution, stdin=subprocess.PIPE):
        return subprocess.Popen(self.world.argv(("jail", "shell-transport"), [execution]), env=self.world.env(),
                                stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_transport_joins_a_slot_and_becomes_the_connect(self):
        proc = self.serve(env={"AB_HOST_SECRET": "s3cret-value"})
        with open(f"{self.records_dir}/shell.json") as stream:
            published = json.load(stream)
        self.assertTrue(published["path"])
        self.assertNotIn("s3cret", json.dumps(published))
        units = self.units()
        caller = {"AB_CALLER_ONLY": "harmless-shell", "SHELL": "/bin/false", "AGENTBOX_CUSTODY": "/bogus",
                  "AGENTBOX_STORAGE_SCOPES": "/bogus/run-limits.json"}
        code, out, err = self.shell(["/bin/echo", "bridged"], env=caller)
        self.assertEqual((code, out), (0, "bridged\n"), err)
        entry = [e for e in self.world.ssh_entries() if e["mode"] == "shell"][-1]
        self.assertEqual((entry["bridge"], entry["echoed"], entry["proxy_exit"]), ("standin-connect", "ping", 0),
                         entry.get("proxy_stderr"))
        self.assertNotIn("ProxyUseFdpass", entry["options"])
        words = entry["proxy_command"].split(" ")
        self.assertEqual(words[5:8], ["jail", "shell-transport", "--config"])
        connect = self.connects()[-1]
        # The very process ssh started (exec all the way): in slot s-1 of
        # D, with the owner's PATH and D as its custody, nothing else of
        # the owner's environment.
        self.assertEqual((connect["pid"], connect["leaf"]), (entry["proxy_pid"], "s-1"))
        self.assertEqual(connect["custody"], self.world.domains()[0])
        self.assertEqual(connect["path"], published["path"])
        self.assertNotIn("AB_HOST_SECRET", connect["env"])
        # The shell caller's own environment reaches it, sanitized: never
        # SHELL, and its AGENTBOX_* never over the owner's.
        self.assertIn("AB_CALLER_ONLY", connect["env"])
        self.assertNotIn("SHELL", connect["env"])
        self.assertEqual(connect["scopes"], f"{self.world.data}/run-limits.json")
        self.assertEqual(entry["env"]["AB_CALLER_ONLY"], "harmless-shell")
        self.assertFalse([k for k in entry["env"] if k == "SHELL" or k.startswith("AGENTBOX_")])
        for name in ("owner.json", "shell.json"):
            self.assertNotIn("harmless", read_text(f"{self.records_dir}/{name}"))
        self.assertFalse(os.path.exists(f"/proc/{connect['pid']}"))
        # The shell's ssh in a delegated unit of its own.
        self.assertEqual(len(self.units()), len(units) + 1)
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)
        self.assertEqual(self.world.domains(), [])
        self.assertEqual([p for p in self.world.listed_pids() if self.world.ours(p)], [])

    def test_sighup_ends_the_bridge(self):
        proc = self.serve()
        self.world.set_ssh(proxy_end="hup")
        code, out, err = self.shell(["/bin/true"])
        self.assertEqual(code, 0, err)
        entry = [e for e in self.world.ssh_entries() if e["mode"] == "shell"][-1]
        self.assertEqual((entry["bridge"], entry["proxy_exit"]), ("standin-connect", -signal.SIGHUP))
        self.assertFalse(os.path.exists(f"/proc/{entry['proxy_pid']}"))
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)

    def test_refusals_make_no_slot(self):
        proc = self.serve()
        execution = self.execution()
        for argument, code in ((store_mod.new_id("e"), "invocation_stale"), ("e-x", "invocation_invalid")):
            done = self.transport_cmd(argument, stdin=subprocess.DEVNULL)
            out, err = done.communicate(timeout=30)
            self.assertEqual((done.returncode, out, err.decode().strip()),
                             (1, b"", f"agentbox: jail shell-transport refused: {code}"))
        self.assertEqual(self.slots(), [])
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)
        done = self.transport_cmd(execution, stdin=subprocess.DEVNULL)
        out, err = done.communicate(timeout=30)
        self.assertEqual((done.returncode, out, err.decode().strip()),
                         (1, b"", "agentbox: jail shell-transport refused: run_not_serving"))
        # An exec owner's execution: no profile, no slot.
        before = self.count("host.execution.ssh_started")
        proc = self.world.start("exec", ["--", "/bin/sleep", "30"], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: self.count("host.execution.ssh_started") > before)
        done = self.transport_cmd(self.execution(), stdin=subprocess.DEVNULL)
        out, err = done.communicate(timeout=30)
        self.assertEqual((done.returncode, out, err.decode().strip()),
                         (1, b"", "agentbox: jail shell-transport refused: shell_unsupported"))
        self.assertEqual(self.slots(), [])
        self.stop()
        self.ended(proc)

    def test_slots_are_cumulative(self):
        """32 transports per execution in all: ended ones are no refund."""
        proc = self.serve()
        execution = self.execution()
        for _ in range(cgroups.MAX_SLOTS):
            bridge = self.transport_cmd(execution)
            self.assertEqual(bridge.stdout.readline(), b"standin-connect\n")
            bridge.stdin.close()
            out, err = bridge.communicate(timeout=30)
            self.assertEqual(bridge.returncode, 0, err)
        self.assertEqual(sorted(self.slots()), sorted(f"s-{n}" for n in range(1, 33)))
        done = self.transport_cmd(execution, stdin=subprocess.DEVNULL)
        out, err = done.communicate(timeout=30)
        self.assertEqual((done.returncode, out, err.decode().strip()),
                         (1, b"", "agentbox: jail shell-transport refused: shell_limit"))
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)
        self.assertEqual(self.world.domains(), [])

    def test_live_transport_killed_with_the_domain(self):
        proc = self.serve()
        bridge = self.transport_cmd(self.execution())
        self.addCleanup(reap, bridge)
        self.assertEqual(bridge.stdout.readline(), b"standin-connect\n")
        self.stop()
        code, out, err = self.ended(proc)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.serve_line(out)["host_cleanup"], "confirmed")
        self.assertEqual(bridge.wait(timeout=10), -signal.SIGKILL)
        self.assertEqual(self.world.domains(), [])

    def test_withdrawn_after_the_join_refuses(self):
        """The profile gone between the join and the recheck (the owner's
        teardown began): no connect started; the process stays D's member
        for the owner's kill."""
        proc = self.serve()
        execution = self.execution()
        opened = store_mod.Store(self.world.data)
        self.addCleanup(opened.close)
        host = fakes.FakeCgroups(self.world.cgroup)
        joined = []
        original = cgroups.Domain.join_slot

        def join(domain):
            joined.append((domain.path, original(domain)))
            os.unlink(f"{self.records_dir}/shell.json")

        def never(*_):
            raise AssertionError("connect started")

        try:
            with mock.patch.object(cgroups.Domain, "join_slot", join):
                with self.assertRaises(HostError) as caught:
                    shell.transport(execute.System(host), opened, self.world.run_id, execution, execve=never)
            self.assertEqual(caught.exception.code, "shell_not_ready")
            self.assertEqual(joined[0][1], "s-1")
        finally:
            # This test process is no transport: out of the fake slot before
            # the owner's kill.
            for path, name in joined:
                write_file(f"{path}/{name}/cgroup.procs", "")
        self.stop()
        self.assertEqual(self.ended(proc)[0], 0)

    def test_unconfirmed_removal_stays_pending(self):
        proc = self.serve(faults={"stuck_remove": True})
        self.stop()
        code, out, err = self.ended(proc)
        line = fields([l for l in (out + err).splitlines() if l.startswith("serve: ")][-1])
        self.assertEqual((code, line["host_cleanup"]), (1, "unconfirmed"), err)
        self.assertIn("host.domain.residue", [e["event_type"] for e in self.world.events()])
        pending = self.world.record()["pending"]
        self.assertEqual(pending["processes"], "unknown")
        self.assertNoRecords()
        # Recovery while the removal still fails: refused, still pending.
        code, out, err = self.world.run(("jail", "stop"), overrides=QUICK, faults={"stuck_remove": True})
        self.assertEqual((code, err.strip()), (1, "agentbox: jail stop refused: processes_unsettled"), out)
        self.assertEqual(self.world.record()["pending"], pending)
        self.assertEqual(len(self.world.domains()), 1)
        # The explicit recovery (no fault now) settles it.
        code, out, err = self.world.run(("jail", "stop"), overrides=QUICK)
        self.assertEqual(code, 0, err)
        self.assertIsNone(self.world.record()["pending"])
        self.assertEqual(self.world.domains(), [])


class StopDuringWaits(Owner):
    """A stop request ends every owner wait, not only the task's."""

    def test_startup_wait(self):
        self.world.set_ssh(fail="hang_bootstrap")
        proc = self.world.start("exec", ["--", "/bin/true"], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: any(e.get("mode") == "bootstrap" for e in self.world.ssh_entries())
              and self.published("owner.json"))
        began = time.monotonic()
        self.stop()
        code, _, err = self.ended(proc)
        self.assertLess(time.monotonic() - began, 30)
        line = fields([l for l in err.splitlines() if l.startswith("execution: ")][-1])
        self.assertEqual((code, line["reason"], line["host_cleanup"]), (1, "cancelled", "confirmed"))

    def test_export_wait(self):
        out = f"{self.world.tmp}/out"
        os.mkdir(out, 0o700)
        self.world.set_ssh(export="hang")
        proc = self.world.start("exec", ["--export-to", f"{out}/h.tar", "--", "/bin/true"], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: any(e["event_type"] == "host.export.started" for e in self.world.events()))
        began = time.monotonic()
        self.stop()
        code, _, err = self.ended(proc)
        self.assertLess(time.monotonic() - began, 30)
        self.assertIn("code=interrupted", err)
        self.assertEqual((code, os.listdir(out)), (1, []))


class AttachedExport(unittest.TestCase):
    def setUp(self):
        self.world = World(kind="attached")
        self.addCleanup(self.world.close)
        self.addCleanup(kill_strays, self.world.tmp)
        code, out, err = self.world.exec(["/bin/sh", "-c", "echo hello > note; mkdir sub; echo x > sub/y"],
                                         overrides=QUICK)
        self.assertEqual(code, 0, err)
        self.out = f"{self.world.tmp}/out"
        os.mkdir(self.out, 0o700)

    def export(self, name="a.tar", extra=(), **kwargs):
        return self.world.run(("jail", "export"), ["--to", f"{self.out}/{name}"] + list(extra), **kwargs)

    def test_published(self):
        code, out, err = self.export()
        self.assertEqual(code, 0, err)
        words = out.split()
        self.assertEqual((words[0], words[2], words[-1]), ("export:", "outcome=published", "reservation=cleared"))
        with tarfile.open(f"{self.out}/a.tar") as archive:
            self.assertIn("./note", archive.getnames())
        self.assertEqual(sorted(os.listdir(self.out)), ["a.tar"])
        self.assertIsNone(self.world.record()["export"])
        entry = [e for e in self.world.ssh_entries() if e["mode"] == "export"][-1]
        self.assertTrue(entry["profile_ok"])
        self.assertEqual((entry["forward"], entry["remote"]), (None, ["/bin/sh", "-s"]))
        # Exists now: refused before any reservation.
        code, _, err = self.export()
        self.assertEqual((code, err.strip()), (1, "agentbox: jail export refused: export_destination_exists"))

    def test_failures_clean_up_exactly(self):
        for conf, extra, expected in (({"export": "exit7"}, [], "export_remote_failed"),
                                      ({"export": "flood", "bytes": 20000}, ["--max-bytes", "10240"],
                                       "export_limit"),
                                      ({"export": "hang"}, ["--timeout-ms", "1500"], "export_timeout")):
            self.world.set_ssh(**conf)
            code, _, err = self.export(extra=extra)
            line = fields(err.strip().split(" ", 2)[2])
            self.assertEqual((code, line["code"], line["partial"], line["reservation"]),
                             (1, expected, "removed", "cleared"), err)
            self.assertEqual(os.listdir(self.out), [])
            self.assertIsNone(self.world.record()["export"])

    def test_crash_then_assertion_releases(self):
        self.world.set_ssh(export="hang")
        proc = self.world.start(("jail", "export"), ["--to", f"{self.out}/a.tar"])
        until(lambda: self.world.record()["export"] is not None and os.listdir(self.out)
              and any(e["mode"] == "export" for e in self.world.ssh_entries()))
        proc.kill()
        proc.communicate()
        # Its ssh outlives it (as the assertion's warning says): ended here.
        kill_strays(self.world.tmp)
        export_id = self.world.record()["export"]["operation"]
        partial = f".agentbox-export-{export_id[2:]}.partial"
        self.assertEqual(os.listdir(self.out), [partial])
        self.assertEqual(self.world.record()["export"], {"operation": export_id, "max_bytes": 4 << 30,
                                                         "processes": "unknown"})
        code, out, _ = self.world.run("status")
        self.assertIn(f"export={export_id} export_processes=unknown export_reserved={4 << 30}", out)
        code, _, err = self.world.exec(["/bin/true"])
        self.assertEqual((code, err.strip()), (1, "agentbox: jail exec refused: export_unsettled"))
        code, _, err = self.export(name="b.tar")
        self.assertEqual((code, err.strip()), (1, "agentbox: jail export refused: export_unsettled"))
        code, _, err = self.world.run("discard")
        self.assertEqual((code, err.strip()), (1, "agentbox: jail discard refused: export_unsettled"))
        code, out, err = self.world.run("stop")
        self.assertEqual(code, 1)
        self.assertIn(f"unproven local work: {export_id} export state=unknown", err)
        for ident, expected in ((store_mod.new_id("x"), "assertion_id_unknown"), ("x-1", "assertion_id_invalid")):
            code, _, err = self.world.run("stop", ["--assert-local-ended", ident])
            self.assertEqual(err.strip(), f"agentbox: jail stop refused: {expected}")
        code, out, err = self.world.run("stop", ["--assert-local-ended", export_id])
        self.assertEqual((code, out.strip()), (0, f"stop: {self.world.run_id} asserted {export_id}"), err)
        self.assertIn("asserting, unverified", err)
        self.assertIn(f"A partial file {partial} may remain", err)
        self.assertIn("Not verified: no process termination, no file cleanup", err)
        # Released despite the residue: nothing guessed or deleted.
        self.assertEqual(os.listdir(self.out), [partial])
        record = self.world.record()
        self.assertEqual((record["export"], record["asserted"][-1]), (None, export_id))
        code, _, err = self.world.run("stop", ["--assert-local-ended", export_id])
        self.assertEqual(err.strip(), "agentbox: jail stop refused: assertion_id_stale")
        self.world.set_ssh(export=None)
        code, _, err = self.world.exec(["/bin/true"], overrides=QUICK)
        self.assertEqual(code, 0, err)

    def test_managed_refused(self):
        managed = World(kind="managed", retention="home")
        self.addCleanup(managed.close)
        code, _, err = managed.run(("jail", "export"), ["--to", f"{self.out}/m.tar"])
        self.assertEqual(err.strip(), "agentbox: jail export refused: target_unsupported")


class Blocked(Owner):
    def test_unread_output_never_holds_the_owner(self):
        r, w = os.pipe()
        os.set_blocking(w, False)
        try:
            while True:
                os.write(w, b"x" * 65536)
        except BlockingIOError:
            pass
        proc = subprocess.Popen(self.world.argv(("jail", "serve"), [],
                                                overrides=QUICK),
                                env=self.world.env(), stdin=subprocess.DEVNULL, stdout=w, stderr=subprocess.PIPE)
        os.close(w)
        self.addCleanup(os.close, r)
        self.addCleanup(reap, proc)
        until(lambda: self.published("owner.json")
              and any(e["event_type"] == "host.serve.ready" for e in self.world.events()))
        self.stop()
        # Bounded: the final line given up (display.emit), as exec's; the
        # status is the report's.
        self.assertEqual(proc.wait(timeout=30), 0)
        self.assertEqual([(e["outcome"], e["reason"], e["host_cleanup"]) for e in self.executions()],
                         [("cancelled", "cancelled", True)])
        code, out, _ = self.world.run("status")
        self.assertIn("state=idle", out)


class ExecExport(Owner):
    def run_export(self, argv, extra=(), name="e.tar", **kwargs):
        return self.world.exec(argv, ["--export-to", f"{self.out}/{name}"] + list(extra), overrides=QUICK,
                               **kwargs)

    def setUp(self):
        super().setUp()
        self.out = f"{self.world.tmp}/out"
        os.mkdir(self.out, 0o700)

    def export_line(self, text):
        return [line for line in text.splitlines() if "export: x-" in line][-1]

    def test_published_after_exit_any_code(self):
        code, out, err = self.run_export(["/bin/sh", "-c", "echo hi > f; exit 3"])
        self.assertEqual(code, 1)
        self.assertIn("outcome=published", self.export_line(out))
        with tarfile.open(f"{self.out}/e.tar") as archive:
            self.assertIn("./f", archive.getnames())
        self.assertIsNone(self.world.record()["export"])
        code, out, err = self.run_export(["/bin/true"], name="ok.tar")
        self.assertEqual(code, 0, err)
        self.assertTrue(self.export_line(out).endswith("reservation=cleared"))
        self.assertEqual(sorted(os.listdir(self.out)), ["e.tar", "ok.tar"])

    def test_only_the_commands_own_exit_exports(self):
        for argv, exit_text in ((["/bin/sh", "-c", "kill -9 $$"], "signaled"),
                                (["/nonexistent-agentbox-command"], "failed")):
            before = len([e for e in self.world.ssh_entries() if e["mode"] == "export"])
            code, out, err = self.run_export(argv, name="n.tar")
            execution = fields([l for l in err.splitlines() if l.startswith("execution: ")][-1])
            export_line = fields(self.export_line(err).split(" ", 3)[3])
            self.assertEqual((code, execution["reason"], execution["exit"]), (1, "completed", exit_text), err)
            self.assertEqual((export_line["code"], export_line["partial"], export_line["reservation"]),
                             ("export_not_run", "removed", "cleared"))
            # No export ssh at all.
            self.assertEqual(len([e for e in self.world.ssh_entries() if e["mode"] == "export"]), before)
            self.assertEqual(os.listdir(self.out), [])
            self.assertIsNone(self.world.record()["export"])

    def test_the_final_decision_rechecks_the_exit(self):
        from agentbox_controller import execute

        class Output:
            sink, bytes, partial = "complete", 7, "kept"

            def publish(self, name):
                raise AssertionError("published")

            def remove(self):
                self.partial = "removed"
                return self.partial

            def close(self):
                pass

        class Lease:
            record = {"export": None}

            class store:
                @staticmethod
                def lock():
                    import contextlib
                    return contextlib.nullcontext()

        for outcome in ("cancelled", "signaled", "failed"):
            owner = execute.Execution.__new__(execute.Execution)
            owner.output, owner.export_end, owner.export_id = Output(), 0, store_mod.new_id("x")
            owner.guest = type("G", (), {"exit": {"outcome": outcome}})()
            owner.report = execute.Report()
            owner.report.host_cleanup = True
            owner.stop_requested, owner.capture, owner.lease = False, None, Lease()
            owner.loop = type("L", (), {"signals": []})()
            owner._conclude_export()
            self.assertEqual(owner.export_result[0], "export_not_run")
            self.assertEqual(owner.output.partial, "removed")

    def crossing(self, detached):
        """`detached` (setsid: it outlives the command's group, so only the
        lane's own close can end its request) still active at the
        command's exit, the export then held: (request ends before the
        export began, all request ends, the command's stderr)."""
        lane = ["--acquisition-config", self.world.acquisition()]
        script = f"setsid -f {detached}; sleep 3; exit 0"
        proc = self.world.start("exec", lane + ["--export-to", f"{self.out}/l.tar", "--export-timeout-ms", "8000",
                                                "--", "/bin/sh", "-c", script], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: any(e["event_type"] == "host.export.started" for e in self.world.events()), 60)
        events = self.world.events()
        started = [e["seq"] for e in events if e["event_type"] == "host.export.started"][0]
        before = [(e["attributes"]["end"], e["attributes"]["uploaded"]) for e in events
                  if e["event_type"] == "host.handler.request" and e["seq"] < started]
        code, out, err = self.ended(proc)
        self.assertEqual(code, 1)
        self.assertIn("code=export_timeout", err)
        ends = [(e["attributes"]["end"], e["attributes"]["uploaded"]) for e in self.world.events()
                if e["event_type"] == "host.handler.request"]
        closed = [e["attributes"] for e in self.world.events() if e["event_type"] == "host.handler.lane_closed"][-1]
        self.assertTrue(closed["cleanup_confirmed"], closed)
        self.assertEqual((closed["reason"], closed["uploads"]), ("stopped", 0))
        self.assertNotIn("spool", self.executions()[-1])
        self.assertEqual(os.listdir(self.world.spool), [])
        self.assertEqual(self.world.domains(), [])
        return before, ends

    def test_a_sleeping_worker_ends_at_the_commands_exit(self):
        from tests.controller.test_b2 import POSTER
        self.world.set_ssh(export="hang")
        before, ends = self.crossing(f"{POSTER} sleep > sleeper.out 2>&1")
        # Cancelled and revoked before the export began; nothing after.
        self.assertEqual((before, ends), ([("cancelled", False)], [("cancelled", False)]))
        # Its client gets no ready: `closed cancelled`, or, once the session's
        # forward ends first, its connection's end (best effort, as at any
        # execution's end).
        until(lambda: read_text(f"{self.world.home}/work/sleeper.out"), 10)
        self.assertNotIn('"ready"', read_text(f"{self.world.home}/work/sleeper.out"))

    def test_an_upload_crossing_the_exit_settles_late_without_ready(self):
        self.world.set_ssh(export="hang", scp_sleep=5)
        before, ends = self.crossing("agentbox-request echo say '{\"text\":\"x\"}' > upload.out 2>&1")
        self.assertEqual((before, ends), ([("cancelled", False)], [("cancelled", False)]))
        # The upload ran across the exit; its late result settled the spool.
        self.assertTrue(any(t["program"] == "scp" for t in self.world.transfers()))
        until(lambda: read_text(f"{self.world.home}/work/upload.out"), 10)
        self.assertNotIn('"ready"', read_text(f"{self.world.home}/work/upload.out"))

    def test_stop_exports_nothing(self):
        proc = self.world.start("exec", ["--export-to", f"{self.out}/s.tar", "--", "/bin/sleep", "30"],
                                overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: self.published("owner.json")
              and any(e["event_type"] == "host.execution.ssh_started" for e in self.world.events()))
        self.stop()
        code, out, err = self.ended(proc)
        line = fields(self.export_line(err).split(" ", 3)[3])
        self.assertEqual((code, line["code"], line["partial"], line["reservation"]),
                         (1, "export_not_run", "removed", "cleared"))
        self.assertEqual(os.listdir(self.out), [])
        self.assertIsNone(self.world.record()["export"])

    def test_stop_during_the_export_aborts_it(self):
        self.world.set_ssh(export="hang")
        proc = self.world.start("exec", ["--export-to", f"{self.out}/h.tar", "--", "/bin/true"], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: any(e["event_type"] == "host.export.started" for e in self.world.events()))
        self.stop()
        code, out, err = self.ended(proc)
        line = fields(self.export_line(err).split(" ", 3)[3])
        self.assertEqual((code, line["code"], line["partial"], line["reservation"]),
                         (1, "interrupted", "removed", "cleared"), err)
        self.assertEqual(os.listdir(self.out), [])
        self.assertEqual(self.world.domains(), [])

    def test_crash_needs_run_stop_then_the_assertion(self):
        self.world.set_ssh(export="hang")
        proc = self.world.start("exec", ["--export-to", f"{self.out}/c.tar", "--", "/bin/true"], overrides=QUICK)
        self.addCleanup(reap, proc)
        until(lambda: any(e["event_type"] == "host.export.started" for e in self.world.events()))
        proc.kill()
        proc.communicate()
        record = self.world.record()
        export_id = record["export"]["operation"]
        self.assertEqual((record["pending"]["processes"], record["export"]["processes"]), ("unknown", "unknown"))
        code, _, err = self.world.run("stop", ["--assert-local-ended", export_id])
        self.assertEqual(err.strip(), "agentbox: jail stop refused: processes_unsettled")
        code, out, err = self.world.run("stop", overrides=QUICK)
        self.assertEqual((code, out.split()[-1]), (1, "recovered"), err)
        self.assertIn(f"{export_id} export state=unknown", err)
        self.assertIsNone(self.world.record()["pending"])
        code, out, err = self.world.run("stop", ["--assert-local-ended", export_id])
        self.assertEqual(code, 0, err)
        self.assertEqual(os.listdir(self.out), [f".agentbox-export-{export_id[2:]}.partial"])
        self.world.set_ssh(export=None)
        code, out, err = self.run_export(["/bin/true"], name="after.tar")
        self.assertEqual(code, 0, err)

    def test_refusals_before_anything(self):
        code, _, err = self.run_export(["/bin/true"], ["--timeout", "100"])
        self.assertEqual(err.strip(), "agentbox: jail exec refused: export_window_insufficient")
        write_file(f"{self.out}/e.tar", "x")
        code, _, err = self.run_export(["/bin/true"])
        self.assertEqual(err.strip(), "agentbox: jail exec refused: export_destination_exists")
        code, _, err = self.world.exec(["/bin/true"], ["--export-max-bytes", "10240"])
        self.assertEqual(code, 2)
        self.assertEqual(self.executions(), [])

    def test_retention_none_refused(self):
        disposable = World(kind="managed", retention="none")
        self.addCleanup(disposable.close)
        code, _, err = disposable.exec(["/bin/true"], ["--export-to", f"{self.out}/n.tar"])
        self.assertEqual(err.strip(), "agentbox: jail exec refused: export_retention_unsupported")


class DoctorCli(unittest.TestCase):
    def test_python_minimum(self):
        from agentbox_controller import doctor
        for version, status in (((3, 11, 9), "unsupported"), ((3, 12, 0), "ok")):
            with mock.patch.object(doctor.sys, "version_info", version):
                self.assertIn(("python", status, True), doctor.facts())

    def test_lines(self):
        world = World(kind="attached")
        self.addCleanup(world.close)
        code, out, err = world.run(("doctor",), command_args=False)
        names = [line.split(":")[0] for line in out.splitlines()]
        self.assertEqual(names, ["platform", "python", "ssh", "ssh_keygen", "scp", "sftp", "cgroup2", "server",
                                 "note"])
        self.assertIn("server: ok\n", out)
        self.assertIn(code, (0, 1))
        argv = world.argv(("doctor",), command_args=False)
        argv.remove("--config")
        argv.remove(world.config)
        done = subprocess.run(argv, env=world.env(), capture_output=True, timeout=30)
        # No configuration and no packaged prefix (a source tree): said so.
        self.assertIn(b"server: unconfigured\n", done.stdout)
        self.assertEqual(done.returncode, 1)
        self.assertIn(b"cgroup2: ", done.stdout)


if __name__ == "__main__":
    unittest.main()
