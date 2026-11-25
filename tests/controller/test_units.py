"""Controller units, offline: arguments, configuration, store, capture,
admission, the SSH profile and bootstrap scripts, the custody domain over
FakeCgroups.

  python3 -I -B -m unittest discover -s tests -t .
"""
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import unittest.mock

from tests.controller import harness  # first: puts the controller on the path
from agentbox_controller import capture, cgroups, cli, config, display, execute, scopes, ssh, store
from agentbox_controller.host import Child, HostError
from tests.controller.fakes import FakeCgroups

KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBqLzVHf3dOTAEuMmL7cMuNwXx3bnF8XkY1aNMYQ8T7E"


def read(path):
    with open(path) as stream:
        return stream.read()


def write(path, value, mode=0o600):
    with open(path, "w") as stream:
        stream.write(value if isinstance(value, str) else json.dumps(value))
    os.chmod(path, mode)


class Private(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abu-")
        os.chmod(self.tmp, 0o700)
        # First registered, so last run: after any cleanup restoring modes.
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def refused(self, code, fn, *args, **kwargs):
        with self.assertRaises(HostError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)


class Arguments(unittest.TestCase):
    def test_parse(self):
        command, options = cli.parse(["jail", "exec", "--config", "/c", "r",
                                      "--env", "A", "--stdin", "--timeout", "5", "--", "true", "--x"])
        self.assertEqual(command, ("jail", "exec"))
        self.assertEqual((options["--env"], options["--stdin"], options["--timeout"], options["argv"],
                          options["positional"]), (["A"], True, "5", ["true", "--x"], ["r"]))
        command, options = cli.parse(["jail", "create", "--config", "/c", "--image", "x",
                                      "-u", "current", "--mount-ro", "/a", "--mount-rw", "/b=c"])
        self.assertEqual((options["--user"], options["--mount-ro"], options["--mount-rw"]),
                         ("current", ["/a"], ["/b=c"]))
        self.assertEqual(cli.parse(["jail", "create", "--config", "/c", "--user=bob"])[1]["--user"], "bob")
        command, options = cli.parse(["image", "prepare", "-t", "mine", "qemu", "--provider-config", "/p",
                                      "--recipe", "/r"])
        self.assertEqual((options["-t"], options["positional"], options["--recipe"]), ("mine", ["qemu"], "/r"))
        self.assertEqual(cli.parse(["image", "recover", "podman", "o-1"])[1]["positional"], ["podman", "o-1"])
        # Serve: acquisitions, never a timeout; run AGENT: both (its own
        # checks decide which mode takes which, agentrun.check_options).
        command, options = cli.parse(["jail", "serve", "r", "--acquisition-config", "/a",
                                      "--acquisition-stage-root", "/s"])
        self.assertEqual((options["--acquisition-config"], options["--acquisition-stage-root"]), ("/a", "/s"))
        self.assertNotIn("--timeout", cli.parse(["jail", "exec", "r", "--", "x"])[1])
        self.assertEqual(cli.parse(["jail", "serve", "r"])[1]["positional"], ["r"])
        command, options = cli.parse(["run", "pi", "--jail", "r", "--timeout",
                                      "604800", "--acquisition-config", "/a"])
        self.assertEqual((options["--timeout"], options["--acquisition-config"]), ("604800", "/a"))
        for bad in (["jail", "exec", "--config", "/c", "r"],
                    ["jail", "exec", "--config", "/c", "r", "--timeout", "0", "--", "x"],
                    ["jail", "exec", "--config", "/c", "r", "--acquisition-stage-root", "/s", "--", "x"],
                    ["jail", "status", "--config", "/c", "r", "--stdin"],
                    ["jail", "status", "--config", "/c", "--config", "/d", "r"], ["jail", "status", "--config", "/c"],
                    ["jail", "create", "--config", "/c", "--provider", "/p"],
                    ["jail", "create", "--ssh-target", "/t", "--image", "x"],
                    ["image", "prepare"], ["image", "prepare", "podman", "--recipe", "/r"],
                    ["image", "prepare", "podman", "qemu"], ["image", "list", "x"],
                    ["image", "recover", "o-1"],
                    ["jail", "create", "--config", "/c", "--ssh-target", "/t", "--user", "x"],
                    ["exec", "--config", "/c", "--run", "r"], ["recover", "--config", "/c", "--run", "r"],
                    ["run", "recover", "--config", "/c", "r"], ["shell"], [],
                    ["jail", "serve", "r", "--timeout", "60"],
                    ["jail", "serve", "r", "--acquisition-stage-root", "/s"],
                    ["jail", "exec", "r", "--timeout", "604801", "--", "x"],
                    ["run", "pi", "--jail", "r", "--timeout", "1.5"]):
            with self.assertRaises(cli.Usage):
                cli.parse(bad)

    def test_run_modes(self):
        # AGENT: the agent's options, its argv after `--` (agentrun.py).
        command, options = cli.parse(["run", "pi", "--image", "x", "--", "-c", "--prompt"])
        self.assertEqual((command, options["positional"], options["argv"]), (("run",), ["pi"], ["-c", "--prompt"]))
        self.assertEqual(cli.parse(["run", "--jail", "r", "pi", "--discard"])[1]["positional"], ["pi"])
        # None: a command, its argv after `--` as is (an agent's name too).
        command, options = cli.parse(["run", "--image", "x", "--env", "A", "--stdin", "--timeout", "5", "--",
                                      "pi", "--prompt", "p"])
        self.assertEqual((options["positional"], options["argv"], options["--env"], options["--stdin"]),
                         ([], ["pi", "--prompt", "p"], ["A"], True))
        self.assertEqual(cli.parse(["run", "--jail", "r", "--", "true"])[1]["--jail"], "r")
        for bad in (["run"], ["run", "--"], ["run", "--image", "x"], ["run", "pi", "codex"],
                    ["run", "--image", "x", "--jail", "r", "--", "true"],
                    ["run", "pi", "--stdin", "--prompt", "p"],
                    ["run", "--timeout", "0", "--", "true"]) + tuple(
                        ["run", option, "v", "--", "true"]
                        for option in ("--ssh-target", "--prompt", "--prompt-file", "--model", "--workspace",
                                       "--copy", "--agent-version", "--copy-auth", "--export-to", "--host-config",
                                       "--user", "--project", "--mount-ro", "--mount-rw", "--acquisition-config")) \
                + tuple(["run", *flag.split(), "--", "true"]
                        for flag in ("--install-agent", "--keep-auth", "--discard", "-u bob")):
            with self.assertRaises(cli.Usage, msg=bad):
                cli.parse(bad)
            err = io.StringIO()
            self.assertEqual(cli.main(bad, err=err), 2)

    def test_no_lan_inventory(self):
        # Removed: an unknown option, a usage error before anything runs.
        for argv in (["jail", "exec", "r", "--lan-inventory", "/l", "--", "true"],
                     ["jail", "serve", "r", "--lan-inventory", "/l"],
                     ["run", "pi", "--jail", "r", "--lan-inventory", "/l"]):
            with self.assertRaises(cli.Usage):
                cli.parse(argv)
            err = io.StringIO()
            self.assertEqual(cli.main(argv, err=err), 2)
            self.assertIn("usage:", err.getvalue())

    def test_allow_connect_is_parsed_before_anything_runs(self):
        command, options = cli.parse(["jail", "exec", "r", "--allow-connect", "Example.COM.:443", "--allow-connect",
                                      "[fd00:0::1]:22", "--allow-connect", "example.com:443",
                                      "--allow-connect", "10.0.0.5:22", "--", "true"])
        self.assertEqual(options["--allow-connect"], ["example.com:443", "[fd00::1]:22", "10.0.0.5:22"])
        for argv in (["jail", "serve", "r"], ["run", "pi", "--jail", "r"], ["run", "--jail", "r"], ["dev", "pi"]):
            tail = ["--", "true"] if argv[1] == "--jail" else []
            self.assertEqual(cli.parse(argv + ["--allow-connect", "nas.lan:445"] + tail)[1]["--allow-connect"],
                             ["nas.lan:445"], argv)
        self.assertEqual(cli.parse(["jail", "exec", "r", "--", "true"])[1]["--allow-connect"], [])
        many = [word for i in range(33) for word in ("--allow-connect", f"h{i}.lan:1")]
        self.assertEqual(len(cli.parse(["jail", "serve", "r"] + many[:64])[1]["--allow-connect"]), 32)
        loopback = [word for value in ("127.0.0.1:22", "127.1.2.3:22", "[::1]:22", "[::ffff:127.0.0.1]:22")
                    for word in ("--allow-connect", value)]
        self.assertEqual(cli.parse(["jail", "serve", "r"] + loopback)[1]["--allow-connect"],
                         ["127.0.0.1:22", "127.1.2.3:22", "[::1]:22", "[::ffff:127.0.0.1]:22"])
        bad = [["jail", "serve", "r", "--allow-connect", value]
               for value in ("0.0.0.0:80", "[::]:80", "[::ffff:0.0.0.0]:80", "*.lan:445", "nas.lan", "nas.lan:0",
                             "nas.lan:1-2", "fd00::1:22", "user@nas.lan:22", "nas.lan:445/x", "")]
        bad += [["jail", "serve", "r"] + many,
                ["shell", "r", "--allow-connect", "nas.lan:445"],
                ["jail", "create", "--allow-connect", "nas.lan:445"],
                ["jail", "export", "r", "--to", "/x", "--allow-connect", "nas.lan:445"],
                ["jail", "stop", "r", "--allow-connect", "nas.lan:445"],
                ["dev", "setup", "--share-agent-dirs", "--allow-connect", "nas.lan:445"]]
        for argv in bad:
            with self.assertRaises(cli.Usage, msg=argv):
                cli.parse(argv)
            err = io.StringIO()
            self.assertEqual(cli.main(argv, err=err), 2, argv)

    def test_insecure_open_is_a_flag_of_the_session_commands_only(self):
        for argv in (["jail", "exec", "r", "--insecure-open", "--", "true"], ["jail", "serve", "r", "--insecure-open"],
                     ["run", "pi", "--jail", "r", "--insecure-open"],
                     ["run", "--jail", "r", "--insecure-open", "--", "true"], ["dev", "pi", "--insecure-open"]):
            self.assertIs(cli.parse(argv)[1].get("--insecure-open"), True, argv)
        self.assertNotIn("--insecure-open", cli.parse(["jail", "serve", "r"])[1])
        self.assertEqual(cli.parse(["jail", "serve", "r", "--insecure-open", "--allow-connect", "Nas.lan:445"])[1]
                         ["--allow-connect"], ["nas.lan:445"])
        for argv in (["shell", "r", "--insecure-open"], ["jail", "create", "--insecure-open"],
                     ["jail", "stop", "r", "--insecure-open"], ["jail", "export", "r", "--to", "/x", "--insecure-open"],
                     ["dev", "setup", "--share-agent-dirs", "--insecure-open"],
                     ["jail", "serve", "r", "--insecure-open", "--allow-connect", "0.0.0.0:1"],
                     ["jail", "serve", "r", "--insecure-open", "x"]):
            with self.assertRaises(cli.Usage, msg=argv):
                cli.parse(argv)
            err = io.StringIO()
            self.assertEqual(cli.main(argv, err=err), 2, argv)
        self.assertIn("Allows workloads to connect to host-local services, including services that trust local "
                      "callers.", " ".join(cli.__doc__.split()))

    def test_usage_exit(self):
        err = io.StringIO()
        self.assertEqual(cli.main(["nope"], err=err), 2)
        self.assertIn("usage:", err.getvalue())

    def test_jail_group(self):
        # `run` is no group (one command: an agent or a command); `jail` is.
        for sub in ("create", "list", "status", "stop", "discard"):
            err = io.StringIO()
            self.assertEqual(cli.main(["run", sub, "r"], err=err), 2)
            self.assertIn("usage:", err.getvalue())
        err = io.StringIO()
        self.assertEqual(cli.main(["agent", "run", "pi"], err=err), 2)
        self.assertIn("agentbox run AGENT        [--config FILE] ", cli.USAGE)
        self.assertIn("agentbox run              [--config FILE] [--image NAME | --jail JAIL] ", cli.USAGE)
        self.assertNotIn("agentbox agent ", cli.USAGE)
        self.assertIn("agentbox jail exec        [--config FILE] JAIL ", cli.USAGE)
        # Every command a diagnostic names exists.
        import re
        from agentbox_controller import agentrun, commandrun, lifecycle
        text = ""
        for module in (cli, agentrun, commandrun, lifecycle):
            with open(module.__file__) as stream:
                text += stream.read()
        self.assertNotIn("agentbox agent ", text)
        named = set(re.findall(r"agentbox (jail|image|checkpoint) ([a-z-]+)", text))
        self.assertTrue({("jail", "status"), ("jail", "stop"), ("jail", "discard"), ("jail", "exec"),
                         ("jail", "create")} <= named, named)
        self.assertEqual({pair for pair in named if pair not in cli.COMMANDS}, set())
        self.assertEqual(re.findall(r"\brun (?:create|exec|status|stop|discard|inputs|serve|export) ", text), [])

    def test_select_env(self):
        self.assertEqual(cli.select_env(["A"], {"A": "1", "B": "2"}), {"A": "1"})
        for names, environ in ((["A"], {}), (["A", "A"], {"A": "1"}), (["A=B"], {"A=B": "1"})):
            with self.assertRaises(HostError) as caught:
                cli.select_env(names, environ)
            self.assertEqual(caught.exception.code, "env_invalid")


class Configuration(Private):
    def test_controller(self):
        data = f"{self.tmp}/data"
        os.mkdir(data, 0o700)
        path = f"{self.tmp}/c.json"
        write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true"})
        loaded = config.load_controller(path, {"HOME": "/nonexistent"})
        self.assertEqual(loaded["policy"], config.DEFAULT_POLICY)
        self.assertEqual(loaded["podman_store"], "shared")
        for store in ("private", "shared"):
            write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true",
                         "podman_store": store})
            self.assertEqual(config.load_controller(path, {})["podman_store"], store)
        for bad in ("Shared", "", None, 1):
            write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true",
                         "podman_store": bad})
            self.refused("config_invalid", config.load_controller, path, {})
        legacy = f"{self.tmp}/agentbox/new"
        write(path, {"schema": config.CONTROLLER_SCHEMA, "data": legacy, "server": "/bin/true"})
        self.refused("data_legacy", config.load_controller, path, {"XDG_DATA_HOME": self.tmp})
        write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true"})
        os.mkdir(f"{data}/runs")
        self.refused("data_legacy", config.load_controller, path, {})
        os.rmdir(f"{data}/runs")
        self.assertIsNone(loaded["connect_proxy"])
        for given, kept in (("Proxy.Corp.:3128", "proxy.corp:3128"), ("[fd00:0::1]:8080", "[fd00::1]:8080"),
                            ("127.0.0.1:3128", "127.0.0.1:3128")):
            write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true",
                         "connect_proxy": given})
            self.assertEqual(config.load_controller(path, {})["connect_proxy"], kept)
        for bad in ("proxy.corp", "0.0.0.0:3128", "[::]:3128", "*.corp:3128", "http://proxy:3128", "", None, 3128):
            write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true",
                         "connect_proxy": bad})
            self.refused("config_invalid", config.load_controller, path, {})
        write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true", "x": 1})
        self.refused("config_invalid", config.load_controller, path, {})
        write(path, {"schema": config.CONTROLLER_SCHEMA, "data": data, "server": "/bin/true"}, 0o620)
        self.refused("config_unreadable", config.load_controller, path, {})

    def test_provider_shape(self):
        good = {"schema": config.PROVIDER_SCHEMA, "provider": "p", "interpreter": "/usr/bin/python3",
                "entry": "/a/e.py", "state": "/s", "assets": "/a"}
        config.check_provider(good)
        for change in ({"entry": "/b/e.py"}, {"state": "/a/s"}, {"guard": {"cpus": 0}}, {"x": 1},
                       {"interpreter": "rel"}):
            self.refused("provider_config_invalid", config.check_provider, dict(good, **change))

    def test_assets(self):
        root = f"{self.tmp}/assets"
        os.mkdir(root, 0o755)
        write(f"{root}/e.py", "", 0o644)
        config.check_assets(root)
        os.chmod(f"{root}/e.py", 0o664)
        config.check_assets(root)
        os.chmod(f"{root}/e.py", 0o666)
        self.refused("provider_untrusted", config.check_assets, root)
        os.chmod(f"{root}/e.py", 0o644)
        os.symlink("/etc/passwd", f"{root}/link")
        self.refused("provider_untrusted", config.check_assets, root)


class Store(Private):
    def make(self, **kwargs):
        data = f"{self.tmp}/data"
        os.makedirs(data, 0o700, exist_ok=True)
        os.chmod(data, 0o700)
        os.makedirs(f"{self.tmp}/a", exist_ok=True)
        provider = {"schema": config.PROVIDER_SCHEMA, "provider": "p", "interpreter": "/usr/bin/python3",
                    "entry": f"{self.tmp}/a/e.py", "state": f"{self.tmp}/s", "assets": f"{self.tmp}/a"}
        opened = store.Store(data)
        self.addCleanup(opened.close)
        manifest = harness.payload()["manifest"]
        return opened, harness.fixture_run(opened, provider, manifest, **kwargs)

    def test_lease_and_status(self):
        opened, run_id = self.make()
        self.assertEqual(opened.status(run_id)["state"], "idle")
        lease = opened.claim(run_id)
        self.refused("run_busy", opened.claim, run_id)
        self.assertEqual(opened.status(run_id)["state"], "active")
        pending = dict({k: None for k in store.PENDING_KEYS}, op="start", processes="unknown")
        lease.save(dict(lease.record, pending=pending))
        lease.release()
        self.assertEqual(opened.status(run_id)["state"], "abandoned")
        lease = opened.claim(run_id)
        self.refused("run_invalid", lease.save, dict(lease.record, pending={"op": "start"}))
        lease.release()
        self.refused("run_unknown", opened.claim, store.new_id("r"))
        self.refused("run_invalid", opened.claim, "../x")

    def test_record_files(self):
        opened, run_id = self.make(limits={"cpus": 2})
        run = f"{self.tmp}/data/controller-runs/{run_id}"
        self.assertEqual(oct(os.stat(run).st_mode & 0o777), "0o700")
        self.assertEqual(oct(os.stat(f"{run}/run.json").st_mode & 0o777), "0o600")
        self.assertEqual(oct(os.stat(f"{run}/worker-manifest.json").st_mode & 0o777), "0o400")
        lease = opened.claim(run_id)
        lease.write_execution("e-" + "0" * 32, {"state": "begun"}, first=True)
        self.assertEqual(lease.execution_count(), 1)
        lease.release()
        os.chmod(f"{run}/run.json", 0o644)
        self.refused("run_invalid", opened.claim, run_id)

    def test_legacy_and_bad_manifest(self):
        opened, _ = self.make()
        self.refused("manifest_invalid", harness.fixture_run, opened,
                     {"schema": config.PROVIDER_SCHEMA, "provider": "p", "interpreter": "/i",
                      "entry": "/a/e", "state": "/s", "assets": "/a"}, "{}")
        # A B2 (v2) root, or any root with controller entries but no
        # marker: refused, untouched.
        old = f"{self.tmp}/old"
        os.makedirs(f"{old}/controller-runs", 0o700)
        os.chmod(old, 0o700)
        self.refused("store_version_unsupported", store.Store, old)
        self.assertEqual(os.listdir(old), ["controller-runs"])


class Capture(Private):
    def test_budget_and_gap(self):
        fd = os.open(self.tmp, os.O_RDONLY | os.O_DIRECTORY)
        cap = capture.Capture(fd, "r-x", "e-x", capture.RESERVE + 2048)
        os.close(fd)
        self.assertTrue(cap.record("guest", "guest.output", body=b"x" * 10))
        self.assertFalse(cap.record("guest", "guest.output", body=b"y" * 4096))
        self.assertFalse(cap.close())
        lines = [json.loads(line) for line in read(f"{self.tmp}/events.jsonl").splitlines()]
        self.assertEqual([line["seq"] for line in lines], [1, 2])
        self.assertEqual(lines[-1]["event_type"], "host.capture.gap")
        self.assertEqual(lines[-1]["attributes"], {"dropped_bytes": 4096, "dropped_records": 1})


class _Calls:
    """A capture stand-in keeping each `record` call's arguments."""

    def __init__(self):
        self.calls = []

    def record(self, origin, event_type, severity="info", attributes=None, body=None, **_):
        self.calls.append((origin, event_type, severity, dict(attributes or {}), body))
        return True


class _Surface:
    def show(self, data):
        pass


def _guest(calls, phase):
    """The real guest frame mapping (guest.py `_handle`/`_reject`) on a
    bare instance in `phase`: no child, loop or session."""
    from agentbox_controller.guest import Guest
    one = object.__new__(Guest)
    one.capture, one.phase, one.nonce, one.exec_id, one.inputs = calls, phase, "s-1", "r1", None
    one.exit = one.failure = None
    one.surfaces = {"stdout": _Surface(), "stderr": _Surface()}
    one._exec = lambda: None
    return one


class EventContract(Private):
    """contracts/v1/events.jsonl, the records the old Rust recorder had to
    produce (its tests/contracts.rs), now through the controller's guest
    mapping and capture."""

    def capture_lines(self, calls, times):
        fd = os.open(self.tmp, os.O_RDONLY | os.O_DIRECTORY)
        cap = capture.Capture(fd, "run-1", "exec-1", 1 << 20)
        os.close(fd)
        with unittest.mock.patch.object(capture.time, "time_ns", side_effect=times):
            for origin, event_type, severity, attributes, body in calls:
                self.assertTrue(cap.record(origin, event_type, severity, attributes, body))
        self.assertTrue(cap.close())
        return read(f"{self.tmp}/events.jsonl").splitlines()

    def test_guest_events_get_host_sequence_and_fixed_origin(self):
        from agentbox_controller.assets import guest_protocol as gp
        calls = _Calls()
        calls.record("host.supervisor", "host.execution.started")
        for phase, text in (("hello", '{"v":1,"type":"hello","session":"s-1","guest_version":"0.1.0"}'),
                            ("running", '{"v":1,"type":"output","id":"r1","stream":"stdout","data":"aGkK"}'),
                            ("running", '{"v":1,"type":"exit","id":"r1","outcome":"exited","code":0}'),
                            ("running", '{"v":1,"type":"error","code":"unknown_type"}')):
            _guest(calls, phase)._handle(gp.decode_guest_frame(text.encode()))
        # A forged guest frame never reaches the mapping; the host records
        # the code only.
        forged = (b'{"v":1,"type":"output","id":"r1","stream":"stdout","data":"aGk=","seq":1,'
                  b'"origin":"host.supervisor"}')
        with self.assertRaises(gp.Refused) as caught:
            gp.decode_guest_frame(forged)
        _guest(calls, "running")._reject(caught.exception.code)
        # The controller's own lifecycle step after the matching hello
        # (contracts/v1 README: `guest_ready` follows it), not a frame's
        # record: outside the vector.
        ready = ("host.supervisor", "host.execution.guest_ready", "info", {}, None)
        self.assertEqual(calls.calls[2], ready)
        del calls.calls[2]
        lines = self.capture_lines(calls.calls, [1_700_000_000_000_000_001 + i for i in range(6)])
        with open(os.path.join(harness.REPO, "contracts", "v1", "events.jsonl")) as stream:
            self.assertEqual(lines, stream.read().splitlines())
        for index, line in enumerate(lines):
            record = json.loads(line)
            self.assertEqual((record["seq"], record["schema"]), (index + 1, capture.SCHEMA))

    def test_guest_output_body_is_the_reported_bytes(self):
        from agentbox_controller.assets import guest_protocol as gp
        calls = _Calls()
        frame = gp.decode_guest_frame(b'{"v":1,"type":"output","id":"r1","stream":"stderr","data":"AP8K"}')
        _guest(calls, "running")._handle(frame)
        record = json.loads(self.capture_lines(calls.calls, [1])[0])
        self.assertEqual((record["origin"], record["body"], record["body_encoding"]), ("guest", "AP8K", "base64"))
        self.assertEqual(record["attributes"], {"bytes": 3, "request_id": "r1", "stream": "stderr"})
        self.assertEqual(record["time_unix_nano"], "1")


class Admission(Private):
    def setUp(self):
        super().setUp()
        self.data = f"{self.tmp}/data"
        self.state = f"{self.tmp}/state"
        os.mkdir(self.data, 0o700)
        os.mkdir(self.state, 0o700)
        write(f"{self.state}/blob", "x" * 100000)
        self.opened = store.Store(self.data)
        self.addCleanup(self.opened.close)

    def limits(self, maximum, scopes_):
        write(f"{self.data}/run-limits.json", {"max_reserved_bytes": maximum, "storage_scopes": scopes_})

    def test_admit(self):
        self.limits(1 << 30, [{"path": self.state, "measure": "tree"}])
        published = []
        figures = scopes.admit(self.opened, self.state, lambda: published.append(1))
        self.assertEqual(published, [1])
        self.assertGreaterEqual(figures["measured_bytes"], 100000)
        self.limits(1000, [{"path": self.state, "measure": "tree"}])
        self.refused("storage_limit", scopes.admit, self.opened, self.state, lambda: None)
        self.limits(1 << 30, [{"path": self.data, "measure": "tree"}])
        self.refused("storage_scope_undeclared", scopes.admit, self.opened, self.state, lambda: None)
        write(f"{self.data}/run-limits.json", '{"max_reserved_bytes": 1.5}')
        self.refused("storage_limits_invalid", scopes.admit, self.opened, self.state, lambda: None)


class Traversal(Private):
    """Bounded streaming of a declared tree: entries, descriptors and memo."""

    def tree(self, scope, **limits):
        saved = {name: getattr(scopes, name) for name in limits}
        for name, value in limits.items():
            setattr(scopes, name, value)
        try:
            measure = scopes._Measure([scope])
            before = len(os.listdir("/proc/self/fd"))
            try:
                measure.tree(scope)
            finally:
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)
            return measure
        finally:
            for name, value in saved.items():
                setattr(scopes, name, value)

    def fill(self, path, count, data=""):
        os.makedirs(path, exist_ok=True)
        for index in range(count):
            write(f"{path}/f{index}", data)

    def test_broad_strict_refuses(self):
        self.fill(f"{self.tmp}/t/broad", 500)
        with self.assertRaises(HostError) as caught:
            self.tree({"path": f"{self.tmp}/t", "measure": "tree"}, MAX_STRICT_ENTRIES=100)
        self.assertEqual(caught.exception.code, "storage_scan_incomplete")

    def test_spent_uncapped_prunes(self):
        for name in ("a", "b", "c"):
            self.fill(f"{self.tmp}/t/cache/{name}", 200)
        self.fill(f"{self.tmp}/t/kept", 5, "x" * 5000)
        measure = self.tree({"path": f"{self.tmp}/t", "measure": "tree", "uncapped": ["cache"]},
                            MAX_UNCAPPED_ENTRIES=50)
        self.assertGreater(measure.warnings, 0)
        self.assertLessEqual(measure.entries, 50 + 10)
        self.assertGreaterEqual(measure.total, 5 * 4096)

    def test_depth_bounded_descriptors(self):
        path = f"{self.tmp}/t"
        for depth in range(12):
            path += "/d"
            self.fill(path + "x", 3)
        os.makedirs(path)
        measure = self.tree({"path": f"{self.tmp}/t", "measure": "tree"})
        self.assertLessEqual(measure.peak, 13)

    def test_strict_gap_refuses_uncapped_warns(self):
        self.fill(f"{self.tmp}/t/locked", 1)
        self.fill(f"{self.tmp}/t/cache/locked", 1)
        os.chmod(f"{self.tmp}/t/cache/locked", 0)
        self.addCleanup(os.chmod, f"{self.tmp}/t/cache/locked", 0o700)
        measure = self.tree({"path": f"{self.tmp}/t", "measure": "tree", "uncapped": ["cache"]})
        self.assertEqual(measure.warnings, 1)
        os.chmod(f"{self.tmp}/t/locked", 0)
        self.addCleanup(os.chmod, f"{self.tmp}/t/locked", 0o700)
        with self.assertRaises(HostError):
            self.tree({"path": f"{self.tmp}/t", "measure": "tree", "uncapped": ["cache"]})

    def test_links_once_while_memo_lasts(self):
        self.fill(f"{self.tmp}/t", 1, "x" * 8192)
        for index in range(3):
            os.link(f"{self.tmp}/t/f0", f"{self.tmp}/t/l{index}")
        once = self.tree({"path": f"{self.tmp}/t", "measure": "tree"}).total
        over = self.tree({"path": f"{self.tmp}/t", "measure": "tree"}, MAX_LINKED=1).total
        self.assertGreater(over, once)


class Emit(unittest.TestCase):
    def test_full_pipe_gives_up(self):
        read, write_end = os.pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write_end)
        os.set_blocking(write_end, False)
        try:
            while True:
                os.write(write_end, b"x" * 65536)
        except BlockingIOError:
            pass
        os.set_blocking(write_end, True)
        began = time.monotonic()
        self.assertFalse(display.emit(write_end, b"final\n", 0.3))
        self.assertLess(time.monotonic() - began, 2)
        os.read(read, 1 << 20)
        self.assertTrue(display.emit(write_end, b"final\n", 0.3))


class Profile(unittest.TestCase):
    def test_argv(self):
        conn = ssh.Connection("agentbox", "/k/id", "/k/known", "agentbox-r-e", endpoint=("127.0.0.1", 2222))
        argv = conn.session("/usr/bin/ssh", "/c/launcher", 40000)
        self.assertEqual(argv[:9], ["/usr/bin/ssh", "-F", "/dev/null", "-T", "-l", "agentbox", "-p", "2222",
                                    "-R"])
        self.assertEqual(argv[9], "127.0.0.1:18080:127.0.0.1:40000")
        self.assertEqual(argv[-2:], ["127.0.0.1", "/c/launcher"])
        options = argv[11:-2:2]
        self.assertEqual(options, list(ssh.OPTIONS) + ["IdentityFile=/k/id", "UserKnownHostsFile=/k/known",
                                                       "HostKeyAlias=agentbox-r-e"])
        self.assertEqual(conn.bootstrap("/s")[-3:], ["127.0.0.1", "/bin/sh", "-s"])
        with self.assertRaises(HostError):
            conn.session("/s", "/c/launcher", 2222)
        proxy = ssh.Connection("agentbox", "/k/id", "/k/known", "agentbox-r-e",
                               proxy=["/usr/bin/python3", "-I", "/a/e.py", "connect", "/s", "r", "e", "i"],
                               proxy_env={"SHELL": "/bin/bash", "A": "1"})
        argv = proxy.bootstrap("/s")
        self.assertIn("ProxyCommand=/usr/bin/python3 -I /a/e.py connect /s r e i", argv)
        self.assertNotIn("ProxyCommand=none", argv)
        self.assertEqual(argv[-3], "agentbox-r-e")
        self.assertEqual(proxy.env({}), {"A": "1", "LC_ALL": "C"})
        for bad in ({"endpoint": ("10.0.0.1", 22)}, {"endpoint": ("127.0.0.1", 22), "proxy": ["/p"]},
                    {"proxy": ["/p", "a;b"]}):
            with self.assertRaises(HostError):
                ssh.Connection("agentbox", "/k/id", "/k/known", "a", **bad)
        with self.assertRaises(HostError):
            ssh.Connection("agentbox", "/k/id x", "/k/known", "a", endpoint=("127.0.0.1", 22))

    def test_layout_and_replies(self):
        layout = ssh.Layout("/c", "/h", "a" * 64, "b" * 32)
        self.assertEqual(layout.launcher, f"/c/agentbox-worker-v1/releases/{'a' * 64}-{'b' * 32}/launcher")
        for bad in (("/c", "/c/h"), ("/c", "/c"), ("/c x", "/h")):
            with self.assertRaises(HostError):
                ssh.Layout(bad[0], bad[1], "a" * 64, "b" * 32)
        good = f"{ssh.READY} {layout.name}\n".encode()
        self.assertEqual(ssh.reply_ok("verify", layout, 0, good), (True, None))
        self.assertEqual(ssh.reply_ok("verify", layout, 1, f"{ssh.FAILED} digest\n".encode()), (False, "digest"))
        self.assertEqual(ssh.reply_ok("verify", layout, 1, f"{ssh.FAILED} other\n".encode()), (False, None))
        self.assertEqual(ssh.reply_ok("prepare", layout, 0, good), (False, None))
        text = ssh.Plan(layout, manifest=harness.payload()["manifest"].encode()).launcher_text()
        self.assertIn(f"'{ssh.PREINSTALLED}/guest/src/main.py' 'supplied-session-v3' '/h' '/h/work'", text)
        manifest = harness.payload()["manifest"].encode()
        self.assertEqual([name for name, _ in ssh.Plan(layout, manifest=manifest).wrapper_texts()],
                         ["agentbox-request"])
        texts = dict(ssh.Plan(layout, manifest=manifest, shims=[("memo", "acquisitions/memo/jail/memo.py")],
                              session="acquisitions/pip/jail/pip.py").wrapper_texts())
        self.assertEqual(sorted(texts), ["agentbox-request", "agentbox-session", "memo"])
        self.assertTrue(texts["agentbox-session"].endswith(
            f"'{ssh.PREINSTALLED}/acquisitions/pip/jail/pip.py' session \"$@\"\n"), texts["agentbox-session"])

    def test_verify_refuses_changed_payload(self):
        """The verify script against a payload copy: a changed byte fails
        `digest` (ownership checks stubbed: tests do not run as root)."""
        built = harness.payload()
        tmp = tempfile.mkdtemp(prefix="abv-")
        self.addCleanup(shutil.rmtree, tmp, True)
        copy = f"{tmp}/worker"
        shutil.copytree(built["path"], copy)
        os.makedirs(f"{tmp}/control/agentbox-worker-v1/releases", 0o700)
        os.chmod(f"{tmp}/control/agentbox-worker-v1", 0o700)
        layout = ssh.Layout(f"{tmp}/control", f"{tmp}/home", built["release"], "c" * 32)

        def run(script):
            script = script.replace(f"payload='{ssh.PREINSTALLED}'", f"payload='{copy}'")
            script = "\n".join("sealed() { :; }" if line.startswith("sealed()") else line
                               for line in script.split("\n"))
            done = subprocess.run(["/bin/sh", "-s"], input=script.encode(), capture_output=True)
            return done.returncode, done.stdout

        manifest = built["manifest"].encode()
        code, out = run(ssh.Plan(layout, manifest=manifest).prepare_script())
        self.assertEqual(ssh.reply_ok("prepare", layout, code, out), (True, None))
        target = f"{copy}/guest/src/protocol.py"
        os.chmod(target, 0o644)
        with open(target, "ab") as stream:
            stream.write(b"#")
        code, out = run(ssh.Plan(layout, manifest=manifest).verify_script())
        self.assertEqual(ssh.reply_ok("verify", layout, code, out), (False, "size"))
        layout2 = ssh.Layout(f"{tmp}/control", f"{tmp}/home", built["release"], "d" * 32)
        shutil.rmtree(copy)
        shutil.copytree(built["path"], copy)
        plan = ssh.Plan(layout2, manifest=manifest, session="acquisitions/pip/jail/pip.py")
        self.assertEqual(ssh.reply_ok("prepare", layout2, *run(plan.prepare_script())), (True, None))
        self.assertEqual(ssh.reply_ok("verify", layout2, *run(plan.verify_script())), (True, None))
        self.assertEqual(oct(os.stat(layout2.launcher).st_mode & 0o777), "0o500")
        wrapper = f"{layout2.install}/bin/agentbox-session"
        self.assertEqual(oct(os.stat(wrapper).st_mode & 0o777), "0o500")
        with open(wrapper) as stream:
            self.assertIn(f"'{ssh.PREINSTALLED}/acquisitions/pip/jail/pip.py' session \"$@\"", stream.read())


class Envelope(unittest.TestCase):
    def test_envelope(self):
        self.assertEqual(cgroups.envelope({"cpus": 2, "memory_mib": 512}),
                         {"cpus": 3, "memory_mib": 1536, "pids": 2048})
        self.assertEqual(cgroups.envelope({}, {"pids": 100}), {"cpus": 4, "memory_mib": 8192, "pids": 100})
        self.assertEqual(cgroups.limit_files({"cpus": 3, "memory_mib": 1, "pids": 7}),
                         [("cpu.max", "300000 100000"), ("memory.max", "1048576"), ("memory.swap.max", "0"),
                          ("pids.max", "7")])

    def test_parse_self(self):
        self.assertEqual(cgroups.parse_self(b"0::/a/b.scope\n"), ["a", "b.scope"])
        for bad in (b"1:cpu:/a\n0::/a\n", b"0::/a (deleted)\n", b"0::/a/../b\n", b"\xff"):
            with self.assertRaises(HostError):
                cgroups.parse_self(bad)


class Domains(Private):
    def host(self):
        fake = FakeCgroups(self.tmp)
        self.addCleanup(lambda: [os.kill(p, 9) for p in fake.pids(fake.root) if p != os.getpid()
                                 and _alive(p)])
        return fake

    def test_enter_and_domain(self):
        fake = self.host()
        names = cgroups.enter(fake)
        self.assertEqual(names[-1], fake.units[0])
        self.assertEqual(fake.self_names(), names + ["controller"])
        domain = cgroups.Domain.create(fake, {"cpus": 2, "memory_mib": 1536, "pids": 100})
        d = os.path.join(fake.root, *names, domain.name)
        self.assertEqual(read(f"{d}/memory.max"), str(1536 << 20))
        self.assertEqual(read(f"{d}/memory.swap.max"), "0")
        self.assertEqual(read(f"{d}/cpu.max"), "200000 100000")
        leaf = domain.leaf()
        child = Child(["sleep", "100"], {}, leaf=leaf, stdin=False, stdout=False, stderr=False)
        os.close(leaf)
        self.assertEqual(read(f"{d}/h-1/cgroup.procs").split(), [str(child.pid)])
        os.mkdir(f"{d}/engine")
        engine = subprocess.Popen(["sleep", "100"], start_new_session=True)
        write(f"{d}/engine/cgroup.procs", f"{engine.pid}\n")
        record = domain.record()
        self.assertTrue(domain.kill_until(time.monotonic() + 5))
        child.finish()
        engine.wait()
        self.assertTrue(domain.remove())
        self.assertFalse(os.path.exists(d))
        self.assertIsNone(cgroups.Domain.adopt(fake, record))

    def test_failures_before_effects(self):
        fake = self.host()
        fake.fail_start = True
        self.refused("delegation_missing", cgroups.enter, fake)
        fake.fail_start, fake.no_membership = False, True
        cgroups.UNIT_REQUEST_TIMEOUT, saved = 0.2, cgroups.UNIT_REQUEST_TIMEOUT
        try:
            self.refused("delegation_uncertain", cgroups.enter, fake)
        finally:
            cgroups.UNIT_REQUEST_TIMEOUT = saved
        fake = FakeCgroups(f"{self.tmp}/b")
        cgroups.enter(fake)
        fake.mismatch = "memory.max"
        self.refused("limit_mismatch", cgroups.Domain.create, fake, cgroups.DEFAULT_ENVELOPE)
        fake.mismatch = None
        unit = os.path.join(fake.root, *fake.self_names()[:-1])
        self.assertEqual([n for n in os.listdir(unit) if n.startswith("agentbox-")], [])
        self.refused("delegation_missing", cgroups.Domain.create, FakeCgroups(f"{self.tmp}/c"),
                     cgroups.DEFAULT_ENVELOPE)

    def test_adopt_identity(self):
        fake = self.host()
        cgroups.enter(fake)
        domain = cgroups.Domain.create(fake, cgroups.DEFAULT_ENVELOPE)
        record = domain.record()
        domain.close()
        self.refused("domain_invalid", cgroups.Domain.adopt, fake, dict(record, identity=[0, 0]))
        self.refused("domain_invalid", cgroups.Domain.adopt, fake, dict(record, path="/sys/fs/cgroup/x"))
        self.refused("domain_invalid", cgroups.Domain.adopt, fake,
                     dict(record, path=record["path"].rsplit("/", 1)[0] + "/other"))
        adopted = cgroups.Domain.adopt(fake, record)
        self.assertTrue(adopted.kill_until(time.monotonic() + 1))
        self.assertTrue(adopted.remove())

    def test_adopt_absent_replaced_unreadable(self):
        """Absence only from ENOENT on the exact path: D gone, or an ancestor
        gone. Another cgroup at the path, or an unreadable level, refuses."""
        fake = self.host()
        cgroups.enter(fake)
        domain = cgroups.Domain.create(fake, cgroups.DEFAULT_ENVELOPE)
        record = domain.record()
        unit = record["path"].rsplit("/", 1)[0]
        # Made while D exists: surely another inode (a test filesystem may
        # reuse a freed one; cgroupfs ids are not reused).
        os.mkdir(f"{unit}/replacement")
        self.assertTrue(domain.kill_until(time.monotonic() + 1))
        self.assertTrue(domain.remove())
        self.assertIsNone(cgroups.Domain.adopt(fake, record))
        os.rename(f"{unit}/replacement", record["path"])
        self.refused("domain_invalid", cgroups.Domain.adopt, fake, record)
        os.rmdir(record["path"])
        os.chmod(unit, 0)
        try:
            self.refused("domain_invalid", cgroups.Domain.adopt, fake, record)
        finally:
            os.chmod(unit, 0o755)
        self.refused("domain_invalid", cgroups.Domain.adopt, fake, {"path": record["path"]})
        shutil.rmtree(unit)
        self.assertIsNone(cgroups.Domain.adopt(fake, record))
        write(unit, "")
        self.refused("domain_invalid", cgroups.Domain.adopt, fake, record)

    def test_stuck_kill_unsettled(self):
        fake = self.host()
        cgroups.enter(fake)
        domain = cgroups.Domain.create(fake, cgroups.DEFAULT_ENVELOPE)
        leaf = domain.leaf()
        child = Child(["sleep", "100"], {}, leaf=leaf, stdin=False, stdout=False, stderr=False)
        os.close(leaf)
        fake.stuck = True
        self.assertFalse(domain.kill_until(time.monotonic() + 0.3))
        self.assertFalse(domain.remove())
        fake.stuck = False
        self.assertTrue(domain.kill_until(time.monotonic() + 5))
        child.finish()
        self.assertTrue(domain.remove())


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class Reporting(unittest.TestCase):
    def test_line(self):
        report = execute.Report()
        report.fail("completed")
        report.exit = {"outcome": "exited", "code": 0}
        report.host_cleanup, report.provider, report.durability = True, "settled", "unchanged"
        report.capture_complete = True
        self.assertTrue(report.ok())
        self.assertEqual(report.line(), "execution: outcome=completed reason=completed exit=0 host_cleanup=confirmed"
                                         " provider=settled durability=unchanged output=complete")
        report.output = "output_behind"
        self.assertFalse(report.ok())
        self.assertIn("output=incomplete output_code=output_behind", report.line())

    def test_render(self):
        self.assertEqual(display.render("a\tb\n\x1b[2J‮"), "a\tb\n\\x1b[2J\\u{202e}")


if __name__ == "__main__":
    unittest.main()
