"""B2 units, offline: run records, input selection, handler selection and
trust, worker result lines, the server client's bounds and the lane's own
decisions over a stub server.

  python3 -I -B -m unittest discover -s tests -t .
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest

from tests.controller import harness
from agentbox_controller import acquisition, handlers, inputs, server as server_mod, store
from agentbox_controller.assets import post_codec
from agentbox_controller.host import HostError, Loop

NONCE = "0123456789abcdef0123456789abcdef"


class Private(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="abu-")
        os.chmod(self.tmp, 0o700)
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def refused(self, code, fn, *args, **kwargs):
        with self.assertRaises(HostError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def handler_tree(self, ids=("echo", "fake"), name="assets"):
        assets = f"{self.tmp}/{name}"
        harness.copy_tree(f"{harness.REPO}/acquisitions/lib", f"{assets}/acquisitions/lib")
        for ident in ids:
            source = f"{harness.HERE}/handlers/fake" if ident == "fake" \
                else f"{harness.REPO}/acquisitions/testing/{ident}"
            harness.copy_tree(source, f"{assets}/acquisitions/{ident}")
        os.chmod(assets, 0o755)
        os.chmod(f"{assets}/acquisitions", 0o755)
        return assets

    def config(self, assets, entries, interpreter=sys.executable):
        handlers_ = {}
        for ident, extra in entries.items():
            policy = f"{self.tmp}/policy-{ident}.json"
            harness.write_file(policy, {"schema": "agentbox.echo.policy.v1", "prefix": "p", "code": "no"}
                               if ident == "echo" else {})
            handlers_[ident] = dict({"policy": policy}, **(extra or {}))
        path = f"{self.tmp}/acq.json"
        harness.write_file(path, {"schema": handlers.CONFIG_SCHEMA, "interpreter": interpreter, "assets": assets,
                                  "handlers": handlers_})
        return path


class Records(Private):
    def test_record_fields(self):
        data = f"{self.tmp}/data"
        os.mkdir(data, 0o700)
        opened = store.Store(data)
        self.addCleanup(opened.close)
        provider = {"schema": "agentbox.provider-config.v1", "provider": "p", "interpreter": "/usr/bin/python3",
                    "entry": f"{self.tmp}/a/e.py", "state": f"{self.tmp}/s", "assets": f"{self.tmp}/a"}
        run_id = harness.fixture_run(opened, provider, harness.payload()["manifest"], retention="disk")
        lease = opened.claim(run_id)
        self.addCleanup(lease.release)
        mount = {"source": "/srv/src", "destination": "src", "access": "rw"}
        lease.save(dict(lease.record, mounts=[mount], project="src/app"))
        for extra in ({"project": "../x"}, {"project": ".hidden/x"}, {"mounts": [dict(mount, access="x")]},
                      {"retention": "operator"}, {"inputs": {"state": "staged"}}, {"phase": "gone"},
                      {"storage": "dirty"}, {"asserted": ["x"]}, {"home": None}):
            self.refused("run_invalid", lease.save, dict(lease.record, **extra))
        self.refused("run_invalid", lease.save, dict(lease.record, retention="none"))
        self.refused("run_invalid", harness.fixture_run, opened, provider, harness.payload()["manifest"],
                     retention="always")


class Selection(Private):
    def test_workspace_and_copies(self):
        chosen = inputs.selection("proj", ["/etc/hosts=notes/hosts", "../x=y"], "/srv/here")
        self.assertEqual(chosen, [("/srv/here/proj", "work", "directory"), ("/etc/hosts", "notes/hosts", "any"),
                                  ("/srv/x", "y", "any")])
        for workspace, copies, code in ((None, [], "inputs_selection_invalid"),
                                        ("/", [], "inputs_selection_invalid"),
                                        (None, ["/a=work", "/b=work/x"], "input_destination_conflict"),
                                        (None, ["/a=.agentbox-root/x"], "input_destination_invalid"),
                                        (None, ["/a=x\x01"], "input_destination_invalid"),
                                        (None, ["rel=x"], "input_cwd_unavailable")):
            cwd = None if code == "input_cwd_unavailable" else "/srv"
            self.refused(code, inputs.selection, workspace, copies, cwd)
        self.refused("inputs_selection_invalid", inputs.selection, None, [f"/s{i}=d{i}" for i in range(33)], "/")


class Handlers(Private):
    def test_selection_and_shims(self):
        assets = self.handler_tree(("echo", "fake", "memo"))
        chosen = handlers.read(self.config(assets, {"echo": {"operations": ["say"]}, "fake": None, "memo": None}))
        self.assertEqual(chosen.handlers["echo"].permitted, ["say"])
        self.assertEqual(chosen.handlers["fake"].metering, "http")
        self.assertEqual(chosen.shims(), [("memo", "acquisitions/memo/jail/memo.py")])
        self.assertTrue(os.path.isabs(chosen.interpreter))

    def manifest(self, assets, ident, **changes):
        path = f"{assets}/acquisitions/{ident}/manifest.json"
        with open(path) as stream:
            value = json.load(stream)
        value.update(changes)
        os.chmod(path, 0o644)
        harness.write_file(path, value, 0o644)

    def test_manifest_bounds(self):
        assets = self.handler_tree(("echo",))
        config = self.config(assets, {"echo": None})
        files = [f"echo/f{i}.py" for i in range(65)]
        for change in ({"files": files}, {"operations": [f"o{i}" for i in range(17)]},
                       {"limits": {"args_bytes": 61441}}, {"limits": {"acquisition_seconds": 0}},
                       {"jail": {"entry": "acquisitions/other/jail/x.py"}},
                       {"jail": {"entry": "acquisitions/echo/jail/x.py", "shims": ["ssh"]}},
                       {"version": "bad version"}, {"id": "other"}, {"metering": "bytes"},
                       {"tools": ["Git"]}, {"entry": "echo/host/missing.py"}, {"extra": 1}):
            self.manifest(assets, "echo", **change)
            self.refused("handler_manifest_invalid", handlers.read, config)
            shutil.rmtree(f"{assets}/acquisitions/echo")
            harness.copy_tree(f"{harness.REPO}/acquisitions/testing/echo", f"{assets}/acquisitions/echo")
        handlers.read(config)

    def test_one_session_handler_and_its_reserved_wrapper(self):
        assets = self.handler_tree(("echo", "memo"))
        harness.copy_tree(f"{harness.REPO}/acquisitions/pip", f"{assets}/acquisitions/pip")
        config = self.config(assets, {"pip": None, "memo": None})
        chosen = handlers.read(config)
        self.assertEqual(chosen.session(), "acquisitions/pip/jail/pip.py")
        self.assertEqual(chosen.handlers["pip"].operations, ["files", "fetch"])
        self.assertEqual(chosen.shims(), [("memo", "acquisitions/memo/jail/memo.py")])
        self.assertIsNone(handlers.read(self.config(assets, {"memo": None})).session())
        config = self.config(assets, {"pip": None, "memo": None})
        self.manifest(assets, "memo", jail={"entry": "acquisitions/memo/jail/memo.py", "shims": ["memo"],
                                            "session": True})
        self.refused("handler_session_conflict", handlers.read, config)
        for jail in ({"entry": "acquisitions/memo/jail/memo.py", "session": 1},
                     {"entry": "acquisitions/memo/jail/memo.py", "shims": ["agentbox-session"]}):
            self.manifest(assets, "memo", jail=jail)
            self.refused("handler_manifest_invalid", handlers.read, config)

    def test_trust_and_policy(self):
        assets = self.handler_tree(("echo", "memo"))
        config = self.config(assets, {"echo": None})
        lib = f"{assets}/acquisitions/lib"
        os.symlink("agentbox_handler.py", f"{lib}/shadow.py")
        self.refused("acquisition_worker_untrusted", handlers.read, config)
        os.unlink(f"{lib}/shadow.py")
        os.chmod(f"{lib}/agentbox_handler.py", 0o664)
        handlers.read(config)
        os.chmod(f"{lib}/agentbox_handler.py", 0o666)
        self.refused("acquisition_worker_untrusted", handlers.read, config)
        os.chmod(f"{lib}/agentbox_handler.py", 0o644)
        os.chmod(f"{self.tmp}/policy-echo.json", 0o620)
        self.refused("handler_policy_unreadable", handlers.read, config)
        harness.write_file(f"{self.tmp}/policy-echo.json", '{"a": 1, "a": 2}')
        self.refused("handler_policy_invalid", handlers.read, config)
        self.refused("handler_operation_unknown", handlers.read, self.config(assets, {"echo": {"operations": ["x"]}}))
        self.refused("acquisition_config_invalid", handlers.read, self.config(assets, {"lib": None}))
        self.refused("acquisition_worker_untrusted", handlers.read,
                     self.config(assets, {"echo": None}, interpreter=f"{self.tmp}/missing"))


class Defaults(Private):
    """The session's selection without --acquisition-config: acquisition.json,
    else (ENOENT only) the packaged git, npm and pip with their own
    policies. A stand-in packaged tree and PATH lookup; nothing runs."""

    def setUp(self):
        super().setUp()
        self.packaged = self.handler_tree((), "packaged")
        for ident in handlers.PACKAGED:
            harness.copy_tree(f"{harness.REPO}/acquisitions/{ident}", f"{self.packaged}/acquisitions/{ident}")
        saved = handlers.PACKAGED_ASSETS, handlers.find_tool
        handlers.PACKAGED_ASSETS = self.packaged
        self.addCleanup(lambda: (setattr(handlers, "PACKAGED_ASSETS", saved[0]),
                                 setattr(handlers, "find_tool", saved[1])))
        self.bin = harness._dir(f"{self.tmp}/bin")
        self.git = f"{self.bin}/git"
        harness.write_file(self.git, "#!/bin/sh\n", 0o755)
        self.tools = {"git": self.git}
        handlers.find_tool = self.find
        self.xdg = harness._dir(f"{self.tmp}/xdg")
        self.environ = {"XDG_CONFIG_HOME": self.xdg}
        self.file = f"{self.xdg}/agentbox/acquisition.json"

    def find(self, name):
        found = self.tools.get(name, "tool_missing")
        if found in ("tool_missing", "tool_untrusted"):
            raise HostError(found)
        return found

    def implicit(self):
        return handlers.implicit(self.environ, lambda: sys.executable)

    def persistent(self, value, mode=0o600):
        harness._dir(f"{self.xdg}/agentbox")
        harness.write_file(self.file, value, mode)

    def test_absent_file_selects_the_packaged_defaults(self):
        chosen = self.implicit()
        self.assertEqual(sorted(chosen.handlers), ["git", "npm", "pip"])
        self.assertEqual((chosen.assets, chosen.interpreter), (self.packaged, os.path.realpath(sys.executable)))
        for ident, handler in chosen.handlers.items():
            with open(f"{harness.REPO}/acquisitions/{ident}/policy.json") as stream:
                self.assertEqual(handler.policy, json.load(stream))
            self.assertEqual(handler.permitted, handler.operations)
        self.assertEqual(chosen.handlers["git"].policy,
                         {"schema": "agentbox.git.request-policy.v1", "grant": "github-public-read-v1"})
        self.assertEqual(chosen.handlers["git"].tools, {"git": self.git})
        self.assertEqual(chosen.session(), "acquisitions/pip/jail/pip.py")
        self.assertEqual(sorted(name for name, _ in chosen.shims()), ["git", "npm", "npx"])
        # Without a default interpreter given: /usr/bin/python3.
        if os.path.exists("/usr/bin/python3"):
            self.assertEqual(handlers.implicit(self.environ).interpreter, os.path.realpath("/usr/bin/python3"))

    def test_git_missing_or_untrusted(self):
        del self.tools["git"]
        with self.assertRaises(HostError) as caught:
            self.implicit()
        self.assertEqual(caught.exception.code, "acquisition_git_missing")
        self.assertIn("git was not found on the host PATH", caught.exception.hint)
        self.assertIn('{"schema": "agentbox.acquisition-config.v2", "handlers": {"npm": {}, "pip": {}}}',
                      caught.exception.hint)
        # The hint's example disables Git: no git needed.
        self.persistent('{"schema": "agentbox.acquisition-config.v2", "handlers": {"npm": {}, "pip": {}}}')
        self.assertEqual(sorted(self.implicit().handlers), ["npm", "pip"])
        os.unlink(self.file)
        # Present but not trusted: never the missing-git diagnostic.
        self.tools["git"] = "tool_untrusted"
        self.refused("acquisition_worker_untrusted", self.implicit)
        self.tools["git"] = self.git
        os.chmod(self.git, 0o777)
        self.refused("acquisition_worker_untrusted", self.implicit)
        os.chmod(self.git, 0o755)
        self.implicit()

    def test_other_missing_tool_is_not_git(self):
        self.manifest_tools("npm", ["git"])
        del self.tools["git"]
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "handlers": {"npm": {}}})
        self.refused("acquisition_tool_missing", self.implicit)

    def manifest_tools(self, ident, tools):
        path = f"{self.packaged}/acquisitions/{ident}/manifest.json"
        with open(path) as stream:
            value = json.load(stream)
        harness.write_file(path, dict(value, tools=tools), 0o644)

    def test_persistent_file_replaces_the_defaults(self):
        policy = f"{self.tmp}/npm-policy.json"
        harness.write_file(policy, {"schema": "agentbox.npm.registry-policy.v1",
                                    "registry": "https://registry.example.org/"})
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "handlers": {"npm": {"policy": policy,
                                                                                "operations": ["metadata"]}}})
        chosen = self.implicit()
        self.assertEqual(sorted(chosen.handlers), ["npm"])
        self.assertEqual(chosen.handlers["npm"].policy["registry"], "https://registry.example.org/")
        self.assertEqual(chosen.handlers["npm"].permitted, ["metadata"])
        # None enabled: no lane at all.
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "handlers": {}})
        self.assertIsNone(self.implicit())
        # An explicit file names everything itself, the old form unchanged.
        assets = self.handler_tree(("echo",))
        self.assertEqual(sorted(handlers.read(self.config(assets, {"echo": None})).handlers), ["echo"])

    def test_dangerous_or_broken_files_never_fall_back(self):
        good = json.dumps({"schema": handlers.CONFIG_SCHEMA, "handlers": {"pip": {}}})
        self.persistent(good)
        self.assertEqual(sorted(self.implicit().handlers), ["pip"])
        for mode in (0o620, 0o602):
            os.chmod(self.file, mode)
            self.refused("acquisition_config_unreadable", self.implicit)
        os.unlink(self.file)
        harness.write_file(f"{self.tmp}/elsewhere.json", good)
        os.symlink(f"{self.tmp}/elsewhere.json", self.file)
        self.refused("acquisition_config_unreadable", self.implicit)
        os.unlink(self.file)
        os.symlink(f"{self.tmp}/missing.json", self.file)
        self.refused("acquisition_config_unreadable", self.implicit)
        os.unlink(self.file)
        os.mkdir(self.file, 0o700)
        self.refused("acquisition_config_unreadable", self.implicit)
        os.rmdir(self.file)
        for bad in ("{", '{"schema": "agentbox.acquisition-config.v2"}', json.dumps(
                {"schema": handlers.CONFIG_SCHEMA, "handlers": {"pip": {}}, "extra": 1}), json.dumps(
                {"schema": handlers.CONFIG_SCHEMA, "handlers": {"pip": {"policy": "rel.json"}}}), json.dumps(
                {"schema": handlers.CONFIG_SCHEMA, "assets": "rel", "handlers": {}})):
            self.persistent(bad)
            self.refused("acquisition_config_invalid", self.implicit)
        os.unlink(self.file)
        # The config directory a file: not absent.
        os.rmdir(f"{self.xdg}/agentbox")
        harness.write_file(f"{self.xdg}/agentbox", "")
        self.refused("acquisition_config_unreadable", self.implicit)
        # Nowhere to look: refused, never defaulted.
        self.refused("acquisition_config_location_invalid", handlers.implicit, {}, None)
        self.refused("acquisition_config_location_invalid", handlers.implicit, {"XDG_CONFIG_HOME": "rel"}, None)
        # An explicit file must exist.
        self.refused("acquisition_config_unreadable", handlers.read, f"{self.tmp}/missing.json")

    def test_packaged_policy_only_from_the_packaged_tree(self):
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "handlers": {"echo": {}}})
        self.refused("handler_policy_required", self.implicit)
        other = self.handler_tree(("echo",))
        harness.copy_tree(f"{harness.REPO}/acquisitions/pip", f"{other}/acquisitions/pip")
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "assets": other, "handlers": {"pip": {}}})
        self.refused("handler_policy_required", self.implicit)
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "assets": self.packaged, "interpreter": sys.executable,
                         "handlers": {"pip": {}}})
        self.assertEqual(sorted(self.implicit().handlers), ["pip"])
        # The packaged policy is installed code: trusted as such.
        os.chmod(f"{self.packaged}/acquisitions/pip/policy.json", 0o666)
        self.refused("handler_policy_unreadable", self.implicit)

    def test_cli_precedence(self):
        from agentbox_controller import cli
        assets = self.handler_tree(("echo",))
        explicit = self.config(assets, {"echo": None})
        self.persistent({"schema": handlers.CONFIG_SCHEMA, "handlers": {"pip": {}}})
        chosen, _ = cli.acquisition_selection({"--acquisition-config": explicit}, self.environ)
        self.assertEqual(sorted(chosen.handlers), ["echo"])
        chosen, _ = cli.acquisition_selection({}, self.environ, interpreter=lambda: sys.executable)
        self.assertEqual(sorted(chosen.handlers), ["pip"])
        # A session without a lane of its own (a headless agent) reads none.
        os.chmod(self.file, 0o666)
        self.assertEqual(cli.acquisition_selection({}, self.environ, implicit=False), (None, None))
        self.refused("acquisition_config_unreadable", cli.acquisition_selection, {}, self.environ)
        os.unlink(self.file)
        chosen, _ = cli.acquisition_selection({}, self.environ, interpreter=lambda: sys.executable)
        self.assertEqual(sorted(chosen.handlers), ["git", "npm", "pip"])


class ResultLines(unittest.TestCase):
    SHA = "ab" * 32

    def line(self, value, allowance=None, metadata=64):
        return acquisition.result_line((json.dumps(value) + "\n").encode(), metadata, allowance)

    def ok(self, **extra):
        return dict({"schema": acquisition.RESULT_SCHEMA, "outcome": "ok", "size": 3, "sha256": self.SHA,
                     "metadata": {}}, **extra)

    def test_grammar(self):
        self.assertIsNotNone(self.line(self.ok()))
        self.assertEqual(self.line(self.ok(acquired=5), allowance=10)[1], 5)
        for value, allowance in ((self.ok(), 10), (self.ok(acquired=11), 10), (self.ok(acquired=1), None),
                                 (self.ok(size=0), None), (self.ok(sha256="AB" * 32), None),
                                 (self.ok(metadata={"k": "x" * 100}), None), (self.ok(metadata={"bad key": 1}), None),
                                 (self.ok(provenance=[{"name": "a", "version": "1", "integrity": "md5-x"}]), None),
                                 (self.ok(provenance=[{"name": "a", "version": "1",
                                                       "integrity": "sha512-" + "A" * 86 + "=="}] * 257), None),
                                 ({"schema": acquisition.RESULT_SCHEMA, "outcome": "error", "code": "Bad"}, None),
                                 ({"schema": acquisition.RESULT_SCHEMA, "outcome": "error", "code": "x",
                                   "provenance": [{"name": "a", "version": "1",
                                                   "integrity": "sha512-" + "A" * 86 + "=="}]}, None)):
            self.assertIsNone(self.line(value, allowance), value)
        two = (json.dumps(self.ok()) + "\n") * 2
        self.assertIsNone(acquisition.result_line(two.encode(), 64, None))
        self.assertIsNone(acquisition.result_line(json.dumps(self.ok()).encode(), 64, None))


class ServerBounds(unittest.TestCase):
    def client(self):
        client = server_mod.Server.__new__(server_mod.Server)
        client.posts, client.outstanding, client.results = [], {}, {}
        client.ready = {"post": True}
        client.stopped = client.broken = None
        client.post_closed = False
        client.input_closed = False
        client.next_id = 1
        client.outgoing = b""
        client.record_event = lambda message: None
        return client

    def test_queues_are_finite(self):
        client = self.client()
        for index in range(server_mod.MAX_QUEUED):
            client._message({"type": "post.ended", "exchange": index, "end": "written"})
        self.assertIsNone(client.broken)
        client._message({"type": "post.ended", "exchange": 99, "end": "written"})
        self.assertEqual(client.broken, "server_queue_full")
        client = self.client()
        client._message({"type": "result", "id": 7, "ok": True})
        self.assertEqual(client.broken, "server_unexpected")
        client = self.client()
        client._send = lambda message: None
        for _ in range(server_mod.MAX_OUTSTANDING):
            client.command("revoke", request="req-1")
        with self.assertRaises(HostError):
            client.command("revoke", request="req-1")
        ident = min(client.outstanding)
        client._message({"type": "result", "id": ident, "ok": False, "code": "not_active"})
        self.assertEqual(client.take_result(ident)["code"], "not_active")
        self.assertIsNone(client.take_result(ident))


class StubServer:
    """Every command answered ok at once, but `hold` kinds (awaiting
    `answer`); `lost`: every command refused, as a gone server's."""

    def __init__(self, hold=()):
        self.sent, self.posts, self.results = [], [], {}
        self.outstanding = {}
        self.post_closed = False
        self.next = 0
        self.hold = hold
        self.lost = False

    def command(self, kind, **fields):
        if self.lost:
            raise HostError("server_queue_full")
        self.next += 1
        self.sent.append((kind, fields))
        if kind in self.hold:
            self.outstanding[self.next] = kind
        else:
            self.results[self.next] = {"type": "result", "id": self.next, "ok": True, "code": None}
        return self.next

    def answer(self, kind, ok, code=None):
        ident = next(i for i, k in self.outstanding.items() if k == kind)
        del self.outstanding[ident]
        self.results[ident] = {"type": "result", "id": ident, "ok": ok, "code": code}

    def take_result(self, ident):
        return self.results.pop(ident, None)

    def take_posts(self):
        taken, self.posts = self.posts, []
        return taken

    def failed(self):
        return self.lost


class StubCapture:
    def __init__(self, lane_room=True):
        self.lane_room = lane_room
        self.records = []

    def record(self, origin, kind, severity="info", attributes=None, body=None, closing=False, lane=False):
        if lane and not closing and not self.lane_room:
            return False
        self.records.append((kind, attributes))
        return True


class Ctx:
    def __init__(self, capture, server=None):
        self.loop = Loop()
        self.server = server or StubServer()
        self.capture = capture
        self.run_id, self.execution_id = store.new_id("r"), store.new_id("e")
        self.deadline = time.monotonic() + 600

    def leaf(self):
        return None

    def kill_leaf(self, name):
        return True


class LaneDecisions(Private):
    def lane(self, capture=None, interpreter=sys.executable, server=None):
        assets = self.handler_tree()
        selection = handlers.read(self.config(assets, {"echo": None, "fake": None}))
        selection.interpreter = interpreter
        ctx = Ctx(capture or StubCapture(), server)
        self.addCleanup(ctx.loop.close)
        spool = tempfile.mkdtemp(prefix="spool-", dir=self.tmp)
        return acquisition.Lane(ctx, selection, NONCE, spool), ctx

    def post(self, ctx, exchange, kind, client, **fields):
        body = post_codec.encode_request(dict({"v": 1, "type": kind, "session": NONCE, "client": client}, **fields))
        ctx.server.posts.append({"type": "post.request", "exchange": exchange, "replay": False, "bytes": len(body),
                                 "body": body.decode()})

    def answers(self, ctx):
        return [json.loads(f["body"]) for kind, f in ctx.server.sent if kind == "respond"]

    def drive(self, lane, ctx, done, timeout=30):
        until = time.monotonic() + timeout
        while not done():
            self.assertLess(time.monotonic(), until)
            lane.pump()
            ctx.loop.step(0.02)

    def summary(self, ctx):
        return [a for kind, a in ctx.capture.records if kind == "host.handler.lane_closed"][-1]

    def test_worker_exit_must_be_zero(self):
        """A valid success line is nothing without exit 0: worker_failed,
        the whole reservation kept, no provenance, no handoff."""
        for mode in ("exit7", "killed"):
            lane, ctx = self.lane()
            self.post(ctx, 1, "submit", "c1", handler="fake", operation="fetch",
                      args={"mode": mode, "size": 3, "acquired": 10, "packages": 1})
            self.drive(lane, ctx, lambda: lane.records and lane.active is None)
            self.assertEqual(self.answers(ctx)[-1]["reason"], "worker_failed", mode)
            self.assertEqual((lane.charged, lane.provenance, lane.uploads), (acquisition.MAX_ACQUIRED_BYTES, 0, 0))
            self.assertNotIn("deliver", [kind for kind, _ in ctx.server.sent])
            self.assertEqual(lane.records[0].status, 7 if mode == "exit7" else -9)
            self.assertEqual(os.listdir(lane.spool), [])

    def test_post_closed_cancels_the_waiting_request_at_once(self):
        client = ServerBounds.client(None)
        client._send = lambda message: None
        events = []
        client.record_event = events.append
        lane, ctx = self.lane(server=client)
        client._message({"type": "post.request", "exchange": 1, "replay": False, "bytes": 1,
                         "body": post_codec.encode_request({"v": 1, "type": "submit", "session": NONCE, "client": "c1",
                                                            "handler": "fake", "operation": "fetch",
                                                            "args": {"mode": "sleep"}}).decode()})
        lane.pump()
        request = lane.active
        self.assertIsNotNone(request.worker)
        event = {"type": "event", "event": "post.closed", "severity": "warn", "attributes": {"closure": "limit"}}
        client._message(event)
        self.assertTrue(client.post_closed)
        self.assertEqual(events, [event])
        began = time.monotonic()
        lane.pump()
        self.assertLess(time.monotonic() - began, 5)
        self.assertEqual((lane.closing, lane.active, request.worker, request.end),
                         ("post_closed", None, None, "cancelled"))
        # Started, no line: its reservation kept; its `closed` answer sent.
        self.assertEqual(lane.charged, acquisition.MAX_ACQUIRED_BYTES)
        self.assertEqual(list(client.outstanding.values()), ["respond"])

    def delivering(self, **server):
        """A lane whose echo artifact's upload is awaiting its result."""
        stub = StubServer(hold=("deliver",))
        lane, ctx = self.lane(server=stub)
        self.post(ctx, 1, "submit", "c1", handler="echo", operation="say", args={"text": "x"})
        self.drive(lane, ctx, lambda: "deliver" in stub.outstanding.values())
        self.assertEqual(os.listdir(lane.spool), ["req-1.artifact"])
        return lane, ctx, stub

    def test_pending_upload_survives_a_forced_close(self):
        lane, ctx, stub = self.delivering()
        lane.close(lambda: True)
        self.assertEqual([kind for kind, _ in stub.sent][-2:], ["respond", "revoke"])
        self.assertEqual(os.listdir(lane.spool), ["req-1.artifact"])
        self.assertFalse(lane.dispose(server_clean=False, domain_settled=False))
        self.assertEqual(os.listdir(lane.spool), ["req-1.artifact"])
        self.assertEqual((self.summary(ctx)["cleanup_confirmed"], self.summary(ctx)["spool_released"]),
                         (False, False))

    def test_pending_upload_survives_a_lost_server(self):
        lane, ctx, stub = self.delivering()
        stub.lost = True
        lane.close(lambda: False)
        self.assertTrue(lane.failed)
        self.assertIsNone(lane.active)
        self.assertEqual(os.listdir(lane.spool), ["req-1.artifact"])
        self.assertFalse(lane.dispose(server_clean=False, domain_settled=False))
        self.assertTrue(os.path.exists(f"{lane.spool}/req-1.artifact"))

    def test_upload_result_after_cancel_removes_the_file(self):
        lane, ctx, stub = self.delivering()
        self.post(ctx, 2, "cancel", "c1")
        lane.pump()
        self.assertEqual([(a["type"], a.get("outcome")) for a in self.answers(ctx)],
                         [("closed", "cancelled"), ("closed", "cancelled")])
        self.assertEqual(os.listdir(lane.spool), ["req-1.artifact"])
        stub.answer("deliver", False, "cancelled")
        lane.pump()
        self.assertEqual(os.listdir(lane.spool), [])
        self.assertNotIn("ready", [a["type"] for a in self.answers(ctx)])
        lane.close(lambda: False)
        self.assertTrue(lane.dispose(server_clean=False, domain_settled=False))
        self.assertFalse(os.path.exists(lane.spool))

    def test_clean_server_stop_or_empty_domain_releases_the_spool(self):
        for clean, settled in ((True, False), (False, True)):
            lane, ctx, stub = self.delivering()
            lane.close(lambda: True)
            self.assertTrue(lane.dispose(server_clean=clean, domain_settled=settled))
            self.assertFalse(os.path.exists(lane.spool))
            self.assertTrue(self.summary(ctx)["spool_released"])

    def test_request_deadline_with_and_without_a_cutoff(self):
        """Untimed (no cutoff: deadline inf): each request still expires
        REQUEST_TIMEOUT after its admission, `closed expired`, while the
        lane stays open for the next; a timed execution's cutoff caps it."""
        saved = acquisition.REQUEST_TIMEOUT
        acquisition.REQUEST_TIMEOUT = 0.5
        self.addCleanup(setattr, acquisition, "REQUEST_TIMEOUT", saved)
        lane, ctx = self.lane()
        ctx.deadline = float("inf")
        self.post(ctx, 1, "submit", "c1", handler="fake", operation="fetch", args={"mode": "sleep"})
        lane.pump()
        request = lane.records[0]
        self.assertEqual(request.deadline, request.admitted + 0.5)
        self.drive(lane, ctx, lambda: lane.active is None)
        self.assertEqual((self.answers(ctx)[-1]["type"], self.answers(ctx)[-1]["outcome"]), ("closed", "expired"))
        self.assertGreaterEqual(time.monotonic(), request.admitted + 0.5)
        self.assertIsNone(lane.closing)
        self.post(ctx, 2, "submit", "c2", handler="fake", operation="fetch", args={"mode": "exit7"})
        self.drive(lane, ctx, lambda: len(lane.records) == 2 and lane.active is None)
        # Still answered, its grant the same: the expired worker's charge
        # kept (it started and gave no line), nothing reset.
        self.assertEqual((lane.submissions, self.answers(ctx)[-1]["reason"]), (2, "byte_limit"))

        acquisition.REQUEST_TIMEOUT = saved
        lane, ctx = self.lane()
        ctx.deadline = time.monotonic() + 0.4
        self.post(ctx, 1, "submit", "c1", handler="fake", operation="fetch", args={"mode": "sleep"})
        lane.pump()
        request = lane.records[0]
        self.assertEqual(request.deadline, ctx.deadline)
        self.drive(lane, ctx, lambda: lane.active is None)
        self.assertEqual(self.answers(ctx)[-1]["outcome"], "expired")

    def test_never_started_refunds(self):
        lane, ctx = self.lane(interpreter=f"{self.tmp}/missing-python")
        self.post(ctx, 1, "submit", "c1", handler="fake", operation="fetch", args={})
        lane.pump()
        self.assertEqual(self.answers(ctx)[-1]["reason"], "worker_failed")
        self.assertEqual((lane.attempts, lane.charged), (1, 0))
        self.assertEqual(os.listdir(lane.spool), [])

    def test_capture_full_closes_only_the_lane(self):
        lane, ctx = self.lane(StubCapture(lane_room=False))
        self.post(ctx, 1, "submit", "c1", handler="echo", operation="say", args={"text": "x"})
        lane.pump()
        self.post(ctx, 2, "submit", "c2", handler="echo", operation="say", args={"text": "y"})
        self.post(ctx, 3, "cancel", "c1")
        lane.pump()
        answers = self.answers(ctx)
        self.assertEqual([(a["type"], a.get("outcome") or a.get("code")) for a in answers],
                         [("closed", "cancelled"), ("rejected", "submission_limit"), ("error", "not_active")])
        self.assertEqual(lane.closing, "capture_full")
        self.assertIn(("host.handler.lane_note", {"note": "capture_full"}), ctx.capture.records)
        lane.close(lambda: False)
        self.assertTrue(lane.dispose(server_clean=True, domain_settled=False))
        self.assertEqual(lane.active, None)

    def test_terminal_ends_revoke_the_server_request(self):
        lane, ctx = self.lane()
        request = acquisition.Request("req-9", "c", {"handler": "echo", "operation": "say", "args": {}}, "0" * 64, 5,
                                      time.monotonic(), time.monotonic() + 10)
        request.deliver = 1
        lane.active = request
        lane.end_request(request, "recorded")
        self.assertEqual(ctx.server.sent[-1], ("revoke", {"request": "req-9"}))
        self.assertIsNone(lane.active)


if __name__ == "__main__":
    unittest.main()
