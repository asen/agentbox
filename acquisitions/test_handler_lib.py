"""Offline suite of the shared handler runtime (lib/agentbox_handler.py), the
handler manifests and the test-only `echo` handler (testing/echo),
which registers by files alone.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""

import hashlib
import json
import os
import stat
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import handler_testing as testing  # noqa: E402

handler = testing.handler
POLICY = {"schema": "agentbox.echo.policy.v1", "prefix": "echo:", "code": "echo_says_no"}
CONTRACT = os.path.join(HERE, "contracts", "handlers", "v1", "contract.json")


class Echo(unittest.TestCase):
    def setUp(self):
        self.scratch = testing.Scratch()
        self.tree = testing.installed_tree(self.scratch, ["echo"])
        self.entry = os.path.join(self.tree, "echo", "host", "worker.py")

    def tearDown(self):
        self.scratch.remove()

    def run_echo(self, operation, args, policy=POLICY, **kwargs):
        stage = self.scratch.stage()
        value = testing.request_value(stage, "echo", operation, args, policy, **kwargs)
        code, lines, _ = testing.run(self.entry, testing.write_request(stage, value))
        return code, lines, stage

    def test_a_handler_installed_by_files_alone_delivers(self):
        code, lines, stage = self.run_echo("say", {"text": "hi"})
        self.assertEqual(code, 0)
        line = testing.result(self, lines)
        data = b"echo:hi"
        self.assertEqual(line, {"schema": handler.RESULT_SCHEMA, "outcome": "ok",
                                "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                                "metadata": {"operation": "say", "length": len(data)}})
        artifact = os.path.join(stage, handler.ARTIFACT_FILE)
        st = os.lstat(artifact)
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        with open(artifact, "rb") as stream:
            self.assertEqual(stream.read(), data)

    def test_denials_crashes_and_unknown_operations(self):
        code, lines, _ = self.run_echo("refuse", {})
        self.assertEqual((code, testing.result(self, lines)["code"]), (0, "echo_says_no"))
        code, lines, _ = self.run_echo("crash", {})
        self.assertEqual((code, lines), (7, []))
        code, lines, _ = self.run_echo("whisper", {})
        self.assertEqual(testing.result(self, lines)["code"], "operation_unsupported")
        code, lines, _ = self.run_echo("say", {"text": 1})
        self.assertEqual(testing.result(self, lines)["code"], "echo_args_invalid")
        code, lines, _ = self.run_echo("say", {"text": "x"}, policy={})
        self.assertEqual(testing.result(self, lines)["code"], "echo_policy_invalid")
        code, lines, _ = self.run_echo("say", {"text": "x" * 600}, metadata_bytes=8)
        self.assertEqual(testing.result(self, lines)["code"], "metadata_too_large")

    def test_only_the_hosts_request_file_is_read(self):
        stage = self.scratch.stage()
        value = testing.request_value(stage, "echo", "say", {"text": "x"}, POLICY)
        path = testing.write_request(stage, value)
        for argv in ([], ["acquire"], ["acquire", path, "x"], ["say", path],
                     ["acquire", "relative/request.json"], ["acquire", stage + "/other.json"],
                     ["acquire", stage + "/../" + os.path.basename(stage) + "/request.json"]):
            with self.subTest(argv=argv):
                with self.assertRaises(handler.Malformed):
                    handler.read_request(argv)
        # A shared, linked or oversized file is not the host's.
        os.chmod(path, 0o640)
        with self.assertRaises(handler.Malformed):
            handler.read_request(["acquire", path])
        os.chmod(path, 0o600)
        self.assertEqual(handler.read_request(["acquire", path]).value, value)
        other = self.scratch.stage()
        os.symlink(path, os.path.join(other, handler.REQUEST_FILE))
        with self.assertRaises(handler.Malformed):
            handler.read_request(["acquire", os.path.join(other, handler.REQUEST_FILE)])

    def test_malformed_request_files_exit_without_a_result(self):
        stage = "/x/request-1"
        base = testing.request_value(stage, "echo", "say", {"text": "x"}, POLICY)
        edits = [{"schema": "x"}, {"handler": "Echo"}, {"operation": "-say"}, {"args": []},
                 {"policy": None}, {"ids": {}}, {"ids": dict(testing.IDS, request="-r")},
                 {"ids": dict(testing.IDS, request_sha256="B" * 64)}, {"stage": "relative"},
                 {"artifact": "/x/request-1/other"}, {"remaining_ms": -1},
                 {"remaining_ms": True}, {"remaining_ms": 2**53}, {"tools": {"Git": "/g"}},
                 {"tools": {"git": "g"}}, {"limits": {"metadata_bytes": -1}},
                 {"limits": {}}, {"limits": {"metadata_bytes": 1, "acquire_bytes": -1}},
                 {"limits": {"metadata_bytes": 1, "acquire_bytes": True}},
                 {"limits": {"metadata_bytes": 1, "other": 1}},
                 {"test": []}, {"extra": 1}, {"version": ""}]
        for edit in edits:
            with self.subTest(edit=edit):
                stage = self.scratch.stage()
                value = dict(base, stage=stage, artifact=stage + "/" + handler.ARTIFACT_FILE)
                value.update(edit)
                code, lines, _ = testing.run(self.entry, testing.write_request(stage, value))
                self.assertEqual((code, lines), (2, []))
        for raw in (b"{", b"[]", b'{"a":NaN}', b'{"a":1,"a":2}', b"\xff",
                    b"[" * 20 + b"]" * 20, b" " * (handler.MAX_REQUEST_BYTES + 1)):
            with self.subTest(raw=raw[:20]):
                stage = self.scratch.stage()
                code, lines, _ = testing.run(self.entry, testing.write_request(stage, raw=raw))
                self.assertEqual((code, lines), (2, []))

    def test_the_stage_must_hold_exactly_the_request_file(self):
        stage = self.scratch.stage()
        value = testing.request_value(stage, "echo", "say", {"text": "x"}, POLICY)
        path = testing.write_request(stage, value)
        with open(os.path.join(stage, handler.ARTIFACT_FILE), "w"):
            pass
        code, lines, _ = testing.run(self.entry, path)
        self.assertEqual(testing.result(self, lines)["code"], "staging_unsafe")


class Metering(unittest.TestCase):
    """`main` for a worker given an allowance: every line carries what its
    meter counted; provenance only on `ok` lines."""

    def setUp(self):
        self.scratch = testing.Scratch()

    def tearDown(self):
        self.scratch.remove()

    def emitted(self, acquire, acquire_bytes):
        import io
        from contextlib import redirect_stdout
        stage = self.scratch.stage()
        value = testing.request_value(stage, "echo", "say", {}, POLICY,
                                      acquire_bytes=acquire_bytes)
        path = testing.write_request(stage, value)
        out = io.StringIO()
        with redirect_stdout(out):
            code = handler.main({"say": acquire}, ["acquire", path])
        lines = out.getvalue().splitlines()
        return code, [json.loads(line) for line in lines]

    def test_every_line_of_a_metered_worker_carries_its_count(self):
        def ok(request):
            request.meter.take(request.meter.room(5))
            return 1, "a" * 64, {}, [{"name": "p", "version": "1.0.0", "integrity": "sha1-x"}]

        def refused(request):
            request.meter.take(request.meter.room(7))
            raise handler.Refused("npm_fetch_failed")

        code, lines = self.emitted(ok, 3)
        self.assertEqual(code, 0)
        self.assertEqual(lines[0]["acquired"], 3)
        self.assertEqual(lines[0]["provenance"],
                         [{"name": "p", "version": "1.0.0", "integrity": "sha1-x"}])
        code, lines = self.emitted(refused, 100)
        self.assertEqual(lines, [{"schema": handler.RESULT_SCHEMA, "outcome": "error",
                                  "code": "npm_fetch_failed", "acquired": 7}])
        code, lines = self.emitted(ok, None)
        self.assertNotIn("acquired", lines[0])

    def test_the_meter_never_counts_past_its_allowance(self):
        meter = handler.Meter(10)
        self.assertEqual(meter.room(64), 10)
        meter.take(10)
        self.assertEqual(meter.room(64), 0)
        with self.assertRaises(handler.Refused) as caught:
            meter.check(1)
        self.assertEqual(caught.exception.code, "acquire_limit")
        with self.assertRaises(AssertionError):
            meter.take(1)
        self.assertEqual(handler.Meter(None).room(64), 64)

    def test_more_provenance_than_the_bound_is_no_result(self):
        def many(request):
            return 1, "a" * 64, {}, [{"name": "p", "version": "1.0.0",
                                      "integrity": "sha1-x"}] * (handler.MAX_PROVENANCE + 1)

        code, lines = self.emitted(many, 1)
        self.assertEqual((code, lines), (3, []))


class Manifests(unittest.TestCase):
    def test_every_manifest_lists_its_tree(self):
        testing_ids = sorted(n for n in os.listdir(testing.TESTING) if not n.startswith((".", "_")))
        self.assertEqual(testing_ids, ["echo", "memo"])
        for root, ids in ((testing.HANDLERS, testing.SHIPPED), (testing.TESTING, testing_ids)):
            for handler_id in ids:
                with self.subTest(handler=handler_id):
                    with open(os.path.join(root, handler_id, "manifest.json"), "rb") as stream:
                        manifest = handler.strict_loads(stream.read())
                    self.assertEqual(manifest["schema"], "agentbox.handler-manifest.v1")
                    self.assertEqual(manifest["id"], handler_id)
                    self.assertEqual(manifest["entry"], "%s/host/worker.py" % handler_id)
                    self.assertIn(manifest["metering"], ("http", "none"))
                    self.assertNotIn("submissions", manifest.get("limits", {}))
                    self.assertNotIn("attempts", manifest.get("limits", {}))
                    self.assertIn(manifest["entry"], manifest["files"])
                    self.assertIn("lib/agentbox_handler.py", manifest["files"])
                    for name in manifest["files"]:
                        base = HERE if name.startswith("lib/") else root
                        self.assertTrue(os.path.isfile(os.path.join(base, name)), name)
                    # A jail module, if any: its sibling jail package's,
                    # by its bundle path.
                    jail = manifest.get("jail")
                    if jail is not None:
                        prefix = "acquisitions/%s/jail/" % handler_id
                        self.assertTrue(jail["entry"].startswith(prefix), jail["entry"])
                        self.assertTrue(jail["entry"].endswith(".py"), jail["entry"])
                        path = os.path.join(root, handler_id, "jail", jail["entry"][len(prefix):])
                        self.assertTrue(os.path.isfile(path), path)
                    # Every lib module a worker imports is listed.
                    with open(os.path.join(root, handler_id, "host", "worker.py")) as stream:
                        source = stream.read()
                    for module in ("agentbox_handler", "agentbox_packages"):
                        if "import %s" % module in source:
                            self.assertIn("lib/%s.py" % module, manifest["files"])

    def test_the_contract_matches_the_runtime(self):
        with open(CONTRACT) as stream:
            contract = json.load(stream)
        self.assertEqual(contract["request"]["schema"], handler.REQUEST_SCHEMA)
        self.assertEqual(contract["result"]["schema"], handler.RESULT_SCHEMA)
        self.assertEqual(contract["request"]["max_bytes"], handler.MAX_REQUEST_BYTES)
        self.assertEqual(contract["stage"]["request_file"], handler.REQUEST_FILE)
        self.assertEqual(contract["stage"]["artifact_file"], handler.ARTIFACT_FILE)
        self.assertEqual(contract["result"]["code_pattern"], handler.CODE.pattern)
        self.assertEqual(contract["limits"]["max_provenance"], handler.MAX_PROVENANCE)


if __name__ == "__main__":
    unittest.main()
