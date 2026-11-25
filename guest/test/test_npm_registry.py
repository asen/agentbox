"""The npm jail module offline, in process: the registry adapter's routes,
batches and delivered-batch checks, and the real host request flow over the
memory POST doubles (post_memory.py). Its HTTP service and the `npm` shim
need a loopback socket and a child process: acquisitions/test_npm_jail.py.
No npm, Node, package code, registry, network or VM."""

import hashlib
import json
import os
import stat
import tempfile
import unittest

from acquisitions.npm.jail import registry
from acquisitions.npm.jail.registry import (
    MISSING, BatchFailed, Delivered, args_for, fetch_batch, read_batch, route, take_batch,
)
from guest.src.artifact_post_context import upload_name
from guest.test.post_memory import (
    SESSION, ManualClock, MemoryHost, closed_for, owned_context, ready, seams_of, upload,
)

ABBREVIATED = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"


def batch_bytes(operation, entries):
    """A batch artifact as the host worker writes it: entries (name,
    version or None, body or None for missing)."""
    bodies, items = b"", []
    for name, version, body in entries:
        item = {"name": name, "status": "missing" if body is None else "ok",
                "bytes": 0 if body is None else len(body)}
        if version is not None:
            item["version"] = version
        if body is not None:
            bodies += body
        items.append(item)
    index = json.dumps({"schema": registry.BATCH_SCHEMA, "operation": operation, "items": items},
                       sort_keys=True, separators=(",", ":")).encode()
    return bodies + index + registry.TRAILER_PREFIX + b"%020d\n" % len(index)


class Routes(unittest.TestCase):
    def test_documents_and_tarballs_route_by_path_and_accept(self):
        cases = [
            ("/cli", "", ("metadata", "full", "cli")),
            ("/cli", ABBREVIATED, ("metadata", "abbreviated", "cli")),
            ("/@scope%2fcore", ABBREVIATED, ("metadata", "abbreviated", "@scope/core")),
            ("/@scope%2Fcore", "", ("metadata", "full", "@scope/core")),
            ("/@scope/core", "", ("metadata", "full", "@scope/core")),
            ("/JSONStream", "", ("metadata", "full", "JSONStream")),
            ("/cli/-/cli-1.0.0.tgz", "", ("tarballs", "cli", "1.0.0")),
            ("/@scope/core/-/core-2.0.0-rc.1.tgz", "", ("tarballs", "@scope/core", "2.0.0-rc.1")),
            ("/@scope%2fcore/-/core-2.0.0.tgz", "", ("tarballs", "@scope/core", "2.0.0")),
            # A registry path prefix before the name, as a lock may carry it.
            ("/npm/registry/cli/-/cli-1.0.0.tgz", "", ("tarballs", "cli", "1.0.0")),
            ("/npm/@scope/core/-/core-2.0.0.tgz", "", ("tarballs", "@scope/core", "2.0.0")),
            ("/cli?write=true", "", ("metadata", "full", "cli")),
        ]
        for path, accept, key in cases:
            with self.subTest(path=path):
                self.assertEqual(route(path, accept), key)
        for path in ("/", "/-/npm/v1/security/advisories/bulk", "/-/v1/search", "/-/ping",
                     "/cli/-/other-1.0.0.tgz", "/cli/-/cli-latest.tgz", "/cli/-/cli-1.0.0.tar.gz",
                     "/cli/1.0.0", "/.hidden", "/a b", "cli", "/@scope", "/" + "x" * 215,
                     "/cli/-/cli-^1.0.0.tgz"):
            with self.subTest(path=path):
                self.assertIsNone(route(path, ""))

    def test_batches_take_one_kind_within_the_item_and_byte_bounds(self):
        keys = [("metadata", "full", "a"), ("tarballs", "a", "1.0.0"), ("metadata", "abbreviated", "b"),
                ("metadata", "full", "c")]
        self.assertEqual(take_batch(keys), [keys[0], keys[3]])
        self.assertEqual(take_batch(keys[1:]), [keys[1]])
        many = [("metadata", "full", "p%d" % n) for n in range(300)]
        self.assertEqual(len(take_batch(many)), registry.MAX_ITEMS)
        long = [("tarballs", "n%03d" % n + "x" * 200, "1.0.0-" + "r" * 200) for n in range(256)]
        batch = take_batch(long)
        self.assertLess(len(batch), 256)
        self.assertLessEqual(registry.canonical_size(args_for(batch)), registry.MAX_ARGS_BYTES)
        self.assertGreater(registry.canonical_size(args_for(long[:len(batch) + 1])), registry.MAX_ARGS_BYTES)
        self.assertEqual(args_for([("tarballs", "a", "1.0.0")]),
                         {"packages": [{"name": "a", "version": "1.0.0"}]})
        self.assertEqual(args_for([("metadata", "abbreviated", "a")]), {"names": ["a"], "format": "abbreviated"})


class Batches(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="agentbox-npm-test-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)

    def write(self, data):
        path = os.path.join(self.dir, "batch")
        with open(path, "wb") as stream:
            stream.write(data)
        return path, len(data)

    def test_a_delivered_batch_is_checked_against_the_keys(self):
        keys = [("tarballs", "a", "1.0.0"), ("tarballs", "@s/b", "2.0.0")]
        path, size = self.write(batch_bytes("tarballs", [("a", "1.0.0", b"AAAA"), ("@s/b", "2.0.0", None)]))
        answers = read_batch(path, size, "tarballs", keys)
        self.assertIsInstance(answers[0], Delivered)
        self.assertEqual((answers[0].offset, answers[0].size), (0, 4))
        self.assertIs(answers[1], MISSING)
        bad = [
            batch_bytes("metadata", [("a", None, b"x"), ("@s/b", None, None)]),
            batch_bytes("tarballs", [("a", "1.0.1", b"x"), ("@s/b", "2.0.0", None)]),
            batch_bytes("tarballs", [("a", "1.0.0", b"x")]),
            batch_bytes("tarballs", [("@s/b", "2.0.0", None), ("a", "1.0.0", b"x")]),
            batch_bytes("tarballs", [("a", "1.0.0", b"x"), ("@s/b", "2.0.0", None)])[:-2] + b"9\n",
            b"x" + batch_bytes("tarballs", [("a", "1.0.0", b"x"), ("@s/b", "2.0.0", None)]),
            b"short",
        ]
        for data in bad:
            with self.subTest(data=data[-60:]):
                path, size = self.write(data)
                with self.assertRaises(BatchFailed):
                    read_batch(path, size, "tarballs", keys)


class HostRequestTest(unittest.IsolatedAsyncioTestCase):
    """`fetch_batch` over the memory POST: the delivered batch copied into the
    spool, verified, its upload removed; a denial carries its reason."""

    async def run_fetch(self, outcome):
        _root, work, context = owned_context()
        spool = tempfile.mkdtemp(prefix="agentbox-npm-spool-")
        args = {"names": ["a"], "format": "full"}
        submission = {"handler": "npm", "operation": "metadata", "args": args}
        data = batch_bytes("metadata", [("a", None, b'{"name":"a"}')])

        def answer(connection, request):
            if request["type"] == "submit":
                if outcome == "denied":
                    return connection.respond(closed_for(submission, "c-1", "req-1", "denied",
                                                         reason="byte_limit"))
                upload(os.path.join(work, ".agentbox-requests"), upload_name(SESSION, "req-1"), data)
                return connection.respond(ready(submission, "c-1", "req-1", {
                    "handler": "npm", "operation": "metadata", "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "metadata": {"format": registry.BATCH_SCHEMA, "items": 1}}))
            if request["type"] == "result":
                return connection.respond(closed_for(submission, "c-1", "req-1", "recorded"))

        host = MemoryHost(answer)
        from guest.src.abort import Abort
        seams = seams_of(host, ManualClock())
        try:
            path, size = await fetch_batch(context, spool, "metadata", args, Abort(), seams)
            return host, work, spool, path, size, data
        except BatchFailed as failed:
            return host, work, spool, failed, None, data

    async def test_a_delivered_batch_lands_in_the_spool_and_its_upload_goes(self):
        host, work, spool, path, size, data = await self.run_fetch("ready")
        self.assertEqual(size, len(data))
        self.assertTrue(path.startswith(spool + "/batch-"))
        with open(path, "rb") as stream:
            self.assertEqual(stream.read(), data)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(os.listdir(os.path.join(work, ".agentbox-requests")), [])
        self.assertEqual([request["type"] for request in host.requests], ["submit", "result"])
        self.assertEqual(host.requests[1]["status"], "applied")

    async def test_a_denial_is_a_failed_batch_with_the_hosts_reason(self):
        host, _work, spool, failed, _, _ = await self.run_fetch("denied")
        self.assertEqual((failed.code, failed.reason), ("request_denied", "byte_limit"))
        self.assertEqual(os.listdir(spool), [])
        self.assertEqual([request["type"] for request in host.requests], ["submit"])


if __name__ == "__main__":
    unittest.main()
