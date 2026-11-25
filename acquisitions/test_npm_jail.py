"""The npm jail module's HTTP service and its `npm` shim, offline: the
registry adapter (acquisitions/npm/jail/registry.py) on an ephemeral
127.0.0.1 port with a stand-in for the host request (no POST, network or
host), and `adapted` with a Python stand-in as the real npm, as a child.
In process requests and batches: guest/test/test_npm_registry.py. Never npm,
Node, package code, a registry or the network: no test PATH reaches the
host's own npm.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""

import asyncio
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from acquisitions.npm.jail import npm as shim  # noqa: E402
from acquisitions.npm.jail.registry import Adapter, BatchFailed  # noqa: E402
from guest.test.test_npm_registry import ABBREVIATED, batch_bytes  # noqa: E402


class Served:
    """A running adapter with a stand-in host: `answers[key]` is a body,
    None (missing) or a BatchFailed; every request recorded."""

    def __init__(self, answers, hold=None):
        self.answers = answers
        self.requests = []
        self.reports = []
        self.hold = hold
        self.aborted = []

    async def fetch(self, operation, args, abort):
        self.requests.append((operation, args))
        if self.hold is not None:
            done = asyncio.get_running_loop().create_future()
            abort.add_listener(lambda: done.done() or done.set_result(None))
            await done
            self.aborted.append(True)
            raise BatchFailed("request_cancelled")
        keys = ([("metadata", args["format"], name) for name in args["names"]] if operation == "metadata"
                else [("tarballs", item["name"], item["version"]) for item in args["packages"]])
        entries = []
        for key in keys:
            answer = self.answers[key]
            if isinstance(answer, BatchFailed):
                raise answer
            entries.append((key[-1] if operation == "metadata" else key[1],
                            None if operation == "metadata" else key[2], answer))
        path = os.path.join(self.adapter.spool, "batch-%d" % len(self.requests))
        data = batch_bytes(operation, entries)
        with open(path, "wb") as stream:
            stream.write(data)
        return path, len(data)

    async def __aenter__(self):
        self.adapter = Adapter(self.fetch, self.reports.append)
        await self.adapter.start()
        return self

    async def __aexit__(self, *_):
        await self.adapter.close()

    async def get(self, path, accept="", method="GET", keep=None):
        reader, writer = keep or await asyncio.open_connection("127.0.0.1", self.adapter.port)
        try:
            writer.write(("%s %s HTTP/1.1\r\nHost: x\r\nAccept: %s\r\n\r\n" % (method, path, accept)).encode())
            await writer.drain()
            head = await reader.readuntil(b"\r\n\r\n")
            status = int(head.split(b" ")[1])
            length = int([line for line in head.split(b"\r\n") if line.lower().startswith(b"content-length:")][0]
                         .split(b":")[1])
            body = await reader.readexactly(length) if method != "HEAD" else b""
        except BaseException:
            writer.close()
            raise
        if keep is None:
            writer.close()
            await writer.wait_closed()
        return status, body


class AdapterTest(unittest.IsolatedAsyncioTestCase):
    async def test_concurrent_misses_are_one_batch_and_answers_are_cached(self):
        answers = {("metadata", "abbreviated", "a"): b'{"name":"a"}',
                   ("metadata", "abbreviated", "@s/b"): b'{"name":"@s/b"}',
                   ("metadata", "abbreviated", "gone"): None,
                   ("metadata", "full", "a"): b'{"name":"a","full":true}',
                   ("tarballs", "a", "1.0.0"): b"\x1f\x8b tarball"}
        async with Served(answers) as served:
            results = await asyncio.gather(*(served.get(path, ABBREVIATED)
                                             for path in ("/a", "/@s%2fb", "/gone", "/a")))
            self.assertEqual(results, [(200, b'{"name":"a"}'), (200, b'{"name":"@s/b"}'),
                                       (404, b'{"error":"Not found"}'), (200, b'{"name":"a"}')])
            self.assertEqual(served.requests, [("metadata", {"names": ["a", "@s/b", "gone"],
                                                             "format": "abbreviated"})])
            # Cached: no new request; a full document then answers both formats.
            self.assertEqual(await served.get("/a", ABBREVIATED), (200, b'{"name":"a"}'))
            self.assertEqual(await served.get("/a"), (200, b'{"name":"a","full":true}'))
            self.assertEqual(len(served.requests), 2)
            # Keep-alive: a tarball and a HEAD on one connection.
            keep = await asyncio.open_connection("127.0.0.1", served.adapter.port)
            self.assertEqual(await served.get("/a/-/a-1.0.0.tgz", keep=keep), (200, b"\x1f\x8b tarball"))
            self.assertEqual(await served.get("/a/-/a-1.0.0.tgz", method="HEAD", keep=keep), (200, b""))
            keep[1].close()
            self.assertEqual(served.requests[-1], ("tarballs", {"packages": [{"name": "a", "version": "1.0.0"}]}))
            self.assertEqual(served.reports, [])

    async def test_unsupported_routes_and_methods_never_reach_the_host(self):
        async with Served({}) as served:
            self.assertEqual((await served.get("/-/npm/v1/security/advisories/bulk"))[0], 404)
            self.assertEqual((await served.get("/-/v1/search?text=x"))[0], 404)
            self.assertEqual((await served.get("/a", method="PUT"))[0], 405)
            self.assertEqual((await served.get("/-/user/org.couchdb.user:x", method="PUT"))[0], 405)
            self.assertEqual(served.requests, [])

    async def test_the_first_failure_is_reported_once_and_ends_every_later_miss(self):
        answers = {("metadata", "full", "a"): BatchFailed("request_denied", "byte_limit"),
                   ("metadata", "full", "b"): b"{}"}
        async with Served(answers) as served:
            status, body = await served.get("/a")
            self.assertEqual(status, 503)
            self.assertIn(b"request_denied", body)
            self.assertEqual((await served.get("/b"))[0], 503)
            self.assertEqual(len(served.requests), 1)
            self.assertEqual(served.reports,
                             ["agentbox-npm: registry request failed (code=request_denied reason=byte_limit)"])

    async def test_a_key_waits_at_most_its_bound_then_504_and_its_batch_goes_on(self):
        served = Served({}, hold=True)
        await served.__aenter__()
        try:
            key = ("metadata", "full", "a")
            with self.assertRaises(TimeoutError):
                await asyncio.to_thread(served.adapter.resolve, key, 0.2)
            self.assertEqual(len(served.requests), 1)
            self.assertIn(key, served.adapter.waiting)
        finally:
            await served.adapter.close()
        self.assertEqual(served.aborted, [True])

    async def test_close_aborts_the_active_request_and_removes_the_spool(self):
        served = Served({}, hold=True)
        await served.__aenter__()
        spool = served.adapter.spool
        waiting = asyncio.ensure_future(served.get("/a"))
        while not served.requests:
            await asyncio.sleep(0.01)
        await served.adapter.close()
        self.assertEqual(served.aborted, [True])
        self.assertFalse(os.path.exists(spool))
        # The waiting client got its answer or lost its connection; never a hang.
        try:
            status, _ = await asyncio.wait_for(waiting, 5)
            self.assertEqual(status, 503)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        self.assertEqual(served.reports, [])


STAND_IN = r'''import json, os, sys, urllib.request
url = os.environ["npm_config_registry"]
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(url + "a") as answer:
    body = answer.read()
keys = ["npm_config_registry", "npm_config_replace_registry_host", "npm_config_noproxy",
        "npm_config_audit", "npm_config_fund", "npm_config_update_notifier", "npm_config_fetch_retries",
        "npm_config_fetch_timeout", "AGENTBOX_NPM_REGISTRY"]
print(json.dumps({"argv": sys.argv[1:], "body": body.decode(), "env": {k: os.environ.get(k) for k in keys}}))
sys.exit(7)
'''


class ShimTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="agentbox-npm-shim-")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)

    def executable(self, directory, name, text):
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "w") as stream:
            stream.write(text)
        os.chmod(path, 0o700)
        return path

    def test_the_real_command_skips_agentbox_command_directories(self):
        ours = os.path.join(self.root, "bin")
        system = os.path.join(self.root, "usr")
        self.executable(ours, "npm", "#!/bin/sh\n")
        self.executable(ours, "agentbox-request", "#!/bin/sh\n")
        real = self.executable(system, "npm", "#!/bin/sh\n")
        os.makedirs(os.path.join(self.root, "empty"))
        path = ":".join(["relative", ours, os.path.join(self.root, "empty"), system])
        self.assertEqual(shim.real_command("npm", path), real)
        self.assertIsNone(shim.real_command("npx", path))
        self.assertIsNone(shim.real_command("npm", ours))

    async def test_the_child_runs_against_the_adapter_and_its_status_is_returned(self):
        real = self.executable(self.root, "npm", "#!%s\n%s" % (sys.executable, STAND_IN))
        out = os.path.join(self.root, "out")
        requests = []

        async def fetch(context, spool, operation, args, abort):
            requests.append((context, operation, args))
            path = os.path.join(spool, "batch")
            data = batch_bytes("metadata", [("a", None, b'{"name":"a"}')])
            with open(path, "wb") as stream:
                stream.write(data)
            return path, len(data)

        env = {"PATH": "/usr/bin:/bin", "HTTP_PROXY": "http://127.0.0.1:9"}
        stdout = os.dup(1)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT, 0o600)
        os.dup2(fd, 1)
        try:
            status = await shim.adapted(real, ["install", "a"], env, "context", fetch, self.root)
        finally:
            os.dup2(stdout, 1)
            os.close(stdout)
            os.close(fd)
        self.assertEqual(status, 7)
        with open(out) as stream:
            seen = json.loads(stream.read())
        self.assertEqual(seen["argv"], ["install", "a"])
        self.assertEqual(seen["body"], '{"name":"a"}')
        url = seen["env"]["npm_config_registry"]
        self.assertRegex(url, r"^http://127\.0\.0\.1:[0-9]+/$")
        self.assertEqual(seen["env"], {
            "npm_config_registry": url, "npm_config_replace_registry_host": "always",
            "npm_config_noproxy": "127.0.0.1,localhost", "npm_config_audit": "false",
            "npm_config_fund": "false", "npm_config_update_notifier": "false",
            "npm_config_fetch_retries": "0", "npm_config_fetch_timeout": "1860000",
            "AGENTBOX_NPM_REGISTRY": url})
        self.assertEqual(requests, [("context", "metadata", {"names": ["a"], "format": "full"})])
        # The spool went with the adapter.
        self.assertEqual([name for name in os.listdir(self.root) if name.startswith("agentbox-npm-")], [])


if __name__ == "__main__":
    unittest.main()
