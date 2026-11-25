"""Offline suite of the trusted `npm` handler worker, the shared TLS seam
(lib/agentbox_packages.py) and the acquired-byte meter
(lib/agentbox_handler.py `Meter`). The pip worker: test_pip_index.py.

A throwaway test CA (the installed openssl) and the owned loopback HTTPS
fixture server (package_fixture_server.py, one per case, its own session,
ended by stdin EOF and killed as a group if it overstays). The handler
cases run each worker as the host runs it (`python3 -I -B worker.py
acquire STAGE/request.json`, its own session, `/dev/null` stdin, only
`LC_ALL=C`). The request's `test` endpoint is the only seam
(`localhost:<port>` with the test CA). No real network, registry,
credential or model. Bodies are opaque synthetic bytes.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""

import base64
import hashlib
import http.client
import json
import os
import signal
import stat
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import handler_testing as testing  # noqa: E402
import agentbox_packages as packages  # noqa: E402

handler = testing.handler
Refused = handler.Refused
PYTHON = sys.executable
OPENSSL = "/usr/bin/openssl"
SERVER = os.path.join(HERE, "package_fixture_server.py")
HOST = "files.example.org"
ARTIFACT = handler.ARTIFACT_FILE
LEFT = sorted([ARTIFACT, handler.REQUEST_FILE])
# The served bodies by name, shared by every case class.
BODIES = {}


class Tls:
    """A throwaway CA, a rogue CA and leaves: `localhost` and
    `other.invalid` by the CA, `localhost` by the rogue one, with the
    extensions the default strict verification requires."""

    def __init__(self, scratch):
        self.dir = scratch.at("package-tls")
        os.mkdir(self.dir, 0o700)
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        for ca in ("ca", "rogue"):
            scratch.run([OPENSSL, "req", "-x509"] + ec + [
                "-keyout", self.at(ca + ".key"), "-out", self.at(ca + ".pem"), "-days", "2",
                "-subj", "/CN=package " + ca, "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign"])
        for leaf, name, ca in (("localhost", "localhost", "ca"), ("other", "other.invalid", "ca"),
                               ("rogue-localhost", "localhost", "rogue")):
            with open(self.at(leaf + ".ext"), "w") as stream:
                stream.write("subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n"
                             "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
                             "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n" % name)
            scratch.run([OPENSSL, "req"] + ec + ["-keyout", self.at(leaf + ".key"), "-out",
                                                 self.at(leaf + ".csr"), "-subj", "/CN=" + name])
            scratch.run([OPENSSL, "x509", "-req", "-in", self.at(leaf + ".csr"), "-CA",
                         self.at(ca + ".pem"), "-CAkey", self.at(ca + ".key"), "-CAcreateserial",
                         "-out", self.at(leaf + ".pem"), "-days", "2", "-extfile",
                         self.at(leaf + ".ext")])
        self.ca = self.at("ca.pem")

    def at(self, name):
        return os.path.join(self.dir, name)


class Server:
    """One owned fixture server: its own session; stdin EOF ends it, a
    group kill if it overstays."""

    def __init__(self, root, tls, leaf="localhost"):
        self.process = subprocess.Popen(
            [PYTHON, "-I", "-S", "-B", SERVER, "serve", root, tls.at(leaf + ".pem"),
             tls.at(leaf + ".key")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C"}, start_new_session=True)
        ready = self.process.stdout.readline().decode()
        assert ready.startswith("ready "), ready
        self.port = int(ready.split()[1])

    def stop(self):
        self.process.stdin.close()
        try:
            out = self.process.stdout.read()
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.kill()
            raise
        self.process.stdout.close()
        return json.loads(out.decode().splitlines()[-1])["requests"]

    def kill(self):
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait()
        for stream in (self.process.stdin, self.process.stdout):
            if not stream.closed:
                stream.close()


def body(name, size):
    """Deterministic opaque bytes of `size`."""
    out = b""
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(b"%s-%d" % (name.encode(), counter)).digest()
        counter += 1
    return out[:size]




class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = testing.Scratch()
        cls.tls = Tls(cls.scratch)
        cls.files = cls.scratch.at("files")
        os.mkdir(cls.files, 0o700)
        os.mkdir(os.path.join(cls.files, "pkg"), 0o700)
        cls.bodies = BODIES
        for name, size in (("a.whl", 3000), ("b.tgz", 70000), ("c.whl", 1),
                           ("left-pad-1.3.0.tgz", 5000), ("cli-0.164.0-linux-x64.tgz", 20000)):
            cls.add(name, body(name, size))
        cls.server = Server(cls.files, cls.tls)

    @classmethod
    def add(cls, name, data):
        cls.bodies[name] = data
        with open(os.path.join(cls.files, "pkg", name), "wb") as stream:
            stream.write(data)

    @classmethod
    def tearDownClass(cls):
        cls.server.kill()
        cls.scratch.remove()

    def stage(self):
        return self.scratch.stage()

    def seam(self, port=None, tls=None):
        return {"endpoint": "localhost:%d" % (port or self.server.port),
                "ca_file": (tls or self.tls).ca}



class Seam(Case):
    def test_the_seam_is_exactly_a_loopback_endpoint_and_a_ca(self):
        class Request:
            test = None
        self.assertEqual(packages.seam(Request()), (None, None))
        Request.test = self.seam()
        self.assertEqual(packages.seam(Request()), (("localhost", self.server.port), self.tls.ca))
        for test in ({"endpoint": "example.org:443", "ca_file": self.tls.ca},
                     {"endpoint": "localhost:0", "ca_file": self.tls.ca},
                     {"endpoint": "localhost:65536", "ca_file": self.tls.ca},
                     {"endpoint": "localhost:1"}, {"ca_file": self.tls.ca},
                     {"endpoint": "localhost:1", "ca_file": "relative.pem"}):
            with self.subTest(test=test):
                Request.test = test
                with self.assertRaises(Refused) as caught:
                    packages.seam(Request())
                self.assertEqual(caught.exception.code, "package_test_seam_invalid")


class Handlers(Case):
    """Each worker as the host runs it."""

    def run_worker(self, handler_id, operation, args, policy, metadata_bytes=32768,
                   acquire_bytes=1 << 31):
        stage = self.stage()
        value = testing.request_value(stage, handler_id, operation, args, policy,
                                      test=self.seam(), metadata_bytes=metadata_bytes,
                                      acquire_bytes=acquire_bytes)
        code, lines, _ = testing.run(testing.entry(handler_id),
                                     testing.write_request(stage, value), {"LC_ALL": "C"})
        self.assertEqual(code, 0, lines)
        return testing.result(self, lines), stage

    def test_an_unknown_operation_is_the_workers_refusal(self):
        line, stage = self.run_worker("npm", "install", {"names": ["cli"]},
                                      {"schema": "agentbox.npm.registry-policy.v1",
                                       "registry": "https://registry.example.org/"})
        self.assertEqual((line["outcome"], line["code"]), ("error", "operation_unsupported"))
        self.assertEqual(os.listdir(stage), [handler.REQUEST_FILE])

    def test_the_maximal_request_parses(self):
        # The largest request file the host writes (handler.rs): every bound.
        stage = "/" + "/".join(["\x01" * 200] * 5) + "/request-" + "0" * 32
        # Arguments of the 60 KiB canonical ceiling, escapes included.
        value = testing.request_value(stage, "npm", "tarballs", {"k": "\"" * 30700},
                                      {"pad": "\"" * 32700}, tools={"git": "/usr/bin/git"},
                                      remaining_ms=2**53 - 1, acquire_bytes=2**53 - 1)
        self.assertLessEqual(len(handler.canonical(value["args"])), 61440)
        data = json.dumps(value, separators=(",", ":")).encode()
        self.assertLessEqual(len(data), handler.MAX_REQUEST_BYTES)
        self.assertEqual(handler.strict_loads(data), value)


REGISTRY = "registry.example.org"
ABBREVIATED_ACCEPT = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
TRAILER = len(b"\nagentbox.npm.batch.v1 ") + 20 + 1


def npm_worker():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "npm_worker", os.path.join(HERE, "npm", "host", "worker.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def batch_of(data):
    """A batch artifact's (index, [body...]) as the jail reads it."""
    trailer = data[-TRAILER:]
    assert trailer.startswith(b"\nagentbox.npm.batch.v1 ") and trailer.endswith(b"\n"), trailer
    length = int(trailer[-21:-1])
    index = json.loads(data[-TRAILER - length:-TRAILER])
    bodies, at = [], 0
    for item in index["items"]:
        bodies.append(data[at:at + item["bytes"]])
        at += item["bytes"]
    assert at == len(data) - TRAILER - length
    return index, bodies


def integrity(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


class NpmRegistry(Case):
    """The `npm` registry worker as the host runs it, against a synthetic
    registry laid out as `GET /MODE/...` serves it."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.docs = {}
        cls.tarballs = {}
        # One file tree serves every mode: other modes' packages have names
        # of their own.
        cls.package("ok", "cli", "1.0.0")
        cls.package("ok", "@scope/core", "2.0.0-rc.1")
        for mode in ("chunked", "close", "http10"):
            cls.package(mode, "cli-" + mode, "1.0.0")
            cls.package(mode, "@scope/core-" + mode, "2.0.0-rc.1")
        cls.package("ok", "old", "0.1.0", sha1_only=True)
        cls.package("ok", "JSONStream", "1.3.5")
        cls.package("ok", "evil", "1.0.0", tarball="https://other.example.org/ok/evil/-/evil-1.0.0.tgz")
        cls.package("ok", "redirected", "1.0.0", tarball="https://%s/redirect/x.tgz" % REGISTRY)
        cls.package("ok", "bad", "1.0.0", corrupt=True)
        cls.package("ok", "liar", "1.0.0", name_field="cli")
        cls.package("ok", "unhashed", "1.0.0", unhashed=True)

    @classmethod
    def write(cls, rel, data):
        path = os.path.join(cls.files, *rel.split("/"))
        os.makedirs(os.path.dirname(path), 0o700, exist_ok=True)
        with open(path, "wb") as stream:
            stream.write(data)

    @classmethod
    def package(cls, mode, name, version, tarball=None, sha1_only=False, corrupt=False,
                name_field=None, unhashed=False):
        name_field = name_field or name
        escaped = name.replace("/", "%2f")
        base = name.rsplit("/", 1)[-1]
        body = globals()["body"]("%s/%s/%s" % (mode, name, version), 3000 + len(name) * 101)
        key = (mode, name, version)
        cls.tarballs[key] = body
        dist = {"tarball": tarball or "https://%s/%s/%s/-/%s-%s.tgz" % (REGISTRY, mode, name, base,
                                                                         version)}
        if not unhashed:
            if sha1_only:
                dist["shasum"] = hashlib.sha1(body).hexdigest()
            else:
                served = body if not corrupt else body[:-1] + bytes([body[-1] ^ 1])
                dist["integrity"] = integrity(body) + " sha1-x"
                dist["shasum"] = hashlib.sha1(body).hexdigest()
                body = served
        document = json.dumps({"name": name_field, "version": version, "dist": dist}).encode()
        packument = json.dumps({"name": name, "versions": {version: {"dist": dist}},
                                "mode": mode}).encode()
        cls.docs[(mode, name)] = packument
        cls.write("%s/_doc" % escaped, packument) if mode == "ok" else None
        cls.write("%s/%s" % (escaped, version), document)
        cls.write("%s/-/%s-%s.tgz" % (name, base, version), body)

    def policy(self, mode="ok"):
        return {"schema": "agentbox.npm.registry-policy.v1",
                "registry": "https://%s/%s/" % (REGISTRY, mode)}

    def run_npm(self, operation, args, policy=None, acquire_bytes=1 << 31):
        stage = self.stage()
        value = testing.request_value(stage, "npm", operation, args, policy or self.policy(),
                                      test=self.seam(), metadata_bytes=1024,
                                      acquire_bytes=acquire_bytes)
        code, lines, _ = testing.run(testing.entry("npm"), testing.write_request(stage, value),
                                     {"LC_ALL": "C"})
        self.assertEqual(code, 0, lines)
        return testing.result(self, lines), stage

    def artifact(self, stage, line):
        with open(os.path.join(stage, ARTIFACT), "rb") as stream:
            data = stream.read()
        self.assertEqual((len(data), hashlib.sha256(data).hexdigest()),
                         (line["size"], line["sha256"]))
        return batch_of(data)

    def test_metadata_delivers_documents_opaque_and_missing_names(self):
        for fmt, accept in (("abbreviated", ABBREVIATED_ACCEPT), ("full", "application/json")):
            with self.subTest(format=fmt):
                server = Server(self.files, self.tls)
                try:
                    stage = self.stage()
                    value = testing.request_value(
                        stage, "npm", "metadata",
                        {"names": ["cli", "@scope/core", "nope"], "format": fmt}, self.policy(),
                        test=self.seam(server.port), metadata_bytes=1024, acquire_bytes=1 << 31)
                    code, lines, _ = testing.run(testing.entry("npm"),
                                                 testing.write_request(stage, value),
                                                 {"LC_ALL": "C"})
                finally:
                    requests = server.stop()
                line = testing.result(self, lines)
                self.assertEqual(code, 0)
                self.assertEqual(line["outcome"], "ok", line)
                self.assertEqual(line["metadata"], {"format": "agentbox.npm.batch.v1", "items": 3})
                self.assertNotIn("provenance", line)
                index, bodies = self.artifact(stage, line)
                cli, core = self.docs[("ok", "cli")], self.docs[("ok", "@scope/core")]
                self.assertEqual(index, {"schema": "agentbox.npm.batch.v1", "operation": "metadata",
                                         "items": [{"name": "cli", "status": "ok",
                                                    "bytes": len(cli)},
                                                   {"name": "@scope/core", "status": "ok",
                                                    "bytes": len(core)},
                                                   {"name": "nope", "status": "missing",
                                                    "bytes": 0}]})
                self.assertEqual(bodies, [cli, core, b""])
                self.assertEqual(line["acquired"], len(cli) + len(core))
                self.assertEqual([r["path"] for r in requests],
                                 ["/ok/cli", "/ok/@scope%2fcore", "/ok/nope"])
                for request in requests:
                    self.assertEqual(request["headers"]["accept"], [accept])
                    self.assertEqual(request["headers"]["accept-encoding"], ["identity"])
                    self.assertNotIn("authorization", request["headers"])

    def test_tarballs_are_derived_from_the_registry_checked_and_recorded(self):
        wanted = [("cli", "1.0.0"), ("@scope/core", "2.0.0-rc.1"), ("old", "0.1.0"),
                  ("JSONStream", "1.3.5"), ("cli", "9.9.9")]
        server = Server(self.files, self.tls)
        try:
            stage = self.stage()
            value = testing.request_value(
                stage, "npm", "tarballs",
                {"packages": [{"name": n, "version": v} for n, v in wanted]}, self.policy(),
                test=self.seam(server.port), metadata_bytes=1024, acquire_bytes=1 << 31)
            code, lines, _ = testing.run(testing.entry("npm"), testing.write_request(stage, value),
                                         {"LC_ALL": "C"})
        finally:
            requests = server.stop()
        self.assertEqual(code, 0)
        line = testing.result(self, lines)
        self.assertEqual(line["outcome"], "ok", line)
        index, bodies = self.artifact(stage, line)
        expected = [self.tarballs[("ok", n, v)] for n, v in wanted[:4]] + [b""]
        self.assertEqual(bodies, expected)
        sha1 = "sha1-" + base64.b64encode(hashlib.sha1(expected[2]).digest()).decode()
        integrities = [integrity(expected[0]), integrity(expected[1]), sha1,
                       integrity(expected[3])]
        self.assertEqual(index["items"][-1], {"name": "cli", "version": "9.9.9",
                                              "status": "missing", "bytes": 0})
        self.assertEqual([item["integrity"] for item in index["items"][:4]], integrities)
        self.assertEqual(line["provenance"],
                         [{"name": n, "version": v, "integrity": i}
                          for (n, v), i in zip(wanted[:4], integrities)])
        self.assertEqual([r["path"] for r in requests], [
            "/ok/cli/1.0.0", "/ok/cli/-/cli-1.0.0.tgz",
            "/ok/@scope%2fcore/2.0.0-rc.1", "/ok/@scope/core/-/core-2.0.0-rc.1.tgz",
            "/ok/old/0.1.0", "/ok/old/-/old-0.1.0.tgz",
            "/ok/JSONStream/1.3.5", "/ok/JSONStream/-/JSONStream-1.3.5.tgz",
            "/ok/cli/9.9.9"])
        documents = sum(os.path.getsize(os.path.join(self.files, *rel.split("/"))) for rel in (
            "cli/1.0.0", "@scope%2fcore/2.0.0-rc.1", "old/0.1.0", "JSONStream/1.3.5"))
        self.assertEqual(line["acquired"], documents + sum(len(b) for b in expected))

    def test_every_framing_delivers(self):
        for mode in ("chunked", "close", "http10"):
            with self.subTest(mode=mode):
                name = "@scope/core-" + mode
                line, stage = self.run_npm(
                    "tarballs", {"packages": [{"name": name, "version": "2.0.0-rc.1"}]},
                    self.policy(mode))
                self.assertEqual(line["outcome"], "ok", line)
                _, bodies = self.artifact(stage, line)
                self.assertEqual(bodies, [self.tarballs[(mode, name, "2.0.0-rc.1")]])

    def test_registry_answers_outside_the_profile_are_refused(self):
        one = lambda name: {"packages": [{"name": name, "version": "1.0.0"}]}  # noqa: E731
        for args, policy, code in (
                (one("evil"), None, "npm_tarball_unexpected"),
                (one("redirected"), None, "npm_tarball_unexpected"),
                (one("bad"), None, "npm_tarball_mismatch"),
                (one("liar"), None, "npm_document_invalid"),
                (one("unhashed"), None, "npm_integrity_missing"),
                ({"names": ["cli"], "format": "full"}, self.policy("redirect"),
                 "npm_response_status"),
                ({"names": ["cli"], "format": "full"}, self.policy("gzip"),
                 "npm_response_encoding"),
                ({"names": ["cli"], "format": "full"}, self.policy("twolengths"),
                 "npm_response_length"),
                ({"names": ["cli"], "format": "full"}, self.policy("short"),
                 "npm_body_incomplete")):
            with self.subTest(code=code, args=args):
                operation = "metadata" if "names" in args else "tarballs"
                line, _ = self.run_npm(operation, args, policy)
                self.assertEqual((line["outcome"], line["code"]), ("error", code))
                self.assertIn("acquired", line)

    def test_arguments_and_policies_are_the_workers_to_check(self):
        ok = {"names": ["cli"], "format": "full"}
        names = lambda items: {"names": items, "format": "full"}  # noqa: E731
        pkgs = lambda items: {"packages": items}  # noqa: E731
        for operation, args in (
                ("metadata", {}), ("metadata", dict(ok, extra=1)),
                ("metadata", {"names": ["cli"], "format": "corgi"}),
                ("metadata", names([])), ("metadata", names(["cli", "cli"])),
                ("metadata", names(["p%d" % n for n in range(257)])),
                ("metadata", names(["Bad Name"])), ("metadata", names([".hidden"])),
                ("metadata", names(["@scope"])), ("metadata", names(["a/b"])),
                ("metadata", names(["x" * 215])), ("metadata", names([1])),
                ("tarballs", pkgs([])), ("tarballs", pkgs([{"name": "cli"}])),
                ("tarballs", pkgs([{"name": "cli", "version": "^1.0.0"}])),
                ("tarballs", pkgs([{"name": "cli", "version": "1.0"}])),
                ("tarballs", pkgs([{"name": "cli", "version": "latest"}])),
                ("tarballs", pkgs([{"name": "cli", "version": "1.0.0", "url": "x"}])),
                ("tarballs", pkgs([{"name": "cli", "version": "1.0.0"}] * 2)),
                ("tarballs", pkgs([{"name": "p%d" % n, "version": "1.0.0"}
                                   for n in range(257)]))):
            with self.subTest(args=json.dumps(args)[:80]):
                line, stage = self.run_npm(operation, args)
                self.assertEqual(line, {"schema": handler.RESULT_SCHEMA, "outcome": "error",
                                        "code": "npm_args_invalid", "acquired": 0})
                self.assertEqual(os.listdir(stage), [handler.REQUEST_FILE])
        base = self.policy()
        for policy in (dict(base, schema="x"), dict(base, extra=1), {"schema": base["schema"]},
                       dict(base, registry="http://%s/ok/" % REGISTRY),
                       dict(base, registry="https://%s:443/ok/" % REGISTRY),
                       dict(base, registry="https://user@%s/ok/" % REGISTRY),
                       dict(base, registry="https://%s/ok" % REGISTRY),
                       dict(base, registry="https://%s/ok/?q/" % REGISTRY),
                       dict(base, registry="https://%s/ok/%%2e/" % REGISTRY),
                       dict(base, registry="https://REGISTRY.example.org/ok/"),
                       dict(base, registry="https://10.0.0.1/"),
                       dict(base, registry="https://localhost/")):
            with self.subTest(policy=policy):
                line, _ = self.run_npm("metadata", ok, policy)
                self.assertEqual((line["code"], line["acquired"]), ("npm_policy_invalid", 0))

    def test_the_allowance_bounds_every_read(self):
        doc = self.docs[("ok", "cli")]
        # A known length past the allowance: nothing read.
        line, _ = self.run_npm("metadata", {"names": ["cli"], "format": "full"},
                               acquire_bytes=len(doc) - 1)
        self.assertEqual((line["code"], line["acquired"]), ("acquire_limit", 0))
        # Exactly the allowance: delivered.
        line, _ = self.run_npm("metadata", {"names": ["cli"], "format": "full"},
                               acquire_bytes=len(doc))
        self.assertEqual((line["outcome"], line["acquired"]), ("ok", len(doc)))
        # An unknown length: read up to the allowance, never past it.
        tarball = self.tarballs[("chunked", "cli-chunked", "1.0.0")]
        document = os.path.getsize(os.path.join(self.files, "cli-chunked", "1.0.0"))
        allowance = document + len(tarball) // 2
        line, _ = self.run_npm("tarballs",
                               {"packages": [{"name": "cli-chunked", "version": "1.0.0"}]},
                               self.policy("chunked"), acquire_bytes=allowance)
        self.assertEqual((line["code"], line["acquired"]), ("acquire_limit", allowance))
        # No allowance at all.
        line, _ = self.run_npm("metadata", {"names": ["cli"], "format": "full"}, acquire_bytes=0)
        self.assertEqual((line["code"], line["acquired"]), ("acquire_limit", 0))

    def test_a_batch_past_its_bound_is_refused(self):
        worker = npm_worker()
        worker.MAX_METADATA_BATCH = len(self.docs[("ok", "cli")]) + 10
        stage = self.stage()
        value = testing.request_value(stage, "npm", "metadata",
                                      {"names": ["cli", "@scope/core"], "format": "full"},
                                      self.policy(), test=self.seam(), metadata_bytes=1024,
                                      acquire_bytes=1 << 31)
        testing.write_request(stage, value)
        request = handler.Request(value)
        with self.assertRaises(Refused) as caught:
            worker.metadata(request)
        self.assertEqual(caught.exception.code, "npm_batch_too_large")
        self.assertLessEqual(request.meter.used, worker.MAX_METADATA_BATCH + 1)


if __name__ == "__main__":
    unittest.main()
