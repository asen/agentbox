"""Offline suite of the `pip` handler: its host worker as the host runs
it (`python3 -I -B worker.py acquire STAGE/request.json`) against a
synthetic PEP 691 index on the loopback HTTPS fixture server
(package_fixture_server.py, a throwaway CA, the request's `test` seam);
its jail index (jail/index.py) on 127.0.0.1 with that worker standing in
for the host lane; real pip resolving, backtracking and building source
distributions through it; and the session wrapper's lifecycle
(jail/pip.py). No real network, index, credential or model: every
proxy variable names a closed port, so pip reaches nothing but the
loopback index.

Real pip is the host's own (`python3 -m pip` in a `--without-pip
--system-site-packages` venv; skipped without one), not the jail image's.
The C extension case needs `cc`, the interpreter's `Python.h` and a local
setuptools wheel (/usr/share/python-wheels), and is skipped otherwise.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""

import asyncio
import base64
import gzip
import hashlib
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
for path in (HERE, ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

import handler_testing as testing  # noqa: E402
from test_package_handlers import Server, Tls  # noqa: E402
from acquisitions.pip.jail import index as jail_index  # noqa: E402
from acquisitions.pip.jail import pip as session_module  # noqa: E402
from acquisitions.pip.jail.index import Adapter, BatchFailed  # noqa: E402

handler = testing.handler
PYTHON = sys.executable
ENTRY = testing.entry("pip")
SESSION = os.path.join(HERE, "pip", "jail", "pip.py")
INDEX_HOST = "index.example.org"
FILES_HOST = "files.example.org"
INDEX = "https://%s/ok/simple/" % INDEX_HOST
FILES = "https://%s/ok/files/" % FILES_HOST
POLICY = {"schema": "agentbox.pip.index-policy.v1", "index": INDEX, "files": [FILES]}
DEAD_PROXY = "http://127.0.0.1:9"
NONCE = "0123456789abcdef0123456789abcdef"
SETUPTOOLS = "/usr/share/python-wheels"

# The fixture build backend (PEP 517), stdlib only. The tests build their
# own wheels with its `write_wheel` too. In a source tree it reads
# `abx.json`: {name, version, requires, files, dynamic}; `dynamic` names
# build dependencies it asks for (`get_requires_for_build_wheel`) and
# imports while building, recording each one's MARK in the wheel.
BACKEND = r'''
import base64, hashlib, json, os, zipfile


def write_wheel(directory, name, version, requires=(), files=None):
    stem = "%s-%s" % (name.replace("-", "_"), version)
    info = stem + ".dist-info"
    entries = dict(files or {})
    entries[info + "/METADATA"] = metadata(name, version, requires)
    entries[info + "/WHEEL"] = (b"Wheel-Version: 1.0\nGenerator: abx\nRoot-Is-Purelib: true\n"
                                b"Tag: py3-none-any\n")
    record = []
    for path in sorted(entries):
        digest = base64.urlsafe_b64encode(hashlib.sha256(entries[path]).digest()).rstrip(b"=").decode()
        record.append("%s,sha256=%s,%d" % (path, digest, len(entries[path])))
    record.append(info + "/RECORD,,")
    entries[info + "/RECORD"] = ("\n".join(record) + "\n").encode()
    filename = stem + "-py3-none-any.whl"
    with zipfile.ZipFile(os.path.join(directory, filename), "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(entries):
            archive.writestr(zipfile.ZipInfo(path, (2020, 1, 1, 0, 0, 0)), entries[path])
    return filename


def metadata(name, version, requires=()):
    lines = ["Metadata-Version: 2.1", "Name: " + name, "Version: " + version]
    lines += ["Requires-Dist: " + requirement for requirement in requires]
    return ("\n".join(lines) + "\n").encode()


def get_requires_for_build_wheel(config_settings=None):
    with open("abx.json") as stream:
        return list(json.load(stream).get("dynamic", []))


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    with open("abx.json") as stream:
        config = json.load(stream)
    marks = {}
    for name in config.get("dynamic", []):
        marks[name] = __import__(name).MARK
    files = {path: text.encode() for path, text in config["files"].items()}
    files[config["name"] + "/_built.py"] = ("BUILT_WITH = %r\n" % marks).encode()
    return write_wheel(wheel_directory, config["name"], config["version"], config.get("requires", []), files)
'''

CEXT_SETUP = '''from setuptools import Extension, setup
setup(name="abxcext", version="1.0", ext_modules=[Extension("abxcext", ["abxcext.c"])])
'''
CEXT_SOURCE = '''#include <Python.h>
static PyObject *answer(PyObject *self, PyObject *args) { return PyLong_FromLong(42); }
static PyMethodDef methods[] = {{"answer", answer, METH_NOARGS, NULL}, {NULL, NULL, 0, NULL}};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "abxcext", NULL, -1, methods};
PyMODINIT_FUNC PyInit_abxcext(void) { return PyModule_Create(&module); }
'''


def backend():
    namespace = {}
    exec(compile(BACKEND, "abxbackend.py", "exec"), namespace)
    return namespace


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def sdist(directory, name, version, files):
    """A `.tar.gz` source distribution of `files` under NAME-VERSION/."""
    stem = "%s-%s" % (name, version)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as archive:
        entries = dict(files, **{"PKG-INFO": backend()["metadata"](name, version)})
        for path in sorted(entries):
            data = entries[path] if isinstance(entries[path], bytes) else entries[path].encode()
            info = tarfile.TarInfo(stem + "/" + path)
            info.size, info.mtime, info.mode = len(data), 1577836800, 0o644
            archive.addfile(info, io.BytesIO(data))
    filename = stem + ".tar.gz"
    with open(os.path.join(directory, filename), "wb") as stream:
        stream.write(gzip.compress(raw.getvalue(), mtime=0))
    return filename


def batch_of(data):
    """A batch artifact's (index, [body...])."""
    prefix = b"\nagentbox.pip.batch.v1 "
    trailer = len(prefix) + 21
    assert data[-trailer:].startswith(prefix), data[-trailer:]
    length = int(data[-21:-1])
    index = json.loads(data[-trailer - length:-trailer])
    bodies, at = [], 0
    for item in index["items"]:
        bodies.append(data[at:at + item["bytes"]])
        at += item["bytes"]
    assert at == len(data) - trailer - length
    return index, bodies


class Fixture:
    """The synthetic index on the fixture server: `ok/simple/NAME/` pages
    and `ok/files/FILENAME` bodies (and `.metadata` sidecars)."""

    def __init__(self, scratch, tls):
        self.root = scratch.at("pip-files")
        self.dist = scratch.at("pip-dist")
        for path in (self.root, self.dist, os.path.join(self.root, "files")):
            os.mkdir(path, 0o700)
        self.build = backend()
        self.pages = {}
        self.cext = None
        self.wheel("abxlib", "1.0", sidecar=True)
        self.wheel("abxlib", "2.0", sidecar=True)
        self.wheel("abxtop", "1.0", ["abxlib<2"], sidecar=True)
        self.wheel("abxtop", "2.0", ["abxlib>=2"], sidecar=True)
        self.wheel("abxother", "1.0", ["abxlib<2"])
        self.wheel("abxbackend", "1.0", files={"abxbackend.py": BACKEND.encode()})
        self.source("abxdyn", "1.0", {"abxdyn/__init__.py": "MARK = 'dyn-1.0'\n"})
        self.source("abxsrc", "1.0", {"abxsrc/__init__.py": "from abxsrc._built import BUILT_WITH\n"},
                    requires=["abxlib<2"], dynamic=["abxdyn"])
        self.wheel("abxbad", "1.0", corrupt=True)
        self.wheel("abxforeign", "1.0", url="https://elsewhere.example.org/ok/files/%s")
        self.wheel("abxrel", "1.0", url="../../files/%s")
        # Two files the worker filters: another project's name, a bad suffix.
        self.add("abxlib", "abxtop-1.0-py3-none-any.whl", self.data("abxtop-1.0-py3-none-any.whl"))
        self.add("abxlib", "abxlib-1.0.exe", b"MZ")
        self.wheel("abxlib", "0.5")
        self.yanked("abxlib", "abxlib-0.5-py3-none-any.whl")
        if os.path.isdir(SETUPTOOLS):
            for name in sorted(os.listdir(SETUPTOOLS)):
                if name.startswith("setuptools-") and name.endswith(".whl"):
                    shutil.copyfile(os.path.join(SETUPTOOLS, name), os.path.join(self.dist, name))
                    self.add("setuptools", name, self.data(name))
                    self.cext = self.source("abxcext", "1.0", {
                        "pyproject.toml": '[build-system]\nrequires = ["setuptools"]\n'
                                          'build-backend = "setuptools.build_meta"\n',
                        "setup.py": CEXT_SETUP, "abxcext.c": CEXT_SOURCE}, raw=True)
        self.write()
        self.server = Server(self.root, tls)

    def data(self, filename):
        with open(os.path.join(self.dist, filename), "rb") as stream:
            return stream.read()

    def add(self, project, filename, data, url=None, digest=None, metadata=None):
        entry = {"filename": filename, "url": (url or FILES + "%s") % filename,
                 "hashes": {"sha256": digest or sha256(data), "md5": "x"}, "requires-python": ">=3.8"}
        if metadata is not None:
            entry["core-metadata"] = {"sha256": sha256(metadata)}
            with open(os.path.join(self.root, "files", filename + ".metadata"), "wb") as stream:
                stream.write(metadata)
        with open(os.path.join(self.root, "files", filename), "wb") as stream:
            stream.write(data)
        self.pages.setdefault(project, []).append(entry)

    def yanked(self, project, filename):
        for entry in self.pages[project]:
            if entry["filename"] == filename:
                entry["yanked"] = "broken"

    def wheel(self, name, version, requires=(), files=None, sidecar=False, corrupt=False, url=None):
        files = dict(files or {name + "/__init__.py": ("VERSION = %r\n" % version).encode()})
        filename = self.build["write_wheel"](self.dist, name, version, requires, files)
        data = self.data(filename)
        metadata = self.build["metadata"](name, version, requires) if sidecar else None
        self.add(name, filename, data[:-1] + bytes([data[-1] ^ 1]) if corrupt else data, url=url,
                 digest=sha256(data), metadata=metadata)

    def source(self, name, version, files, requires=(), dynamic=(), raw=False):
        if not raw:
            config = {"name": name, "version": version, "requires": list(requires), "files": files,
                      "dynamic": list(dynamic)}
            files = {"abx.json": json.dumps(config),
                     "pyproject.toml": '[build-system]\nrequires = ["abxbackend"]\n'
                                       'build-backend = "abxbackend"\n'}
        filename = sdist(self.dist, name, version, files)
        self.add(name, filename, self.data(filename))
        return filename

    def write(self):
        for project, files in self.pages.items():
            directory = os.path.join(self.root, "simple", project)
            os.makedirs(directory, 0o700)
            page = {"meta": {"api-version": "1.1"}, "name": project.upper(), "files": files, "versions": []}
            with open(os.path.join(directory, "_doc"), "w") as stream:
                json.dump(page, stream)

    def policy(self, **changes):
        return dict(POLICY, **changes)


class Case(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = testing.Scratch()
        cls.tls = Tls(cls.scratch)
        cls.fixture = Fixture(cls.scratch, cls.tls)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.server.kill()
        cls.scratch.remove()

    def seam(self):
        return {"endpoint": "localhost:%d" % self.fixture.server.port, "ca_file": self.tls.ca}

    def worker(self, operation, args, policy=None, acquire_bytes=1 << 31):
        """The worker as the host runs it: (result line, artifact bytes)."""
        stage = self.scratch.stage()
        value = testing.request_value(stage, "pip", operation, args, policy or POLICY, test=self.seam(),
                                      acquire_bytes=acquire_bytes)
        code, lines, _ = testing.run(ENTRY, testing.write_request(stage, value))
        self.assertEqual(code, 0, lines)
        line = testing.result(self, lines)
        artifact = os.path.join(stage, handler.ARTIFACT_FILE)
        data = None
        if os.path.exists(artifact):
            with open(artifact, "rb") as stream:
                data = stream.read()
        return line, data


class Worker(Case):
    def page(self, project):
        line, data = self.worker("files", {"projects": [project]})
        self.assertEqual(line["outcome"], "ok", line)
        index, bodies = batch_of(data)
        self.assertEqual(index["items"], [{"name": project, "status": "ok", "bytes": len(bodies[0])}])
        return json.loads(bodies[0])

    def test_pages_keep_only_approved_hashed_files_of_their_project_as_jail_urls(self):
        page = self.page("abxlib")
        self.assertEqual((page["meta"], page["name"]), ({"api-version": "1.0"}, "abxlib"))
        files = {entry["filename"]: entry for entry in page["files"]}
        self.assertEqual(sorted(files), ["abxlib-0.5-py3-none-any.whl", "abxlib-1.0-py3-none-any.whl",
                                         "abxlib-2.0-py3-none-any.whl"])
        self.assertEqual(files["abxlib-0.5-py3-none-any.whl"]["yanked"], "broken")
        wheel = files["abxlib-1.0-py3-none-any.whl"]
        digest = sha256(self.fixture.data("abxlib-1.0-py3-none-any.whl"))
        metadata = sha256(self.fixture.build["metadata"]("abxlib", "1.0"))
        self.assertEqual(wheel, {"filename": "abxlib-1.0-py3-none-any.whl",
                                 "url": "/files/abxlib/%s/abxlib-1.0-py3-none-any.whl" % digest,
                                 "hashes": {"sha256": digest}, "requires-python": ">=3.8",
                                 "core-metadata": {"sha256": metadata},
                                 "dist-info-metadata": {"sha256": metadata}})
        # Another origin is dropped; a relative URL resolves against the
        # page (index.example.org), outside the approved file origin.
        self.assertEqual(self.page("abxforeign")["files"], [])
        self.assertEqual(self.page("abxrel")["files"], [])
        wider = self.fixture.policy(files=[FILES, "https://%s/ok/files/" % INDEX_HOST])
        line, data = self.worker("files", {"projects": ["abxrel", "nothing-here"]}, wider)
        index, bodies = batch_of(data)
        self.assertEqual([item["status"] for item in index["items"]], ["ok", "missing"])
        self.assertEqual(len(json.loads(bodies[0])["files"]), 1)
        self.assertEqual(line["metadata"], {"format": "agentbox.pip.batch.v1", "items": 2})

    def test_fetch_delivers_listed_files_and_sidecars_checked_by_digest(self):
        wheel = "abxtop-2.0-py3-none-any.whl"
        data = self.fixture.data(wheel)
        source = self.fixture.data("abxsrc-1.0.tar.gz")
        args = {"files": [{"project": "abxtop", "filename": wheel, "sha256": sha256(data)},
                          {"project": "abxtop", "filename": wheel + ".metadata", "sha256": sha256(data)},
                          {"project": "abxsrc", "filename": "abxsrc-1.0.tar.gz", "sha256": sha256(source)},
                          {"project": "abxtop", "filename": "abxtop-9.0-py3-none-any.whl", "sha256": "0" * 64},
                          {"project": "abxtop", "filename": "abxtop-1.0-py3-none-any.whl", "sha256": "0" * 64},
                          {"project": "abxsrc", "filename": "abxsrc-1.0.tar.gz.metadata",
                           "sha256": sha256(source)}]}
        line, artifact = self.worker("fetch", args)
        self.assertEqual(line["outcome"], "ok", line)
        index, bodies = batch_of(artifact)
        self.assertEqual([item["status"] for item in index["items"]], ["ok", "ok", "ok", "missing", "missing",
                                                                        "missing"])
        self.assertEqual(bodies[:3], [data, self.fixture.build["metadata"]("abxtop", "2.0", ["abxlib>=2"]), source])
        self.assertEqual([(entry["name"], entry["version"]) for entry in line["provenance"]],
                         [("abxtop", wheel), ("abxtop", wheel + ".metadata"), ("abxsrc", "abxsrc-1.0.tar.gz")])
        self.assertEqual(line["provenance"][0]["integrity"],
                         "sha256-" + base64.b64encode(hashlib.sha256(data).digest()).decode())

    def test_a_file_that_is_not_its_listed_digest_is_refused(self):
        data = self.fixture.data("abxbad-1.0-py3-none-any.whl")
        line, _ = self.worker("fetch", {"files": [{"project": "abxbad", "filename": "abxbad-1.0-py3-none-any.whl",
                                                   "sha256": sha256(data)}]})
        self.assertEqual((line["outcome"], line["code"]), ("error", "pip_file_mismatch"))

    def test_redirects_are_never_followed(self):
        redirect = "https://%s/redirect/simple/" % INDEX_HOST
        line, _ = self.worker("files", {"projects": ["abxlib"]}, self.fixture.policy(index=redirect))
        self.assertEqual((line["outcome"], line["code"]), ("error", "pip_response_status"))

    def test_the_allowance_bounds_every_read(self):
        line, _ = self.worker("files", {"projects": ["abxlib"]}, acquire_bytes=100)
        self.assertEqual((line["outcome"], line["code"]), ("error", "acquire_limit"))
        self.assertLessEqual(line["acquired"], 100)

    def test_arguments_and_policies_are_checked(self):
        for args in ({}, {"projects": []}, {"projects": ["ABX"]}, {"projects": ["a", "a"]},
                     {"projects": ["a"] * 65}, {"projects": ["a"], "x": 1}):
            line, _ = self.worker("files", args)
            self.assertEqual(line.get("code"), "pip_args_invalid", args)
        good = {"project": "abxlib", "filename": "abxlib-1.0-py3-none-any.whl", "sha256": "0" * 64}
        for item in (dict(good, sha256="A" * 64), dict(good, filename="../x"), dict(good, project="a_b"),
                     dict(good, url="https://x/")):
            line, _ = self.worker("fetch", {"files": [item]})
            self.assertEqual(line.get("code"), "pip_args_invalid", item)
        for change in ({"index": "http://%s/ok/simple/" % INDEX_HOST}, {"index": INDEX[:-1]},
                       {"files": []}, {"files": [FILES, FILES]}, {"files": ["https://x.org:8443/"]},
                       {"schema": "x"}, {"extra": 1}, {"index": "https://127.0.0.1/simple/"}):
            line, _ = self.worker("files", {"projects": ["abxlib"]}, self.fixture.policy(**change))
            self.assertEqual(line.get("code"), "pip_policy_invalid", change)
        # An unknown operation is refused before its policy is read.
        for policy in (None, self.fixture.policy(schema="x")):
            line, _ = self.worker("install", {"projects": ["abxlib"]}, policy)
            self.assertEqual(line.get("code"), "operation_unsupported")

    def test_file_urls_follow_a_narrow_grammar(self):
        worker = backend_worker()
        page = "https://%s/simple/p/" % INDEX_HOST
        origins = ["https://f.example.org/a/"]
        for raw, ok in (("https://f.example.org/a/p-1.0.tar.gz", True),
                        ("https://f.example.org/a/x/p-1.0.tar.gz#sha256=00", True),
                        ("https://f.example.org/a/%2e%2e/p-1.0.tar.gz", False),
                        ("https://f.example.org/a/x%2Fy/p-1.0.tar.gz", False),
                        ("https://f.example.org/a/../b/p-1.0.tar.gz", False),
                        ("https://f.example.org/a/p-1.0.tar.gz?x=1", False),
                        ("https://u@f.example.org/a/p-1.0.tar.gz", False),
                        ("https://f.example.org:443/a/p-1.0.tar.gz", False),
                        ("http://f.example.org/a/p-1.0.tar.gz", False),
                        ("https://f.example.org/a/q-1.0.tar.gz", False),
                        ("//f.example.org/a/p-1.0.tar.gz", True)):
            self.assertEqual(worker.file_url(page, raw, "p-1.0.tar.gz", origins) is not None, ok, raw)
        for filename, project, ok in (("p-1.0.tar.gz", "p", True), ("P_x-1.0-py3-none-any.whl", "p-x", True),
                                      ("p_x-1.0.zip", "p-x", True), ("px-1.0.tar.gz", "p", False),
                                      ("p-1.0.exe", "p", False), ("p-.tar.gz", "p", False),
                                      ("p-1.0-py3-none.whl", "p", False)):
            self.assertEqual(worker.belongs(filename, project), ok, filename)


def spool_fds(directory, pid="self"):
    """The descriptors of `pid` on an unnamed file of `directory`."""
    found = []
    for name in os.listdir("/proc/%s/fd" % pid):
        try:
            target = os.readlink("/proc/%s/fd/%s" % (pid, name))
        except OSError:
            continue
        if target.startswith(directory + "/") and target.endswith(" (deleted)"):
            found.append(int(name))
    return sorted(found)


def backend_worker():
    import importlib.util
    spec = importlib.util.spec_from_file_location("pip_worker", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Lane:
    """The host lane as the jail index sees it: each batch run by the real
    worker against the fixture index, its artifact copied into the spool."""

    def __init__(self, case, policy=None):
        self.case = case
        self.policy = policy
        self.requests = []
        self.adapter = None

    async def fetch(self, operation, args, abort):
        self.requests.append((operation, args))
        line, data = await asyncio.to_thread(self.case.worker, operation, args, self.policy)
        if line["outcome"] != "ok":
            raise BatchFailed(line["code"])
        batch = jail_index.Batch(tempfile.TemporaryFile(dir=self.adapter.spool, buffering=0))
        os.pwrite(batch.file.fileno(), data, 0)
        return batch, len(data)

    async def __aenter__(self):
        self.adapter = Adapter(self.fetch, spool=self.case.scratch.at("tmp"))
        await self.adapter.start()
        return self

    async def __aexit__(self, *_):
        await self.adapter.close()

    async def get(self, path, method="GET"):
        def call():
            request = urllib.request.Request(self.adapter.url + path.lstrip("/"), method=method)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            try:
                with opener.open(request, timeout=60) as response:
                    return response.status, response.reason, response.headers.get("Content-Type"), response.read()
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, error.reason, error.headers.get("Content-Type"), error.read()

        return await asyncio.to_thread(call)


class JailIndex(Case, unittest.IsolatedAsyncioTestCase):
    async def test_pages_and_files_are_served_as_delivered(self):
        async with Lane(self) as lane:
            status, _, kind, body = await lane.get("/simple/AbxLib/")
            self.assertEqual((status, kind), (200, "application/vnd.pypi.simple.v1+json"))
            page = json.loads(body)
            entry = page["files"][0]
            status, _, _, data = await lane.get(entry["url"])
            self.assertEqual((status, data), (200, self.fixture.data(entry["filename"])))
            status, _, _, data = await lane.get(entry["url"] + ".metadata")
            self.assertEqual((status, data), (200, self.fixture.build["metadata"]("abxlib", "1.0")))
            # Cached: no request; HEAD has no body.
            self.assertEqual((await lane.get(entry["url"], method="HEAD"))[::3], (200, b""))
            self.assertEqual([operation for operation, _ in lane.requests], ["files", "fetch", "fetch"])
            self.assertEqual((await lane.get("/simple/nothing-here/"))[0], 404)
            for path in ("/simple/", "/simple/a/b/", "/files/abxlib/%s/x" % ("0" * 63), "/other"):
                self.assertEqual((await lane.get(path))[0], 404, path)
            self.assertEqual((await lane.get("/simple/abxlib/", method="PUT"))[0], 405)
            self.assertEqual(len(lane.requests), 4)

    async def test_a_failed_request_fails_its_keys_only_with_its_code(self):
        async with Lane(self, policy=dict(POLICY, schema="x")) as lane:
            status, reason, _, _ = await lane.get("/simple/abxlib/")
            self.assertEqual((status, reason), (424, "agentbox index request failed (pip_policy_invalid)"))
            lane.policy = None
            self.assertEqual((await lane.get("/simple/abxlib/"))[0], 200)
        self.assertTrue(all(batch.closed for batch in lane.adapter.delivered))
        self.assertEqual((os.listdir(self.scratch.at("tmp")), spool_fds(self.scratch.at("tmp"))), ([], []))

    async def test_each_batch_is_an_unnamed_file_and_a_bad_one_is_closed(self):
        tmp = self.scratch.at("tmp")
        async with Lane(self) as lane:
            self.assertEqual((await lane.get("/simple/abxlib/"))[0], 200)
            self.assertEqual((await lane.get("/simple/abxtop/"))[0], 200)
            delivered = lane.adapter.delivered
            self.assertEqual(os.listdir(tmp), [])
            self.assertEqual([os.fstat(batch.file.fileno()).st_nlink for batch in delivered], [0, 0])
            self.assertEqual(spool_fds(tmp), sorted(batch.file.fileno() for batch in delivered))
            good, bad_batches = lane.fetch, []

            async def bad(operation, args, abort):
                batch, size = await good(operation, args, abort)
                os.pwrite(batch.file.fileno(), b"x", size - 1)
                bad_batches.append(batch)
                return batch, size

            lane.adapter.fetch = bad
            status, reason, _, _ = await lane.get("/simple/abxother/")
            self.assertEqual((status, reason), (424, "agentbox index request failed (pip_batch_invalid)"))
            self.assertEqual((bad_batches[0].closed, len(delivered), len(spool_fds(tmp))), (True, 2, 2))
            lane.adapter.fetch = good
            self.assertEqual((await lane.get("/simple/abxother/"))[0], 200)
            page = json.loads((await lane.get("/simple/abxlib/"))[3])
            self.assertEqual(page["name"], "abxlib")
        self.assertEqual(spool_fds(tmp), [])


def host_pip():
    """The host's pip in a venv, or None."""
    probe = subprocess.run([PYTHON, "-I", "-m", "pip", "--version"], capture_output=True)
    return probe.returncode == 0


@unittest.skipUnless(host_pip(), "no host pip")
class RealPip(Case, unittest.IsolatedAsyncioTestCase):
    """Real pip through the jail index, no other route."""

    def setUp(self):
        self.venv = self.scratch.at("venv-%s" % self.id().rsplit(".", 1)[-1])
        subprocess.run([PYTHON, "-I", "-m", "venv", "--without-pip", "--system-site-packages", self.venv],
                       check=True)
        self.home = self.venv + "-home"
        os.mkdir(self.home, 0o700)

    async def pip(self, lane, *args):
        python = os.path.join(self.venv, "bin", "python")
        env = session_module.session_environment(
            {"PATH": os.path.join(self.venv, "bin") + ":/usr/bin:/bin", "HOME": self.home, "TMPDIR": self.home,
             "LC_ALL": "C.UTF-8", "PIP_CONFIG_FILE": os.devnull, "PIP_NO_CACHE_DIR": "1",
             "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PYTHONNOUSERSITE": "1", "no_proxy": "example.org",
             **{name: DEAD_PROXY for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}},
            lane.adapter.url)
        child = await asyncio.create_subprocess_exec(python, "-m", "pip", *args, cwd=self.home, env=env,
                                                     stdout=asyncio.subprocess.PIPE,
                                                     stderr=asyncio.subprocess.STDOUT)
        out, _ = await asyncio.wait_for(child.communicate(), 600)
        return child.returncode, out.decode(errors="replace")

    def imported(self, code):
        done = subprocess.run([os.path.join(self.venv, "bin", "python"), "-c", code], capture_output=True,
                              cwd=self.home, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.decode().strip()

    async def test_requirements_backtrack_and_source_builds_get_dynamic_build_dependencies(self):
        requirements = os.path.join(self.home, "requirements.txt")
        with open(requirements, "w") as stream:
            stream.write("abxtop\nabxother\nabxsrc\n")
        async with Lane(self) as lane:
            code, out = await self.pip(lane, "install", "-r", requirements)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.imported("import abxtop, abxlib, abxother, abxsrc; "
                                       "print(abxtop.VERSION, abxlib.VERSION, abxsrc.BUILT_WITH)"),
                         "1.0 1.0 {'abxdyn': 'dyn-1.0'}")
        fetched = [item["filename"] for operation, args in lane.requests if operation == "fetch"
                   for item in args["files"]]
        # abxtop 2.0 was judged by its metadata sidecar alone; the source
        # build dependency was built from its sdist in pip's build env.
        self.assertIn("abxtop-2.0-py3-none-any.whl.metadata", fetched)
        self.assertNotIn("abxtop-2.0-py3-none-any.whl", fetched)
        self.assertIn("abxdyn-1.0.tar.gz", fetched)
        self.assertIn("abxbackend-1.0-py3-none-any.whl", fetched)

    async def test_a_bad_digest_or_an_unapproved_origin_installs_nothing(self):
        async with Lane(self) as lane:
            code, out = await self.pip(lane, "install", "abxbad")
            self.assertNotEqual(code, 0, out)
            self.assertIn("pip_file_mismatch", out)
            code, out = await self.pip(lane, "install", "abxforeign")
            self.assertNotEqual(code, 0, out)
            self.assertIn("No matching distribution", out)

    @unittest.skipUnless(shutil.which("cc") and os.path.isfile(os.path.join(sysconfig.get_paths()["include"],
                                                                               "Python.h")),
                         "no compiler or Python.h")
    async def test_a_c_extension_builds_from_source(self):
        if self.fixture.cext is None:
            self.skipTest("no local setuptools wheel")
        async with Lane(self) as lane:
            code, out = await self.pip(lane, "install", "abxcext")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.imported("import abxcext; print(abxcext.answer())"), "42")


class BatchFile(unittest.IsolatedAsyncioTestCase):
    """A batch's unnamed file (artifact_save_client.save_upload_unnamed) and
    its reads."""

    def setUp(self):
        self.scratch = testing.Scratch()
        self.addCleanup(self.scratch.remove)
        self.tmp = self.scratch.at("tmp")

    def upload(self, data):
        path = self.scratch.at("home", "upload")
        with open(path, "wb") as stream:
            stream.write(data)
        return path, {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    async def test_a_kept_copy_is_unnamed_and_any_other_is_closed(self):
        from guest.src.artifact_save_client import save_upload_unnamed
        path, ready = self.upload(b"x" * 300000)
        saved = await save_upload_unnamed(path, self.tmp, ready, lambda: False)
        self.addCleanup(saved.file.close)
        self.assertEqual((saved.ok, saved.removed, os.path.exists(path)), (True, True, False))
        self.assertEqual(os.pread(saved.file.fileno(), 300001, 0), b"x" * 300000)
        self.assertEqual((os.listdir(self.tmp), os.fstat(saved.file.fileno()).st_nlink), ([], 0))
        kept = spool_fds(self.tmp)
        self.assertEqual(kept, [saved.file.fileno()])
        # A digest that is not the ready's, a late copy, a cancelled one: no
        # file stays, the upload does.
        path, ready = self.upload(b"y" * 1000)
        saved = await save_upload_unnamed(path, self.tmp, dict(ready, sha256="0" * 64), lambda: False)
        self.assertEqual((saved.ok, saved.code, saved.file, os.path.exists(path)),
                         (False, "artifact_mismatch", None, True))
        saved = await save_upload_unnamed(path, self.tmp, ready, lambda: True)
        self.assertEqual((saved.ok, saved.code, os.path.exists(path)), (False, "artifact_expired", True))
        self.assertEqual(spool_fds(self.tmp), kept)
        path, ready = self.upload(b"z" * (3 << 20))
        task = asyncio.ensure_future(save_upload_unnamed(path, self.tmp, ready, lambda: False))
        while spool_fds(self.tmp) == kept:
            await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual((spool_fds(self.tmp), os.path.exists(path), os.listdir(self.tmp)), (kept, True, []))

    def test_a_reply_after_close_never_reads_a_reused_descriptor(self):
        batch = jail_index.Batch(tempfile.TemporaryFile(dir=self.tmp, buffering=0))
        os.pwrite(batch.file.fileno(), b"batch", 0)
        self.assertEqual(batch.pread(5, 0), b"batch")
        number = batch.file.fileno()
        batch.close()
        other = os.open(self.scratch.at("home", "other"), os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, other)
        os.pwrite(other, b"other", 0)
        self.assertEqual(other, number)
        with self.assertRaises(ConnectionError):
            batch.pread(5, 0)
        batch.close()


class Session(unittest.TestCase):
    """The session wrapper as the guest runs it: `PYTHON ENTRY session ARGV`."""

    def setUp(self):
        self.scratch = testing.Scratch()
        self.addCleanup(self.scratch.remove)
        self.work = self.scratch.at("work")
        os.mkdir(self.work, 0o700)

    def env(self, context=True, **extra):
        env = {"PATH": "/usr/bin:/bin", "TMPDIR": self.scratch.at("tmp"), "HOME": self.scratch.at("home"),
               "LANG": "C.UTF-8", "NO_PROXY": "internal.example"}
        if context:
            env.update({"AGENTBOX_REQUEST_SESSION": NONCE, "AGENTBOX_WORK_ROOT": self.work})
        env.update(extra)
        return env

    def start(self, argv, env, **options):
        return subprocess.Popen([PYTHON, "-I", "-S", "-B", "-X", "utf8", SESSION, "session", *argv], env=env,
                                cwd=self.work, **options)

    def spools(self):
        """Anything named in TMPDIR: the spool never is."""
        return os.listdir(self.scratch.at("tmp"))

    def wait_gone(self, url):
        """The sidecar's port closed and TMPDIR empty, within 10 s."""
        port = int(url.rsplit(":", 1)[1].strip("/"))
        until = time.monotonic() + 10
        while time.monotonic() < until:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
            except OSError:
                if not self.spools():
                    return
            time.sleep(0.1)
        self.fail("sidecar still serving or spool left")

    def test_the_command_keeps_its_process_argv_and_status_with_the_index_in_its_environment(self):
        script = ('printf "%s|%s|%s|%s\\n" "$0" "$1" "$$" "$(cat /proc/$$/stat | cut -d" " -f6)"; '
                  'env | sort; exit 7')
        child = self.start(["sh", "-c", script, "name", "arg one"], self.env(), stdout=subprocess.PIPE)
        out, _ = child.communicate(timeout=60)
        self.assertEqual(child.returncode, 7)
        lines = out.decode().splitlines()
        self.assertEqual(lines[0], "name|arg one|%d|%d" % (child.pid, os.getsid(0)))
        env = dict(line.split("=", 1) for line in lines[1:])
        url = env["AGENTBOX_PIP_INDEX"]
        self.assertRegex(url, r"^http://127\.0\.0\.1:[0-9]+/$")
        self.assertEqual({name: env[name] for name in ("PIP_INDEX_URL", "PIP_RETRIES", "PIP_TIMEOUT", "NO_PROXY",
                                                       "no_proxy")},
                         {"PIP_INDEX_URL": url + "simple/", "PIP_RETRIES": "0", "PIP_TIMEOUT": "1860",
                          "NO_PROXY": "internal.example,127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"})
        # Nothing of Python's own start-up (its C locale coercion, say).
        self.assertEqual(sorted(set(env) - set(self.env()) - {"PWD"}),
                         ["AGENTBOX_PIP_INDEX", "PIP_INDEX_URL", "PIP_RETRIES", "PIP_TIMEOUT", "no_proxy"])
        self.wait_gone(url)

    def test_the_index_serves_while_the_command_runs_and_ends_with_it(self):
        script = ("import os, urllib.request, urllib.error\n"
                  "opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
                  "try:\n opener.open(os.environ['AGENTBOX_PIP_INDEX'] + 'other', timeout=10)\n"
                  "except urllib.error.HTTPError as e:\n print(e.code, e.headers['Server'].split()[0])\n"
                  "print(os.environ['AGENTBOX_PIP_INDEX'])\n")
        done = subprocess.run([PYTHON, "-I", "-S", "-B", SESSION, "session", PYTHON, "-I", "-c", script],
                              env=self.env(), cwd=self.work, capture_output=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        status, url = done.stdout.decode().splitlines()
        self.assertEqual(status, "404 agentbox-pip")
        self.wait_gone(url)

    def test_a_signal_ends_the_command_as_its_own_and_the_index_follows(self):
        for number in (signal.SIGTERM, signal.SIGKILL):
            child = self.start(["sh", "-c", 'echo "$AGENTBOX_PIP_INDEX"; exec sleep 60'], self.env(),
                               stdout=subprocess.PIPE)
            url = child.stdout.readline().decode().strip()
            child.send_signal(number)
            child.wait(timeout=30)
            child.stdout.close()
            self.assertEqual(child.returncode, -number)
            self.wait_gone(url)

    def test_a_killed_sidecar_leaves_nothing_named(self):
        child = self.start(["sh", "-c", 'echo "$AGENTBOX_PIP_INDEX"; exec sleep 60'], self.env(),
                           stdout=subprocess.PIPE)
        self.addCleanup(child.wait, 30)
        self.addCleanup(child.kill)
        url = child.stdout.readline().decode().strip()
        child.stdout.close()
        tmp = self.scratch.at("tmp")
        sidecars = []
        for name in os.listdir("/proc"):
            if name.isdigit() and int(name) != child.pid:
                try:
                    with open("/proc/%s/cmdline" % name, "rb") as stream:
                        argv = stream.read().split(b"\0")
                    with open("/proc/%s/environ" % name, "rb") as stream:
                        env = stream.read().split(b"\0")
                except OSError:
                    continue
                # This test's own: its private TMPDIR.
                if SESSION.encode() in argv and b"session" in argv and ("TMPDIR=" + tmp).encode() in env:
                    sidecars.append(int(name))
        self.assertEqual(len(sidecars), 1, sidecars)
        self.assertEqual((self.spools(), spool_fds(tmp, sidecars[0])), ([], []))
        os.kill(sidecars[0], signal.SIGKILL)
        until = time.monotonic() + 10
        while os.path.exists("/proc/%d" % sidecars[0]) and time.monotonic() < until:
            time.sleep(0.05)
        self.assertEqual(self.spools(), [])
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", int(url.rsplit(":", 1)[1].strip("/"))), timeout=1).close()

    def test_a_terminal_stays_the_commands(self):
        main, other = os.openpty()
        self.addCleanup(os.close, main)
        child = self.start(["sh", "-c", 'test -t 0 && test -t 1 && echo "tty $(tty)"'], self.env(),
                           stdin=other, stdout=other, stderr=other)
        os.close(other)
        child.wait(timeout=60)
        out = b""
        while True:
            try:
                chunk = os.read(main, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        self.assertEqual(child.returncode, 0, out)
        self.assertIn(b"tty /dev/pts/", out)

    def test_without_a_request_context_or_inside_a_session_nothing_is_added(self):
        for env in (self.env(context=False), self.env(AGENTBOX_PIP_INDEX="http://127.0.0.1:1/")):
            done = subprocess.run([PYTHON, "-I", "-S", "-B", SESSION, "session", "env"], env=env, cwd=self.work,
                                  capture_output=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(dict(line.split("=", 1) for line in done.stdout.decode().splitlines()), env)
        self.assertEqual(self.spools(), [])

    def test_a_command_that_cannot_run(self):
        done = subprocess.run([PYTHON, "-I", "-S", "-B", SESSION, "session", "agentbox-no-such-command"],
                              env=self.env(), cwd=self.work, capture_output=True, timeout=60)
        self.assertEqual((done.returncode, done.stderr), (127, b"agentbox-session: command not run\n"))
        done = subprocess.run([PYTHON, "-I", "-S", "-B", SESSION, "session"], env=self.env(), cwd=self.work,
                              capture_output=True, timeout=60)
        self.assertEqual(done.returncode, 2)
        until = time.monotonic() + 10
        while self.spools() and time.monotonic() < until:
            time.sleep(0.1)
        self.assertEqual(self.spools(), [])


class GuestPaths(unittest.IsolatedAsyncioTestCase):
    """The guest helper's exec and the interactive form, with the real
    session wrapper in the installation's bin/ as the controller writes it
    (ssh.py `wrapper_texts`)."""

    def setUp(self):
        self.scratch = testing.Scratch()
        self.addCleanup(self.scratch.remove)
        self.home = self.scratch.at("home")
        os.chmod(self.home, 0o700)
        self.bin = self.scratch.at("bin")
        os.mkdir(self.bin, 0o700)
        with open(os.path.join(self.bin, "agentbox-session"), "w") as stream:
            stream.write("#!/bin/sh\nexec %s -I -S -B -X utf8 '%s' session \"$@\"\n" % (PYTHON, SESSION))
        os.chmod(os.path.join(self.bin, "agentbox-session"), 0o500)
        os.environ["TMPDIR"] = self.scratch.at("tmp")
        self.addCleanup(os.environ.pop, "TMPDIR")

    def spools(self):
        return os.listdir(self.scratch.at("tmp"))

    def wait_gone(self, url):
        Session.wait_gone(self, url)

    async def gone(self, url):
        await asyncio.to_thread(self.wait_gone, url)

    async def started(self, argv):
        """A helper session with a request context (the host's nonce), its
        exec sent."""
        from guest.test.session_harness import Harness
        session = Harness(self.home, wrapper_bin=self.bin)
        session.send({"v": 1, "type": "hello", "session": NONCE})
        await session.until(lambda frame: frame["type"] == "hello")
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": argv})
        return session

    async def test_an_exec_runs_behind_the_index_and_a_cancel_ends_both(self):
        session = await self.started(["sh", "-c", 'echo "$AGENTBOX_PIP_INDEX"; exit 3'])
        frame = await session.until(lambda item: item["type"] == "exit", timeout=30)
        self.assertEqual((frame["outcome"], frame["code"]), ("exited", 3))
        await self.gone(session.output("stdout").decode().strip())
        session.end()
        await session.status()
        session = await self.started(["sh", "-c", 'echo "$AGENTBOX_PIP_INDEX"; exec sleep 60'])
        until = time.monotonic() + 30
        while b"\n" not in session.output("stdout") and time.monotonic() < until:
            await asyncio.sleep(0.05)
        session.send({"v": 1, "type": "cancel", "id": "e-1"})
        frame = await session.until(lambda item: item["type"] == "exit", timeout=30)
        self.assertEqual(frame["outcome"], "cancelled")
        await self.gone(session.output("stdout").decode().strip())
        session.end()
        await session.status()

    async def test_an_exec_that_cannot_start_behind_the_index_is_a_failed_start(self):
        work = os.path.join(self.home, "work")
        os.mkdir(work, 0o700)
        with open(os.path.join(work, "run.sh"), "w") as stream:
            stream.write("#!/nonexistent/agentbox-interpreter\n")
        os.chmod(os.path.join(work, "run.sh"), 0o700)
        session = await self.started(["./run.sh"])
        frame = await session.until(lambda item: item["type"] == "exit", timeout=30)
        self.assertEqual(frame["outcome"], "failed")
        self.assertEqual((session.output("stdout"), session.output("stderr")), (b"", b""))
        session.end()
        await session.status()
        until = time.monotonic() + 10
        while self.spools() and time.monotonic() < until:
            await asyncio.sleep(0.1)
        self.assertEqual(self.spools(), [])

    def test_the_interactive_form_runs_behind_the_index(self):
        from guest.src.runtime import python_argv
        from guest.src.worker_profile import SHELL, SUPPLIED_SESSION
        main = os.path.join(ROOT, "guest", "src", "main.py")
        done = subprocess.run(python_argv(main, SUPPLIED_SESSION, self.home, os.path.join(self.home, "work"),
                                          self.bin, SHELL, "dumb", NONCE, "sh", "-c",
                                          'echo "$AGENTBOX_PIP_INDEX"; echo "$PIP_INDEX_URL"'),
                              capture_output=True, timeout=60, env={"PATH": "/usr/bin:/bin",
                                                                    "TMPDIR": self.scratch.at("tmp")})
        self.assertEqual(done.returncode, 0, done.stderr)
        url, index = done.stdout.decode().split()
        self.assertEqual(index, url + "simple/")
        self.wait_gone(url)


class StartStatus(Session):
    """`--status=FD`: `r` before the exec, `f` after a failed one; never the
    command's to hold."""

    def told(self, argv):
        read_end, write_end = os.pipe()
        self.status_fd = write_end
        child = self.start(["--status=%d" % write_end, *argv], self.env(), pass_fds=(write_end,),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(write_end)
        with os.fdopen(read_end, "rb") as stream:
            told = stream.read()
        out, err = child.communicate(timeout=60)
        return told, child.returncode, out, err

    def test_a_command_that_runs_is_told_and_exits_as_itself(self):
        told, code, out, _ = self.told(["sh", "-c", "ls /proc/$$/fd; exit 127"])
        self.assertEqual((told, code), (b"r", 127))
        self.assertNotIn(str(self.status_fd), out.decode().split())

    def test_a_failed_exec_is_told_and_silent(self):
        script = os.path.join(self.work, "run.sh")
        with open(script, "w") as stream:
            stream.write("#!/nonexistent/agentbox-interpreter\n")
        os.chmod(script, 0o700)
        for argv in (["./run.sh"], ["agentbox-no-such-command"]):
            self.assertEqual(self.told(argv), (b"rf", 127, b"", b""), argv)
        until = time.monotonic() + 10
        while self.spools() and time.monotonic() < until:
            time.sleep(0.1)
        self.assertEqual(self.spools(), [])


class Routes(unittest.TestCase):
    def test_routes(self):
        digest = "a" * 64
        self.assertEqual(jail_index.route("/simple/Foo.Bar_baz/"), ("files", "foo-bar-baz"))
        self.assertEqual(jail_index.route("/simple/foo/?x=1"), ("files", "foo"))
        self.assertEqual(jail_index.route("/files/foo/%s/foo-1.0%%2Blocal-py3-none-any.whl" % digest),
                         ("fetch", "foo", digest, "foo-1.0+local-py3-none-any.whl"))
        for path in ("/simple/foo", "/simple/-foo/", "/simple/%2e%2e/", "/files/Foo/%s/x" % digest,
                     "/files/foo/%s/../x" % digest, "/files/foo/%s/" % digest, "/files/foo/x/y"):
            self.assertIsNone(jail_index.route(path), path)


if __name__ == "__main__":
    unittest.main()
