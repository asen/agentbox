"""Offline suite of the trusted `git` handler worker (git/host/worker.py).

Real installed /usr/bin/git and openssl, synthetic bare repositories made by
git fast-import, a throwaway test CA and the owned loopback HTTPS fixture
server (git_fixture_server.py `serve`, one per case, its own session, ended
by stdin EOF and killed as a group if it overstays). The worker runs as the
host runs it: `python3 -I -B worker.py acquire STAGE/request.json`, its own
session, `/dev/null` stdin, a minimal environment; the request's `test`
endpoint is the only test seam (`localhost:<port>` with the test CA). No
real network, GitHub, credential or model.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""

import hashlib
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import handler_testing as testing  # noqa: E402
from handler_testing import SESSION, Scratch  # noqa: E402

sys.path.insert(0, os.path.join(HERE, "git", "host"))
import worker  # noqa: E402

handler = testing.handler
GIT = "/usr/bin/git"
OPENSSL = "/usr/bin/openssl"
PYTHON = sys.executable
SERVER = os.path.join(HERE, "git_fixture_server.py")
WORKER = testing.entry("git")
CONTRACT = os.path.join(ROOT, "acquisitions", "git", "contract", "v1")
POLICY = {"schema": worker.POLICY_SCHEMA, "grant": worker.GRANT}
with open(os.path.join(HERE, "git", "manifest.json")) as _stream:
    METADATA_BYTES = json.load(_stream)["limits"]["metadata_bytes"]
# The longest usable HEAD whose metadata escapes most: every short-name byte
# a double quote (the grammar's only JSON-escaped byte).
QUOTED = "refs/heads/" + '"' * (worker.MAX_REF_BYTES - len("refs/heads/"))
ARTIFACT = handler.ARTIFACT_FILE
LEFT = sorted([ARTIFACT, handler.REQUEST_FILE])


def contract(name):
    with open(os.path.join(CONTRACT, name)) as stream:
        return json.load(stream)


# Synthetic repositories: bare, filled by fast-import, never checked out.

def blob(mark, data):
    return b"blob\nmark :%d\ndata %d\n" % (mark, len(data)) + data + b"\n"


def commit(name, mark, message, files, parent=None):
    out = "commit %s\nmark :%d\ncommitter Fixture <f@example.invalid> %d +0000\ndata %d\n%s\n" % (
        name, mark, 1700000000 + mark, len(message), message)
    if parent is not None:
        out += "from :%d\n" % parent
    for mode, data, path in files:
        out += "M %s %s %s\n" % (mode, data, path)
    return out.encode()


def repository(scratch, name, stream):
    path = scratch.at("repos", name + ".git")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    scratch.run([GIT, "init", "--bare", "--template=", "--initial-branch=main", "-q", path])
    marks = scratch.at("logs", name.replace("/", "-") + ".marks")
    scratch.run([GIT, "-C", path, "fast-import", "--quiet", "--done", "--export-marks=" + marks],
                stream + b"done\n")
    with open(marks) as stream:
        found = dict(line.split(" ", 1) for line in stream.read().splitlines())
    return path, {int(mark[1:]): oid for mark, oid in found.items()}


def small(scratch, name):
    """Two branches, a lightweight and an annotated tag, HEAD at main."""
    s = blob(1, b"hello\n")
    s += commit("refs/heads/main", 2, "one", [("100644", ":1", "README")])
    s += blob(3, b"hello again\n")
    s += commit("refs/heads/main", 4, "two", [("100644", ":3", "README")], 2)
    s += commit("refs/heads/dev", 5, "dev", [("100644", ":1", "DEV")], 2)
    s += b"reset refs/tags/v1\nfrom :2\n\n"
    s += b"tag v2\nfrom :4\ntagger Fixture <f@example.invalid> 1700000300 +0000\ndata 3\nv2\n\n"
    return repository(scratch, name, s)


class Tls:
    """A throwaway CA, a rogue CA and leaves: `localhost` and
    `other.invalid` by the CA, `localhost` by the rogue one."""

    def __init__(self, scratch):
        self.dir = scratch.at("tls")
        os.mkdir(self.dir, 0o700)
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
        for ca in ("ca", "rogue"):
            scratch.run([OPENSSL, "req", "-x509"] + ec + [
                "-keyout", self.at(ca + ".key"), "-out", self.at(ca + ".pem"), "-days", "2",
                "-subj", "/CN=acq " + ca])
        for leaf, name, ca in (("github", "localhost", "ca"), ("other", "other.invalid", "ca"),
                               ("rogue-github", "localhost", "rogue")):
            with open(self.at(leaf + ".ext"), "w") as stream:
                stream.write("subjectAltName=DNS:%s\n" % name)
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

    def __init__(self, scratch, mode, leaf, tls):
        self.process = subprocess.Popen(
            [PYTHON, "-I", "-S", "-B", SERVER, "serve", mode, scratch.at("repos"),
             tls.at(leaf + ".pem"), tls.at(leaf + ".key"), GIT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, start_new_session=True)
        ready = self.process.stdout.readline().decode()
        assert ready.startswith("ready "), ready
        self.port, self.tripwire = (int(word) for word in ready.split()[1:3])

    def stop(self):
        self.process.stdin.close()
        try:
            out = self.process.stdout.read()
            self.process.wait(timeout=40)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait()
            raise
        self.process.stdout.close()
        lines = [line for line in out.decode().splitlines() if line.startswith("{")]
        assert self.process.returncode == 0
        return json.loads(lines[-1])

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


def contained(test, accounting):
    """No connection reached the tripwire; nothing asked for a bundle or a
    packfile URI or carried credentials or proxy headers."""
    test.assertEqual(accounting["tripwire"], 0, accounting)
    for request in accounting["requests"]:
        if request.get("refused") is not None:
            continue
        test.assertFalse(request["authorization"], request)
        test.assertEqual(request["proxy_headers"], [], request)
        test.assertFalse(request["packfile_uris"], request)
        test.assertFalse(request["bundle_uri"], request)


def request(stage, port=None, tls=None, repository="octocat/hello-world", selector=None,
            remaining_ms=60000, git=GIT, policy=None, operation="clone", args=None):
    """STAGE/request.json of one acquisition, as the host writes it."""
    if args is None:
        args = {"repository": repository}
        if selector is not None:
            args["selector"] = selector
    test = None
    if port is not None:
        test = {"endpoint": "localhost:%d" % port, "ca_file": tls.ca}
    value = testing.request_value(stage, "git", operation, args, policy or POLICY,
                                  tools={"git": git} if git else {}, test=test, remaining_ms=remaining_ms,
                                  metadata_bytes=METADATA_BYTES)
    return testing.write_request(stage, value)


def acquire(path, env=None, timeout=120):
    """The worker as the host runs it; (exit code, stdout lines)."""
    code, lines, _ = testing.run(WORKER, path, env, timeout)
    return code, lines


def result(test, lines):
    return testing.result(test, lines)


def list_heads(path):
    """A delivered bundle's refs, by the real Git: [(oid, name)]."""
    done = subprocess.run([GIT, "bundle", "list-heads", path], stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, env={"PATH": "/usr/bin:/bin"})
    return [tuple(line.split(" ", 1)) for line in done.stdout.decode().splitlines()]


def refs_of(scratch, path):
    out = scratch.run([GIT, "--git-dir=" + path, "for-each-ref",
                       "--format=%(objectname) %(refname)", "refs/heads/", "refs/tags/"])
    return [tuple(line.split(" ", 1)) for line in out.decode().splitlines()]


def unbundle(scratch, bundle, target):
    """The guest's import, by the real Git: a fresh bare repository fetching
    every branch and tag of the bundle, nothing else."""
    scratch.run([GIT, "init", "--bare", "--template=", "-q", target])
    scratch.run([GIT, "--git-dir=" + target, "fetch", "--quiet", "--no-tags",
                 "--no-write-fetch-head", "--refmap=", "--", bundle,
                 "+refs/heads/*:refs/heads/*", "+refs/tags/*:refs/tags/*"])
    scratch.run([GIT, "--git-dir=" + target, "fsck", "--full", "--strict", "--no-dangling"])


class Case(unittest.TestCase):
    def setUp(self):
        self.scratch = Scratch()
        self.servers = []

    def tearDown(self):
        for server in self.servers:
            server.kill()
        self.scratch.remove()

    def server(self, mode="backend", leaf="github", tls=None):
        tls = tls or self.tls
        server = Server(self.scratch, mode, leaf, tls)
        self.servers.append(server)
        return server


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.scratch = Scratch()

    def tearDown(self):
        self.scratch.remove()

    def outcome(self, **kwargs):
        stage = self.scratch.stage()
        code, lines = acquire(request(stage, **kwargs))
        self.assertEqual(code, 0, lines)
        return result(self, lines).get("code"), stage

    def test_arguments_and_policy_are_the_workers_to_check(self):
        cases = [
            ({"args": {}}, "git_args_invalid"),
            ({"args": {"repository": "Octocat/hello-world"}}, "git_args_invalid"),
            ({"args": {"repository": "octocat/hello-world", "extra": 1}}, "git_args_invalid"),
            ({"args": {"repository": "octocat/hello-world", "selector": "HEAD"}},
             "git_args_invalid"),
            ({"args": {"repository": "octocat/hello-world", "selector": "a..b"}},
             "git_args_invalid"),
            ({"args": {"repository": ["octocat/hello-world"]}}, "git_args_invalid"),
            ({"policy": {"schema": worker.POLICY_SCHEMA}}, "git_policy_invalid"),
            ({"policy": dict(POLICY, grant="github-write")}, "git_policy_invalid"),
            ({"policy": dict(POLICY, repositories=[])}, "git_policy_invalid"),
            ({"policy": dict(POLICY, repositories=["b/b", "a/a"])}, "git_policy_invalid"),
            ({"policy": dict(POLICY, extra=1)}, "git_policy_invalid"),
            ({"policy": dict(POLICY, repositories=["octocat/other"])}, "git_repository_denied"),
            ({"git": None}, "git_tool_failed"),
            ({"operation": "push"}, "operation_unsupported"),
        ]
        for kwargs, code in cases:
            with self.subTest(kwargs=kwargs):
                found, stage = self.outcome(**kwargs)
                self.assertEqual(found, code)
                self.assertEqual(os.listdir(stage), [handler.REQUEST_FILE])

    def test_a_malformed_request_exits_without_a_result(self):
        base = testing.request_value("/x", "git", "clone", {"repository": "o/r"}, POLICY)
        for edit in ({"schema": "agentbox.handler-request.v0"}, {"extra": 1},
                     {"remaining_ms": -1}, {"remaining_ms": 1.5}, {"args": []},
                     {"ids": {"session": SESSION}}, {"tools": {"git": "git"}},
                     {"limits": {}}, {"artifact": "/elsewhere"}):
            stage = self.scratch.stage()
            value = dict(base, stage=stage, artifact=stage + "/" + ARTIFACT)
            value.update(edit)
            with self.subTest(edit=edit):
                code, lines = acquire(testing.write_request(stage, value))
                self.assertEqual((code, lines), (2, []))
        stage = self.scratch.stage()
        path = testing.write_request(stage, raw=b'{"schema":1,"schema":2}')
        self.assertEqual(acquire(path), (2, []))
        # A request file elsewhere, by another name or shared is not the host's.
        stage = self.scratch.stage()
        path = request(stage)
        os.chmod(path, 0o644)
        self.assertEqual(acquire(path), (2, []))
        self.assertEqual(acquire(stage + "/other.json"), (2, []))


class GrammarTests(unittest.TestCase):
    def test_repository_grammar_follows_the_shared_fixtures(self):
        fixtures = contract("repository-fixtures.json")
        for key, check in (("repositories", worker.is_repository),
                           ("selectors", worker.is_selector), ("refs", worker.is_ref),
                           ("oids", worker.is_oid)):
            for item in fixtures[key]["valid"]:
                self.assertTrue(check(item), (key, item))
            for item in fixtures[key]["invalid"]:
                self.assertFalse(check(item), (key, item))

    def test_the_version_profile_is_bounded_and_minimal(self):
        ok = b"git version 2.53.0\ncpu: x86_64\nlibcurl: 8.18.0\nzlib: 1.3\n"
        self.assertEqual(worker.check_profile(ok), ((2, 53, 0), (8, 18, 0)))
        for output, code in (
                (b"git version 2.52.9\nlibcurl: 8.18.0\n", "git_profile_unsupported"),
                (b"git version 2.53.0\nlibcurl: 8.3.0\n", "git_profile_unsupported"),
                (b"git version 2.53.0\n", "git_profile_unsupported"),
                (b"git version 2.53.0\nlibcurl: 8.18.0\nlibcurl: 8.18.0\n", "git_profile_malformed"),
                (b"git version 2.53.01\nlibcurl: 8.18.0\n", "git_profile_malformed"),
                (b"version 2.53.0\nlibcurl: 8.18.0\n", "git_profile_malformed"),
                (b"git version 2.53.0\n" + b"x\n" * 40, "git_profile_malformed"),
                (b"git version 2.53.0\nlibcurl: 8.18.0\n\xff", "git_profile_malformed"),
                (b"", "git_profile_malformed")):
            with self.assertRaises(worker.Refused, msg=output) as refused:
                worker.check_profile(output)
            self.assertEqual(refused.exception.code, code, output)

    def test_only_a_branch_of_the_grammar_is_a_usable_head(self):
        self.assertEqual(worker.symbolic_head(b"refs/heads/main\n"), "refs/heads/main")
        for output in (b"refs/heads/a..b\n", b"refs/tags/v1\n", b"refs/heads/main",
                       b"refs/heads/main\n\n", b"refs/heads/\xff\n", b"", b"HEAD\n"):
            self.assertIsNone(worker.symbolic_head(output), output)


class CallTests(Case):
    """One `run` call's own bounds, on a plain shell child of this process."""

    def call(self, sleep, timeout, remaining_ms=60000):
        pid_file = self.scratch.at("pid-%s-%s" % (sleep, timeout))
        # Writes its pid, closes both pipes (EOF at once), then outlives them.
        script = 'echo $$ > "$1"; exec >&- 2>&-; exec sleep "$2"'
        argv = ("/bin/sh", "-c", script, "sh", pid_file, str(sleep))
        started = time.monotonic()
        try:
            outcome = worker.run(argv, [("PATH", "/usr/bin:/bin")], "/",
                                 worker.Clock(remaining_ms), cap=worker.MAX_PROFILE_BYTES,
                                 merge=False, timeout=timeout)
        except worker.Refused as refused:
            outcome = refused.code
        elapsed = time.monotonic() - started
        with open(pid_file) as stream:
            pid = int(stream.read())
        # Ended either way and reaped by `run` itself: no process, no zombie.
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)
        return outcome, elapsed

    def test_the_profile_cutoff_bounds_the_exit_past_pipe_eof(self):
        outcome, elapsed = self.call(sleep=30, timeout=0.2)
        self.assertEqual(outcome, "git_profile_malformed")
        self.assertLess(elapsed, 5)

    def test_an_exit_within_the_cutoff_completes(self):
        outcome, _ = self.call(sleep=0.2, timeout=10)
        self.assertEqual(outcome, (0, b""))

    def test_without_a_cutoff_the_acquisition_deadline_bounds_it(self):
        outcome, elapsed = self.call(sleep=30, timeout=None, remaining_ms=300)
        self.assertEqual(outcome, "git_acquisition_expired")
        self.assertLess(elapsed, 5)


class ContractTests(unittest.TestCase):
    def test_constants_match_the_contract(self):
        spec = contract("contract.json")
        delivery = spec["delivery"]
        self.assertEqual(delivery["formats"], [worker.FORMAT_BUNDLE, worker.FORMAT_EMPTY])
        self.assertEqual(delivery["empty_marker"].encode(), worker.EMPTY)
        self.assertEqual(delivery["bundle_command"], list(worker.BUNDLE))
        self.assertEqual(delivery["bundle_config"], list(worker.BUNDLE_CONFIG))
        self.assertEqual(delivery["error_codes"], ["git_bundle_failed"])
        for removed in ("manifest", "archive", "upload", "host_upload"):
            self.assertNotIn(removed, spec)
        bounds = spec["bounds"]
        self.assertEqual(bounds["max_tool_diagnostic_bytes"],
                         {"value": worker.MAX_DIAGNOSTIC_BYTES, "enforcement": "host_worker"})
        self.assertEqual(bounds["max_tool_profile_bytes"],
                         {"value": worker.MAX_PROFILE_BYTES, "enforcement": "host_worker"})
        self.assertEqual(spec["repository"]["object_format"], "sha1")
        self.assertTrue(worker.is_ref(QUOTED))
        worst = handler.canonical({"format": worker.FORMAT_BUNDLE, "head": QUOTED})
        self.assertEqual(len(worst), 530)
        self.assertLessEqual(len(worst), METADATA_BYTES)


class AcquisitionTests(Case):
    def setUp(self):
        super().setUp()
        self.tls = Tls(self.scratch)

    def artifact(self, stage):
        return os.path.join(stage, ARTIFACT)

    def fetch(self, repository="octocat/hello-world", selector=None):
        """One acquisition from a fresh fixture server; (result, stage, accounting)."""
        server = self.server()
        stage = self.scratch.stage()
        code, lines = acquire(request(stage, server.port, self.tls, repository=repository,
                                      selector=selector))
        accounting = server.stop()
        self.assertEqual(code, 0, lines)
        self.port = server.port
        return result(self, lines), stage, accounting

    def test_a_clone_is_bundled_once_with_every_branch_and_tag(self):
        source, marks = small(self.scratch, "octocat/hello-world")
        value, stage, accounting = self.fetch()
        self.assertEqual(value["outcome"], "ok", value)
        # Only the artifact is left beside the request, private, of the
        # stated size and digest: a stock self-contained v2 bundle.
        self.assertEqual(sorted(os.listdir(stage)), LEFT)
        path = self.artifact(stage)
        self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o600)
        with open(path, "rb") as stream:
            data = stream.read()
        self.assertEqual((value["size"], value["sha256"]),
                         (len(data), hashlib.sha256(data).hexdigest()))
        self.assertTrue(data.startswith(b"# v2 git bundle\n"))
        self.assertEqual(value["metadata"], {"format": "bundle", "head": "refs/heads/main"})
        self.assertEqual(list_heads(path), refs_of(self.scratch, source))
        for name, mark in (("refs/heads/main", 4), ("refs/heads/dev", 5), ("refs/tags/v1", 2)):
            self.assertIn((marks[mark], name), list_heads(path))
        # No prerequisite: it imports into an empty repository, complete.
        copy = self.scratch.at("copy.git")
        unbundle(self.scratch, path, copy)
        self.assertEqual(refs_of(self.scratch, copy), refs_of(self.scratch, source))
        # The fixture saw the loopback name, protocol v2, ls-refs then fetch.
        contained(self, accounting)
        seen = [(r["method"], r["path"], r["commands"]) for r in accounting["requests"]]
        path = "/octocat/hello-world.git"
        self.assertEqual(seen, [("GET", path + "/info/refs", []),
                                ("POST", path + "/git-upload-pack", ["command=ls-refs"]),
                                ("POST", path + "/git-upload-pack", ["command=fetch"])])
        for r in accounting["requests"]:
            self.assertEqual(r["host"], "localhost:%d" % self.port)
            self.assertEqual(r["git_protocol"], "version=2")

    def test_selectors_empty_and_unusable_heads(self):
        small(self.scratch, "octocat/hello-world")
        repository(self.scratch, "octocat/empty", b"")
        path, _ = small(self.scratch, "octocat/moved")
        with open(os.path.join(path, "HEAD"), "w") as stream:
            stream.write("ref: refs/heads/gone\n")
        server = self.server()
        outcomes = {}
        for name, repo, selector in (("tag", "hello-world", "v2"), ("branch", "hello-world", "dev"),
                                     ("missing", "hello-world", "nope"), ("empty", "empty", None),
                                     ("empty-selector", "empty", "main"), ("moved", "moved", None)):
            stage = self.scratch.stage()
            code, lines = acquire(request(stage, server.port, self.tls,
                                          repository="octocat/" + repo, selector=selector))
            outcomes[name] = (result(self, lines), stage)
        server.stop()
        self.assertEqual(outcomes["tag"][0]["metadata"], {"format": "bundle", "head": "refs/heads/main"})
        self.assertEqual(outcomes["branch"][0]["outcome"], "ok")
        for name in ("missing", "empty-selector"):
            self.assertEqual(outcomes[name][0], {"schema": handler.RESULT_SCHEMA,
                                                 "outcome": "error",
                                                 "code": "git_selector_not_acquired"}, name)
            self.assertNotIn(ARTIFACT, os.listdir(outcomes[name][1]), name)
        # Git bundles nothing of no refs: the fixed marker, nothing else.
        value, stage = outcomes["empty"]
        self.assertEqual(value["metadata"], {"format": "empty"})
        with open(self.artifact(stage), "rb") as stream:
            self.assertEqual(stream.read(), worker.EMPTY)
        self.assertEqual((value["size"], value["sha256"]),
                         (len(worker.EMPTY), hashlib.sha256(worker.EMPTY).hexdigest()))
        self.assertEqual(outcomes["moved"][0]["metadata"], {"format": "bundle"})

    def test_tags_of_trees_blobs_and_tags_and_names_shared_are_bundled(self):
        s = blob(1, b"hello\n")
        s += commit("refs/heads/main", 2, "one", [("100644", ":1", "README")])
        source, marks = repository(self.scratch, "octocat/tags", s)
        tree = self.scratch.run([GIT, "--git-dir=" + source, "rev-parse", "main^{tree}"]).decode().strip()
        tag = [GIT, "-c", "user.name=F", "-c", "user.email=f@example.invalid", "--git-dir=" + source,
               "tag"]
        self.scratch.run(tag + ["lblob", marks[1]])
        self.scratch.run(tag + ["ltree", tree])
        self.scratch.run(tag + ["-a", "-m", "t", "atree", tree])
        self.scratch.run(tag + ["-a", "-m", "b", "ablob", marks[1]])
        self.scratch.run(tag + ["-a", "-m", "n", "nested", "atree"])
        # Full names: a branch and a tag of one name, nested and HEAD-named refs.
        for ref in ("refs/heads/atree", "refs/heads/topic/deep/x", "refs/heads/HEAD"):
            self.scratch.run([GIT, "--git-dir=" + source, "update-ref", ref, marks[2]])
        value, stage, _ = self.fetch("octocat/tags", selector="ablob")
        self.assertEqual(value["outcome"], "ok", value)
        self.assertEqual(list_heads(self.artifact(stage)), refs_of(self.scratch, source))
        copy = self.scratch.at("copy.git")
        unbundle(self.scratch, self.artifact(stage), copy)
        self.assertEqual(refs_of(self.scratch, copy), refs_of(self.scratch, source))

    def test_refs_ambiguous_with_others_are_all_bundled(self):
        # A full name that is another ref's short form: Git's default
        # ambiguity check would omit refs/heads/x and refs/tags/v1 here.
        s = blob(1, b"hello\n")
        s += commit("refs/heads/main", 2, "one", [("100644", ":1", "README")])
        s += commit("refs/heads/refs/heads/x", 3, "other", [("100644", ":1", "OTHER")], 2)
        s += b"reset refs/heads/x\nfrom :2\n\nreset refs/tags/v1\nfrom :2\n\n"
        s += b"reset refs/heads/refs/tags/v1\nfrom :3\n\nreset refs/tags/refs/heads/main\nfrom :3\n\n"
        s += b"reset refs/heads/heads/x\nfrom :3\n\nreset refs/tags/heads/x\nfrom :3\n\n"
        source, _ = repository(self.scratch, "octocat/ambiguous", s)
        value, stage, _ = self.fetch("octocat/ambiguous")
        self.assertEqual(value["outcome"], "ok", value)
        self.assertEqual(list_heads(self.artifact(stage)), refs_of(self.scratch, source))
        self.assertEqual(len(list_heads(self.artifact(stage))), 8)
        copy = self.scratch.at("copy.git")
        unbundle(self.scratch, self.artifact(stage), copy)
        self.assertEqual(refs_of(self.scratch, copy), refs_of(self.scratch, source))

    def test_a_head_of_every_escaped_byte_fits_the_metadata(self):
        s = blob(1, b"hello\n")
        s += commit(QUOTED, 2, "one", [("100644", ":1", "README")])
        source, _ = repository(self.scratch, "octocat/quoted", s)
        self.scratch.run([GIT, "--git-dir=" + source, "symbolic-ref", "HEAD", QUOTED])
        value, stage, _ = self.fetch("octocat/quoted")
        self.assertEqual(value["outcome"], "ok", value)
        self.assertEqual(value["metadata"], {"format": "bundle", "head": QUOTED})
        self.assertEqual(len(handler.canonical(value["metadata"])), 530)
        self.assertEqual(list_heads(self.artifact(stage)), refs_of(self.scratch, source))

    def test_links_stay_objects_and_their_targets_are_never_read(self):
        # Tracked links out of any checkout and to nothing: blobs on the host.
        secret = self.scratch.at("secret")
        with open(secret, "w") as stream:
            stream.write("host secret\n")
        s = blob(1, secret.encode()) + blob(2, b"../../../../nowhere") + blob(3, b"hello\n")
        s += commit("refs/heads/main", 4, "links", [("120000", ":1", "out"),
                                                     ("120000", ":2", "dangling"),
                                                     ("100644", ":3", "README")])
        source, marks = repository(self.scratch, "octocat/links", s)
        value, stage, _ = self.fetch("octocat/links")
        self.assertEqual(value["outcome"], "ok", value)
        self.assertEqual(sorted(os.listdir(stage)), LEFT)
        with open(self.artifact(stage), "rb") as stream:
            self.assertNotIn(b"host secret", stream.read())
        copy = self.scratch.at("copy.git")
        unbundle(self.scratch, self.artifact(stage), copy)
        tree = self.scratch.run([GIT, "--git-dir=" + copy, "ls-tree", "main"]).decode()
        self.assertIn("120000 blob %s\tout" % marks[1], tree)
        self.assertIn("120000 blob %s\tdangling" % marks[2], tree)

    def test_large_repositories_are_not_refused(self):
        # Above the removed G0 ceilings (4096 refs, a 32 MiB object).
        s = blob(1, b"\0" * ((32 << 20) + 1))
        s += commit("refs/heads/main", 2, "big", [("100644", ":1", "ZERO")])
        for n in range(5001):
            s += b"reset refs/heads/b%05d\nfrom :2\n\n" % n
        repository(self.scratch, "octocat/large", s)
        value, stage, _ = self.fetch("octocat/large")
        self.assertEqual(value["outcome"], "ok")
        self.assertEqual(len(list_heads(self.artifact(stage))), 5002)

    def test_redirects_auth_and_bad_certificates_fail_without_fallback(self):
        small(self.scratch, "octocat/hello-world")
        for mode, leaf in (("redirect", "github"), ("auth", "github"), ("backend", "other"),
                           ("backend", "rogue-github")):
            server = self.server(mode, leaf)
            stage = self.scratch.stage()
            code, lines = acquire(request(stage, server.port, self.tls))
            accounting = server.stop()
            self.assertEqual(result(self, lines)["code"], "git_clone_failed", (mode, leaf))
            self.assertNotIn(ARTIFACT, os.listdir(stage))
            contained(self, accounting)
            self.assertEqual(accounting["accepted"], 1, (mode, leaf, accounting))

    def test_hostile_sources_do_not_expand_where_git_connects(self):
        server = self.server()
        trip = "https://127.0.0.1:%d" % server.tripwire
        bundle, _ = small(self.scratch, "octocat/bundle")
        packfile, marks = small(self.scratch, "octocat/packfile")
        promisor, _ = small(self.scratch, "octocat/promisor")
        modules = '[submodule "sub"]\n\tpath = sub\n\turl = %s/sub.git\n' % trip
        s = blob(1, modules.encode())
        s += commit("refs/heads/main", 2, "submodule",
                    [("100644", ":1", ".gitmodules"), ("160000", "1" * 40, "sub")])
        repository(self.scratch, "octocat/submodule", s)
        shallow, shallow_marks = small(self.scratch, "octocat/shallow")
        config = lambda repo, pairs: [self.scratch.run([GIT, "-C", repo, "config", k, v])
                                      for k, v in pairs]
        config(bundle, [("uploadpack.advertiseBundleURIs", "true"), ("bundle.version", "1"),
                        ("bundle.mode", "all"), ("bundle.evil.uri", trip + "/evil.bundle")])
        config(packfile, [("uploadpack.blobPackfileUri",
                           "%s %s %s/evil.pack" % (marks[1], "2" * 40, trip))])
        config(promisor, [("promisor.advertise", "true"), ("remote.evil.url", trip + "/evil.git"),
                          ("remote.evil.promisor", "true")])
        with open(os.path.join(shallow, "shallow"), "w") as stream:
            stream.write(shallow_marks[4] + "\n")
        outcomes = {}
        for name in ("bundle", "packfile", "promisor", "submodule", "shallow"):
            stage = self.scratch.stage()
            code, lines = acquire(request(stage, server.port, self.tls,
                                          repository="octocat/" + name))
            outcomes[name] = result(self, lines)
        accounting = server.stop()
        contained(self, accounting)
        self.assertEqual(outcomes.pop("shallow")["code"], "git_clone_failed")
        for name, value in outcomes.items():
            self.assertEqual(value["outcome"], "ok", name)
        offered = set()
        for r in accounting["requests"]:
            for command in r["commands"]:
                self.assertIn(command, ("command=ls-refs", "command=fetch"))
            for feature in r.get("offered") or []:
                offered.add((r["path"].split("/")[2], feature))
        for expected in (("bundle.git", "bundle-uri"), ("packfile.git", "packfile-uris"),
                         ("promisor.git", "promisor-remote"), ("shallow.git", "shallow-info")):
            self.assertIn(expected, offered)

    def test_dumb_http_alternates_are_refused(self):
        dumb = self.scratch.at("repos", "octocat", "dumb.git")
        for sub in ("info", "objects/info", "objects/pack"):
            os.makedirs(os.path.join(dumb, sub))
        server = self.server("dumb")
        oid = "1" * 40
        files = {"HEAD": "ref: refs/heads/main\n", "info/refs": "%s\trefs/heads/main\n" % oid,
                 "objects/info/packs": "",
                 "objects/info/http-alternates": "https://127.0.0.1:%d/objects\n" % server.tripwire}
        for name, text in files.items():
            with open(os.path.join(dumb, name), "w") as stream:
                stream.write(text)
        stage = self.scratch.stage()
        code, lines = acquire(request(stage, server.port, self.tls, repository="octocat/dumb"))
        accounting = server.stop()
        self.assertEqual(result(self, lines)["code"], "git_clone_failed")
        contained(self, accounting)
        paths = [r["path"] for r in accounting["requests"]]
        self.assertIn("/octocat/dumb.git/objects/info/http-alternates", paths)

    def test_host_configuration_and_environment_are_isolated(self):
        small(self.scratch, "octocat/hello-world")
        server = self.server()
        trip = "https://127.0.0.1:%d/" % server.tripwire
        fixture = "https://localhost:%d/" % server.port
        marker = self.scratch.at("credential-helper-ran")
        hostile = ('[url "%s"]\n\tinsteadOf = %s\n[http]\n\tproxy = %s\n\tsslVerify = false\n'
                   '[credential]\n\thelper = !touch %s\n[protocol "file"]\n\tallow = always\n'
                   % (trip, fixture, trip, marker))
        home = self.scratch.at("evil-home")
        os.makedirs(os.path.join(home, ".config", "git"))
        for path in (os.path.join(home, ".gitconfig"), os.path.join(home, ".config/git/config")):
            with open(path, "w") as stream:
                stream.write(hostile)
        with open(os.path.join(home, ".netrc"), "w") as stream:
            stream.write("machine localhost login evil password evil\n")
        # A repository right above the request directory: never discovered.
        above = self.scratch.at("stages", ".git")
        for sub in ("objects", "refs"):
            os.makedirs(os.path.join(above, sub))
        with open(os.path.join(above, "HEAD"), "w") as stream:
            stream.write("ref: refs/heads/main\n")
        with open(os.path.join(above, "config"), "w") as stream:
            stream.write("[core]\n\trepositoryformatversion = 0\n" + hostile)
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": home, "XDG_CONFIG_HOME":
               os.path.join(home, ".config"), "https_proxy": trip, "HTTPS_PROXY": trip,
               "ALL_PROXY": trip, "GIT_SSL_NO_VERIFY": "1", "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "url.%s.insteadOf" % trip, "GIT_CONFIG_VALUE_0": fixture,
               "GIT_CONFIG_PARAMETERS": "'http.proxy'='%s'" % trip, "GIT_DIR": above,
               "GIT_CONFIG_GLOBAL": os.path.join(home, ".gitconfig"), "PYTHONPATH": home}
        stage = self.scratch.stage()
        code, lines = acquire(request(stage, server.port, self.tls), env=env)
        accounting = server.stop()
        self.assertEqual(result(self, lines)["outcome"], "ok")
        contained(self, accounting)
        self.assertEqual(len(accounting["requests"]), 3)
        self.assertFalse(os.path.exists(marker))

    def test_forbidden_transports_are_refused_by_the_fixed_configuration(self):
        repo, _ = small(self.scratch, "octocat/hello-world")
        server = self.server()
        marker = self.scratch.at("ext-ran")
        trip = server.tripwire
        for url in ("file://" + repo, repo, "ext::sh -c touch% " + marker,
                    "ssh://127.0.0.1:%d/o/r.git" % trip, "git://127.0.0.1:%d/o/r.git" % trip,
                    "http://127.0.0.1:%d/o/r.git" % trip):
            stage = self.scratch.stage()
            for sub in (worker.CWD, worker.HOME, worker.TMP):
                os.mkdir(os.path.join(stage, sub), 0o700)
            argv = [GIT]
            for item in worker.CONFIG:
                argv += ["-c", item]
            argv += list(worker.CLONE_OPTIONS) + ["--", url, os.path.join(stage, worker.REPOSITORY)]
            env = dict(worker.git_env("/usr/bin:/bin", os.path.join(stage, worker.HOME),
                                      os.path.join(stage, worker.TMP), stage))
            done = subprocess.run(argv, env=env, cwd=os.path.join(stage, worker.CWD),
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            self.assertNotEqual(done.returncode, 0, url)
            self.assertIn(b"not allowed", done.stderr, url)
        accounting = server.stop()
        self.assertEqual((accounting["tripwire"], accounting["accepted"]), (0, 0))
        self.assertFalse(os.path.exists(marker))

    def test_the_stage_must_be_the_hosts_fresh_private_directory(self):
        crowded = self.scratch.stage()
        crowded_request = request(crowded, 1, self.tls)
        with open(os.path.join(crowded, "x"), "w"):
            pass
        shared = self.scratch.stage()
        shared_request = request(shared, 1, self.tls)
        os.chmod(shared, 0o750)
        target = self.scratch.stage()
        link = self.scratch.at("stages", "link")
        os.symlink(target, link)
        # Written through the link, as if the host had: the stage is a link.
        value = testing.request_value(link, "git", "clone", {"repository": "octocat/x"},
                                      POLICY, tools={"git": GIT},
                                      test={"endpoint": "localhost:1", "ca_file": self.tls.ca})
        link_request = testing.write_request(link, value)
        for path in (crowded_request, shared_request, link_request):
            code, lines = acquire(path)
            self.assertEqual(result(self, lines)["code"], "git_staging_unsafe", path)
        self.assertEqual(sorted(os.listdir(crowded)), [handler.REQUEST_FILE, "x"])
        self.assertEqual(os.listdir(target), [handler.REQUEST_FILE])


# A stand-in `git`: the version profile and every local call are the real
# Git's; `clone` copies the fixture's bare repository into place and then
# applies MODE to it, or misbehaves as MODE says.
STAND_IN = r'''#!/usr/bin/python3 -IS
import os, shutil, subprocess, sys, time
here = os.path.dirname(os.path.abspath(__file__))
mode = open(os.path.join(here, "MODE")).read().strip()
args = sys.argv[1:]
while args and args[0] == "-c":
    args = args[2:]
if args[:1] != ["clone"]:
    argv = sys.argv[1:]
    if mode == "omit" and "bundle" in argv and "create" in argv:
        at = argv.index("core.warnAmbiguousRefs=false")
        del argv[at - 1:at + 1]
    os.execv("/usr/bin/git", ["git"] + argv)
target = args[-1]
if mode == "hang":
    pid = os.fork()
    if pid == 0:
        open(os.path.join(here, "child.pid"), "w").write(str(os.getpid()))
        time.sleep(600)
        os._exit(0)
    time.sleep(600)
subprocess.run(["/usr/bin/git", "clone", "--bare", "--no-local", "--template=", "--quiet",
                os.path.join(here, "source.git"), target], check=True,
               env={"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": here})
pack = os.path.join(target, "objects", "pack")
name = [n for n in os.listdir(pack) if n.endswith(".pack")][0]
if mode == "corrupt":
    data = bytearray(open(os.path.join(pack, name), "rb").read())
    data[len(data) // 2] ^= 0xff
    os.chmod(os.path.join(pack, name), 0o644)
    open(os.path.join(pack, name), "wb").write(data)
elif mode == "missing":
    # A branch whose commit the clone does not hold.
    open(os.path.join(target, "packed-refs"), "a").write("%s refs/heads/zz\n" % ("1" * 40))
elif mode == "omit":
    # A ref that a bundle without the worker's setting omits.
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": here}
    subprocess.run(["/usr/bin/git", "--git-dir=" + target, "update-ref", "refs/heads/refs/heads/main",
                    "refs/heads/main"], check=True, env=env)
elif mode == "fail":
    sys.exit(128)
elif mode == "noisy":
    sys.stderr.write("x" * 70000)
'''


class StandInTests(Case):
    """The worker's own process discipline and a broken clone, offline: a
    stand-in `git` whose clone copies a local fixture."""

    def setUp(self):
        super().setUp()
        self.tools = self.scratch.at("tools")
        os.mkdir(self.tools, 0o700)
        source, _ = small(self.scratch, "octocat/hello-world")
        shutil.copytree(source, os.path.join(self.tools, "source.git"))
        self.git = os.path.join(self.tools, "git")
        with open(self.git, "w") as stream:
            stream.write(STAND_IN)
        os.chmod(self.git, 0o700)

    def run_mode(self, mode, remaining_ms=60000):
        with open(os.path.join(self.tools, "MODE"), "w") as stream:
            stream.write(mode)
        stage = self.scratch.stage()
        code, lines = acquire(request(stage, git=self.git, remaining_ms=remaining_ms))
        return result(self, lines), stage

    def test_a_clean_local_clone_is_accepted(self):
        value, stage = self.run_mode("plain")
        self.assertEqual(value["outcome"], "ok")
        self.assertEqual(sorted(os.listdir(stage)), LEFT)

    def test_broken_clones_and_tools_refuse_without_a_delivery(self):
        for mode, code in (("corrupt", "git_bundle_failed"),
                           ("omit", "git_bundle_failed"),
                           ("missing", "git_repository_inconsistent"),
                           ("fail", "git_clone_failed"),
                           ("noisy", "git_diagnostic_limit")):
            value, stage = self.run_mode(mode)
            self.assertEqual(value.get("code"), code, (mode, value))
            self.assertNotEqual(value["outcome"], "ok", mode)

    def test_its_own_deadline_kills_and_reaps_what_it_started(self):
        started = time.monotonic()
        value, _ = self.run_mode("hang", remaining_ms=1500)
        self.assertEqual(value["code"], "git_acquisition_expired")
        self.assertLess(time.monotonic() - started, 30)
        # The stand-in's own child outlived its parent's kill: it is still in
        # the worker's group, which the host (here, `acquire`) kills; it does
        # not escape the group.
        with open(os.path.join(self.tools, "child.pid")) as stream:
            pid = int(stream.read())
        until = time.monotonic() + 10
        while time.monotonic() < until:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("the stand-in's descendant survived its group's kill")

    def test_no_bytecode_is_written(self):
        tree = testing.installed_tree(self.scratch, ["git"])
        stage = self.scratch.stage()
        subprocess.run([PYTHON, "-I", "-B", os.path.join(tree, "git", "host", "worker.py"),
                        "acquire", request(stage, git=self.git)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"}, timeout=120)
        found = sorted(os.path.relpath(os.path.join(d, n), tree)
                       for d, _, names in os.walk(tree) for n in names)
        self.assertEqual(found, ["git/host/worker.py", "git/manifest.json", "git/policy.json",
                                 "lib/agentbox_handler.py", "lib/agentbox_packages.py"])


if __name__ == "__main__":
    unittest.main()
