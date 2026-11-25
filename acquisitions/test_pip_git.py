"""Offline end-to-end case of stock pip's Git requirements through the `git`
shim: the literal `python3 -m pip install 'git+https://github.com/OWNER/
REPO.git@TAG'` in a fresh venv, with pip's own clone flags and its default
TMPDIR, a sticky other-writable directory as /tmp is.

pip runs `git` from PATH; there a test entry (this file, `git-shim`) runs the
shim's dispatch (acquisitions/git/jail/dispatch.py) with one stand-in seam,
the request client: it writes the host's request file and runs the real host
worker as the host runs it, against the loopback HTTPS fixture server
(test_git_handler.py's `Tls`, `Server`, `request`; the request's `test`
seam), then gives the delivery to the real G3 `Application`. The artifact
POST, controller and broker are not exercised; their own suites cover them.
Real pip is the host's own (`--without-pip --system-site-packages` venv,
skipped without one), not the jail image's; the fixture package builds with
an in-tree backend and no requirements, so pip needs no index
(PIP_NO_INDEX). No real network, GitHub, index or credential.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""

import asyncio
import json
import os
import subprocess
import sys
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
for _path in (HERE, ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import handler_testing as testing  # noqa: E402
from handler_testing import SESSION, Scratch  # noqa: E402
import test_git_handler as fixture  # noqa: E402
from test_git_handler import PYTHON, Server, Tls, blob, commit  # noqa: E402

CONFIG_ENV = "AGENTBOX_TEST_PIP_GIT"
DEAD_PROXY = "http://127.0.0.1:9"
REPOSITORY = "fixture/project"
URL = "https://github.com/fixture/project.git"

BACKEND = b'''import base64, hashlib, os, zipfile

NAME, VERSION = "abxgit", "1.0"


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    info = "%s-%s.dist-info" % (NAME, VERSION)
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "abxgit.py"), "rb") as stream:
        module = stream.read()
    entries = [("abxgit.py", module),
               (info + "/METADATA", ("Metadata-Version: 2.1\\nName: %s\\nVersion: %s\\n" % (NAME, VERSION)).encode()),
               (info + "/WHEEL", b"Wheel-Version: 1.0\\nGenerator: fixture\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n")]
    record = []
    for path, data in entries:
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        record.append("%s,sha256=%s,%d" % (path, digest, len(data)))
    name = "%s-%s-py3-none-any.whl" % (NAME, VERSION)
    with zipfile.ZipFile(os.path.join(wheel_directory, name), "w") as wheel:
        for path, data in entries:
            wheel.writestr(path, data)
        wheel.writestr(info + "/RECORD", "\\n".join(record + [info + "/RECORD,,"]) + "\\n")
    return name
'''
PYPROJECT = b'[build-system]\nrequires = []\nbuild-backend = "backend"\nbackend-path = ["."]\n'


def project(scratch):
    """The package at main~1 (`v1`, annotated `v1a`) and changed at main; its marks' ids."""
    s = blob(1, PYPROJECT) + blob(2, BACKEND) + blob(3, b'STATE = "tagged"\n') + blob(4, b'STATE = "main"\n')
    s += commit("refs/heads/main", 5, "tagged",
                [("100644", ":1", "pyproject.toml"), ("100644", ":2", "backend.py"), ("100644", ":3", "abxgit.py")])
    s += commit("refs/heads/main", 6, "main", [("100644", ":4", "abxgit.py")], 5)
    s += b"reset refs/tags/v1\nfrom :5\n\n"
    s += b"tag v1a\nfrom :5\ntagger Fixture <f@example.invalid> 1700000300 +0000\ndata 4\nv1a\n\n"
    return fixture.repository(scratch, REPOSITORY, s)[1]


def host_pip():
    probe = subprocess.run([PYTHON, "-I", "-m", "pip", "--version"], capture_output=True)
    return probe.returncode == 0


@unittest.skipUnless(host_pip(), "no host pip")
class PipGitTest(unittest.TestCase):
    def setUp(self):
        self.scratch = Scratch()
        self.addCleanup(self.scratch.remove)
        self.tls = Tls(self.scratch)
        self.marks = project(self.scratch)
        self.server = Server(self.scratch, "backend", "github", self.tls)
        self.addCleanup(self.server.kill)
        at = self.scratch.at
        for name in ("bin", "uploads", "requests", "pip-home"):
            os.mkdir(at(name), 0o700)
        # pip's TMPDIR, as /tmp is: sticky and other-writable.
        os.mkdir(at("pip-tmp"))
        os.chmod(at("pip-tmp"), 0o1777)
        with open(at("bin", "git"), "w") as stream:
            stream.write('#!/bin/sh\nexec %s -I -B %s git-shim "$@"\n' % (PYTHON, os.path.abspath(__file__)))
        os.chmod(at("bin", "git"), 0o700)
        subprocess.run([PYTHON, "-I", "-m", "venv", "--without-pip", "--system-site-packages", at("venv")],
                       check=True)
        self.config = {"root": self.scratch.path, "uploads": at("uploads"), "requests": at("requests"),
                       "port": self.server.port, "ca": self.tls.ca,
                       "policy": dict(fixture.POLICY, repositories=[REPOSITORY])}

    def pip(self, spec, *flags):
        at = self.scratch.at
        env = {"PATH": ":".join((at("bin"), at("venv", "bin"), "/usr/bin", "/bin")), "HOME": at("pip-home"),
               "TMPDIR": at("pip-tmp"), "LC_ALL": "C.UTF-8", "PIP_CONFIG_FILE": os.devnull, "PIP_NO_CACHE_DIR": "1",
               "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INDEX": "1", "PYTHONNOUSERSITE": "1",
               CONFIG_ENV: json.dumps(self.config),
               **{name: DEAD_PROXY for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")}}
        done = subprocess.run(["python3", "-m", "pip", "install", *flags, spec], cwd=at("pip-home"), env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        return done.returncode, done.stdout.decode(errors="replace")

    def installed(self):
        """abxgit's STATE and its direct_url.json, or None."""
        python = self.scratch.at("venv", "bin", "python")
        done = subprocess.run([python, "-c", "import abxgit, importlib.metadata as m, json; print(json.dumps("
                                             "[abxgit.STATE, json.loads(m.distribution('abxgit')"
                                             ".read_text('direct_url.json'))]))"],
                              capture_output=True, cwd=self.scratch.at("pip-home"), timeout=60)
        return json.loads(done.stdout) if done.returncode == 0 else None

    def requests(self):
        with open(self.scratch.at("requests.log")) as stream:
            return [json.loads(line) for line in stream]

    def assert_clean(self):
        self.assertEqual(os.listdir(self.scratch.at("pip-tmp")), [])
        self.assertEqual(os.listdir(self.scratch.at("uploads")), [])

    def test_a_tag_one_commit_behind_installs_from_its_commit_with_provenance(self):
        tagged = self.marks[5]
        for tag, flags in (("v1", ()), ("v1a", ("-vv",))):
            code, out = self.pip("git+%s@%s" % (URL, tag), *flags)
            self.assertEqual(code, 0, out)
            self.assertIn('agentbox-request: git {"ok":true,"code":"git_applied"', out)
            self.assertEqual(self.installed(), ["tagged", {"url": URL, "vcs_info": {
                "commit_id": tagged, "requested_revision": tag, "vcs": "git"}}])
            self.assert_clean()
            uninstall = subprocess.run([self.scratch.at("venv", "bin", "python"), "-m", "pip", "uninstall", "-qy",
                                        "abxgit"], capture_output=True,
                                       env={"PIP_CONFIG_FILE": os.devnull, "PIP_NO_INDEX": "1"})
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
        # One acquisition each, of the repository alone: no selector, no flag.
        self.assertEqual(self.requests(), [{"repository": REPOSITORY, "worker": "ok"}] * 2)
        fixture.contained(self, self.server.stop())

    def test_a_missing_tag_or_a_denied_repository_installs_nothing(self):
        code, out = self.pip("git+%s@v9" % URL)
        self.assertNotEqual(code, 0, out)
        self.assertIsNone(self.installed())
        self.assert_clean()
        code, out = self.pip("git+https://github.com/fixture/other.git@v1")
        self.assertNotEqual(code, 0, out)
        self.assertIn('agentbox-request: git {"ok":false,"code":"git_request_denied"', out)
        self.assertIsNone(self.installed())
        self.assert_clean()
        # The tag is missing locally after one full delivery; the policy denies the other.
        self.assertEqual(self.requests(), [{"repository": REPOSITORY, "worker": "ok"},
                                           {"repository": "fixture/other", "worker": "git_repository_denied"}])
        fixture.contained(self, self.server.stop())


def shim(argv):
    """The `git` pip runs: the shim's dispatch, its request client standing
    in for the artifact POST lane (see the module docstring)."""
    from acquisitions.git.jail.application import Application, Layout, delivery, resolve_remote
    from acquisitions.git.jail.dispatch import DispatchSeams, run_git_command_with
    from acquisitions.git.jail.main import pass_through
    from guest.src.request_status import EXIT_OK, EXIT_RUNTIME

    config = json.loads(os.environ[CONFIG_ENV])

    async def client(operation, repository, local, context, report, deadline, abort, selector=None):
        number = len(os.listdir(config["requests"])) + 1
        stage = os.path.join(config["requests"], "request-%032x" % number)
        os.mkdir(stage, 0o700)
        path = fixture.request(stage, config["port"], SimpleNamespace(ca=config["ca"]), repository=repository,
                               selector=selector, policy=config["policy"])
        code, lines = fixture.acquire(path)
        value = json.loads(lines[0]) if code == 0 and len(lines) == 1 else {}
        logged = {"repository": repository, "worker": value.get("code", value.get("outcome"))}
        if selector is not None:
            logged["selector"] = selector
        with open(os.path.join(config["root"], "requests.log"), "a") as stream:
            stream.write(json.dumps(logged) + "\n")
        if value.get("outcome") != "ok":
            report({"ok": False, "code": "git_request_denied", "changes": "none", "cleanup": "observed"})
            return EXIT_RUNTIME
        request = "r-%d" % number
        os.rename(os.path.join(stage, testing.handler.ARTIFACT_FILE),
                  os.path.join(config["uploads"], "%s-%s.artifact" % (SESSION, request)))
        given = {"session": SESSION, "request": request, "request_sha256": "b" * 64, "operation": operation,
                 "repository": repository}
        if selector is not None:
            given["selector"] = selector
        given.update(delivery=delivery(value["metadata"]), size=value["size"], sha256=value["sha256"], local=local)
        outcome = await Application(given).run(deadline.local_until, abort, Layout(config["root"], config["uploads"]))
        report(outcome)
        return EXIT_OK if outcome["ok"] else EXIT_RUNTIME

    def report(line):
        sys.stderr.write(line + "\n")
        sys.stderr.flush()

    return asyncio.run(run_git_command_with(DispatchSeams(client, resolve_remote), argv, os.getcwd(), None, report,
                                            pass_through))


if __name__ == "__main__" and sys.argv[1:2] == ["git-shim"]:
    sys.exit(shim(sys.argv[2:]))
