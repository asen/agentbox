"""Test support of the handler suites (never packaged): a private scratch
tree, request files as the host writes them, and a worker run as the host
runs it (`INTERPRETER -I -B ENTRY acquire STAGE/request.json`, its own
session, `/dev/null` stdin, a minimal environment)."""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "lib")
# Each handler's directory, named by its id: the shipped ones beside lib,
# the test-only ones under testing/.
HANDLERS = HERE
SHIPPED = ("git", "npm", "pip")
TESTING = os.path.join(HERE, "testing")
PYTHON = sys.executable
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import agentbox_handler as handler  # noqa: E402

SESSION = "0123456789abcdef0123456789abcdef"
REQUEST = "r-1"
DIGEST = "b" * 64
IDS = {"run": "run-1", "execution": "exec-1", "session": SESSION, "request": REQUEST,
       "request_sha256": DIGEST}


class Scratch:
    """A private directory under TMPDIR, removed with everything in it."""

    def __init__(self):
        self.path = tempfile.mkdtemp(prefix="agentbox-acq-")
        for sub in ("tmp", "home", "repos", "logs", "stages"):
            os.mkdir(os.path.join(self.path, sub), 0o700)
        self.stages = 0

    def at(self, *parts):
        return os.path.join(self.path, *parts)

    def env(self):
        return {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": self.at("home"),
                "TMPDIR": self.at("tmp"), "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CEILING_DIRECTORIES": self.path}

    def run(self, argv, data=None, cwd=None):
        done = subprocess.run(argv, input=data, cwd=cwd or self.path, env=self.env(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        if done.returncode != 0:
            raise AssertionError("%s: %s" % (argv, done.stderr.decode(errors="replace")))
        return done.stdout

    def stage(self):
        """A fresh private request directory, as the host makes it."""
        self.stages += 1
        path = self.at("stages", "request-%032x" % self.stages)
        os.mkdir(path, 0o700)
        os.chmod(path, 0o700)
        return path

    def remove(self):
        for dirpath, dirnames, _ in os.walk(self.path):
            for name in dirnames:
                try:
                    os.chmod(os.path.join(dirpath, name), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.path, ignore_errors=True)


def request_value(stage, handler_id, operation, args, policy, tools=None, test=None,
                  remaining_ms=60000, metadata_bytes=32768, ids=None, acquire_bytes=None):
    """A request file's value; `acquire_bytes` as the host gives it to an
    `http`-metered handler."""
    limits = {"metadata_bytes": metadata_bytes}
    if acquire_bytes is not None:
        limits["acquire_bytes"] = acquire_bytes
    value = {"schema": handler.REQUEST_SCHEMA, "handler": handler_id, "version": "1",
             "operation": operation, "args": args, "policy": policy, "ids": ids or dict(IDS),
             "stage": stage, "artifact": stage + "/" + handler.ARTIFACT_FILE,
             "remaining_ms": remaining_ms, "tools": tools or {}, "limits": limits}
    if test is not None:
        value["test"] = test
    return value


def write_request(stage, value=None, raw=None):
    """STAGE/request.json (O_EXCL, 0600): `value` or `raw` bytes. Its path."""
    path = os.path.join(stage, handler.REQUEST_FILE)
    data = raw if raw is not None else json.dumps(value, separators=(",", ":")).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def run(entry, path, env=None, timeout=120):
    """The worker as the host runs it; (exit code, stdout lines, seconds)."""
    started = time.monotonic()
    process = subprocess.Popen(
        [PYTHON, "-I", "-B", entry, "acquire", path],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env=env or {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, start_new_session=True)
    try:
        out, _ = process.communicate(timeout=timeout)
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    return process.returncode, out.decode().splitlines(), time.monotonic() - started


def result(test, lines):
    """The one result line, of the result schema."""
    test.assertEqual(len(lines), 1, lines)
    value = json.loads(lines[0])
    test.assertEqual(value["schema"], handler.RESULT_SCHEMA)
    return value


def entry(handler_id):
    return os.path.join(HANDLERS, handler_id, "host", "worker.py")


def installed_tree(scratch, ids):
    """A copy of lib and the host parts (manifest, packaged policy, host/) of the handlers
    `ids` (testing ones included) as ASSETS/acquisitions lays them out; its
    root."""
    root = scratch.at("assets-acquisitions-%d" % len(os.listdir(scratch.path)))
    os.mkdir(root, 0o700)
    shutil.copytree(LIB, os.path.join(root, "lib"),
                    ignore=shutil.ignore_patterns("__pycache__"))
    for handler_id in ids:
        source = os.path.join(HANDLERS if handler_id in SHIPPED else TESTING, handler_id)
        shutil.copytree(source, os.path.join(root, handler_id),
                        ignore=shutil.ignore_patterns("__pycache__", "jail", "contract", "__init__.py"))
    return root
