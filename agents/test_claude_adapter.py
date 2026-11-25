"""Offline suite of the trusted `claude` adapter (claude/adapter.py), run as
the host's guard runs it: `python3 -I -S -B adapter.py`, an empty
environment, `/` as working directory, the request on stdin, the plan on
stdout and the result line on fd 3. Credentials are synthetic; nothing is
contacted and no `claude` runs.

    python3 -I -B -m unittest discover -s agents -p 'test_*.py'
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "claude", "adapter.py")
RUNNER = os.path.join(HERE, "jail", "run.py")
SECRET = "synthetic-access-8e41c2"
REFRESH = "synthetic-refresh-5a07fd"
# A Claude `.credentials.json` shape with a field no version of this
# adapter knows: copied byte for byte.
AUTH = ('{\n  "claudeAiOauth": {\n    "accessToken": "%s",\n    "refreshToken": "%s",\n'
        '    "expiresAt": 1700000000000,\n    "scopes": ["user:inference"]\n  },\n'
        '  "future_field": {"x": [1, "\\u00e9"]}\n}' % (SECRET, REFRESH))
FLAGS = ["claude", "-p", "--dangerously-skip-permissions", "--permission-prompts", "none"]
PACKAGE = {"agent": "claude", "name": "@anthropic-ai/claude-code", "bin": "claude", "install": None}


def request(**fields):
    value = {"schema": "agentbox.agent-request.v1", "agent": "claude", "model": None,
             "install": None, "auth": None, "interactive": None}
    value.update(fields)
    return value


def run_adapter(value, raw=False):
    """(exit status, plan or None (its bytes if `raw`), result, stderr)."""
    read, write = os.pipe()
    try:
        # fd 3 the result pipe, as the host's worker runner arranges it.
        process = subprocess.run(
            ["/bin/sh", "-c", 'exec "$0" "$@" 3>&%d %d>&-' % (write, write),
             sys.executable, "-I", "-S", "-B", ADAPTER],
            input=json.dumps(value).encode() if not isinstance(value, bytes) else value,
            capture_output=True, env={}, cwd="/", pass_fds=(write,), timeout=30)
    finally:
        os.close(write)
    with os.fdopen(read, "rb") as stream:
        result = json.loads(stream.read().decode())
    plan = json.loads(process.stdout) if process.stdout and not raw else process.stdout or None
    return process.returncode, plan, result, process.stderr


class Adapter(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="agentbox-claude-adapter-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def auth(self, data, mode=0o600, name=".credentials.json"):
        path = os.path.join(self.dir, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data if isinstance(data, bytes) else data.encode())
        os.chmod(path, mode)
        return path

    def ok(self, value):
        code, plan, result, stderr = run_adapter(value)
        self.assertEqual((code, result), (0, {"schema": "agentbox.agent-result.v1",
                                              "outcome": "ok"}), stderr)
        self.assertEqual(stderr, b"")
        return plan

    def refused(self, value, expected):
        code, plan, result, stderr = run_adapter(value)
        self.assertEqual((code, plan, stderr), (1, None, b""))
        self.assertEqual(result, {"schema": "agentbox.agent-result.v1", "outcome": "error",
                                  "code": expected})

    def test_the_plan_is_the_common_runner_and_the_argv_private(self):
        plan = self.ok(request())
        self.assertEqual(plan["argv"][:7], ["-I", "-S", "-B", "-X", "utf8", "-c",
                                            'import sys;exec("".join(sys.argv[1:-3]))'])
        self.assertIs(plan["python"], True)
        with open(RUNNER) as stream:
            self.assertEqual("".join(plan["argv"][7:]), stream.read())
        self.assertTrue(all(len(item.encode()) <= 4096 for item in plan["argv"]))
        self.assertEqual(plan["settings"], {"argv": FLAGS, "auth": None, "package": PACKAGE})
        self.assertIsNone(plan["credential"])
        self.assertIsNone(plan["not_after_ms"])
        self.assertIs(plan["install"], False)
        # The model in the settings only, never the runner's argv.
        plan = self.ok(request(model="claude-fable-5-1"))
        self.assertEqual(plan["settings"]["argv"], FLAGS + ["--model", "claude-fable-5-1"])
        self.assertNotIn("claude-fable-5-1", json.dumps(plan["argv"]))

    def test_an_install_asks_for_the_lane_latest_or_an_exact_version(self):
        plan = self.ok(request(install={"version": None}))
        self.assertIs(plan["install"], True)
        self.assertEqual(plan["settings"]["package"], dict(PACKAGE, install={"version": None}))
        for version in ('2.1.327', '2.1.328'):
            plan = self.ok(request(install={"version": version}))
            self.assertIs(plan["install"], True)
            self.assertEqual(plan["settings"]["package"], dict(PACKAGE, install={"version": version}))
        for version in ('latest', '1.5', '^1.5.2', '../1.5.2', '1.5.2/x', '', '01.5.2', '1.5.2+build', '-1.5.2'):
            self.refused(request(install={"version": version}), "agent_version_invalid")
        # A credential is still checked with an install.
        path = self.auth(AUTH, mode=0o644)
        self.refused(request(install={"version": None}, auth={"path": path, "keep": False}),
                     "credential_not_private")

    def test_interactive_is_claudes_own_interface_with_the_bypass_and_literal_arguments(self):
        args = ["--continue", "\u00e9t\u00e9"]
        plan = self.ok(request(model="claude-test-model", interactive={"args": args}))
        self.assertEqual(plan["settings"], {
            "argv": ["claude", "--dangerously-skip-permissions", "--model", "claude-test-model"]
            + args, "auth": None, "package": PACKAGE})
        self.refused(request(install={"version": None}, interactive={"args": []}),
                     "interactive_install_unsupported")
        self.refused(request(interactive={"args": "x"}), "request_invalid")
        self.refused(request(interactive={"args": ["x" * 9000]}), "settings_too_large")

    def test_requests_are_closed_and_agents_explicit(self):
        self.refused(request(agent="codex"), "agent_unknown")
        self.refused(dict(request(), extra=1), "request_invalid")
        self.refused(b"{", "request_invalid")
        self.refused(request(auth={"path": "relative.json", "keep": False}), "request_invalid")
        self.refused(request(install={"version": 1}), "request_invalid")
        for model in ("", "has space", "-flag", "a\nb", "x" * 257):
            self.refused(request(model=model), "model_invalid")

    def test_the_whole_file_goes_to_claudes_credentials_file(self):
        path = self.auth(AUTH)
        plan = self.ok(request(model="opus", auth={"path": path, "keep": True}))
        self.assertEqual(plan["credential"], AUTH)
        self.assertIsNone(plan["not_after_ms"])
        self.assertEqual(plan["settings"], {"argv": FLAGS + ["--model", "opus"],
                                            "auth": {"path": ".claude/.credentials.json",
                                                     "keep": True},
                                            "package": PACKAGE})
        self.assertNotIn(SECRET, json.dumps(plan["settings"]))
        path = self.auth('{"x":1}', name="other.json")
        plan = self.ok(request(auth={"path": path, "keep": False}))
        self.assertEqual(plan["credential"], '{"x":1}')
        self.assertFalse(plan["settings"]["auth"]["keep"])

    def test_the_file_is_private_regular_bounded_and_strict(self):
        good = self.auth(AUTH)
        link = os.path.join(self.dir, "link.json")
        os.symlink(good, link)
        self.refused(request(auth={"path": link, "keep": False}), "credential_unreadable")
        self.refused(request(auth={"path": self.dir, "keep": False}), "credential_unreadable")
        self.refused(request(auth={"path": os.path.join(self.dir, "missing"), "keep": False}),
                     "credential_unreadable")
        shared = self.auth(AUTH, mode=0o640, name="s.json")
        self.refused(request(auth={"path": shared, "keep": False}), "credential_not_private")
        for index, data in enumerate((b"not json", b'{"x":1,"x":2}', b'{"x":NaN}', b"[]",
                                      b"{}", b"\xff", b"null")):
            path = self.auth(data, name="i%d.json" % index)
            self.refused(request(auth={"path": path, "keep": False}), "credential_invalid")
        for index, size in enumerate((16 * 1024, 1024 * 1024)):
            path = self.auth(b'{"x":"' + b"a" * size + b'"}', name="l%d.json" % index)
            self.refused(request(auth={"path": path, "keep": False}), "credential_too_large")
        exact = 16 * 1024 - len(b'{"x":""}')
        path = self.auth(b'{"x":"' + b"a" * exact + b'"}', name="max.json")
        self.assertEqual(len(self.ok(request(auth={"path": path, "keep": False}))["credential"]),
                         16 * 1024)

    def test_a_largest_unicode_or_escaped_credential_fits_the_hosts_plan(self):
        # The host reads at most 64 KiB of plan (agent.rs MAX_PLAN_BYTES): a
        # 16 KiB credential's text stays its own UTF-8 bytes, only JSON's
        # own escapes (quote, backslash) doubled.
        body = '\\"\\\\\\n\\u0001\u00e9\U0001f600'
        head, tail = b'{"x":"', b'"}'
        room = 16 * 1024 - len(head) - len(tail) - len(body.encode())
        unicode = head + (body + "\u00e9" * (room // 2) + "a" * (room % 2)).encode() + tail
        escaped = head + b"\\\\" * ((16 * 1024 - len(head) - len(tail)) // 2) + tail
        for index, data in enumerate((unicode, escaped)):
            self.assertEqual(len(data), 16 * 1024)
            path = self.auth(data, name="u%d.json" % index)
            code, raw, result, stderr = run_adapter(request(auth={"path": path, "keep": False}),
                                                    raw=True)
            self.assertEqual((code, result["outcome"], stderr), (0, "ok", b""))
            self.assertLessEqual(len(raw), 64 * 1024)
            self.assertEqual(json.loads(raw.decode("utf-8"))["credential"].encode(), data)
        # Escaped surrogates are text, copied as written; encoded ones are
        # not UTF-8 and refuse.
        path = self.auth(b'{"x":"\\ud800"}', name="s1.json")
        self.assertEqual(self.ok(request(auth={"path": path, "keep": False}))["credential"],
                         '{"x":"\\ud800"}')
        path = self.auth(b'{"x":"\xed\xa0\x80"}', name="s2.json")
        self.refused(request(auth={"path": path, "keep": False}), "credential_invalid")

    def test_a_plan_past_the_hosts_bound_refuses_whole(self):
        # Each part within its own cap (a 16 KiB credential of escapes, the
        # settings under 8 KiB) can still make a plan past the host's 64 KiB
        # (agent.rs MAX_PLAN_BYTES): refused as a whole, nothing written.
        head, tail = b'{"x":"', b'"}'
        escaped = head + b"\\\\" * ((16 * 1024 - len(head) - len(tail)) // 2) + tail
        path = self.auth(escaped, name="escaped.json")
        auth = {"path": path, "keep": False}
        code, raw, _, _ = run_adapter(request(auth=auth, interactive={"args": []}), raw=True)
        self.assertEqual(code, 0)
        self.assertLessEqual(len(raw), 64 * 1024)
        args = ["a" * 3900, "b" * 3900]
        settings = self.ok(request(interactive={"args": args}))["settings"]
        self.assertLess(len(json.dumps(settings, separators=(",", ":")).encode()), 8 * 1024)
        self.refused(request(auth=auth, interactive={"args": args}), "plan_too_large")

    def test_refusals_never_echo_the_secret(self):
        path = self.auth(AUTH, mode=0o604)
        code, plan, result, stderr = run_adapter(request(auth={"path": path, "keep": False}))
        text = json.dumps(result).encode() + stderr
        self.assertEqual((code, plan), (1, None))
        self.assertNotIn(SECRET.encode(), text)
        self.assertNotIn(path.encode(), text)


if __name__ == "__main__":
    unittest.main()
