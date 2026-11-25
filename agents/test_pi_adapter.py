"""Offline suite of the trusted `pi` adapter (pi/adapter.py), run as the
host's guard runs it: `python3 -I -S -B adapter.py`, an empty environment,
`/` as working directory, the request on stdin, the plan on stdout and the
result line on fd 3. Credentials are synthetic; nothing is contacted.

    python3 -I -B -m unittest discover -s agents -p 'test_*.py'
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADAPTER = os.path.join(HERE, "pi", "adapter.py")
WRAPPER = os.path.join(HERE, "jail", "run.py")
PACKAGE = {"agent": "pi", "name": "@earendil-works/pi-coding-agent", "bin": "pi", "install": None}
SECRET = "synthetic-access-7f3a9c"
REFRESH = "synthetic-refresh-0b41d2"
KEY = "synthetic-key-55e1"


def request(**fields):
    value = {"schema": "agentbox.agent-request.v1", "agent": "pi", "model": None,
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
        self.dir = tempfile.mkdtemp(prefix="agentbox-pi-adapter-")
        self.now = int(time.time() * 1000)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def auth(self, document, mode=0o600, name="auth.json"):
        path = os.path.join(self.dir, name)
        data = document if isinstance(document, bytes) else json.dumps(document).encode()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(path, mode)
        return path

    def oauth(self, expires=None, **extra):
        entry = {"type": "oauth", "access": SECRET, "refresh": REFRESH,
                 "expires": self.now + 3600000 if expires is None else expires,
                 "accountId": "acct-1"}
        entry.update(extra)
        return entry

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
        return result

    def test_the_plan_is_the_common_runner_and_the_argv_private(self):
        plan = self.ok(request(model="openai-codex/gpt-6.1-sol"))
        self.assertEqual(plan["argv"][:7], ["-I", "-S", "-B", "-X", "utf8", "-c",
                                            'import sys;exec("".join(sys.argv[1:-3]))'])
        self.assertIs(plan["python"], True)
        with open(WRAPPER) as stream:
            self.assertEqual("".join(plan["argv"][7:]), stream.read())
        self.assertTrue(all(len(item.encode()) <= 4096 for item in plan["argv"]))
        self.assertEqual(plan["settings"], {
            "argv": ["pi", "--offline", "-p", "--model", "openai-codex/gpt-6.1-sol"],
            "auth": None, "package": PACKAGE})
        self.assertIsNone(plan["credential"])
        self.assertIsNone(plan["not_after_ms"])
        self.assertIs(plan["install"], False)
        # The model in the private settings only, never the runner's argv.
        self.assertNotIn("gpt-6.1-sol", json.dumps(plan["argv"]))
        self.assertEqual(self.ok(request())["settings"]["argv"], ["pi", "--offline", "-p"])

    def test_an_install_asks_for_the_lane_latest_or_an_exact_version(self):
        plan = self.ok(request(install={"version": None}))
        self.assertIs(plan["install"], True)
        self.assertEqual(plan["settings"]["package"], dict(PACKAGE, install={"version": None}))
        for version in ('1.5.2', '9.9.9', '2.0.0-rc.1'):
            plan = self.ok(request(install={"version": version}))
            self.assertIs(plan["install"], True)
            self.assertEqual(plan["settings"]["package"], dict(PACKAGE, install={"version": version}))
        for version in ('latest', '1.5', '^1.5.2', '../1.5.2', '1.5.2/x', '', '01.5.2', '1.5.2+build', '-1.5.2'):
            self.refused(request(install={"version": version}), "agent_version_invalid")

    def test_interactive_is_pis_own_interface_with_literal_arguments(self):
        args = ["--continue", "--", "it's $HOME", "\u00e9t\u00e9"]
        plan = self.ok(request(model="openai-codex/gpt-6.1-sol", interactive={"args": args}))
        self.assertEqual(plan["settings"]["argv"],
                         ["pi", "--offline", "--model", "openai-codex/gpt-6.1-sol"] + args)
        self.assertEqual(plan["settings"]["package"], PACKAGE)
        self.assertIs(plan["install"], False)
        self.refused(request(install={"version": None}, interactive={"args": []}),
                     "interactive_install_unsupported")
        self.refused(request(interactive={"args": [None]}), "request_invalid")
        self.refused(request(interactive={"args": ["x" * 9000]}), "settings_too_large")

    def test_requests_are_closed_and_agents_explicit(self):
        self.refused(request(agent="codex"), "agent_unknown")
        self.refused(request(agent="claude"), "agent_unknown")
        self.refused(dict(request(), extra=1), "request_invalid")
        self.refused(b"{", "request_invalid")
        self.refused(b'{"schema":"agentbox.agent-request.v1","schema":"x"}', "request_invalid")
        self.refused(request(auth={"path": "relative.json", "keep": False}), "request_invalid")
        for model in ("", "has space", "-flag", "a\nb", "x" * 257):
            self.refused(request(model=model), "model_invalid")

    def test_an_oauth_credential_is_copied_access_only(self):
        path = self.auth({"openai-codex": self.oauth(email="me@example.org"),
                          "anthropic": {"type": "api_key", "key": KEY}})
        plan = self.ok(request(model="openai-codex/gpt-6.1-sol",
                               auth={"path": path, "keep": True}))
        credential = json.loads(plan["credential"])
        self.assertEqual(credential, {"openai-codex": {
            "type": "oauth", "access": SECRET, "expires": self.now + 3600000,
            "accountId": "acct-1", "refresh": ""}})
        self.assertNotIn(REFRESH, json.dumps(plan))
        self.assertNotIn(KEY, json.dumps(plan))
        self.assertEqual(plan["not_after_ms"], self.now + 3600000)
        self.assertEqual(plan["settings"]["auth"], {"path": ".pi/agent/auth.json", "keep": True})

    def test_selection_is_the_models_provider_or_the_only_entry(self):
        single = self.auth({"anthropic": {"type": "api_key", "key": KEY, "env": {"X": "y"}}})
        plan = self.ok(request(auth={"path": single, "keep": False}))
        self.assertEqual(json.loads(plan["credential"]),
                         {"anthropic": {"type": "api_key", "key": KEY}})
        self.assertIsNone(plan["not_after_ms"])
        both = self.auth({"openai-codex": self.oauth(),
                          "anthropic": {"type": "api_key", "key": KEY}}, name="both.json")
        self.refused(request(auth={"path": both, "keep": False}), "credential_ambiguous")
        self.refused(request(model="sonnet", auth={"path": both, "keep": False}),
                     "credential_ambiguous")
        self.refused(request(model="google/gemini", auth={"path": both, "keep": False}),
                     "credential_provider_missing")
        plan = self.ok(request(model="anthropic/claude", auth={"path": both, "keep": False}))
        self.assertEqual(list(json.loads(plan["credential"])), ["anthropic"])

    def test_unsupported_and_expiring_credentials_refuse(self):
        cases = [
            ({"openai-codex": self.oauth(expires=self.now - 1)}, "credential_expired"),
            ({"openai-codex": self.oauth(expires=self.now + 60000)}, "credential_expired"),
            ({"openai-codex": self.oauth(expires="soon")}, "credential_invalid"),
            ({"openai-codex": self.oauth(access="")}, "credential_invalid"),
            ({"anthropic": self.oauth()}, "credential_type_unsupported"),
            ({"x": {"type": "api_key", "key": "!security find-generic-password"}},
             "credential_command_unsupported"),
            ({"x": {"type": "api_key", "key": ""}}, "credential_invalid"),
            ({"x": {"type": "token"}}, "credential_type_unsupported"),
            ({"x": "plain"}, "credential_invalid"),
            ({}, "credential_invalid"),
        ]
        for index, (document, code) in enumerate(cases):
            with self.subTest(code=code, index=index):
                path = self.auth(document, name="c%d.json" % index)
                self.refused(request(auth={"path": path, "keep": False}), code)

    def test_the_file_is_private_regular_bounded_and_strict(self):
        good = self.auth({"x": {"type": "api_key", "key": KEY}})
        link = os.path.join(self.dir, "link.json")
        os.symlink(good, link)
        self.refused(request(auth={"path": link, "keep": False}), "credential_unreadable")
        self.refused(request(auth={"path": self.dir, "keep": False}), "credential_unreadable")
        self.refused(request(auth={"path": os.path.join(self.dir, "missing"), "keep": False}),
                     "credential_unreadable")
        shared = self.auth({"x": {"type": "api_key", "key": KEY}}, mode=0o644, name="s.json")
        self.refused(request(auth={"path": shared, "keep": False}), "credential_not_private")
        large = self.auth(b'{"x":"' + b"a" * (1024 * 1024) + b'"}', name="l.json")
        self.refused(request(auth={"path": large, "keep": False}), "credential_too_large")
        for index, data in enumerate((b"not json", b'{"x":1,"x":2}', b'{"x":NaN}', b"[]",
                                      b"\xff")):
            path = self.auth(data, name="i%d.json" % index)
            self.refused(request(auth={"path": path, "keep": False}), "credential_invalid")

    def test_a_largest_unicode_key_fits_the_hosts_plan(self):
        # The minimized copy's text at its 16 KiB bound, its non-ASCII kept
        # as UTF-8 in the plan (agent.rs MAX_PLAN_BYTES: 64 KiB).
        key = '"\\\n\u00e9\U0001f600'

        def text(value):
            return json.dumps({"x": {"type": "api_key", "key": value}}, separators=(",", ":"),
                              ensure_ascii=False).encode()

        room = 16 * 1024 - len(text(key))
        key += "\u00e9" * (room // 2) + "a" * (room % 2)
        self.assertEqual(len(text(key)), 16 * 1024)
        path = self.auth({"x": {"type": "api_key", "key": key}})
        code, raw, result, stderr = run_adapter(request(auth={"path": path, "keep": False}),
                                                raw=True)
        self.assertEqual((code, result["outcome"], stderr), (0, "ok", b""))
        self.assertLessEqual(len(raw), 64 * 1024)
        self.assertEqual(json.loads(raw.decode("utf-8"))["credential"].encode(), text(key))
        path = self.auth({"x": {"type": "api_key", "key": key + "a"}}, name="over.json")
        self.refused(request(auth={"path": path, "keep": False}), "credential_too_large")
        # A lone surrogate is no UTF-8 text: a fixed failure, as before.
        path = self.auth(b'{"x":{"type":"api_key","key":"\\ud800"}}', name="s.json")
        self.refused(request(auth={"path": path, "keep": False}), "adapter_failed")

    def test_a_plan_past_the_hosts_bound_refuses_whole(self):
        # Each part within its own cap (a 16 KiB minimized key of escapes,
        # the settings under 8 KiB) can still make a plan past the host's
        # 64 KiB (agent.rs MAX_PLAN_BYTES): refused as a whole.
        def text(value):
            return json.dumps({"x": {"type": "api_key", "key": value}}, separators=(",", ":"),
                              ensure_ascii=False).encode()

        key = "\\" * ((16 * 1024 - len(text(""))) // 2)
        self.assertLessEqual(len(text(key)), 16 * 1024)
        path = self.auth({"x": {"type": "api_key", "key": key}})
        auth = {"path": path, "keep": False}
        code, raw, _, _ = run_adapter(request(auth=auth, interactive={"args": []}), raw=True)
        self.assertEqual(code, 0)
        self.assertLessEqual(len(raw), 64 * 1024)
        # The plan carries the runner's source: a margin past the bound,
        # not an edge a comment's length moves.
        args = ["a" * 4000, "b" * 4000]
        settings = self.ok(request(interactive={"args": args}))["settings"]
        self.assertLess(len(json.dumps(settings, separators=(",", ":")).encode()), 8 * 1024)
        self.refused(request(auth=auth, interactive={"args": args}), "plan_too_large")

    def test_refusals_never_echo_the_secret(self):
        path = self.auth({"anthropic": {"type": "oauth", "access": SECRET, "refresh": REFRESH,
                                        "expires": 1}})
        code, plan, result, stderr = run_adapter(request(auth={"path": path, "keep": False}))
        text = json.dumps(result).encode() + stderr
        self.assertEqual(code, 1)
        self.assertIsNone(plan)
        self.assertNotIn(SECRET.encode(), text)
        self.assertNotIn(path.encode(), text)


if __name__ == "__main__":
    unittest.main()
