"""Offline suite of the trusted `codex` adapter (codex/adapter.py), run as
the host's guard runs it: `python3 -I -S -B adapter.py`, an empty
environment, `/` as working directory, the request on stdin, the plan on
stdout and the result line on fd 3. Credentials are synthetic; nothing is
contacted.

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
ADAPTER = os.path.join(HERE, "codex", "adapter.py")
WRAPPER = os.path.join(HERE, "jail", "run.py")
FLAGS = ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check",
         "--color", "never"]
STORE = ["-c", 'cli_auth_credentials_store="file"']
PACKAGE = {"agent": "codex", "name": "@openai/codex", "bin": "codex", "install": None}
SECRET = "synthetic-access-2b7d0e"
REFRESH = "synthetic-refresh-c4a913"
# Codex's auth.json as written by its login, with a field no version of
# this adapter knows: copied byte for byte.
AUTH = ('{\n  "auth_mode": "chatgpt",\n  "OPENAI_API_KEY": null,\n  "tokens": {\n'
        '    "id_token": "synthetic-id",\n    "access_token": "%s",\n'
        '    "refresh_token": "%s",\n    "account_id": "acct-1"\n  },\n'
        '  "last_refresh": "2026-11-14T00:00:00Z",\n  "future_field": {"x": [1, "\\u00e9"]}\n}'
        % (SECRET, REFRESH))


def request(**fields):
    value = {"schema": "agentbox.agent-request.v1", "agent": "codex", "model": None,
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
        self.dir = tempfile.mkdtemp(prefix="agentbox-codex-adapter-")

    def tearDown(self):
        shutil.rmtree(self.dir)

    def auth(self, data, mode=0o600, name="auth.json"):
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
        plan = self.ok(request(model="gpt-6.1-sol"))
        self.assertEqual(plan["argv"][:7], ["-I", "-S", "-B", "-X", "utf8", "-c",
                                            'import sys;exec("".join(sys.argv[1:-3]))'])
        self.assertIs(plan["python"], True)
        with open(WRAPPER) as stream:
            self.assertEqual("".join(plan["argv"][7:]), stream.read())
        self.assertTrue(all(len(item.encode()) <= 4096 for item in plan["argv"]))
        self.assertEqual(plan["settings"], {"argv": FLAGS + ["-m", "gpt-6.1-sol", "-"],
                                            "auth": None, "package": PACKAGE})
        self.assertIsNone(plan["credential"])
        self.assertIsNone(plan["not_after_ms"])
        self.assertIs(plan["install"], False)
        self.assertNotIn("gpt-6.1-sol", json.dumps(plan["argv"]))
        self.assertEqual(self.ok(request())["settings"]["argv"], FLAGS + ["-"])

    def test_an_install_asks_for_the_lane_latest_or_an_exact_version(self):
        plan = self.ok(request(install={"version": None}))
        self.assertIs(plan["install"], True)
        self.assertEqual(plan["settings"]["package"], dict(PACKAGE, install={"version": None}))
        for version in ('0.166.0', '0.170.0', '0.171.0-alpha.3'):
            plan = self.ok(request(install={"version": version}))
            self.assertIs(plan["install"], True)
            self.assertEqual(plan["settings"]["package"], dict(PACKAGE, install={"version": version}))
        for version in ('latest', '1.5', '^1.5.2', '../1.5.2', '1.5.2/x', '', '01.5.2', '1.5.2+build', '-1.5.2'):
            self.refused(request(install={"version": version}), "agent_version_invalid")

    def test_interactive_is_codexs_own_interface_with_the_bypass_and_literal_arguments(self):
        path = self.auth(AUTH)
        args = ["resume", "--last", "--", "it's $HOME `x`", "\u00e9t\u00e9 \u4e2d"]
        plan = self.ok(request(model="gpt-6.1-sol", auth={"path": path, "keep": False},
                               interactive={"args": args}))
        self.assertEqual(plan["settings"]["argv"],
                         ["codex", "--dangerously-bypass-approvals-and-sandbox"] + STORE
                         + ["-m", "gpt-6.1-sol"] + args)
        self.assertEqual(plan["settings"]["package"], PACKAGE)
        self.assertEqual(plan["credential"], AUTH)
        self.assertIs(plan["install"], False)
        self.assertEqual(self.ok(request(interactive={"args": []}))["settings"]["argv"],
                         ["codex", "--dangerously-bypass-approvals-and-sandbox"])
        # Unescaped UTF-8 in the plan, as the host frames it.
        code, raw, _, _ = run_adapter(request(interactive={"args": args}), raw=True)
        self.assertEqual(code, 0)
        self.assertIn("\u00e9t\u00e9 \u4e2d".encode(), raw)
        self.refused(request(install={"version": None}, interactive={"args": []}),
                     "interactive_install_unsupported")
        for bad in ({"args": "x"}, {"args": [1]}, {"args": ["a\u0000b"]}, {"args": ["\ud800"]},
                    {"args": []} | {"extra": 1}, []):
            self.refused(request(interactive=bad), "request_invalid")
        self.refused(request(interactive={"args": ["x" * 4000, "y" * 4200]}),
                     "settings_too_large")

    def test_requests_are_closed_and_agents_explicit(self):
        self.refused(request(agent="pi"), "agent_unknown")
        self.refused(dict(request(), extra=1), "request_invalid")
        self.refused(b"{", "request_invalid")
        self.refused(request(auth={"path": "relative.json", "keep": False}), "request_invalid")
        for model in ("", "has space", "-flag", "a\nb", "x" * 257):
            self.refused(request(model=model), "model_invalid")

    def test_the_whole_file_is_copied_unchanged(self):
        path = self.auth(AUTH)
        plan = self.ok(request(model="gpt-6.1-sol", auth={"path": path, "keep": True}))
        self.assertEqual(plan["credential"], AUTH)
        self.assertIsNone(plan["not_after_ms"])
        # The file store with a copied credential only, so the copy is used.
        self.assertEqual(plan["settings"]["argv"], FLAGS + STORE + ["-m", "gpt-6.1-sol", "-"])
        self.assertEqual(plan["settings"]["auth"], {"path": ".codex/auth.json", "keep": True})
        # Any object: an API key, a key and tokens, fields this adapter
        # does not know; never interpreted.
        for index, data in enumerate(('{"OPENAI_API_KEY":"synthetic-key"}', '{"x":1}')):
            path = self.auth(data, name="o%d.json" % index)
            self.assertEqual(self.ok(request(auth={"path": path, "keep": False}))["credential"],
                             data)

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
        # Above the framed input's credential cap (16 KiB), and above the
        # adapter's read bound (1 MiB).
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
