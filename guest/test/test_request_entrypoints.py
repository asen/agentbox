"""The installed `agentbox-request` command, the handlers' shims (`git`,
`npm`) and pip's session wrapper as real child processes of this interpreter, without
any delivery: no request command gets a valid request context, so none dials
the POST endpoint or reaches an installer; delivery is covered on owned roots
and memory doubles. There is no jail registry: `agentbox-request` is the
generic client for every handler. Each child is bounded by a timeout and
killed then."""

import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
REQUEST_MAIN = os.path.join(ROOT, "guest", "src", "request_main.py")


def jail(handler):
    return os.path.join(ROOT, "acquisitions", handler, "jail", handler + ".py")


def run(script, args, env=None):
    """(status, stdout, stderr) of one isolated child; killed after 10 s."""
    done = subprocess.run([sys.executable, "-I", "-S", "-B", script, *args], stdin=subprocess.DEVNULL,
                          capture_output=True, env=dict({"PATH": "/usr/bin:/bin"}, **(env or {})), timeout=10)
    return done.returncode, done.stdout.decode(), done.stderr.decode()


def line(prefix, code):
    return '%s {"ok":false,"code":"%s","changes":"none","cleanup":"observed"}\n' % (prefix, code)


def unavailable(handler):
    return 'agentbox-request: %s {"ok":false,"code":"request_unavailable","cleanup":"observed"}\n' % handler


BAD_CONTEXTS = (
    {},
    {"AGENTBOX_REQUEST_SESSION": "s1", "AGENTBOX_WORK_ROOT": "/nonexistent/agentbox-work"},
    {"AGENTBOX_REQUEST_SESSION": "0123456789abcdef0123456789abcdef", "AGENTBOX_WORK_ROOT": "relative/work"},
    {"AGENTBOX_REQUEST_SESSION": "0123456789abcdef0123456789abcdef"},
)


class EntrypointTest(unittest.TestCase):
    def request(self, args, env=None):
        return run(REQUEST_MAIN, args, env)

    def test_every_handler_is_the_generic_client_and_sends_nothing_without_a_context(self):
        for handler, operation, args in (("echo", "say", '{"text":"hi"}'), ("git", "clone", "{}"),
                                         ("npm", "metadata", '{"names":["a"],"format":"full"}'),
                                         ("pip", "files", '{"projects":["x"]}'), ("ruby", "gems", "{}")):
            for env in BAD_CONTEXTS:
                self.assertEqual(self.request([handler, operation, args], env), (3, unavailable(handler), ""),
                                 (handler, env))
        self.assertFalse(os.path.exists("/nonexistent/agentbox-work"))

    def test_usage_and_bad_arguments_send_nothing(self):
        for args in ([], ["echo"], ["Echo", "say"], ["echo", "say", "{}", "extra"], ["--registry=/x", "echo", "say"]):
            status, stdout, stderr = self.request(args)
            self.assertEqual((status, stdout), (2, ""), args)
            self.assertTrue(stderr.startswith("usage: agentbox-request "), args)
        for text in ("[]", "1", "{", '{"a":-1}', '{"a":1.5}', '{"bad key":1}', '{"t":"%s"}' % ("x" * 61441)):
            status, _stdout, stderr = self.request(["echo", "say", text])
            self.assertEqual(status, 2, text)
            self.assertIn("ARGS_JSON", stderr, text)
        # Arguments up to the host's 60 KiB ceiling pass the client.
        self.assertEqual(self.request(["echo", "say", '{"t":"%s"}' % ("x" * 61432)]), (3, unavailable("echo"), ""))
        status, stdout, _stderr = self.request(["--help"])
        self.assertEqual(status, 0)
        self.assertTrue(stdout.startswith("usage: agentbox-request HANDLER OPERATION [ARGS_JSON]\n"))
        self.assertIn("Nothing is installed or applied", stdout)

    def test_the_git_shim_refuses_push_and_needs_its_own_name(self):
        self.assertEqual(run(jail("git"), ["shim", "git", "push"]),
                         (1, "", line("agentbox-request: git", "git_push_refused")))
        for args in (["shim", "hg", "push"], ["request", "clone", "{}"], []):
            status, _stdout, stderr = run(jail("git"), args)
            self.assertEqual(status, 2, args)
            self.assertTrue(stderr.startswith("usage: SHIM "), args)

    def test_the_pip_module_is_a_session_wrapper_only(self):
        # Without a context: the command as is, nothing added.
        status, stdout, _stderr = run(jail("pip"), ["session", "/bin/sh", "-c", 'echo "${PIP_INDEX_URL-unset}"'])
        self.assertEqual((status, stdout), (0, "unset\n"))
        for args in (["session"], ["shim", "pip", "install", "x"], []):
            self.assertEqual(run(jail("pip"), args)[0], 2, args)

    def test_the_npm_shim_without_a_context_is_the_real_npm(self):
        owned = tempfile.mkdtemp(prefix="agentbox-npm-entry-")
        ours, system = os.path.join(owned, "ours"), os.path.join(owned, "system")
        for directory, name, text in ((ours, "agentbox-request", "#!/bin/sh\nexit 99\n"),
                                      (ours, "npm", "#!/bin/sh\nexit 98\n"),
                                      (system, "npm", '#!/bin/sh\necho "real $*"\nexit 5\n')):
            os.makedirs(directory, exist_ok=True)
            path = os.path.join(directory, name)
            with open(path, "w") as stream:
                stream.write(text)
            os.chmod(path, 0o700)
        # Never a directory that could hold the host's own npm or npx.
        path = "%s:%s" % (ours, system)
        self.assertEqual(run(jail("npm"), ["shim", "npm", "view", "x"], {"PATH": path}), (5, "real view x\n", ""))
        # Nested in an adapted npm: the real command too, its settings kept.
        self.assertEqual(run(jail("npm"), ["shim", "npm", "ci"], {"PATH": path,
                                                                   "AGENTBOX_NPM_REGISTRY": "http://127.0.0.1:1/"}),
                         (5, "real ci\n", ""))
        status, _stdout, stderr = run(jail("npm"), ["shim", "npx", "x"], {"PATH": path})
        self.assertEqual((status, stderr), (127, "agentbox-npm: npx: command not found\n"))


if __name__ == "__main__":
    unittest.main()
