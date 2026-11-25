"""Offline suite of the common jail runner (agents/jail/run.py), run as the
jail runs it: this Python on `-I -S -B -X utf8 -c LOADER TEXT` with the
framed input on stdin, in an owned scratch HOME. The agent, `npm` and the
package are stand-ins of names no adapter uses (`xyz-agent`, `@xyz/agent`):
the runner knows none. No real agent, npm, model, registry or network is
involved, and nothing is installed outside the scratch.

    python3 -I -B -m unittest discover -s agents -p 'test_*.py'
"""

import json
import os
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RUNNER = os.path.join(HERE, "jail", "run.py")
LOADER = 'import sys;exec("".join(sys.argv[1:-3]))'
CREDENTIAL = '{"token":"synthetic-token-7f3a","refresh":"synthetic-refresh-0c9d"}'
AUTH = ".config/xyz/token.json"
NAME = "xyz-agent"
PACKAGE = "@xyz/agent"
INSTALLS = ".local/share/agentbox-agents/xyz"
MARKER = ".agentbox-installed"

# A stand-in agent: records its program, argv, stdin and the credential it
# saw ($HOME/$FAKE_AUTH).
FAKE = """#!/bin/sh
log="$FAKE_LOG"
printf '%s\\n' "$0" > "$log.program"
printf '%s\\n' "$@" > "$log.argv"
cat > "$log.stdin"
a="$HOME/$FAKE_AUTH"
d=$(dirname "$a")
if [ -f "$a" ]; then
  cp "$a" "$log.auth"
  stat -c %a "$a" > "$log.mode"
fi
# A rewrite in place: a lock beside it, then the same path truncated.
[ -n "$FAKE_REFRESH" ] && : > "$d/token.lock" && printf '{"refreshed":true}' > "$a"
# Created before the original goes: never its reused inode.
[ -n "$FAKE_REPLACE_FILE" ] && echo replaced > "$d/new.json" && mv "$d/new.json" "$a"
if [ -n "$FAKE_REPLACE_DIR" ]; then
  mv "$d" "$d-old" && mkdir "$d" && echo replaced > "$a"
fi
if [ -n "$FAKE_LINK_DIR" ]; then
  mkdir "$HOME/linked" && cp "$a" "$HOME/linked/" && mv "$d" "$d-old" && ln -s "$HOME/linked" "$d"
fi
[ -n "$FAKE_LOCKDIR" ] && chmod 500 "$d"
if [ -n "$FAKE_SLEEP" ]; then
  for s in TERM INT HUP; do
    trap "echo $s > '$log.signal'; kill \\$! 2>/dev/null; exit 99" $s
  done
  echo ready > "$log.ready"
  sleep "$FAKE_SLEEP" & wait
fi
exit "${FAKE_EXIT:-0}"
"""

# A stand-in npm: each call logged; `view` prints $FAKE_LATEST as JSON;
# `install --global --prefix DIR ... NAME@V` lays out DIR as npm does (the
# command a relative link to the package's FAKE agent), output on stdout.
FAKE_NPM = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_LOG.npm"
if [ "$1" = view ]; then
  [ -n "$FAKE_VIEW_FAIL" ] && exit 1
  printf '%s\\n' "${FAKE_VIEW_OUT:-\\"${FAKE_LATEST:-2.0.0}\\"}"
  exit 0
fi
prefix="$4"
mkdir -p "$prefix/lib/node_modules/@xyz/agent"
if [ -n "$FAKE_NPM_SLEEP" ]; then
  trap 'echo term > "$FAKE_LOG.npm-term"; kill $! 2>/dev/null; exit 143' TERM
  echo ready > "$FAKE_LOG.ready"
  sleep "$FAKE_NPM_SLEEP" & wait
fi
[ -n "$FAKE_NPM_FAIL" ] && { echo "npm error" >&2; exit 1; }
cp "$FAKE_AGENT" "$prefix/lib/node_modules/@xyz/agent/cli.js"
chmod 755 "$prefix/lib/node_modules/@xyz/agent/cli.js"
[ -n "$FAKE_NO_BIN" ] || { mkdir -p "$prefix/bin"; ln -s ../lib/node_modules/@xyz/agent/cli.js "$prefix/bin/xyz-agent"; }
echo "added 1 package"
"""


def descriptor(install=None, name=PACKAGE, agent="xyz", bin=NAME):
    return {"agent": agent, "name": name, "bin": bin, "install": install}


def payload(prompt, argv=None, credential=None, auth=None, package=None, settings=None):
    if settings is None:
        settings = {"argv": argv or [NAME], "auth": auth, "package": package}
    header = {"schema": "agentbox.agent-input.v3",
              "prompt_bytes": len(prompt.encode()),
              "credential_bytes": len(credential.encode()) if credential else 0,
              "settings": settings}
    data = json.dumps(header).encode() + b"\n" + prompt.encode()
    return data + (credential.encode() if credential else b"")


def with_auth(prompt="go", keep=False, argv=None, package=None):
    return payload(prompt, argv=argv, credential=CREDENTIAL, auth={"path": AUTH, "keep": keep},
                   package=package)


class Scratch(unittest.TestCase):
    """An owned scratch HOME, work and PATH, and the runner's text."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="agentbox-jail-runner-")
        self.home = os.path.join(self.root, "home")
        self.work = os.path.join(self.home, "work")
        self.bin = os.path.join(self.root, "bin")
        self.elsewhere = os.path.join(self.root, "elsewhere")
        for path in (self.home, self.work, self.bin, self.elsewhere):
            os.makedirs(path, 0o700)
        self.log = os.path.join(self.root, "log")
        with open(RUNNER) as stream:
            self.text = stream.read()
        self.argv = self.runner("headless", "-", "-")

    def runner(self, mode, nonce, receipt):
        return [sys.executable, "-I", "-S", "-B", "-X", "utf8", "-c", LOADER, self.text, mode,
                nonce, receipt]

    def tearDown(self):
        for dirpath, dirnames, _ in os.walk(self.root):
            for name in dirnames:
                if not os.path.islink(os.path.join(dirpath, name)):
                    os.chmod(os.path.join(dirpath, name), 0o700)
        shutil.rmtree(self.root)

    def script(self, name, text=FAKE, directory=None, mode=0o700):
        path = os.path.join(directory or self.bin, name)
        with open(path, "w") as stream:
            stream.write(text)
        os.chmod(path, mode)
        return path

    def start(self, data, **env):
        full = {"HOME": self.home, "PATH": "%s:/usr/bin:/bin" % self.bin, "LANG": "C.UTF-8",
                "FAKE_LOG": self.log, "FAKE_AUTH": AUTH}
        full.update(env)
        process = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, cwd=self.work, env=full)
        try:
            process.stdin.write(data)
        except BrokenPipeError:
            pass  # Refused before reading it all.
        process.stdin.close()
        return process

    def run_runner(self, data, **env):
        process = self.start(data, **env)
        out, err = process.communicate(timeout=60)
        process.stdout.close()
        process.stderr.close()
        return process.returncode, out.decode(), err.decode()

    def wait_for(self, suffix):
        deadline = time.monotonic() + 20
        while not os.path.exists(self.log + suffix):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)

    def read(self, suffix):
        with open(self.log + suffix) as stream:
            return stream.read()

    def args(self):
        return self.read(".argv").split("\n")[:-1]

    def auth(self):
        return os.path.join(self.home, AUTH)

    def npm(self):
        """The stand-in npm on PATH, its agent beside it; the install root."""
        self.script("npm", FAKE_NPM)
        self.script("agent-source", directory=self.elsewhere)
        return os.path.join(self.home, INSTALLS)

    def npm_calls(self):
        if not os.path.exists(self.log + ".npm"):
            return []
        calls = self.read(".npm").split("\n")[:-1]
        os.unlink(self.log + ".npm")
        return calls

    def install(self, data, **env):
        return self.run_runner(data, FAKE_AGENT=os.path.join(self.elsewhere, "agent-source"), **env)


class Runner(Scratch):
    def test_the_argv_runs_literally_with_the_prompt_on_stdin_and_its_status(self):
        program = self.script(NAME)
        argv = [NAME, "-p", "$HOME", "*", "--model", "m'; rm -rf /", "-"]
        prompt = "@README.md -- fix it\n--model other\n"
        code, _, err = self.run_runner(payload(prompt, argv), FAKE_EXIT="7")
        self.assertEqual(code, 7, err)
        self.assertEqual(self.read(".program").strip(), program)
        self.assertEqual(self.args(), argv[1:])
        self.assertEqual(self.read(".stdin"), prompt)
        self.assertFalse(os.path.exists(self.log + ".auth"))
        self.assertEqual(sorted(os.listdir(self.home)), ["work"])
        self.assertEqual(err, "")

    def test_an_absolute_program_runs_as_named_off_path(self):
        program = self.script("agent", directory=self.elsewhere)
        code, _, err = self.run_runner(payload("abs", [program, "x"]))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(".program").strip(), program)
        self.assertEqual(self.args(), ["x"])
        self.assertEqual(self.read(".stdin"), "abs")
        # Not executable, a directory or missing: not installed.
        os.chmod(program, 0o600)
        for path in (program, self.elsewhere, os.path.join(self.elsewhere, "none")):
            code, _, err = self.run_runner(with_auth(argv=[path]))
            self.assertEqual(code, 93, path)
            self.assertIn("error code=agent_not_installed", err)
        self.assertFalse(os.path.lexists(os.path.join(self.home, ".config")))

    def test_a_bare_name_needs_an_executable_regular_file_on_path(self):
        self.script(NAME, mode=0o600)
        os.mkdir(os.path.join(self.bin, "dir-agent"))
        for name in (NAME, "dir-agent", "missing-agent"):
            code, _, err = self.run_runner(with_auth(argv=[name]))
            self.assertEqual(code, 93, name)
            self.assertIn("error code=agent_not_installed", err)
        self.assertFalse(os.path.lexists(os.path.join(self.home, ".config")))
        # A relative PATH entry is never searched.
        self.script(NAME, directory=self.work)
        code, _, _ = self.run_runner(payload("go"), PATH="work:.:/usr/bin:/bin")
        self.assertEqual(code, 93)

    def test_a_bad_input_fails_before_anything(self):
        self.script(NAME)
        good = {"argv": [NAME], "auth": None, "package": None}
        settings = [[], {}, {"argv": [NAME], "auth": None}, dict(good, extra=1),
                    dict(good, argv=[]), dict(good, argv=NAME), dict(good, argv=[NAME, 1]),
                    dict(good, argv=[NAME, "a\0b"]), dict(good, argv=[""]),
                    dict(good, argv=["bin/" + NAME]), dict(good, argv=["./" + NAME]),
                    dict(good, auth={"path": AUTH}), dict(good, auth={"path": AUTH, "keep": 1})]
        for path in ("", "/abs", "../x", "a/../b", "a//b", "a/./b", "a/", ".", "a\0b"):
            settings.append(dict(good, auth={"path": path, "keep": False}))
        for package in ([], dict(descriptor(), extra=1), dict(descriptor(), pin=None),
                        descriptor(agent="../x"), descriptor(agent=""), descriptor(bin="a/b"),
                        descriptor(bin=".."), descriptor(name="../x"), descriptor(name="@x/../y"),
                        descriptor(name="--global"), descriptor(name=""),
                        descriptor(install={}), descriptor(install={"version": None, "extra": 1}),
                        descriptor(install={"version": ".."}), descriptor(install={"version": "1/2"}),
                        descriptor(install={"version": "latest"}), descriptor(install={"version": "^1.0.0"}),
                        descriptor(install={"version": 1})):
            settings.append(dict(good, package=package))
        cases = [payload("go", settings=value) for value in settings]
        header = {"schema": "agentbox.agent-input.v3", "prompt_bytes": 2, "credential_bytes": 0,
                  "settings": good}
        cases += [b"", b"{}\n", payload("go")[:-1], b"x" * 100,
                  json.dumps(dict(header, settings=None)).encode() + b"\ngo",
                  # The old schema, or a model beside the settings: refused.
                  json.dumps(dict(header, schema="agentbox.agent-input.v1")).encode() + b"\ngo",
                  json.dumps(dict(header, model="m")).encode() + b"\ngo",
                  # A credential without a destination, a destination without one.
                  payload("go", credential=CREDENTIAL),
                  payload("go", auth={"path": AUTH, "keep": False})]
        for data in cases:
            code, _, err = self.run_runner(data)
            self.assertEqual(code, 90, data)
            self.assertIn("error code=input_invalid", err)
            self.assertNotIn("synthetic-", err)
        self.assertFalse(os.path.exists(self.log + ".argv"))
        self.assertEqual(sorted(os.listdir(self.home)), ["work"])
        code, _, err = self.run_runner(b"x" * ((1 << 20) + 1))
        self.assertEqual(code, 90)
        self.assertIn("error code=input_too_large", err)
        code, _, err = self.run_runner(payload("go"), HOME="relative")
        self.assertEqual(code, 90)
        self.assertIn("error code=home_invalid", err)

    def test_the_copy_is_private_its_parents_made_and_it_is_removed(self):
        self.script(NAME)
        code, _, err = self.run_runner(with_auth(), FAKE_EXIT="5")
        self.assertEqual(code, 5, err)
        self.assertEqual(self.read(".auth"), CREDENTIAL)
        self.assertEqual(self.read(".mode").strip(), "600")
        for parent in (".config", ".config/xyz"):
            info = os.lstat(os.path.join(self.home, parent))
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700, parent)
        self.assertFalse(os.path.lexists(self.auth()))
        self.assertIn("agentbox-agent: credential removed", err)
        self.assertNotIn("synthetic-", err)
        # Existing parents and their other files stay as they are.
        settings = os.path.join(self.home, ".config/xyz/settings.json")
        with open(settings, "w") as stream:
            stream.write("{}")
        code, _, err = self.run_runner(with_auth())
        self.assertEqual(code, 0, err)
        self.assertEqual(os.listdir(os.path.dirname(self.auth())), ["settings.json"])

    def test_a_rewrite_in_place_is_removed_and_everything_else_left(self):
        self.script(NAME)
        code, _, err = self.run_runner(with_auth(), FAKE_REFRESH="1")
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.lexists(self.auth()))
        self.assertEqual(os.listdir(os.path.dirname(self.auth())), ["token.lock"])
        self.assertIn("credential removed", err)
        self.assertNotIn("note:", err)

    def test_a_replaced_file_or_directory_is_left_with_a_warning(self):
        self.script(NAME)
        parent = os.path.dirname(self.auth())
        for flag, why in (("FAKE_REPLACE_FILE", "file replaced"),
                          ("FAKE_REPLACE_DIR", "directory replaced"),
                          ("FAKE_LINK_DIR", "directory replaced")):
            with self.subTest(flag=flag):
                code, _, err = self.run_runner(with_auth(), FAKE_EXIT="4", **{flag: "1"})
                self.assertEqual(code, 4, err)
                self.assertIn("warning: credential_left (%s): ~/%s" % (why, AUTH), err)
                self.assertNotIn("credential removed", err)
                self.assertTrue(os.path.lexists(self.auth()))
                if flag == "FAKE_REPLACE_FILE":
                    with open(self.auth()) as stream:
                        self.assertEqual(stream.read(), "replaced\n")
                else:
                    # The original directory, moved, keeps the created file.
                    with open(os.path.join(parent + "-old", "token.json")) as stream:
                        self.assertEqual(stream.read(), CREDENTIAL)
                    shutil.rmtree(parent + "-old")
                if flag == "FAKE_LINK_DIR":
                    self.assertTrue(os.path.islink(parent))
                    os.unlink(parent)
                    shutil.rmtree(os.path.join(self.home, "linked"))
                else:
                    shutil.rmtree(parent)

    def test_a_cleanup_failure_warns_without_changing_the_status(self):
        self.script(NAME)
        code, _, err = self.run_runner(with_auth(), FAKE_LOCKDIR="1", FAKE_EXIT="3")
        self.assertEqual(code, 3)
        self.assertIn("warning: credential_left (not removable): ~/%s" % AUTH, err)

    def test_keep_leaves_the_credential(self):
        self.script(NAME)
        code, _, err = self.run_runner(with_auth(keep=True))
        self.assertEqual(code, 0, err)
        with open(self.auth()) as stream:
            self.assertEqual(stream.read(), CREDENTIAL)
        self.assertEqual(stat.S_IMODE(os.stat(self.auth()).st_mode), 0o600)
        self.assertNotIn("credential removed", err)

    def test_an_existing_linked_or_unsafe_destination_refuses_and_stays(self):
        self.script(NAME)
        os.makedirs(os.path.dirname(self.auth()), 0o700)
        with open(self.auth(), "w") as stream:
            stream.write("{}")
        code, _, err = self.run_runner(with_auth())
        self.assertEqual(code, 92)
        self.assertIn("error code=auth_exists", err)
        with open(self.auth()) as stream:
            self.assertEqual(stream.read(), "{}")
        self.assertFalse(os.path.exists(self.log + ".argv"))
        os.unlink(self.auth())
        nowhere = os.path.join(self.root, "nowhere")
        os.symlink(nowhere, self.auth())
        code, _, err = self.run_runner(with_auth())
        self.assertEqual(code, 92)
        self.assertIn("error code=auth_exists", err)
        self.assertFalse(os.path.lexists(nowhere))
        # A linked parent, at any level, or a file where a directory goes:
        # never followed, never replaced.
        shutil.rmtree(os.path.join(self.home, ".config"))
        for parent in (".config", ".config/xyz"):
            if parent != ".config":
                os.mkdir(os.path.join(self.home, ".config"), 0o700)
            os.symlink(self.elsewhere, os.path.join(self.home, parent))
            code, _, err = self.run_runner(with_auth())
            self.assertEqual(code, 92, parent)
            self.assertIn("error code=auth_location_unsafe", err)
            self.assertEqual(os.listdir(self.elsewhere), [])
            config = os.path.join(self.home, ".config")
            os.unlink(config) if os.path.islink(config) else shutil.rmtree(config)
        os.makedirs(os.path.join(self.home, ".config"), 0o700)
        with open(os.path.join(self.home, ".config/xyz"), "w") as stream:
            stream.write("file")
        code, _, err = self.run_runner(with_auth())
        self.assertEqual(code, 92)
        self.assertIn("error code=auth_location_unsafe", err)
        self.assertFalse(os.path.exists(self.log + ".argv"))

    def test_a_launch_failure_removes_the_credential(self):
        self.script(NAME, "#!/nonexistent/interpreter\n")
        code, _, err = self.run_runner(with_auth())
        self.assertEqual(code, 94, err)
        self.assertIn("error code=agent_launch_failed", err)
        self.assertFalse(os.path.lexists(self.auth()))

    def test_a_stop_is_forwarded_and_the_credential_removed(self):
        self.script(NAME)
        for number, name in ((signal.SIGTERM, "TERM"), (signal.SIGINT, "INT"),
                             (signal.SIGHUP, "HUP")):
            with self.subTest(signal=name):
                for suffix in (".ready", ".signal"):
                    if os.path.exists(self.log + suffix):
                        os.unlink(self.log + suffix)
                process = self.start(with_auth(), FAKE_SLEEP="30")
                self.wait_for(".ready")
                process.send_signal(number)
                _, err = process.communicate(timeout=20)
                process.stdout.close()
                process.stderr.close()
                self.assertEqual(process.returncode, 99, err)
                self.assertEqual(self.read(".signal").strip(), name)
                self.assertFalse(os.path.lexists(self.auth()))
                self.assertIn(b"credential removed", err)

    def test_install_resolves_latest_into_its_version_and_wins_over_path(self):
        installs = self.npm()
        self.script(NAME, "#!/bin/sh\nexit 99\n")  # on PATH, ignored for the install
        latest = descriptor(install={"version": None})
        code, out, err = self.install(with_auth(argv=[NAME, "-x"], package=latest))
        self.assertEqual(code, 0, err)
        directory = os.path.join(installs, "2.0.0")
        program = os.path.join(directory, "bin", NAME)
        self.assertEqual(self.npm_calls(), [
            "view --json @xyz/agent@latest version",
            "install --global --prefix %s --no-audit --no-fund @xyz/agent@2.0.0" % directory])
        self.assertIn("xyz 2.0.0 installed", err)
        # npm's own output is the runner's stderr, never the agent's answer.
        self.assertIn("added 1 package", err)
        self.assertEqual(out, "")
        self.assertEqual(self.read(".program").strip(), program)
        self.assertEqual(self.args(), ["-x"])
        self.assertEqual(self.read(".auth"), CREDENTIAL)
        self.assertTrue(os.path.isfile(os.path.join(directory, MARKER)))
        self.assertEqual(os.readlink(os.path.join(installs, "current")), "2.0.0")
        self.assertEqual(sorted(os.listdir(installs)), ["2.0.0", "current"])
        self.assertEqual(stat.S_IMODE(os.stat(installs).st_mode), 0o700)
        self.assertEqual(os.listdir(self.work), [])
        # Again, latest unchanged: resolved, kept, nothing installed.
        code, _, err = self.install(payload("again", package=latest))
        self.assertEqual(code, 0, err)
        self.assertIn("xyz 2.0.0 already installed", err)
        self.assertEqual(self.npm_calls(), ["view --json @xyz/agent@latest version"])
        # A newer latest: installed beside it even though one is installed.
        code, _, err = self.install(payload("newer", package=latest), FAKE_LATEST="2.1.0")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(".program").strip(), os.path.join(installs, "2.1.0", "bin", NAME))
        self.assertEqual(os.readlink(os.path.join(installs, "current")), "2.1.0")
        self.assertEqual(sorted(os.listdir(installs)), ["2.0.0", "2.1.0", "current"])
        self.assertEqual(len(self.npm_calls()), 2)

    def test_an_exact_version_installs_without_resolving(self):
        installs = self.npm()
        for version in ("1.0.0", "3.0.0-rc.1"):
            code, _, err = self.install(payload("go", package=descriptor(install={"version": version})))
            self.assertEqual(code, 0, err)
            directory = os.path.join(installs, version)
            self.assertEqual(self.npm_calls(), [
                "install --global --prefix %s --no-audit --no-fund @xyz/agent@%s" % (directory, version)])
            self.assertEqual(self.read(".program").strip(), os.path.join(directory, "bin", NAME))
            self.assertEqual(os.readlink(os.path.join(installs, "current")), version)
        # An older exact version, already installed: kept, made current.
        code, _, err = self.install(payload("go", package=descriptor(install={"version": "1.0.0"})))
        self.assertEqual(code, 0, err)
        self.assertIn("xyz 1.0.0 already installed", err)
        self.assertEqual(self.npm_calls(), [])
        self.assertEqual(os.readlink(os.path.join(installs, "current")), "1.0.0")

    def test_without_install_current_then_path_and_never_npm(self):
        installs = self.npm()
        unflagged = descriptor()
        # Nothing installed, nothing on PATH.
        code, _, err = self.install(payload("go", package=unflagged))
        self.assertEqual(code, 93)
        self.assertIn("error code=agent_not_installed", err)
        on_path = self.script(NAME)
        code, _, err = self.install(payload("path", package=unflagged))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read(".program").strip(), on_path)
        self.install(payload("go", package=descriptor(install={"version": "1.0.0"})))
        self.npm_calls()
        # The last explicit install wins over PATH (a baked agent), bare
        # name or absolute path alike.
        for program in (NAME, on_path):
            code, _, err = self.install(payload("current", [program], package=unflagged))
            self.assertEqual(code, 0, err)
            self.assertEqual(self.read(".program").strip(), os.path.join(installs, "1.0.0", "bin", NAME))
        # Incomplete (no marker), a bad or a dangling `current`: PATH.
        current = os.path.join(installs, "current")
        os.unlink(os.path.join(installs, "1.0.0", MARKER))
        for target in ("1.0.0", "../elsewhere", "9.9.9", "/abs"):
            os.unlink(current)
            os.symlink(target, current)
            code, _, err = self.install(payload("fallback", package=unflagged))
            self.assertEqual(code, 0, err)
            self.assertEqual(self.read(".program").strip(), on_path, target)
        # An earlier layout (an unpacked tarball, no marker): ignored.
        old = os.path.join(installs, "0.9.0", "package", "dist", "bundle")
        os.makedirs(old)
        self.script("cli.js", directory=old)
        os.unlink(current)
        os.symlink("0.9.0", current)
        code, _, _ = self.install(payload("old", package=unflagged))
        self.assertEqual(self.read(".program").strip(), on_path)
        # No install asked: npm is never run.
        self.assertEqual(self.npm_calls(), [])

    def test_a_stale_incomplete_install_is_replaced(self):
        installs = self.npm()
        directory = os.path.join(installs, "1.0.0")
        os.makedirs(os.path.join(directory, "lib", "node_modules", "stale"))
        os.makedirs(os.path.join(directory, "bin"))
        self.script(NAME, directory=os.path.join(directory, "bin"))  # a complete-looking bin, no marker
        code, _, err = self.install(payload("go", package=descriptor(install={"version": "1.0.0"})))
        self.assertEqual(code, 0, err)
        self.assertIn("xyz 1.0.0 installed", err)
        self.assertFalse(os.path.exists(os.path.join(directory, "lib", "node_modules", "stale")))
        self.assertTrue(os.path.islink(os.path.join(directory, "bin", NAME)))
        # A file or link where the version's directory goes: replaced too.
        os.unlink(os.path.join(directory, MARKER))
        shutil.rmtree(directory)
        os.symlink(self.elsewhere, directory)
        code, _, err = self.install(payload("go", package=descriptor(install={"version": "1.0.0"})))
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.islink(directory))
        self.assertEqual(sorted(os.listdir(self.elsewhere)), ["agent-source"])

    def test_failed_installs_leave_no_complete_version_and_no_credential(self):
        installs = self.npm()
        self.install(payload("go", package=descriptor(install={"version": "1.0.0"})))
        self.npm_calls()
        os.unlink(self.log + ".argv")
        cases = [
            ({"version": None}, {"FAKE_VIEW_FAIL": "1"}, "install_resolve_failed", None),
            ({"version": None}, {"FAKE_VIEW_OUT": "latest"}, "install_resolve_failed", None),
            ({"version": None}, {"FAKE_VIEW_OUT": '"../x"'}, "install_resolve_failed", None),
            ({"version": None}, {"FAKE_VIEW_OUT": '["2.0.0"]'}, "install_resolve_failed", None),
            ({"version": "2.0.0"}, {"FAKE_NPM_FAIL": "1"}, "install_failed", "2.0.0"),
            ({"version": "2.0.0"}, {"FAKE_NO_BIN": "1"}, "install_incomplete", "2.0.0"),
        ]
        for install, env, code_name, version in cases:
            with self.subTest(code_name, env=env):
                code, _, err = self.install(with_auth(package=descriptor(install=install)), **env)
                self.assertEqual(code, 91, err)
                self.assertIn("error code=%s" % code_name, err)
                self.assertFalse(os.path.lexists(self.auth()))
                self.assertFalse(os.path.exists(self.log + ".argv"))
                if version is not None:
                    self.assertFalse(os.path.exists(os.path.join(installs, version, MARKER)))
                self.assertEqual(os.readlink(os.path.join(installs, "current")), "1.0.0")
                self.npm_calls()
        # Without npm on PATH (only the scratch's: never a real npm).
        os.unlink(os.path.join(self.bin, "npm"))
        code, _, err = self.install(with_auth(package=descriptor(install={"version": "2.0.0"})), PATH=self.bin)
        self.assertEqual(code, 91)
        self.assertIn("error code=install_npm_missing", err)
        # An unusable install root.
        shutil.rmtree(os.path.join(self.home, ".local"))
        with open(os.path.join(self.home, ".local"), "w") as stream:
            stream.write("not a directory")
        self.npm()
        code, _, err = self.install(payload("go", package=descriptor(install={"version": "2.0.0"})))
        self.assertEqual(code, 91)
        self.assertIn("error code=install_location_unusable", err)

    def test_a_stop_during_npm_is_forwarded_and_completes_nothing(self):
        installs = self.npm()
        process = self.start(with_auth(package=descriptor(install={"version": "1.0.0"})),
                             FAKE_AGENT=os.path.join(self.elsewhere, "agent-source"), FAKE_NPM_SLEEP="30")
        self.wait_for(".ready")
        process.send_signal(signal.SIGTERM)
        _, err = process.communicate(timeout=20)
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(process.returncode, 143, err)
        self.assertEqual(self.read(".npm-term").strip(), "term")
        self.assertFalse(os.path.exists(os.path.join(installs, "1.0.0", MARKER)))
        self.assertFalse(os.path.lexists(os.path.join(installs, "current")))
        self.assertFalse(os.path.lexists(os.path.join(self.home, ".config")))
        self.assertFalse(os.path.exists(self.log + ".argv"))
        # The next install replaces the interrupted one.
        os.unlink(self.log + ".ready")
        code, _, err = self.install(payload("go", package=descriptor(install={"version": "1.0.0"})))
        self.assertEqual(code, 0, err)
        self.assertTrue(os.path.isfile(os.path.join(installs, "1.0.0", MARKER)))


def staged(nonce, credential=None, auth=None, argv=None, package=None, prompt="", env=None):
    """The interactive payload: no prompt, the header naming `nonce`, with
    the `--env` selection (`env`)."""
    settings = {"argv": argv or [NAME], "auth": auth, "package": package}
    body = (credential or "").encode()
    header = {"schema": "agentbox.agent-input.v3", "prompt_bytes": len(prompt.encode()),
              "credential_bytes": len(body), "settings": settings, "stage": nonce,
              "env": {} if env is None else env}
    return json.dumps(header, ensure_ascii=False).encode() + b"\n" + prompt.encode() + body


NONCE = "0123456789abcdef0123456789abcdef"

# A stand-in agent recording, as JSON, its environment's `FAKE_ENV_*` and
# fixed names, then its child's (the agent's own subprocess).
FAKE_ENV = """#!%s -I
import json, os, subprocess, sys
def seen():
    return {k: v for k, v in os.environ.items()
            if k.startswith("FAKE_ENV_") or k in ("HOME", "PATH", "LANG", "AMBIENT")}
child = subprocess.run([sys.executable, "-I", "-c", "import json, os; print(json.dumps(dict(os.environ)))"],
                       capture_output=True, check=True)
with open(os.environ["FAKE_LOG"] + ".env", "w") as f:
    json.dump({"agent": seen(), "child": json.loads(child.stdout)}, f)
""" % sys.executable

# Exact values: Unicode, empty, spaces, `$`, quotes, newlines, a tab.
ENV_VALUES = {"FAKE_ENV_A": "\u00e9t\u00e9 \U0001f600", "FAKE_ENV_EMPTY": "",
              "FAKE_ENV_SPACE": "  two  spaces ", "FAKE_ENV_SHELL": "$HOME `x` \"q\" 'y' \\",
              "FAKE_ENV_LINES": "one\ntwo\n\tthree\n"}

# A stand-in interactive agent (this Python): its process group and the
# terminal's foreground group, the interrupts it saw, then lines until
# `exit` (status 7); FAKE_STOP stops itself first.
FAKE_TTY = """#!%s -I
import os, signal, sys
log = os.environ["FAKE_LOG"]
count = [0]
def interrupted(*_):
    count[0] += 1
    with open(log + ".int", "w") as f:
        f.write(str(count[0]))
signal.signal(signal.SIGINT, interrupted)
with open(log + ".argv", "w") as f:
    f.write("\\n".join(sys.argv[1:]) + "\\n")
auth = os.path.join(os.environ["HOME"], os.environ["FAKE_AUTH"])
if os.path.exists(auth):
    with open(auth, "rb") as f, open(log + ".auth", "wb") as out:
        out.write(f.read())
with open(log + ".pgrp", "w") as f:
    f.write("%%d %%d %%d" %% (os.getpgrp(), os.tcgetpgrp(0), os.getppid()))
if os.environ.get("FAKE_STOP"):
    os.kill(os.getpid(), signal.SIGSTOP)
with open(log + ".ready", "w") as f:
    f.write("ready")
while True:
    line = sys.stdin.readline()
    if not line or line.strip() == "exit":
        sys.exit(7 if line else 8)
""" % sys.executable


class Interactive(Scratch):
    """The interactive modes: `stage` (stdin to the private staging file,
    its receipt on stdout), `run` (that very file consumed, the agent on
    the terminal) and `unstage`; /dev/shm replaced by a scratch root."""

    def setUp(self):
        super().setUp()
        self.shm = os.path.join(self.root, "shm")
        os.mkdir(self.shm, 0o700)
        fixed = 'SHM = "/dev/shm"'
        self.assertEqual(self.text.count(fixed), 1)
        self.text = self.text.replace(fixed, "SHM = %r" % self.shm)
        self.dir = os.path.join(self.shm, "agentbox-agent-%d" % os.getuid())
        self.file = os.path.join(self.dir, NONCE)

    def mode(self, mode, nonce=NONCE, receipt="-", data=None, **env):
        full = {"HOME": self.home, "PATH": "%s:/usr/bin:/bin" % self.bin, "LANG": "C.UTF-8",
                "FAKE_LOG": self.log, "FAKE_AUTH": AUTH}
        full.update(env)
        process = subprocess.run(self.runner(mode, nonce, receipt), input=data,
                                 stdin=None if data is not None else subprocess.DEVNULL,
                                 capture_output=True, cwd=self.work, env=full, timeout=60)
        return process.returncode, process.stdout.decode(), process.stderr.decode()

    def stage(self, data):
        code, out, err = self.mode("stage", data=data)
        self.assertEqual(code, 0, err)
        self.assertRegex(out, r"^\d+:\d+:\d+:\d+\n$")
        return out.strip()

    def test_a_staged_payload_is_consumed_once_and_the_credential_placed_and_removed(self):
        self.script(NAME)
        credential = '{"token":"synthetic-\u00e9t\u00e9-\u4e2d","refresh":"synthetic-r"}'
        for keep in (False, True):
            receipt = self.stage(staged(NONCE, credential=credential,
                                        auth={"path": AUTH, "keep": keep}, argv=[NAME, "--x"]))
            info = os.lstat(self.file)
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_nlink), (0o600, 1))
            self.assertEqual(stat.S_IMODE(os.lstat(self.dir).st_mode), 0o700)
            self.assertEqual(receipt, "%d:%d:%d:%d" % (info.st_dev, info.st_ino,
                                                       os.lstat(self.dir).st_dev,
                                                       os.lstat(self.dir).st_ino))
            code, out, err = self.mode("run", receipt=receipt, FAKE_EXIT="3")
            self.assertEqual((code, out), (3, ""), err)
            self.assertEqual(self.args(), ["--x"])
            with open(self.log + ".auth", "rb") as stream:
                self.assertEqual(stream.read(), credential.encode())
            # The staged copy is gone whatever keep; its directory too.
            self.assertFalse(os.path.lexists(self.dir))
            self.assertEqual(os.path.lexists(self.auth()), keep)
            self.assertNotIn("synthetic-", out + err)
            if keep:
                os.unlink(self.auth())
            # Consumed: a second run finds nothing, refuses, runs nothing.
            os.unlink(self.log + ".argv")
            code, _, err = self.mode("run", receipt=receipt)
            self.assertEqual(code, 95)
            self.assertIn("error code=stage_missing", err)
            self.assertFalse(os.path.exists(self.log + ".argv"))

    def test_an_agent_ending_at_once_keeps_its_own_status(self):
        # Ended (or killed) before the runner waits for it, its process
        # object held meanwhile: its status is the runner's, never lost to a
        # reap of its own (94). Each Popen here lingers 0.3 s after its
        # start, so the agent has always ended by then.
        slow = ('import sys,time,subprocess as s;i=s.Popen.__init__;'
                's.Popen.__init__=lambda o,*a,**k:(i(o,*a,**k),time.sleep(0.3))[0];'
                'exec("".join(sys.argv[1:-3]))')
        runner = self.runner
        self.runner = lambda *words: [arg if arg != LOADER else slow for arg in runner(*words)]
        for text, expected in (("#!/bin/sh\nexit 7\n", 7),
                               ("#!/bin/sh\nkill -TERM $$\n", 128 + 15)):
            self.script(NAME, text)
            for _ in range(3):
                receipt = self.stage(staged(NONCE))
                code, _, err = self.mode("run", receipt=receipt)
                self.assertEqual(code, expected, err)

    def test_a_replacement_is_refused_and_left_even_a_byte_identical_one(self):
        self.script(NAME)
        data = staged(NONCE, credential=CREDENTIAL, auth={"path": AUTH, "keep": False})
        for replace in ("copy", "link", "directory", "hardlink"):
            receipt = self.stage(data)
            if replace == "copy":
                # The valid nonce and header, byte for byte: another inode.
                with open(self.file + ".new", "wb") as stream:
                    stream.write(data)
                os.chmod(self.file + ".new", 0o600)
                os.rename(self.file + ".new", self.file)
            elif replace == "link":
                with open(os.path.join(self.root, "elsewhere", "copy"), "wb") as stream:
                    stream.write(data)
                os.unlink(self.file)
                os.symlink(os.path.join(self.root, "elsewhere", "copy"), self.file)
            elif replace == "directory":
                os.rename(self.dir, self.dir + "-old")
                os.mkdir(self.dir, 0o700)
                shutil.copy(self.dir + "-old/" + NONCE, self.file)
                os.chmod(self.file, 0o600)
            else:
                os.link(self.file, os.path.join(self.root, "elsewhere", "second"))
            code, _, err = self.mode("run", receipt=receipt)
            self.assertEqual(code, 95, (replace, err))
            self.assertIn("error code=stage_mismatch", err)
            self.assertTrue(os.path.lexists(self.file), replace)
            code, _, err = self.mode("unstage", receipt=receipt)
            if replace == "hardlink":
                # The very file staged, another name beside it: never
                # consumed, but its own name removed.
                self.assertEqual(code, 0, err)
                self.assertFalse(os.path.lexists(self.file))
                os.mkdir(self.dir, 0o700)
            else:
                self.assertEqual(code, 95, (replace, err))
                self.assertIn("warning: staging_left", err)
                self.assertTrue(os.path.lexists(self.file), replace)
            self.assertFalse(os.path.exists(self.log + ".argv"))
            self.assertFalse(os.path.lexists(self.auth()))
            shutil.rmtree(self.dir)
            shutil.rmtree(self.dir + "-old", ignore_errors=True)
            for name in os.listdir(os.path.join(self.root, "elsewhere")):
                os.unlink(os.path.join(self.root, "elsewhere", name))

    def test_unstaging_removes_only_the_staged_file_once(self):
        receipt = self.stage(staged(NONCE))
        code, _, err = self.mode("unstage", receipt=receipt)
        self.assertEqual(code, 0, err)
        self.assertIn("staged payload removed", err)
        self.assertFalse(os.path.lexists(self.dir))
        code, _, err = self.mode("unstage", receipt=receipt)
        self.assertEqual(code, 0, err)
        self.assertIn("staged payload already gone", err)
        # Another staged file in the directory keeps it.
        other = "f" * 32
        self.stage(staged(NONCE))
        code, _, err = self.mode("stage", nonce=other, data=staged(other))
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(os.listdir(self.dir)), sorted([NONCE, other]))

    def test_staging_refuses_unsafe_places_existing_files_and_foreign_input(self):
        receipt = self.stage(staged(NONCE))
        code, _, err = self.mode("stage", data=staged(NONCE))
        self.assertEqual(code, 95)
        self.assertIn("error code=stage_exists", err)
        self.assertTrue(os.path.exists(self.file))
        self.assertEqual(self.mode("unstage", receipt=receipt)[0], 0)
        for data in (staged("f" * 32), staged(NONCE, prompt="go"), payload("go"),
                     staged(NONCE, package=descriptor(install={"version": None}))):
            code, _, err = self.mode("stage", data=data)
            self.assertEqual(code, 90, data)
            self.assertIn("error code=input_invalid", err)
        self.assertFalse(os.path.lexists(self.dir))
        os.mkdir(self.dir, 0o755)
        code, _, err = self.mode("stage", data=staged(NONCE))
        self.assertEqual(code, 95)
        self.assertIn("error code=staging_unsafe", err)
        os.rmdir(self.dir)
        os.symlink(self.elsewhere, self.dir)
        self.assertEqual(self.mode("stage", data=staged(NONCE))[0], 95)
        self.assertEqual(os.listdir(self.elsewhere), [])
        os.unlink(self.dir)
        os.rmdir(self.shm)
        code, _, err = self.mode("stage", data=staged(NONCE))
        self.assertEqual(code, 95)
        self.assertIn("error code=staging_unavailable", err)
        # Malformed mode words: nothing read or run.
        for words in (("stage", "-", "-"), ("stage", NONCE, "1:2:3:4"), ("run", NONCE, "-"),
                      ("run", NONCE, "1:2:3"), ("run", NONCE, "\u0661:2:3:4"),
                      ("unstage", NONCE, "1:2:3:" + "9" * 21), ("unstage", "x" * 32, "1:2:3:4"),
                      ("headless", NONCE, "-"), ("other", "-", "-")):
            code, _, err = self.mode(*words, data=b"")
            self.assertEqual(code, 90, words)

    def test_the_staged_environment_reaches_the_agent_and_its_children_only(self):
        self.script(NAME, FAKE_ENV)
        receipt = self.stage(staged(NONCE, env=ENV_VALUES))
        # The staged copy holds them, private; the stage applied none.
        self.assertEqual(stat.S_IMODE(os.lstat(self.file).st_mode), 0o600)
        self.assertFalse(os.path.exists(self.log + ".env"))
        code, out, err = self.mode("run", receipt=receipt, AMBIENT="session", FAKE_ENV_A="ambient")
        self.assertEqual((code, out), (0, ""), err)
        with open(self.log + ".env") as stream:
            seen = json.load(stream)
        # Over the session's own: the selection wins, the rest stays.
        expected = dict(ENV_VALUES, HOME=self.home, PATH="%s:/usr/bin:/bin" % self.bin,
                        LANG="C.UTF-8", AMBIENT="session")
        self.assertEqual(seen["agent"], expected)
        for name, value in expected.items():
            self.assertEqual(seen["child"][name], value)
        for value in ENV_VALUES.values():
            if value:
                self.assertNotIn(value, out + err)
        self.assertFalse(os.path.lexists(self.dir))
        # Without a selection: the session's environment as it is.
        receipt = self.stage(staged(NONCE))
        code, _, err = self.mode("run", receipt=receipt)
        self.assertEqual(code, 0, err)
        with open(self.log + ".env") as stream:
            self.assertEqual(json.load(stream)["agent"],
                             {"HOME": self.home, "PATH": "%s:/usr/bin:/bin" % self.bin,
                              "LANG": "C.UTF-8"})
        # Unstage applies nothing either: it runs nothing.
        os.unlink(self.log + ".env")
        receipt = self.stage(staged(NONCE, env=ENV_VALUES))
        code, _, err = self.mode("unstage", receipt=receipt)
        self.assertEqual(code, 0, err)
        self.assertFalse(os.path.exists(self.log + ".env"))

    def test_a_malformed_staged_environment_refuses_before_anything(self):
        self.script(NAME, FAKE_ENV)
        secret = "synthetic-env-value-6b1f"
        for env in ([["A", secret]], {"A": 1}, {"A": None}, {"A-B": secret}, {"1A": secret},
                    {"": secret}, {"A=B": secret}, {"A": "x\0" + secret}, "A=" + secret):
            code, out, err = self.mode("stage", data=staged(NONCE, env=env))
            self.assertEqual(code, 90, env)
            self.assertIn("error code=input_invalid", err)
            self.assertNotIn(secret, out + err)
            self.assertFalse(os.path.lexists(self.dir))
        # A staged header without `env`, or a headless one with it: refused.
        data = staged(NONCE)
        end = data.index(b"\n")
        header = json.loads(data[:end])
        del header["env"]
        code, _, err = self.mode("stage", data=json.dumps(header).encode() + data[end:])
        self.assertEqual(code, 90)
        data = payload("go")
        end = data.index(b"\n")
        header = json.loads(data[:end])
        header["env"] = {"FAKE_ENV_A": secret}
        code, out, err = self.mode("headless", "-", "-", data=json.dumps(header).encode() + data[end:])
        self.assertEqual(code, 90)
        self.assertNotIn(secret, out + err)
        self.assertFalse(os.path.exists(self.log + ".env"))

    def pty_run(self, receipt, keys, **env):
        """The runner's `run` on a new terminal as a session's (an SSH
        login's) process: `keys` typed once the agent is ready; its status
        and the terminal's output."""
        import pty
        import select
        full = {"HOME": self.home, "PATH": "%s:/usr/bin:/bin" % self.bin, "LANG": "C.UTF-8",
                "FAKE_LOG": self.log, "FAKE_AUTH": AUTH}
        full.update(env)
        pid, master = pty.fork()
        if pid == 0:
            os.chdir(self.work)
            os.execve(sys.executable, self.runner("run", NONCE, receipt), full)
        output = bytearray()
        deadline = time.monotonic() + 30
        typed = list(keys)
        status = None
        while status is None:
            self.assertLess(time.monotonic(), deadline, output)
            ready, _, _ = select.select([master], [], [], 0.05)
            if ready:
                try:
                    output.extend(os.read(master, 65536))
                except OSError:
                    pass
            if typed and os.path.exists(self.log + ".ready"):
                os.write(master, typed.pop(0))
                time.sleep(0.2)
            done, code = os.waitpid(pid, os.WNOHANG)
            if done:
                status = os.waitstatus_to_exitcode(code)
        while select.select([master], [], [], 0.2)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
        os.close(master)
        return status, output.decode(errors="replace"), pid

    def test_on_a_terminal_the_agent_has_the_foreground_and_its_own_keys(self):
        self.script(NAME, FAKE_TTY)
        receipt = self.stage(staged(NONCE, credential=CREDENTIAL,
                                    auth={"path": AUTH, "keep": False}))
        # Ctrl-C reaches the agent once (never forwarded again); Ctrl-Z
        # stops nothing for good; then its own exit.
        status, output, runner = self.pty_run(receipt, [b"\x03", b"\x1a", b"exit\n"])
        self.assertEqual(status, 7, output)
        self.assertEqual(self.read(".int"), "1")
        group, foreground, parent = (int(word) for word in self.read(".pgrp").split())
        self.assertEqual((group, foreground, parent), (runner, runner, runner))
        self.assertEqual(self.read(".auth"), CREDENTIAL)
        self.assertFalse(os.path.lexists(self.auth()))
        self.assertIn("credential removed", output)
        self.assertFalse(os.path.lexists(self.dir))
        # An agent stopped (SIGSTOP) is continued: no job control here.
        os.unlink(self.log + ".ready")
        receipt = self.stage(staged(NONCE))
        status, output, _ = self.pty_run(receipt, [b"exit\n"], FAKE_STOP="1")
        self.assertEqual(status, 7, output)


class WrapperCap(unittest.TestCase):
    """Each adapter's runner bound (MAX_WRAPPER_BYTES, 26 KiB), on a copy
    of its tree with a runner of the size tested: at the cap its plan, past
    it `wrapper_invalid`. The cap is no promise that every combination fits
    the host's 64 KiB plan: a cap-sized runner of JSON escapes with the
    largest escaped credential refuses whole (`plan_too_large`)."""

    CAP = 26 * 1024

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="agentbox-wrapper-cap-")

    def tearDown(self):
        shutil.rmtree(self.root)

    def adapter(self, agent, size, auth=None):
        tree = tempfile.mkdtemp(prefix="%s-%d-" % (agent, size), dir=self.root)
        shutil.copytree(os.path.join(HERE, agent), os.path.join(tree, agent),
                        ignore=shutil.ignore_patterns("__pycache__"))
        os.mkdir(os.path.join(tree, "jail"))
        text = ('"\\\n' * size)[:size]
        with open(os.path.join(tree, "jail", "run.py"), "w") as stream:
            stream.write(text)
        request = {"schema": "agentbox.agent-request.v1", "agent": agent, "model": None,
                   "install": None, "auth": auth, "interactive": None}
        read, write = os.pipe()
        try:
            process = subprocess.run(
                ["/bin/sh", "-c", 'exec "$0" "$@" 3>&%d %d>&-' % (write, write),
                 sys.executable, "-I", "-S", "-B", os.path.join(tree, agent, "adapter.py")],
                input=json.dumps(request).encode(), capture_output=True, env={}, cwd="/",
                pass_fds=(write,), timeout=30)
        finally:
            os.close(write)
        with os.fdopen(read, "rb") as stream:
            result = json.loads(stream.read().decode())
        return result, process.stdout

    def test_the_runner_cap_and_the_plans_own_bound(self):
        for agent in ("pi", "codex", "claude"):
            result, plan = self.adapter(agent, self.CAP)
            self.assertEqual(result, {"schema": "agentbox.agent-result.v1", "outcome": "ok"}, agent)
            self.assertLessEqual(len(plan), 64 * 1024)
            self.assertEqual("".join(json.loads(plan)["argv"][7:]), ('"\\\n' * self.CAP)[:self.CAP])
            result, plan = self.adapter(agent, self.CAP + 1)
            self.assertEqual(result.get("code"), "wrapper_invalid", agent)
            self.assertEqual(plan, b"")
        head, tail = b'{"x":"', b'"}'
        escaped = head + b"\\\\" * ((16 * 1024 - len(head) - len(tail)) // 2) + tail
        path = os.path.join(self.root, "auth.json")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(escaped)
        for agent in ("codex", "claude"):
            result, plan = self.adapter(agent, self.CAP, auth={"path": path, "keep": False})
            self.assertEqual(result.get("code"), "plan_too_large", agent)
            self.assertEqual(plan, b"")


if __name__ == "__main__":
    unittest.main()
