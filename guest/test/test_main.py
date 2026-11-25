"""The installed entrypoint over real stdio, the marker diagnostic, the
supplied profile, the request clock and the HOME guidance. Only argument
refusals and sessions that end before any command: nothing touches the fixed
guest directories and nothing runs."""

import os
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

from guest.src.artifact_post_clock import capture_request_deadline
from guest.src.artifact_post_protocol import REQUEST_TIMEOUT_MS
from guest.src.execution import GUEST_VERSION
from guest.src.persistence_marker import MARKER_FILE, check_marker, marker_main, write_marker
from guest.src.protocol import decode_guest_frame, encode_host_frame
from guest.src.runtime import FLAGS, python_argv
from guest.src.main import DEFAULT_SHELL, shell
from guest.src.worker_profile import (MAX_PATH_BYTES, SHELL, SUPPLIED_MOUNTED, SUPPLIED_SESSION, is_plain_absolute,
                                      shell_session,
                                      supplied_session)

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAIN = os.path.join(REPO, "guest", "src", "main.py")
HOME = "/srv/jail-root/agentbox-worker-v1/home"
WORK = "/srv/jail-root/agentbox-worker-v1/home/work"
BIN = "/srv/jail-root/agentbox-worker-v1/releases/abc-0123/bin"
# The serving owner's session nonce (the interactive form's SESSION).
NONCE = "0123456789abcdef0123456789abcdef"


def run(args, data=b"", env=None):
    done = subprocess.run(python_argv(MAIN, *args), input=data, capture_output=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin"} if env is None else env)
    return done.returncode, done.stdout


class Entrypoint(unittest.TestCase):
    def test_unknown_arguments_and_marker_misuse_are_refused(self):
        self.assertEqual(run(["--shell"]), (2, b""))
        self.assertEqual(run(["runtime-check-v1"]), (2, b""))
        self.assertEqual(run(["persistence-marker", "erase", "x"]), (2, b"persistence-marker: usage\n"))

    def test_a_session_answers_the_host_hello_on_stdout(self):
        # The input ends before any exec: the session reports its input lost.
        status, stdout = run([], encode_host_frame({"v": 1, "type": "hello", "session": "nonce-1"}) + b"\n")
        self.assertEqual(status, 2)
        lines = stdout.split(b"\n")
        self.assertEqual(lines[-1], b"")
        self.assertEqual(len(lines), 2)
        self.assertEqual(decode_guest_frame(lines[0]),
                         {"v": 1, "type": "hello", "session": "nonce-1", "guest_version": GUEST_VERSION})

    def test_retired_v2_agent_sessions_are_refused_without_fallback_or_payload_echo(self):
        data = (b'{"v":2,"type":"hello","session":"nonce-2"}\n'
                b'{"v":2,"type":"agent","credential":{"access":"retired-secret-sentinel"}}\n')
        status, stdout = run([], data)
        self.assertEqual(status, 1)
        self.assertEqual(stdout, b'{"v":1,"type":"error","code":"unsupported_version"}\n')

    def test_sigterm_or_sighup_is_the_loss_of_the_hosts_input(self):
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        os.mkdir(os.path.join(directory, "work"), 0o700)
        for number in (signal.SIGTERM, signal.SIGHUP):
            child = subprocess.Popen(python_argv(MAIN, SUPPLIED_SESSION, directory, os.path.join(directory, "work"),
                                                 os.path.join(directory, "bin")),
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, env={"PATH": "/usr/bin:/bin"})
            child.stdin.write(encode_host_frame({"v": 1, "type": "hello", "session": "s1"}) + b"\n")
            child.stdin.flush()
            line = child.stdout.readline()
            self.assertEqual(decode_guest_frame(line.rstrip(b"\n"))["type"], "hello")
            child.send_signal(number)
            self.assertEqual(child.wait(timeout=10), 2)
            child.stdin.close()
            child.stdout.close()

    def test_the_interactive_form_runs_its_command_in_the_tasks_fixed_environment(self):
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        work, binary = os.path.join(directory, "work"), os.path.join(directory, "bin")
        script = ('pwd; echo "$TERM"; echo "$PATH"; echo "$HOME"; echo "$HTTPS_PROXY"; echo "${SSH_TTY-unset}"; '
                  'echo "$AGENTBOX_REQUEST_SESSION"; echo "$AGENTBOX_WORK_ROOT"; echo "${AGENTBOX_WORK_MOUNT-unset}"')
        done = subprocess.run(python_argv(MAIN, SUPPLIED_SESSION, directory, work, binary, SHELL, "xterm-256color",
                                          NONCE, "sh", "-c", script),
                              capture_output=True, timeout=30,
                              env={"PATH": "/usr/bin:/bin", "SSH_TTY": "/dev/pts/9", "TERM": "vt100",
                                   "AGENTBOX_REQUEST_SESSION": "f" * 32, "AGENTBOX_WORK_MOUNT": "/stale"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.decode().split("\n"), [
            work, "xterm-256color",
            binary + ":/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:" + directory + "/.local/bin",
            directory, "http://127.0.0.1:18080", "unset", NONCE, work, "unset", ""])
        self.assertEqual(os.stat(work).st_mode & 0o777, 0o700)

    def test_the_interactive_form_names_a_mounted_working_directorys_root(self):
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        mount = os.path.join(directory, "src")
        project = os.path.join(mount, "app")
        os.makedirs(project, 0o755)
        os.chmod(directory, 0o700)
        script = 'echo "$AGENTBOX_REQUEST_SESSION"; echo "$AGENTBOX_WORK_ROOT"; echo "$AGENTBOX_WORK_MOUNT"'
        done = subprocess.run(python_argv(MAIN, SUPPLIED_MOUNTED, directory, project, os.path.join(directory, "bin"),
                                          mount, SHELL, "dumb", NONCE, "sh", "-c", script),
                              capture_output=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.decode().split("\n"), [NONCE, project, mount, ""])

    def test_the_interactive_form_reports_a_command_it_cannot_run(self):
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        done = subprocess.run(python_argv(MAIN, SUPPLIED_SESSION, directory, os.path.join(directory, "work"),
                                          os.path.join(directory, "bin"), SHELL, "dumb", NONCE,
                                          "agentbox-no-such-command"),
                              capture_output=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual((done.returncode, done.stdout), (127, b""))
        self.assertEqual(done.stderr, b"agentbox-shell: command not run\n")

    def test_without_a_command_the_accounts_shell_runs_interactive(self):
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        calls = []
        profile = shell_session([SUPPLIED_SESSION, directory, os.path.join(directory, "work"),
                                 os.path.join(directory, "bin"), SHELL, "dumb", NONCE])
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        self.assertEqual(shell(profile, execvpe=lambda *call: calls.append(call)), 127)
        ((program, argv, env),) = calls
        self.assertEqual(argv, [program, "-i"])
        self.assertTrue(program.startswith("/"), program)
        self.assertEqual(env["TERM"], "dumb")
        self.assertEqual((env["AGENTBOX_REQUEST_SESSION"], env["AGENTBOX_WORK_ROOT"]),
                         (NONCE, os.path.join(directory, "work")))
        self.assertNotIn("AGENTBOX_WORK_MOUNT", env)
        self.assertEqual(DEFAULT_SHELL, "/bin/sh")

    def test_the_interactive_form_runs_behind_the_installations_session_wrapper(self):
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        binary = os.path.join(directory, "bin")
        os.mkdir(binary)
        wrapper = os.path.join(binary, "agentbox-session")
        with open(wrapper, "w") as stream:
            stream.write("#!/bin/sh\nexec \"$@\"\n")
        os.chmod(wrapper, 0o700)
        cwd = os.getcwd()
        self.addCleanup(os.chdir, cwd)
        for argv, expected in (([], None), (["sh", "-c", "x"], [wrapper, "sh", "-c", "x"]),
                               (["agentbox-no-such-command"], ["agentbox-no-such-command"])):
            calls = []
            profile = shell_session([SUPPLIED_SESSION, directory, os.path.join(directory, "work"), binary, SHELL,
                                     "dumb", NONCE, *argv])
            self.assertEqual(shell(profile, execvpe=lambda *call: calls.append(call)), 127)
            ((program, called, _env),) = calls
            if expected is None:
                self.assertEqual((program, called[0], called[2]), (wrapper, wrapper, "-i"))
            else:
                self.assertEqual((program, called), (expected[0], expected))

    def test_the_isolated_interpreter_ignores_its_environment_and_working_directory(self):
        # A module of a guest name in the working directory, HOME or
        # PYTHONPATH never shadows the bundle's.
        directory = tempfile.mkdtemp(prefix="agentbox-main-")
        self.addCleanup(shutil.rmtree, directory, True)
        for name in ("json.py", "asyncio.py", "sitecustomize.py", "usercustomize.py"):
            with open(os.path.join(directory, name), "w") as stream:
                stream.write("raise SystemExit(99)\n")
        os.makedirs(os.path.join(directory, "guest", "src"))
        for name in ("__init__.py", os.path.join("guest", "__init__.py"), os.path.join("guest", "src", "__init__.py"),
                     os.path.join("guest", "src", "protocol.py")):
            with open(os.path.join(directory, name), "w") as stream:
                stream.write("raise SystemExit(98)\n")
        done = subprocess.run(python_argv(MAIN, "--shell"), capture_output=True, timeout=30, cwd=directory,
                              env={"PATH": "/usr/bin:/bin", "HOME": directory, "PYTHONPATH": directory,
                                   "PYTHONSTARTUP": os.path.join(directory, "json.py"), "PYTHONUSERBASE": directory})
        self.assertEqual(done.returncode, 2, done.stderr)
        self.assertEqual(FLAGS, ("-I", "-S", "-B", "-X", "utf8"))


class Marker(unittest.TestCase):
    def scratch(self):
        directory = tempfile.mkdtemp(prefix="agentbox-marker-test-")
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    def test_a_written_marker_is_present_for_its_token_only(self):
        directory = os.path.join(self.scratch(), "state")
        self.assertEqual(check_marker(directory, "boot-1"), "absent")
        write_marker(directory, "boot-1")
        self.assertEqual(check_marker(directory, "boot-1"), "present")
        self.assertEqual(check_marker(directory, "boot-2"), "mismatch")
        self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(directory, MARKER_FILE)).st_mode & 0o777, 0o600)
        write_marker(directory, "boot-2")
        self.assertEqual(check_marker(directory, "boot-2"), "present")

    def test_tampered_linked_or_invalid_markers_are_refused(self):
        root = self.scratch()
        directory = os.path.join(root, "state")
        write_marker(directory, "boot-1")
        with open(os.path.join(directory, MARKER_FILE), "w") as stream:
            stream.write("agentbox.persistence-marker.v1 boot-1 extra\n")
        self.assertEqual(check_marker(directory, "boot-1"), "mismatch")
        other = os.path.join(root, "other")
        write_marker(other, "boot-1")
        os.unlink(os.path.join(directory, MARKER_FILE))
        os.symlink(os.path.join(other, MARKER_FILE), os.path.join(directory, MARKER_FILE))
        self.assertEqual(check_marker(directory, "boot-1"), "mismatch")
        with self.assertRaises(ValueError):
            write_marker(directory, "bad token")
        with self.assertRaises(ValueError):
            check_marker(directory, "")

    def test_the_command_form_prints_one_fixed_word_and_its_status(self):
        directory = os.path.join(self.scratch(), "state")
        lines = []
        self.assertEqual(marker_main(["check", "boot-1"], directory, lines.append), 1)
        self.assertEqual(marker_main(["write", "boot-1"], directory, lines.append), 0)
        self.assertEqual(marker_main(["check", "boot-1"], directory, lines.append), 0)
        self.assertEqual(marker_main(["check", "boot-2"], directory, lines.append), 1)
        self.assertEqual(marker_main(["erase", "boot-1"], directory, lines.append), 2)
        self.assertEqual(marker_main(["write"], directory, lines.append), 2)
        self.assertEqual(marker_main(["write", "a/b"], directory, lines.append), 2)
        self.assertEqual(lines, ["persistence-marker: absent", "persistence-marker: written",
                                 "persistence-marker: present", "persistence-marker: mismatch",
                                 "persistence-marker: usage", "persistence-marker: usage",
                                 "persistence-marker: usage"])


class Profile(unittest.TestCase):
    def test_the_launchers_exact_invocation_selects_the_supplied_session(self):
        self.assertEqual(SUPPLIED_SESSION, "supplied-session-v3")
        self.assertEqual(supplied_session([SUPPLIED_SESSION, HOME, WORK, BIN]),
                         {"home": HOME, "work_dir": WORK, "wrapper_bin": BIN, "mount": None})
        self.assertEqual(supplied_session([SUPPLIED_SESSION, "/h", "/w", "/b"]),
                         {"home": "/h", "work_dir": "/w", "wrapper_bin": "/b", "mount": None})

    def test_the_mounted_form_names_the_mount_root_above_the_working_directory(self):
        self.assertEqual(SUPPLIED_MOUNTED, "supplied-mounted-v1")
        project = HOME + "/src/app/sub"
        for mount in (HOME + "/src/app", project):
            self.assertEqual(supplied_session([SUPPLIED_MOUNTED, HOME, project, BIN, mount]),
                             {"home": HOME, "work_dir": project, "wrapper_bin": BIN, "mount": mount})
        for mount in (HOME, HOME + "/src/other", HOME + "/src/ap", project + "/x", "/srv", "relative",
                      HOME + "/src/../src/app", BIN):
            self.assertIsNone(supplied_session([SUPPLIED_MOUNTED, HOME, project, BIN, mount]), mount)
        # Each form has exactly its own arity.
        self.assertIsNone(supplied_session([SUPPLIED_MOUNTED, HOME, project, BIN]))
        self.assertIsNone(supplied_session([SUPPLIED_SESSION, HOME, project, BIN, HOME + "/src/app"]))
        shell = shell_session([SUPPLIED_MOUNTED, HOME, project, BIN, HOME + "/src", SHELL, "dumb", NONCE, "ls"])
        self.assertEqual(shell, {"home": HOME, "work_dir": project, "wrapper_bin": BIN, "mount": HOME + "/src",
                                 "term": "dumb", "session": NONCE, "argv": ["ls"]})
        self.assertIsNone(shell_session([SUPPLIED_MOUNTED, HOME, project, BIN, SHELL, "dumb", NONCE]))

    def test_other_invocations_are_not_the_supplied_session(self):
        for args in ([], ["request-relay"], ["runtime-check-v1"], ["persistence-marker", "write", "x"],
                     [SUPPLIED_SESSION], [SUPPLIED_SESSION, HOME], [SUPPLIED_SESSION, HOME, WORK],
                     # The v2 form: a Node directory, retired.
                     ["supplied-session-v2", HOME, WORK, BIN, "/opt/node/bin"],
                     [SUPPLIED_SESSION, HOME, WORK, BIN, "/opt/node/bin"], ["Supplied-session-v3", HOME, WORK, BIN],
                     [SUPPLIED_SESSION, HOME, HOME, BIN], [SUPPLIED_SESSION, HOME, WORK, HOME],
                     [SUPPLIED_SESSION, HOME, WORK, WORK]):
            self.assertIsNone(supplied_session(args), args)

    def test_the_interactive_form_adds_a_plain_terminal_type_and_any_command(self):
        base = [SUPPLIED_SESSION, HOME, WORK, BIN]
        self.assertEqual(shell_session(base + [SHELL, "xterm-256color", NONCE]),
                         {"home": HOME, "work_dir": WORK, "wrapper_bin": BIN, "mount": None, "term": "xterm-256color",
                          "session": NONCE, "argv": []})
        self.assertEqual(shell_session(base + [SHELL, "screen.xterm+x_1", NONCE, "pi", "--flag", "a b"])["argv"],
                         ["pi", "--flag", "a b"])
        for args in (base, base + [SHELL], base + ["shells", "dumb", NONCE], base + [SHELL, "", NONCE],
                     base + [SHELL, "a b", NONCE], base + [SHELL, "x;y", NONCE], base + [SHELL, "t" * 65, NONCE],
                     base + [SHELL, "dumb\n", NONCE], [SUPPLIED_SESSION, HOME, HOME, BIN, SHELL, "dumb", NONCE],
                     ["supplied-session-v2"] + base[1:] + [SHELL, "dumb", NONCE],
                     # The session nonce: always there, exactly 32 lowercase hex digits.
                     base + [SHELL, "dumb"], base + [SHELL, "dumb", "ls"], base + [SHELL, "dumb", NONCE.upper()],
                     base + [SHELL, "dumb", NONCE[:-1]], base + [SHELL, "dumb", NONCE + "0"],
                     base + [SHELL, "dumb", "-" + NONCE[1:]]):
            self.assertIsNone(shell_session(args), args)
        # Neither form takes the other's arguments.
        self.assertIsNone(supplied_session(base + [SHELL, "dumb", NONCE]))

    def test_every_path_is_plain_absolute_and_normalized(self):
        for bad in ("", "/", "relative/home", "./home", "/srv//home", "/srv/home/", "/srv/./home", "/srv/../home",
                    "/srv/a b", "/srv/a%b", "/srv/a:b", "/srv/~", "/srv/$HOME", "/srv/a\nb", "/srv/ä",
                    "/" + "a" * MAX_PATH_BYTES, "/srv/home\n"):
            self.assertFalse(is_plain_absolute(bad), repr(bad))
            self.assertIsNone(supplied_session([SUPPLIED_SESSION, bad, WORK, BIN]))
            self.assertIsNone(supplied_session([SUPPLIED_SESSION, HOME, bad, BIN]))
            self.assertIsNone(supplied_session([SUPPLIED_SESSION, HOME, WORK, bad]))
        for good in ("/a", "/srv/jail-root/x.y-z", "/srv/a_b", "/" + "a" * (MAX_PATH_BYTES - 1)):
            self.assertTrue(is_plain_absolute(good), good)


class Clock(unittest.TestCase):
    def test_clients_capture_the_original_bound_once(self):
        for milliseconds in (REQUEST_TIMEOUT_MS, 1000):
            before = time.monotonic()
            deadline = capture_request_deadline(milliseconds)
            self.assertEqual(deadline.until_ns - deadline.started_ns, milliseconds * 1_000_000)
            self.assertGreater(deadline.local_until, before)
            self.assertLessEqual(deadline.local_until, time.monotonic() + milliseconds / 1000)
        expired = capture_request_deadline(0)
        self.assertEqual(expired.until_ns, expired.started_ns)
        self.assertEqual(expired.local_until, 0)


class Home(unittest.TestCase):
    def test_claude_references_shared_guidance_conditional_on_host_request_authority(self):
        with open(os.path.join(REPO, "guest", "home", "AGENTS.md")) as stream:
            agents = stream.read()
        with open(os.path.join(REPO, "guest", "home", "CLAUDE.md")) as stream:
            self.assertEqual(stream.read().splitlines(), ["@AGENTS.md"])
        for expected in ("`agentbox-request HANDLER OPERATION [ARGS_JSON]`", "`pip` (when the host enabled pip)",
                         "`npm` and `npx` (when the host enabled npm)", "installs nothing",
                         "With the git handler, `git clone https://github.com/OWNER/REPO [DEST]`",
                         "refuse without network fallback", "Having a command does not enable a request lane",
                         "no guest SSH access to the host", "command -v npm agentbox-request"):
            self.assertIn(expected, agents)
        self.assertNotIn("npm packages", agents)
        flat = " ".join(agents.split())
        self.assertIn("A denial prints the host's reason", flat)
        self.assertIn("depends only on the host's explicit policy", flat)
        self.assertNotIn("image capability", agents)
        self.assertNotIn("Git-capable image", agents)


if __name__ == "__main__":
    unittest.main()
