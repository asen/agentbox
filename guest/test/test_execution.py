"""The guest helper session on owned pipes. Commands are owned synthetic
fixtures (/bin/sh, /bin/echo, /usr/bin/env, /bin/pwd with fixed arguments) run
in an owned temporary working directory, under the real group anchor unless a
test replaces it with a stand-in (session_harness.FakeAnchor). A session ends
only after its command's group anchor is gone; owned commands record their
process group, which must be gone at the end."""

import asyncio
import base64
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from guest.src import execution
from guest.src.abort import Abort
from guest.src.execution import (
    ANCHOR, EXIT_CLEANUP, EXIT_INPUT_LOST, EXIT_OK, EXIT_OUTPUT_LOST, EXIT_PROTOCOL, REAP_MS, SYSTEM_PATH,
    command_environment,
)
from guest.src.protocol import MAX_OUTPUT_BYTES
from guest.src.runtime import python_argv
from guest.src.worker_profile import SUPPLIED_SESSION, supplied_session
from guest.test.session_harness import Harness, fake_anchors, fake_exec, scratch, wait_for

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# grace 200 ms + the fixed reap bound, with a margin for a loaded host.
BOUND = 5.0
# Writes without end and ignores SIGTERM, so only the group's SIGKILL ends it.
FLOOD = ["/bin/sh", "-c", "trap '' TERM; while :; do echo flood; done"]
# Owned fake values only; nothing of the host's environment is read.
FAKE_ENV = (("AGENTBOX_FAKE", "fake-task-value-3b9e"), ("AGENTBOX_FAKE_EMPTY", ""))


def fixed(directory):
    return sorted("%s=%s" % item for item in command_environment(directory).items())


def errors(session):
    return [frame for frame in session.frames if frame["type"] == "error"]


def credit(seq):
    return lambda frame: frame["type"] == "stdin_ready" and frame["seq"] == seq


def group_gone(group):
    """Whether process group `group` is gone: probed only, never signalled."""
    try:
        os.killpg(group, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False


class Case(unittest.IsolatedAsyncioTestCase):
    async def blocked(self, directory):
        """FLOOD under a host that stopped reading, its streams paused."""
        session = Harness(directory, held=True, small=True)
        session.release()
        await session.hello()
        session.hold()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": FLOOD})
        await wait_for(lambda: session.session.paused)
        return session

    def owned(self, directory, **options):
        """A session whose commands record their process group (`wrap`). Its
        end aborts the session's input, awaits its end, bounded, then
        requires every recorded group gone, bounded; nothing is signalled."""
        marks = tempfile.mkdtemp(prefix="agentbox-guest-owned-")
        abort = Abort()
        session = Harness(directory, abort=abort, **options)
        count = [0]

        def wrap(script):
            mark = os.path.join(marks, "group-%d" % count[0])
            count[0] += 1
            return ["/bin/sh", "-c", "cut -d ' ' -f 5 /proc/$$/stat > '%s.tmp' && mv '%s.tmp' '%s'; %s"
                    % (mark, mark, mark, script)]

        async def recorded():
            await wait_for(lambda: len([n for n in os.listdir(marks) if not n.endswith(".tmp")]) == count[0])

        async def cleanup():
            abort.abort()
            try:
                await asyncio.wait_for(asyncio.shield(session.task), 5)
                ended = True
            except asyncio.TimeoutError:
                ended = False
            session.close()
            groups = []
            for name in os.listdir(marks):
                if not name.endswith(".tmp"):
                    with open(os.path.join(marks, name)) as stream:
                        text = stream.read().strip()
                    if text.isdigit():
                        groups.append(int(text))
            deadline = time.monotonic() + 3
            while not all(group_gone(group) for group in groups) and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            shutil.rmtree(marks, ignore_errors=True)
            self.assertTrue(ended, "owned session did not end")
            self.assertTrue(all(group_gone(group) for group in groups), "owned fixture group still present")

        self.addAsyncCleanup(cleanup)
        return session, wrap, recorded


class Commands(Case):
    async def test_a_session_runs_one_command_and_reports_its_output_and_exit(self):
        directory = scratch(self)
        session = Harness(directory)
        exit_frame = await session.exec(["/bin/sh", "-c", "printf hi; printf err >&2; exit 0"])
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        self.assertEqual(session.output("stdout"), b"hi")
        self.assertEqual(session.output("stderr"), b"err")
        self.assertIs(session.frames[-1], exit_frame)
        for frame in session.frames:
            if frame["type"] == "output":
                self.assertEqual(frame["id"], "e-1")
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)
        info = os.stat(os.path.join(directory, "work"))
        self.assertEqual(info.st_mode & 0o777, 0o700)

    async def test_outcomes_keep_nonzero_signaled_and_failed_apart(self):
        directory = scratch(self)
        for argv, expected in ((["/bin/sh", "-c", "exit 3"], {"outcome": "exited", "code": 3}),
                               (["/bin/sh", "-c", "kill -TERM $$"], {"outcome": "signaled"}),
                               (["/nonexistent/agentbox-command"], {"outcome": "failed"})):
            session = Harness(directory)
            self.assertEqual(await session.exec(argv), dict({"v": 1, "type": "exit", "id": "e-1"}, **expected))
            session.end()
            self.assertEqual(await session.status(), EXIT_OK)

    async def test_argv_runs_without_a_shell_in_a_fixed_directory_and_environment(self):
        directory = scratch(self)
        literal = Harness(directory)
        await literal.exec(["/bin/echo", "$HOME; touch injected"])
        self.assertEqual(literal.output("stdout"), b"$HOME; touch injected\n")
        literal.end()
        await literal.status()
        env = Harness(directory)
        await env.exec(["/usr/bin/env"])
        self.assertEqual(sorted(env.output("stdout").decode().strip().split("\n")), fixed(directory))
        env.end()
        await env.status()
        pwd = Harness(directory)
        await pwd.exec(["/bin/pwd"])
        self.assertEqual(pwd.output("stdout").decode(), os.path.join(directory, "work") + "\n")
        pwd.end()
        await pwd.status()

    async def test_large_output_is_framed_in_bounded_chunks_under_backpressure(self):
        directory = scratch(self)
        session = Harness(directory, small=True)
        size = 5 * MAX_OUTPUT_BYTES + 123
        exit_frame = await session.exec(["/bin/sh", "-c", "head -c %d /dev/zero | tr '\\0' x" % size])
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        for frame in session.frames:
            if frame["type"] == "output":
                self.assertLessEqual(len(base64.b64decode(frame["data"])), MAX_OUTPUT_BYTES)
        self.assertEqual(session.output("stdout"), b"x" * size)
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)

    async def test_a_matching_cancel_ends_the_commands_group_with_term_then_kill(self):
        directory = scratch(self)
        for script in ("sleep 30", "trap '' TERM; sleep 30 & wait; sleep 30"):
            session = Harness(directory)
            await session.hello()
            session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/sh", "-c", script]})
            await asyncio.sleep(0.3)
            started = time.monotonic()
            session.send({"v": 1, "type": "cancel", "id": "e-1"})
            exit_frame = await session.until(lambda frame: frame["type"] == "exit")
            self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})
            self.assertLess(time.monotonic() - started, BOUND)
            # A late cancel crossing the exit frame is ignored.
            session.send({"v": 1, "type": "cancel", "id": "e-1"})
            session.end()
            self.assertEqual(await session.status(), EXIT_OK)

    async def test_the_command_gets_the_groups_sigterm_its_anchor_ignores(self):
        directory = scratch(self)
        session = Harness(directory, grace=5000)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1",
                      "argv": ["/bin/sh", "-c", "trap 'echo term; exit 7' TERM; while :; do sleep 0.05; done"]})
        await asyncio.sleep(0.3)
        started = time.monotonic()
        session.send({"v": 1, "type": "cancel", "id": "e-1"})
        await session.until(lambda frame: frame["type"] == "output")
        # Delivered at once, not left to the SIGKILL after the 5 s grace,
        # which the stop's deadline still waits for.
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(session.output("stdout"), b"term\n")
        self.assertEqual(await session.until(lambda frame: frame["type"] == "exit"),
                         {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)

    async def test_an_anchor_lost_before_its_final_kill_is_never_a_clean_exit(self):
        directory = scratch(self)
        session = Harness(directory)
        exit_frame = await session.exec(["/bin/sh", "-c", "kill -KILL $PPID; printf done"])
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "failed"})
        session.end()
        self.assertEqual(await session.status(), EXIT_CLEANUP)

    async def test_losing_the_hosts_input_ends_the_command(self):
        directory = scratch(self)
        session = Harness(directory)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/sh", "-c", "trap '' TERM; sleep 30"]})
        await asyncio.sleep(0.3)
        started = time.monotonic()
        session.end()
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertEqual(session.frames[-1], {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})

    async def test_an_abort_as_on_sigterm_ends_the_command_and_the_session(self):
        directory = scratch(self)
        abort = Abort()
        session = Harness(directory, abort=abort)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/sh", "-c", "trap '' TERM; sleep 30"]})
        await asyncio.sleep(0.3)
        started = time.monotonic()
        abort.abort()
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertEqual(session.frames[-1], {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})

    async def test_protocol_violations_end_the_session_with_a_fixed_code(self):
        directory = scratch(self)

        async def exec_first(session):
            session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/true"]})

        async def hello_twice(session):
            await session.hello()
            session.send({"v": 1, "type": "hello", "session": "again"})

        async def other_cancel(session):
            await session.hello()
            session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/sh", "-c", "sleep 30"]})
            session.send({"v": 1, "type": "cancel", "id": "other"})

        async def raw(text, session):
            session.raw(text)

        cases = ((exec_first, "invalid_field"),
                 (lambda s: raw("{not json}\n", s), "invalid_json"),
                 (lambda s: raw('{"v":1,"type":"hello","session":"s","seq":1}\n', s), "unknown_field"),
                 (lambda s: raw('{"v":1,"type":"exit","id":"x","outcome":"exited","code":0}\n', s), "wrong_direction"),
                 # No frame asks for a poweroff.
                 (lambda s: raw('{"v":1,"type":"shutdown"}\n', s), "unknown_type"),
                 (hello_twice, "invalid_field"),
                 (other_cancel, "invalid_field"))
        for act, code in cases:
            session = Harness(directory)
            await act(session)
            self.assertEqual(await session.until(lambda frame: frame["type"] == "error"),
                             {"v": 1, "type": "error", "code": code})
            self.assertEqual(await session.status(), EXIT_PROTOCOL)
        truncated = Harness(directory)
        truncated.raw('{"v":1,"type":"hello"')
        truncated.end()
        self.assertEqual(await truncated.until(lambda frame: frame["type"] == "error"),
                         {"v": 1, "type": "error", "code": "truncated_frame"})
        self.assertEqual(await truncated.status(), EXIT_PROTOCOL)


class WithheldOutput(Case):
    async def test_input_loss_under_a_withheld_output_ends_within_the_cleanup_bound(self):
        session = await self.blocked(scratch(self))
        started = time.monotonic()
        session.end()
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertLess(time.monotonic() - started, BOUND)

    async def test_a_protocol_failure_under_a_withheld_output_ends_within_the_cleanup_bound(self):
        session = await self.blocked(scratch(self))
        started = time.monotonic()
        session.raw("{not json}\n")
        self.assertEqual(await session.status(), EXIT_PROTOCOL)
        self.assertLess(time.monotonic() - started, BOUND)

    async def test_an_output_closed_under_paused_streams_releases_the_command(self):
        session = await self.blocked(scratch(self))
        started = time.monotonic()
        session.close_output()
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertLess(time.monotonic() - started, BOUND)

    async def test_a_withheld_flush_after_the_exit_frame_does_not_hold_the_session(self):
        directory = scratch(self)
        session = Harness(directory, small=True)
        self.assertEqual(await session.exec(["/bin/echo", "hi"]),
                         {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        session.hold()
        # Fill the host's pipe so the last flush cannot complete.
        session.fill()
        session.send({"v": 1, "type": "cancel", "id": "e-1"})
        session.session._send({"v": 1, "type": "stdin_closed", "id": "e-1"})
        started = time.monotonic()
        session.end()
        # An unconfirmed flush is never a clean end.
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertLess(time.monotonic() - started, BOUND)

    def test_a_blocked_output_keeps_nothing_alive_after_the_session_ends(self):
        directory = scratch(self)
        script = (
            "import asyncio, fcntl, os, sys\n"
            "sys.path.insert(0, %r)\n"
            "from guest.src.execution import SessionOptions, run_session\n"
            "from guest.src.protocol import encode_host_frame\n"
            "async def main():\n"
            "    in_r, in_w = os.pipe()\n"
            "    out_r, out_w = os.pipe()\n"
            "    fcntl.fcntl(out_w, fcntl.F_SETPIPE_SZ, 4096)\n"
            "    task = asyncio.ensure_future(run_session(SessionOptions(in_r, out_w, %r, %r, kill_grace_ms=200)))\n"
            "    os.write(in_w, encode_host_frame({'v': 1, 'type': 'hello', 'session': 's1'}) + b'\\n')\n"
            "    os.write(in_w, encode_host_frame({'v': 1, 'type': 'exec', 'id': 'e-1', 'argv': %r}) + b'\\n')\n"
            "    await asyncio.sleep(0.5)\n"
            "    os.close(in_w)\n"
            "    return await task\n"
            "sys.stdout.write(str(asyncio.run(main())))\n"
        ) % (REPO, os.path.join(directory, "work"), directory, FLOOD)
        done = subprocess.run([sys.executable, "-I", "-S", "-B", "-c", script], capture_output=True, timeout=30)
        self.assertEqual((done.returncode, done.stdout), (0, str(EXIT_INPUT_LOST).encode()), done.stderr)


class StandIns(Case):
    async def test_a_failed_read_of_either_output_stream_is_never_a_clean_exit(self):
        directory = scratch(self)
        anchors = fake_anchors(self)
        for index, stream in enumerate(("stdout", "stderr")):
            session = Harness(directory)
            anchor = await fake_exec(session, anchors)
            anchor.write(stream, b"before")
            await session.until(lambda frame: frame["type"] == "output")
            reader = session.session.streams[index]
            reader._finish(reader._error)
            await wait_for(lambda: bytes(anchor.stops) == b"s")
            anchor.finish("e0\nk\n")
            exit_frame = await session.until(lambda frame: frame["type"] == "exit")
            self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "failed"})
            self.assertEqual(session.output(stream), b"before")
            session.end()
            self.assertEqual(await session.status(), EXIT_OUTPUT_LOST)
            self.assertEqual(len([f for f in session.frames if f["type"] == "exit"]), 1)

    async def test_an_input_closed_is_its_loss_with_one_stop(self):
        directory = scratch(self)
        anchors = fake_anchors(self)
        session = Harness(directory)
        anchor = await fake_exec(session, anchors)
        session.end()
        await wait_for(lambda: len(anchor.stops) > 0)
        await asyncio.sleep(0.05)
        self.assertEqual(bytes(anchor.stops), b"s")
        anchor.finish("k\n")
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertEqual([f for f in session.frames if f["type"] == "exit"],
                         [{"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"}])

    async def test_an_input_closed_without_an_anchors_report_still_ends_at_the_original_deadline(self):
        directory = scratch(self)
        anchors = fake_anchors(self)
        session = Harness(directory)
        anchor = await fake_exec(session, anchors)
        started = time.monotonic()
        session.end()
        self.assertEqual(await session.status(), EXIT_INPUT_LOST)
        self.assertLess(time.monotonic() - started, BOUND)
        self.assertEqual(bytes(anchor.stops), b"s")
        self.assertEqual(session.frames[-1], {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})

    async def test_a_normal_end_is_one_clean_end(self):
        directory = scratch(self)
        anchors = fake_anchors(self)
        session = Harness(directory)
        anchor = await fake_exec(session, anchors)
        anchor.write("stdout", b"hi")
        anchor.finish("e0\nk\n")
        self.assertEqual(await session.until(lambda frame: frame["type"] == "exit"),
                         {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)
        self.assertEqual(bytes(anchor.stops), b"")
        self.assertEqual(session.output("stdout"), b"hi")

    async def test_a_clean_end_waits_for_the_frames_already_written(self):
        directory = scratch(self)
        anchors = fake_anchors(self)
        session = Harness(directory, small=True)
        anchor = await fake_exec(session, anchors)
        session.hold()
        # The host's pipe is full: the last frames wait here, below the high water.
        session.fill()
        anchor.write("stdout", b"hi")
        await wait_for(lambda: session.session.output.pending > 0)
        anchor.finish("e0\nk\n")
        await wait_for(lambda: session.session.phase == "finished")
        self.assertFalse(session.session.paused)
        session.end()
        await asyncio.sleep(0.2)
        self.assertFalse(session.task.done())
        session.release()
        self.assertEqual(await session.status(), EXIT_OK)
        self.assertEqual(session.session.output.pending, 0)
        self.assertEqual(session.output("stdout"), b"hi")
        self.assertEqual(session.frames[-1], {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})

    async def test_the_helper_passes_a_selection_on_the_config_pipe_never_in_arguments_or_environment(self):
        directory = scratch(self)
        anchors = fake_anchors(self, after=lambda anchor: asyncio.get_running_loop().call_later(0.1, anchor.finish,
                                                                                                "e0\nk\n"))
        for env in (FAKE_ENV, None):
            session = Harness(directory)
            await session.hello()
            frame = {"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/true", "x"]}
            if env is not None:
                frame["env"] = dict(env)
            session.send(frame)
            await session.until(lambda frame: frame["type"] == "exit")
            session.end()
            await session.status()
        selected, generic = anchors
        prefix = python_argv(ANCHOR)
        self.assertEqual(selected.argv[:len(prefix)], prefix)
        self.assertEqual(list(selected.flags), ["--env"])
        self.assertEqual(selected.words[2:], ["200", "/bin/true", "x"])
        self.assertEqual(generic.flags, {})
        self.assertEqual(generic.words[2:], ["200", "/bin/true", "x"])
        for anchor in (selected, generic):
            self.assertEqual(anchor.env, command_environment(directory))
            self.assertNotIn("fake-task-value", repr(anchor.argv))
        self.assertEqual(bytes(selected.config), b'{"AGENTBOX_FAKE":"fake-task-value-3b9e","AGENTBOX_FAKE_EMPTY":""}')

    async def test_the_helper_passes_input_on_its_own_pipe_and_flag_never_in_arguments_or_environment(self):
        directory = scratch(self)
        anchors = fake_anchors(self, after=lambda anchor: asyncio.get_running_loop().call_later(0.3, anchor.finish,
                                                                                                "e0\nk\n"))
        secret = b"fake-stdin-bytes-5c1d\n"
        for env in (None, FAKE_ENV):
            session = Harness(directory)
            await session.hello()
            frame = {"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/true", "x"], "stdin": True}
            if env is not None:
                frame["env"] = dict(env)
            session.send(frame)
            await session.until(credit(0))
            session.send({"v": 1, "type": "stdin", "id": "e-1", "seq": 0, "data": base64.b64encode(secret).decode()})
            await session.until(credit(1))
            await session.until(lambda frame: frame["type"] == "exit")
            session.end()
            await session.status()
        alone, both = anchors
        self.assertEqual(list(alone.flags), ["--stdin"])
        self.assertEqual(list(both.flags), ["--env", "--stdin"])
        for anchor in (alone, both):
            self.assertEqual(anchor.words[2:], ["200", "/bin/true", "x"])
            self.assertEqual(anchor.env, command_environment(directory))
            self.assertNotIn("fake-stdin", repr(anchor.argv))
            self.assertEqual(bytes(anchor.input), secret)


class Environment(Case):
    async def test_a_selected_env_reaches_only_the_command_and_its_children(self):
        directory = scratch(self)
        session = Harness(directory)
        await session.hello()
        script = "; ".join([
            'printf "task=%s|%s\\n" "$AGENTBOX_FAKE" "${AGENTBOX_FAKE_EMPTY-unset}"',
            "/bin/sh -c 'printf \"child=%s\\n\" \"$AGENTBOX_FAKE\"'",
            'tr "\\0" "\\n" < /proc/$PPID/environ | sort | sed "s/^/anchor-env=/"',
            'tr "\\0" " " < /proc/$PPID/cmdline | grep -cF -- "$AGENTBOX_FAKE" || true',
        ])
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["/bin/sh", "-c", script], "env": dict(FAKE_ENV)})
        exit_frame = await session.until(lambda frame: frame["type"] == "exit")
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        lines = session.output("stdout").decode().strip().split("\n")
        self.assertEqual(lines[0], "task=fake-task-value-3b9e|")
        self.assertEqual(lines[1], "child=fake-task-value-3b9e")
        self.assertEqual([line[11:] for line in lines if line.startswith("anchor-env=")], fixed(directory))
        self.assertEqual(lines[-1], "0")
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)

    def test_a_supplied_sessions_wrappers_lead_the_fixed_path_nothing_ambient_is_inherited(self):
        home, work, binary = "/srv/jail/home", "/srv/jail/home/work", "/srv/jail/releases/abc/bin"
        self.assertEqual(SUPPLIED_SESSION, "supplied-session-v3")
        self.assertEqual(supplied_session([SUPPLIED_SESSION, home, work, binary]),
                         {"home": home, "work_dir": work, "wrapper_bin": binary, "mount": None})
        self.assertEqual(SYSTEM_PATH, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
        supplied = command_environment(home, None, binary)
        task_path = SYSTEM_PATH + ":" + home + "/.local/bin"
        self.assertEqual(supplied["PATH"], binary + ":" + task_path)
        plain = command_environment(home)
        self.assertEqual(plain["PATH"], task_path)
        self.assertEqual(dict(supplied, PATH=task_path), plain)
        self.assertEqual(sorted(plain), ["HOME", "HTTPS_PROXY", "HTTP_PROXY", "LANG", "PATH", "TERM", "http_proxy",
                                         "https_proxy"])
        for bad in ("", "/", "bin", "./bin", "/a:/b", "/a/bin:", ":/a", "/a/../b", "/a//b", "/a/b/", "/a b", "/a\nb"):
            with self.assertRaises(ValueError):
                command_environment(home, None, bad)

    async def test_user_installed_commands_resolve_after_wrappers_and_system_tools(self):
        directory = scratch(self)
        local_bin = os.path.join(directory, ".local", "bin")
        wrappers = os.path.join(directory, "wrappers")
        os.makedirs(local_bin)
        os.mkdir(wrappers)
        for folder, name, message in ((local_bin, "user-tool", "local"),
                                      (local_bin, "sh", "wrong-shell"),
                                      (local_bin, "wrapped-tool", "wrong-wrapper"),
                                      (wrappers, "wrapped-tool", "wrapper")):
            path = os.path.join(folder, name)
            with open(path, "w") as output:
                output.write("#!/bin/sh\nprintf '%s\\n' " + message + "\n")
            os.chmod(path, 0o700)
        env = command_environment(directory, wrapper_bin=wrappers)
        self.assertEqual(shutil.which("sh", path=env["PATH"]), shutil.which("sh", path=SYSTEM_PATH))
        self.assertEqual(shutil.which("wrapped-tool", path=env["PATH"]),
                         os.path.join(wrappers, "wrapped-tool"))
        session = Harness(directory)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": ["user-tool"]})
        frame = await session.until(lambda item: item["type"] == "exit")
        self.assertEqual(frame["code"], 0)
        self.assertEqual(session.output("stdout"), b"local\n")
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)


class SessionWrapper(Case):
    """An installation's `agentbox-session` before the command: pip's real
    module (no request context here, so it adds nothing and serves nothing;
    acquisitions/test_pip_index.py runs its index) or a stand-in."""

    def wrapper(self, directory, text=None):
        wrappers = os.path.join(directory, "wrappers")
        os.makedirs(wrappers, exist_ok=True)
        path = os.path.join(wrappers, execution.SESSION_WRAPPER)
        module = os.path.join(REPO, "acquisitions", "pip", "jail", "pip.py")
        with open(path, "w") as output:
            output.write(text or "#!/bin/sh\nexec %s -I -S -B -X utf8 '%s' session \"$@\"\n"
                         % (sys.executable, module))
        os.chmod(path, 0o700)
        return wrappers

    async def run_behind(self, argv, text=None, prepare=None):
        """The exit frame and stdout and stderr of `argv` behind the wrapper."""
        directory = scratch(self)
        if prepare is not None:
            prepare(directory)
        session = Harness(directory, wrapper_bin=self.wrapper(directory, text))
        frame = await session.exec(argv)
        output = session.output("stdout"), session.output("stderr")
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)
        return frame, output

    async def test_a_command_runs_behind_the_wrapper_with_its_own_argv_and_status(self):
        frame, (out, err) = await self.run_behind(["sh", "-c", 'printf "%s|%s\\n" "$0" "$1"; exit 5', "name",
                                                   "one two"])
        self.assertEqual((frame["outcome"], frame["code"], out, err), ("exited", 5, b"name|one two\n", b""))

    async def test_a_command_exiting_126_or_127_is_its_exit(self):
        for code in (126, 127):
            frame, _ = await self.run_behind(["sh", "-c", "exit %d" % code])
            self.assertEqual((frame["outcome"], frame["code"]), ("exited", code))

    async def test_a_command_that_resolves_but_cannot_start_is_a_failed_start(self):
        def script(directory):
            path = os.path.join(directory, "work", "run.sh")
            os.makedirs(os.path.dirname(path), 0o700)
            with open(path, "w") as output:
                output.write("#!/nonexistent/agentbox-interpreter\n")
            os.chmod(path, 0o700)

        frame, (out, err) = await self.run_behind(["./run.sh"], prepare=script)
        self.assertEqual((frame, out, err), ({"v": 1, "type": "exit", "id": "e-1", "outcome": "failed"}, b"", b""))
        # As without a wrapper.
        directory = scratch(self)
        script(directory)
        session = Harness(directory)
        frame = await session.exec(["./run.sh"])
        self.assertEqual(frame["outcome"], "failed")
        session.end()
        await session.status()

    async def test_a_wrapper_that_ends_before_its_exec_is_a_failed_start(self):
        for text in ("#!/bin/sh\nexit 7\n", "#!/bin/sh\nexec /nonexistent/agentbox-python \"$@\"\n",
                     '#!/bin/sh\nfd=${1#--status=}; shift; printf rf >&$fd; exit 127\n'):
            frame, _ = await self.run_behind(["sh", "-c", "exit 0"], text=text)
            self.assertEqual(frame["outcome"], "failed", text)

    async def test_a_command_that_cannot_be_found_is_not_wrapped(self):
        frame, (out, err) = await self.run_behind(["agentbox-no-such-command"],
                                                  text="#!/bin/sh\necho wrapped\nexit 9\n")
        self.assertEqual((frame["outcome"], out), ("failed", b""))

    def test_only_a_resolvable_program_behind_an_executable_wrapper(self):
        directory = scratch(self)
        wrappers = self.wrapper(directory)
        wrapper = os.path.join(wrappers, execution.SESSION_WRAPPER)
        env = command_environment(directory, wrapper_bin=wrappers)
        script = os.path.join(directory, "work", "run.sh")
        os.makedirs(os.path.dirname(script))
        with open(script, "w") as output:
            output.write("#!/bin/sh\n")
        os.chmod(script, 0o700)
        work = os.path.join(directory, "work")
        self.assertEqual(execution.session_argv(wrappers, ["sh", "-c", "x"], env, work), [wrapper, "sh", "-c", "x"])
        self.assertEqual(execution.session_argv(wrappers, ["./run.sh"], env, work), [wrapper, "./run.sh"])
        self.assertEqual(execution.session_argv(wrappers, ["./run.sh"], env, directory), ["./run.sh"])
        self.assertEqual(execution.session_argv(wrappers, ["no-such"], env, work), ["no-such"])
        self.assertEqual(execution.session_argv(None, ["sh"], env, work), ["sh"])
        os.chmod(wrapper, 0o600)
        self.assertEqual(execution.session_argv(wrappers, ["sh"], env, work), ["sh"])


class Anchor(Case):
    async def raw_anchor(self, directory, script, env=False, stdin=False, flag_text=None):
        """The real anchor with its pipes, as the helper starts it: (process,
        control lines future, stdout read end, config write end, input write end)."""
        ctl_in, ctl_out, out, err = os.pipe2(os.O_CLOEXEC), os.pipe2(os.O_CLOEXEC), os.pipe2(os.O_CLOEXEC), \
            os.pipe2(os.O_CLOEXEC)
        config = os.pipe2(os.O_CLOEXEC) if env else (None, None)
        task = os.pipe2(os.O_CLOEXEC) if stdin else (None, None)
        flags = []
        if env:
            flags.append("--env=%d" % config[0])
        if stdin:
            flags.append("--stdin=%d" % task[0])
        passed = tuple(fd for fd in (out[1], err[1], config[0], task[0]) if fd is not None)
        process = await asyncio.create_subprocess_exec(
            *python_argv(ANCHOR, *flags, str(out[1]), str(err[1]), "200", "/bin/sh", "-c", script),
            stdin=ctl_in[0], stdout=ctl_out[1], stderr=subprocess.DEVNULL, pass_fds=passed, cwd=directory,
            env=command_environment(directory), start_new_session=True)
        for fd in (ctl_in[0], ctl_out[1], out[1], err[1], config[0], task[0], err[0]):
            if fd is not None:
                os.close(fd)

        async def lines():
            await process.wait()
            data = b""
            while True:
                chunk = os.read(ctl_out[0], 1024)
                if not chunk:
                    break
                data += chunk
            os.close(ctl_out[0])
            return data.decode("latin-1")

        self.addCleanup(os.close, ctl_in[1])
        return process, asyncio.ensure_future(lines()), out[0], config[1], task[1], ctl_in[1]

    async def test_an_invalid_or_interrupted_anchor_config_or_a_stop_before_it_starts_nothing(self):
        directory = scratch(self)

        def end(fd, data):
            os.set_blocking(fd, True)
            try:
                os.write(fd, data)
            except OSError:
                pass
            os.close(fd)

        cases = (("reserved", b'{"PATH":"/x"}'), ("duplicate", b'{"AGENTBOX_FAKE":"a","AGENTBOX_FAKE":"b"}'),
                 ("surrogate", b'{"AGENTBOX_FAKE":"\\ud800"}'), ("utf8", b'{"AGENTBOX_FAKE":"\xff"}'),
                 ("truncated", b'{"AGENTBOX_FAKE":"fake'), ("empty", b""), ("oversized", b" " * 70_000), ("stopped", None))
        for name, data in cases:
            marker = os.path.join(directory, "ran-" + name)
            process, lines, out, config, _task, control = await self.raw_anchor(directory, ": > %s" % marker, env=True)
            if data is None:
                os.write(control, b"s")
                await asyncio.sleep(0.1)
                end(config, b'{"AGENTBOX_FAKE":"fake-task-value-3b9e"}')
            else:
                await asyncio.get_running_loop().run_in_executor(None, end, config, data)
            self.assertEqual(await asyncio.wait_for(lines, 10), "f\nk\n", name)
            self.assertFalse(os.path.exists(marker), name)
            os.close(out)
        marker = os.path.join(directory, "ran-valid")
        process, lines, out, config, _task, _control = await self.raw_anchor(directory, ": > %s" % marker, env=True)
        end(config, b'{"AGENTBOX_FAKE":"fake-task-value-3b9e"}')
        self.assertEqual(await asyncio.wait_for(lines, 10), "e0\nk\n")
        self.assertTrue(os.path.exists(marker))
        os.close(out)

    async def test_the_anchor_hands_its_input_pipe_to_the_command_as_descriptor_0_and_keeps_none(self):
        directory = scratch(self)
        for env in (False, True):
            process, lines, out, config, task, _control = await self.raw_anchor(
                directory, 'sleep 0.2; n=$(ls /proc/$PPID/fd | wc -l); echo "anchor-fds=$n"; cat; '
                           'printf "|%s" "${AGENTBOX_FAKE-unset}"', env=env, stdin=True)
            if env:
                os.write(config, b'{"AGENTBOX_FAKE":"fake-task-value-3b9e"}')
                os.close(config)
            os.write(task, bytes([0, 0xFF, 0x0A, 0x41]))
            os.close(task)
            self.assertEqual(await asyncio.wait_for(lines, 10), "e0\nk\n")
            data = b""
            while True:
                chunk = os.read(out, 65536)
                if not chunk:
                    break
                data += chunk
            os.close(out)
            head, _, rest = data.partition(b"\n")
            # The anchor holds no task input: its own pipes and loop only.
            self.assertTrue(head.startswith(b"anchor-fds="), data)
            self.assertEqual(rest, bytes([0, 0xFF, 0x0A, 0x41]) + (b"|fake-task-value-3b9e" if env else b"|unset"))

    async def test_an_anchor_that_is_not_its_groups_leader_signals_nothing(self):
        done = await asyncio.create_subprocess_exec(*python_argv(ANCHOR, "1", "2", "200", "/bin/true"),
                                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                    stderr=subprocess.DEVNULL)
        output, _ = await done.communicate()
        self.assertEqual((done.returncode, output), (2, b""))


class Input(Case):
    async def feed(self, session, chunks, end=True):
        for seq, chunk in enumerate(chunks):
            await session.until(credit(seq))
            session.send({"v": 1, "type": "stdin", "id": "e-1", "seq": seq, "data": base64.b64encode(chunk).decode()})
        if end:
            await session.until(credit(len(chunks)))
            session.send({"v": 1, "type": "stdin_eof", "id": "e-1", "seq": len(chunks)})

    async def test_opted_in_input_reaches_the_command_as_raw_bytes_in_order(self):
        directory = scratch(self)
        session, wrap, _recorded = self.owned(directory)
        await session.hello()
        raw = (bytes([0, 0xFF, 0xFE, 0x0D, 0x0A]) + '{"v":1,"type":"cancel","id":"e-1"}\nsecond line\n\u00e9'.encode()
               + bytes(i % 256 for i in range(5000)))
        chunks = [raw[at:at + 2048] for at in range(0, len(raw), 2048)]
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": wrap('cat; printf "[after]"'), "stdin": True})
        await self.feed(session, chunks)
        exit_frame = await session.until(lambda frame: frame["type"] == "exit")
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        self.assertEqual(session.output("stdout"), raw + b"[after]")
        credits = [frame["seq"] for frame in session.frames if frame["type"] == "stdin_ready"]
        self.assertEqual(credits, list(range(len(chunks) + 1)))
        self.assertFalse(any(frame["type"] == "stdin_closed" for frame in session.frames))
        self.assertEqual(errors(session), [])
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)

    async def test_without_the_opt_in_the_input_is_null_and_input_frames_are_refused(self):
        directory = scratch(self)
        plain, wrap, _ = self.owned(directory)
        exit_frame = await plain.exec(wrap("cat; echo done"))
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        self.assertEqual(plain.output("stdout"), b"done\n")
        self.assertFalse(any(frame["type"] == "stdin_ready" for frame in plain.frames))
        plain.end()
        self.assertEqual(await plain.status(), EXIT_OK)
        refused, wrap_refused, _ = self.owned(directory)
        await refused.hello()
        refused.send({"v": 1, "type": "exec", "id": "e-1", "argv": wrap_refused("sleep 5")})
        refused.send({"v": 1, "type": "stdin", "id": "e-1", "seq": 0, "data": "AA=="})
        await refused.until(lambda frame: frame["type"] == "error")
        self.assertEqual(errors(refused), [{"v": 1, "type": "error", "code": "invalid_field"}])
        self.assertEqual(await refused.status(), EXIT_PROTOCOL)

    async def test_input_credits_are_exact_one_at_a_time_and_bound_to_the_command(self):
        directory = scratch(self)

        def frame(fields):
            return '{"v":1,"type":%s}\n' % fields

        cases = (("ahead", frame('"stdin","id":"e-1","seq":1,"data":"AA=="')),
                 ("other id", frame('"stdin","id":"e-2","seq":0,"data":"AA=="')),
                 ("second before its credit", frame('"stdin","id":"e-1","seq":0,"data":"AA=="')
                  + frame('"stdin","id":"e-1","seq":1,"data":"AA=="')),
                 ("after the end", frame('"stdin_eof","id":"e-1","seq":0')
                  + frame('"stdin","id":"e-1","seq":1,"data":"AA=="')),
                 ("a second end", frame('"stdin_eof","id":"e-1","seq":0') + frame('"stdin_eof","id":"e-1","seq":0')))
        for name, text in cases:
            session, wrap, recorded = self.owned(directory)
            await session.hello()
            session.send({"v": 1, "type": "exec", "id": "e-1", "argv": wrap("cat > /dev/null; sleep 5"), "stdin": True})
            await session.until(credit(0))
            await recorded()
            session.raw(text)
            await session.until(lambda received: received["type"] == "error")
            self.assertEqual(len(errors(session)), 1, name)
            await session.until(lambda received: received["type"] == "exit")
            self.assertEqual(await session.status(), EXIT_PROTOCOL, name)

    async def test_an_early_close_of_the_commands_input_is_reported_once_and_decides_nothing(self):
        directory = scratch(self)
        session, wrap, _ = self.owned(directory)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": wrap("exec 0<&-; sleep 0.3; printf ok"),
                      "stdin": True})
        await session.until(credit(0))
        await session.until(lambda frame: frame["type"] == "stdin_closed")
        # A frame already in flight on the credit is dropped unwritten.
        session.send({"v": 1, "type": "stdin", "id": "e-1", "seq": 0, "data": base64.b64encode(b"late").decode()})
        exit_frame = await session.until(lambda frame: frame["type"] == "exit")
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "exited", "code": 0})
        self.assertEqual(session.output("stdout"), b"ok")
        self.assertEqual(len([f for f in session.frames if f["type"] == "stdin_closed"]), 1)
        self.assertEqual(errors(session), [])
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)

    async def test_a_stop_destroys_the_commands_input_unreported_and_drops_a_frame_in_flight(self):
        directory = scratch(self)
        session, wrap, recorded = self.owned(directory)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": wrap("cat > /dev/null"), "stdin": True})
        await session.until(credit(0))
        await recorded()
        session.raw('{"v":1,"type":"cancel","id":"e-1"}\n{"v":1,"type":"stdin","id":"e-1","seq":0,"data":"AA=="}\n')
        exit_frame = await session.until(lambda frame: frame["type"] == "exit")
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})
        await asyncio.sleep(0.05)
        self.assertEqual(errors(session), [])
        self.assertFalse(any(frame["type"] == "stdin_closed" for frame in session.frames))
        self.assertFalse(any(credit(1)(frame) for frame in session.frames))
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)

    async def test_a_command_that_never_reads_holds_at_most_one_chunk_here_and_its_cancel_lands(self):
        directory = scratch(self)
        session, wrap, _ = self.owned(directory)
        await session.hello()
        session.send({"v": 1, "type": "exec", "id": "e-1", "argv": wrap("sleep 30"), "stdin": True})
        chunk = base64.b64encode(b"a" * 2048).decode()
        seq = 0
        while await session.within(0.3, credit(seq)) is not None:
            session.send({"v": 1, "type": "stdin", "id": "e-1", "seq": seq, "data": chunk})
            seq += 1
            self.assertLess(seq, 4096, "credit never stopped")
        # Credits stopped with the kernel's buffer full; one chunk waits here.
        self.assertGreater(seq, 0)
        self.assertLessEqual(session.session.input_pipe.pending, 2048)
        cancelled = time.monotonic()
        session.send({"v": 1, "type": "cancel", "id": "e-1"})
        exit_frame = await session.until(lambda frame: frame["type"] == "exit")
        self.assertEqual(exit_frame, {"v": 1, "type": "exit", "id": "e-1", "outcome": "cancelled"})
        self.assertLess(time.monotonic() - cancelled, 0.2 + REAP_MS / 1000 + 1)
        self.assertEqual(errors(session), [])
        session.end()
        self.assertEqual(await session.status(), EXIT_OK)


if __name__ == "__main__":
    unittest.main()


class WorkingDirectory(unittest.TestCase):
    """The working directory beneath HOME (a project location, or work):
    made private one level at a time; HOME and every directory down to it
    real, this user's and not group or other writable."""

    def test_a_project_location_is_made_private_beneath_home(self):
        home = scratch(self)
        work = os.path.join(home, "src", "app")
        self.assertTrue(execution.prepare_work_dir(work, home))
        for path in (os.path.join(home, "src"), work):
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)
        # Again: existing, unchanged.
        self.assertTrue(execution.prepare_work_dir(work, home))
        self.assertTrue(execution.prepare_work_dir(os.path.join(home, ".agentbox-root", "srv", "x"), home))

    def test_a_replaced_or_open_ancestor_refuses(self):
        home = scratch(self)
        elsewhere = os.path.join(scratch(self), "elsewhere")
        os.mkdir(elsewhere, 0o700)
        os.symlink(elsewhere, os.path.join(home, "src"))
        self.assertFalse(execution.prepare_work_dir(os.path.join(home, "src", "app"), home))
        self.assertFalse(os.path.exists(os.path.join(elsewhere, "app")))
        os.unlink(os.path.join(home, "src"))
        os.mkdir(os.path.join(home, "src"), 0o700)
        os.chmod(os.path.join(home, "src"), 0o777)
        self.assertFalse(execution.prepare_work_dir(os.path.join(home, "src", "app"), home))
        os.chmod(os.path.join(home, "src"), 0o700)
        with open(os.path.join(home, "src", "file"), "w"):
            pass
        self.assertFalse(execution.prepare_work_dir(os.path.join(home, "src", "file", "x"), home))
        os.chmod(home, 0o777)
        self.assertFalse(execution.prepare_work_dir(os.path.join(home, "src", "app"), home))
        os.chmod(home, 0o700)
        os.mkdir(os.path.join(home, "open"), 0o700)
        os.chmod(os.path.join(home, "open"), 0o750)
        # The working directory itself is private.
        self.assertFalse(execution.prepare_work_dir(os.path.join(home, "open"), home))
        self.assertTrue(execution.prepare_work_dir(os.path.join(home, "src", "app"), home))

    def test_a_mounted_project_admits_the_hosts_ordinary_modes_from_its_root_down(self):
        home = scratch(self)
        os.makedirs(os.path.join(home, "src"), 0o700)
        mount = os.path.join(home, "src", "app")
        work = os.path.join(mount, "sub")
        os.mkdir(mount)
        os.mkdir(work)
        for root_mode, work_mode in ((0o755, 0o755), (0o775, 0o775), (0o750, 0o700)):
            os.chmod(mount, root_mode)
            os.chmod(work, work_mode)
            self.assertTrue(execution.prepare_work_dir(work, home, mount), oct(root_mode))
            self.assertTrue(execution.prepare_work_dir(mount, home, mount), oct(root_mode))
            # Without the mount root the host's ordinary modes refuse, as ever.
            if work_mode != 0o700:
                self.assertFalse(execution.prepare_work_dir(work, home), oct(root_mode))
        # Other-writable refuses, at the root or beneath it.
        os.chmod(mount, 0o777)
        self.assertFalse(execution.prepare_work_dir(work, home, mount))
        os.chmod(mount, 0o755)
        os.chmod(work, 0o757)
        self.assertFalse(execution.prepare_work_dir(work, home, mount))
        os.chmod(work, 0o755)
        # Nothing is made in the mount: a missing project refuses.
        self.assertFalse(execution.prepare_work_dir(os.path.join(mount, "missing"), home, mount))
        self.assertFalse(os.path.exists(os.path.join(mount, "missing")))
        # A symlink in the mounted part refuses.
        os.symlink(work, os.path.join(mount, "link"))
        self.assertFalse(execution.prepare_work_dir(os.path.join(mount, "link"), home, mount))
        # The HOME side stays strict.
        os.chmod(os.path.join(home, "src"), 0o775)
        self.assertFalse(execution.prepare_work_dir(work, home, mount))
        os.chmod(os.path.join(home, "src"), 0o700)
        # The mount root is beneath HOME, above or at the working directory.
        for bad in (home, os.path.join(home, "src", "other"), os.path.join(work, "x"), "/tmp"):
            self.assertFalse(execution.prepare_work_dir(work, home, bad), bad)
        self.assertTrue(execution.prepare_work_dir(work, home, mount))

    def test_only_beneath_home(self):
        home = scratch(self)
        for work in (home, os.path.dirname(home), home + "x/w", os.path.join(home, "a", "..", "b"), "/tmp"):
            self.assertFalse(execution.prepare_work_dir(work, home), work)
