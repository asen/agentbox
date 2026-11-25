"""Copied-input setup (inputs.py) and its session step, data-only: tar is an
owned stand-in that writes into the staging directory it is given, and the
session's setup is stubbed. No process is started."""

import asyncio
import os
import shutil
import tempfile
import unittest

from guest.src.inputs import (
    MAX_PLAN_BYTES, PLAN_HEADER, ROOTS, TAR, TAR_ENV, archive_path, parse_plan, setup_inputs, staging_path, tar_args,
    valid_destination,
)
from guest.test.session_harness import Harness

ID = "e-0123456789abcdef0123456789abcdef"


def plan(*lines):
    return PLAN_HEADER + "".join(line + "\n" for line in lines)


class FakeTar:
    """A tar stand-in: records its call, runs `extract` in the staging
    directory it was given, then exits with `code`; `hold` keeps it running
    until killed."""

    def __init__(self, extract, code=0, hold=False):
        self.calls = []
        self.extract = extract
        self.code = code
        self.hold = hold
        self.killed = False

    async def __call__(self, command, args, cwd, env):
        self.calls.append((command, args, cwd, env))
        self.extract(cwd)
        self.done = asyncio.get_running_loop().create_future()
        if not self.hold:
            self.done.set_result(self.code)
        return self

    async def wait(self):
        return await self.done

    def kill(self):
        self.killed = True
        if not self.done.done():
            self.done.set_result(-9)


def write(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data.encode() if isinstance(data, str) else data)
    finally:
        os.close(fd)


def extract_slots(plan_text, slots):
    """A stand-in extraction of the archive: `plan` and numbered `slots`."""

    def extract(staging):
        write(os.path.join(staging, "plan"), plan_text)
        os.mkdir(os.path.join(staging, "slots"), 0o700)
        for name, kind, fill in slots:
            path = os.path.join(staging, "slots", name)
            if kind == "d":
                os.mkdir(path, 0o700)
            fill(path)

    return extract


def file_of(data, mode=0o600):
    return lambda path: write(path, data, mode)


def dir_of(name, data):
    return lambda path: write(os.path.join(path, name), data)


def link_of(target):
    return lambda path: os.symlink(target, path)


def nothing(_path):
    pass


def _work(path):
    os.mkdir(os.path.join(path, "src"), 0o700)
    write(os.path.join(path, "src", "a.txt"), "a")


# The workspace alone: `d work` with one file.
EXTRACT_WORK = extract_slots(plan("d work"), [("0", "d", _work)])


def read(path):
    with open(path, "rb") as stream:
        return stream.read()


class Setup(unittest.IsolatedAsyncioTestCase):
    def home(self):
        directory = tempfile.mkdtemp(prefix="agentbox-inputs-")
        self.addCleanup(shutil.rmtree, directory, True)
        return directory

    async def setup_slots(self, directory, extract, live=lambda: True):
        write(archive_path(directory, ID), "archive bytes")
        return await setup_inputs(directory, ID, live, FakeTar(extract))

    async def test_setup_extracts_with_the_fixed_tar_call_and_publishes_the_planned_slots(self):
        directory = self.home()
        write(archive_path(directory, ID), "archive bytes")
        tar = FakeTar(EXTRACT_WORK)
        self.assertTrue(await setup_inputs(directory, ID, lambda: True, tar))
        self.assertEqual(len(tar.calls), 1)
        command, args, cwd, env = tar.calls[0]
        self.assertEqual((command, TAR), (TAR, "/usr/bin/tar"))
        self.assertEqual(args, tar_args(archive_path(directory, ID)))
        self.assertEqual(args, ["--extract", "--file", os.path.join(directory, ".agentbox-inputs-%s.tar" % ID),
                                "--no-same-owner", "--no-same-permissions", "--no-overwrite-dir"])
        self.assertEqual(cwd, staging_path(directory, ID))
        self.assertEqual(env, TAR_ENV)
        self.assertEqual(read(os.path.join(directory, "work", "src", "a.txt")), b"a")
        self.assertEqual(sorted(os.listdir(directory)), ["work"])
        self.assertEqual(ROOTS, ("plan", "slots"))

    async def test_an_empty_directory_destination_is_replaced_an_occupied_one_never_touched(self):
        directory = self.home()
        write(archive_path(directory, ID), "x")
        os.mkdir(os.path.join(directory, "work"), 0o700)
        self.assertTrue(await setup_inputs(directory, ID, lambda: True, FakeTar(EXTRACT_WORK)))
        self.assertEqual(read(os.path.join(directory, "work", "src", "a.txt")), b"a")

        def keep(d):
            os.mkdir(os.path.join(d, "work"), 0o700)
            write(os.path.join(d, "work", "keep"), "mine")

        for occupy in (keep, lambda d: write(os.path.join(d, "work"), "a file"),
                       lambda d: os.symlink("/tmp", os.path.join(d, "work"))):
            directory = self.home()
            write(archive_path(directory, ID), "x")
            occupy(directory)
            before = sorted(name for name in os.listdir(directory) if not name.startswith(".agentbox-inputs-"))
            self.assertFalse(await setup_inputs(directory, ID, lambda: True, FakeTar(EXTRACT_WORK)))
            after = sorted(name for name in os.listdir(directory) if not name.startswith(".agentbox-inputs-"))
            self.assertEqual(after, before)
            if os.path.isdir(os.path.join(directory, "work")) and not os.path.islink(os.path.join(directory, "work")):
                self.assertEqual(read(os.path.join(directory, "work", "keep")), b"mine")

    async def test_only_the_two_fixed_roots_a_regular_upload_and_tar_success_publish(self):
        def linked(d):
            write(os.path.join(d, "elsewhere"), "x")
            os.symlink(os.path.join(d, "elsewhere"), archive_path(d, ID))

        def extra(staging):
            EXTRACT_WORK(staging)
            os.mkdir(os.path.join(staging, "etc"))

        def old_layout(staging):
            os.mkdir(os.path.join(staging, "work"))
            os.mkdir(os.path.join(staging, "refs"))

        def reused(d):
            write(archive_path(d, ID), "x")
            os.mkdir(staging_path(d, ID))

        cases = (("no upload", lambda d: None, FakeTar(EXTRACT_WORK)),
                 ("linked upload", linked, FakeTar(EXTRACT_WORK)),
                 ("tar fails", lambda d: write(archive_path(d, ID), "x"), FakeTar(EXTRACT_WORK, 2)),
                 ("tar killed", lambda d: write(archive_path(d, ID), "x"), FakeTar(EXTRACT_WORK, -9)),
                 ("extra root", lambda d: write(archive_path(d, ID), "x"), FakeTar(extra)),
                 ("old work and refs layout", lambda d: write(archive_path(d, ID), "x"), FakeTar(old_layout)),
                 ("staging reused", reused, FakeTar(EXTRACT_WORK)))
        for name, prepare, tar in cases:
            directory = self.home()
            prepare(directory)
            self.assertFalse(await setup_inputs(directory, ID, lambda: True, tar), name)
            self.assertFalse(os.path.lexists(os.path.join(directory, "work")), name)

    async def test_a_setup_the_session_stops_wanting_kills_tar_and_publishes_nothing(self):
        directory = self.home()
        write(archive_path(directory, ID), "x")
        live = [True]
        tar = FakeTar(EXTRACT_WORK, 0, True)
        pending = asyncio.ensure_future(setup_inputs(directory, ID, lambda: live[0], tar))
        await asyncio.sleep(0.02)
        live[0] = False
        self.assertFalse(await pending)
        self.assertTrue(tar.killed)
        self.assertEqual(len(tar.calls), 1)
        self.assertFalse(os.path.lexists(os.path.join(directory, "work")))

    def test_plans_are_bounded_strict_utf8_lines_of_valid_disjoint_destinations(self):
        self.assertEqual(parse_plan(plan("d .config/tool", "f .gitconfig", "l a=b").encode()),
                         [(".config/tool", "d"), (".gitconfig", "f"), ("a=b", "l")])
        host = b"agentbox-inputs-v2\nl .auth\nf .config/tool.conf\nd work\n"
        self.assertEqual(["%s %s" % (kind, destination) for destination, kind in parse_plan(host)],
                         ["l .auth", "f .config/tool.conf", "d work"])
        every = ["f h%d" % index for index in range(32)]
        self.assertEqual(len(parse_plan(plan(*every).encode())), 32)
        longest = ["f %02d/%sb" % (index, "a/" * 510) for index in range(32)]
        self.assertEqual(len(plan(*longest).encode()), MAX_PLAN_BYTES)
        self.assertEqual(len(parse_plan(plan(*longest).encode())), 32)
        for name, data in (("empty", b""), ("header only", PLAN_HEADER.encode()),
                           ("old header", b"agentbox-home-plan-v1\nf a\n"),
                           ("bom", b"\xef\xbb\xbf" + plan("f a").encode()),
                           ("no final newline", (PLAN_HEADER + "f a").encode()),
                           ("crlf", (PLAN_HEADER + "f a\r\n").encode()), ("blank line", plan("f a", "").encode()),
                           ("kind", plan("x a").encode()), ("no space", plan("fa").encode()),
                           ("thirty-three", plan(*every, "f h32").encode()), ("oversized", b"a" * (MAX_PLAN_BYTES + 1)),
                           ("invalid utf-8", (PLAN_HEADER + "f a").encode() + b"\xff\n"),
                           ("duplicate", plan("f a", "d a").encode()), ("descendant", plan("d a", "f a/b").encode()),
                           ("ancestor", plan("l a/b", "d a").encode())):
            self.assertIsNone(parse_plan(data), name)
        for ok in (".config", "a=b", "work", "work/x", "refs/r", ".agentbox", "ü ñ", "a" * 255):
            self.assertTrue(valid_destination(ok), ok)
        for bad in ("", "/a", "a/", "a//b", ".", "..", "a/../b", "./a", "a\tb", "a\u007f", "a\u0085", "a\u0000",
                    "a" * 256, "a/" * 512 + "a", ".agentbox-inputs-e-x.tar", ".agentbox-inputs-x/y"):
            self.assertFalse(valid_destination(bad), repr(bad))

    async def test_slots_publish_directories_files_and_links_at_their_destinations_sharing_parents(self):
        directory = self.home()
        os.mkdir(os.path.join(directory, ".config"), 0o700)
        write(os.path.join(directory, ".config", "keep"), "mine")
        os.mkdir(os.path.join(directory, ".config", "tool"), 0o700)
        binary = bytes([0, 255, 0, 10, 13, 0])
        ok = await self.setup_slots(directory, extract_slots(
            plan("d .config/tool", "f .config/other", "f .local/bin/x", "l .local/share/y", "f .zero", "d notes",
                 "l .dangling"),
            [("0", "d", dir_of("settings", "s")), ("1", "f", file_of(binary)), ("2", "f", file_of("#!/bin/sh\n", 0o700)),
             ("3", "l", link_of("../../.config/other")), ("4", "f", file_of("")), ("5", "d", nothing),
             ("6", "l", link_of("/nonexistent/secret"))]))
        self.assertTrue(ok)
        self.assertEqual(read(os.path.join(directory, ".config", "keep")), b"mine")
        self.assertEqual(read(os.path.join(directory, ".config", "tool", "settings")), b"s")
        self.assertEqual(read(os.path.join(directory, ".config", "other")), binary)
        info = os.stat(os.path.join(directory, ".local", "bin", "x"))
        self.assertTrue(info.st_mode & 0o100)
        self.assertEqual(info.st_nlink, 1)
        self.assertTrue(os.path.islink(os.path.join(directory, ".local", "share", "y")))
        self.assertEqual(os.readlink(os.path.join(directory, ".local", "share", "y")), "../../.config/other")
        self.assertEqual(read(os.path.join(directory, ".local", "share", "y")), binary)
        self.assertEqual(os.readlink(os.path.join(directory, ".dangling")), "/nonexistent/secret")
        self.assertEqual(read(os.path.join(directory, ".zero")), b"")
        self.assertEqual(os.listdir(os.path.join(directory, "notes")), [])
        self.assertEqual(sorted(os.listdir(directory)), [".config", ".dangling", ".local", ".zero", "notes"])

    async def test_occupied_destinations_and_unsafe_parents_refuse_before_anything_is_published(self):
        def nonempty(d):
            os.makedirs(os.path.join(d, ".config", "tool"))
            write(os.path.join(d, ".config", "tool", "keep"), "mine")

        def file_for_dir(d):
            os.mkdir(os.path.join(d, ".config"))
            write(os.path.join(d, ".config", "tool"), "mine")

        def symlink_parent(d):
            os.mkdir(os.path.join(d, "real"))
            os.symlink(os.path.join(d, "real"), os.path.join(d, ".config"))

        cases = (("existing file", "f .gitconfig", "f", lambda d: write(os.path.join(d, ".gitconfig"), "mine")),
                 ("empty dir for a file", "f .gitconfig", "f", lambda d: os.mkdir(os.path.join(d, ".gitconfig"))),
                 ("dangling symlink", "f .gitconfig", "f",
                  lambda d: os.symlink(os.path.join(d, "nowhere"), os.path.join(d, ".gitconfig"))),
                 ("nonempty dir", "d .config/tool", "d", nonempty),
                 ("file for a dir", "d .config/tool", "d", file_for_dir),
                 ("symlink parent", "f .config/x", "f", symlink_parent),
                 ("file parent", "f .config/x", "f", lambda d: write(os.path.join(d, ".config"), "mine")),
                 ("existing file for a link", "l .auth", "l", lambda d: write(os.path.join(d, ".auth"), "mine")),
                 ("empty dir for a link", "l .auth", "l", lambda d: os.mkdir(os.path.join(d, ".auth"))),
                 ("symlink parent of a link", "l .config/x", "l", symlink_parent))
        for name, line, kind, occupy in cases:
            directory = self.home()
            occupy(directory)
            before = sorted(os.listdir(directory))
            fill = file_of("new") if kind == "f" else link_of("/new") if kind == "l" else dir_of("n", "new")
            ok = await self.setup_slots(directory, extract_slots(plan(line, "f .other"),
                                                                 [("0", kind, fill), ("1", "f", file_of("o"))]))
            self.assertFalse(ok, name)
            after = sorted(entry for entry in os.listdir(directory) if not entry.startswith(".agentbox-inputs-"))
            self.assertEqual(after, before, name)
            self.assertFalse(os.path.exists(os.path.join(directory, ".other")), name)
            self.assertFalse(os.path.exists(os.path.join(directory, "real", "x")), name)

    async def test_plans_and_slots_must_agree_exactly_or_nothing_is_published(self):
        def missing_plan(staging):
            extract_slots(plan("f a"), [("0", "f", file_of("a"))])(staging)
            os.unlink(os.path.join(staging, "plan"))

        def missing_slots(staging):
            extract_slots(plan("f a"), [])(staging)
            shutil.rmtree(os.path.join(staging, "slots"))

        def plan_dir(staging):
            os.mkdir(os.path.join(staging, "slots"))
            os.mkdir(os.path.join(staging, "plan"))

        def plan_link(staging):
            extract_slots(plan("f a"), [("0", "f", file_of("a"))])(staging)
            os.unlink(os.path.join(staging, "plan"))
            write(os.path.join(staging, "real-plan"), plan("f a"))
            os.symlink(os.path.join(staging, "real-plan"), os.path.join(staging, "plan"))

        cases = (("missing plan", missing_plan), ("missing slots", missing_slots), ("plan is a directory", plan_dir),
                 ("plan is a symlink", plan_link),
                 ("oversized plan", extract_slots(b"a" * (MAX_PLAN_BYTES + 1), [("0", "f", file_of("a"))])),
                 ("malformed plan", extract_slots(plan("f ../a"), [("0", "f", file_of("a"))])),
                 ("reserved plan", extract_slots(plan("f .agentbox-inputs-a"), [("0", "f", file_of("a"))])),
                 ("missing slot", extract_slots(plan("f a", "f b"), [("0", "f", file_of("a"))])),
                 ("extra slot", extract_slots(plan("f a"), [("0", "f", file_of("a")), ("1", "f", file_of("b"))])),
                 ("misnamed slot", extract_slots(plan("f a"), [("00", "f", file_of("a"))])),
                 ("kind mismatch", extract_slots(plan("f a"), [("0", "d", nothing)])),
                 ("dir for a file", extract_slots(plan("d a"), [("0", "f", file_of("a"))])),
                 ("symlink for a file", extract_slots(plan("f a"), [("0", "f", link_of("/etc/hostname"))])),
                 ("file for a link", extract_slots(plan("l a"), [("0", "f", file_of("a"))])),
                 ("dir for a link", extract_slots(plan("l a"), [("0", "d", nothing)])),
                 ("plan without slots", lambda staging: write(os.path.join(staging, "plan"), plan("f a"))))
        for name, extract in cases:
            directory = self.home()
            self.assertFalse(await self.setup_slots(directory, extract), name)
            self.assertEqual([e for e in os.listdir(directory) if not e.startswith(".agentbox-inputs-")], [], name)

    async def test_a_file_destination_taken_after_the_checks_is_never_overwritten(self):
        directory = self.home()
        raced = [False]

        def live():
            if not raced[0] and os.path.exists(os.path.join(directory, ".first")):
                raced[0] = True
                write(os.path.join(directory, ".second"), "theirs")
            return True

        ok = await self.setup_slots(directory, extract_slots(plan("f .first", "f .second", "f .third"),
                                                             [("0", "f", file_of("1")), ("1", "f", file_of("2")),
                                                              ("2", "f", file_of("3"))]), live)
        self.assertFalse(ok)
        self.assertTrue(raced[0])
        self.assertEqual(read(os.path.join(directory, ".second")), b"theirs")
        # No rollback, repair or retry: what was published stays, the rest is not.
        self.assertEqual(read(os.path.join(directory, ".first")), b"1")
        self.assertFalse(os.path.exists(os.path.join(directory, ".third")))
        self.assertTrue(os.path.exists(staging_path(directory, ID)))

    async def test_a_directory_destination_filled_after_the_checks_is_never_merged_into(self):
        directory = self.home()
        os.mkdir(os.path.join(directory, "tool"))
        raced = [False]

        def live():
            if not raced[0] and os.path.exists(os.path.join(staging_path(directory, ID), "slots", "0")):
                raced[0] = True
                write(os.path.join(directory, "tool", "theirs"), "theirs")
            return True

        ok = await self.setup_slots(directory, extract_slots(plan("d tool"), [("0", "d", dir_of("mine", "m"))]), live)
        self.assertFalse(ok)
        self.assertTrue(raced[0])
        self.assertEqual(os.listdir(os.path.join(directory, "tool")), ["theirs"])

    async def test_a_publication_failure_after_the_checks_leaves_what_was_published(self):
        if os.geteuid() == 0:
            self.skipTest("root ignores directory modes")
        directory = self.home()
        os.mkdir(os.path.join(directory, "locked"), 0o700)
        os.chmod(os.path.join(directory, "locked"), 0o500)
        try:
            ok = await self.setup_slots(directory, extract_slots(plan("f a", "f locked/b"),
                                                                 [("0", "f", file_of("a")), ("1", "f", file_of("b"))]))
            self.assertFalse(ok)
            self.assertEqual(read(os.path.join(directory, "a")), b"a")
            self.assertEqual(os.listdir(os.path.join(directory, "locked")), [])
        finally:
            os.chmod(os.path.join(directory, "locked"), 0o700)


class SessionStep(unittest.IsolatedAsyncioTestCase):
    async def session(self, frames, setup, end_after=True):
        directory = tempfile.mkdtemp(prefix="agentbox-inputs-")
        self.addCleanup(shutil.rmtree, directory, True)
        harness = Harness(directory)
        harness.session.options.inputs_setup = setup
        for frame in frames:
            harness.send(frame)
            await asyncio.sleep(0.01)
        if end_after:
            harness.end()
        status = await harness.status()
        return status, harness.frames

    HELLO = {"v": 1, "type": "hello", "session": "s1"}
    SETUP = {"v": 1, "type": "inputs_setup", "execution_id": ID}

    async def test_the_session_sets_up_once_after_hello_before_exec_then_reports_ready(self):
        seen = []

        async def setup(execution_id, _live):
            seen.append(execution_id)
            return True

        _status, frames = await self.session([self.HELLO, self.SETUP], setup)
        self.assertEqual(seen, [ID])
        self.assertEqual([f["type"] for f in frames], ["hello", "inputs_ready"])

        async def ok(_id, _live):
            return True

        _status, again = await self.session([self.HELLO, self.SETUP, self.SETUP], ok)
        self.assertEqual([f["type"] for f in again], ["hello", "inputs_ready", "error"])
        _status, early = await self.session([self.SETUP], ok)
        self.assertEqual([f["type"] for f in early], ["error"])

    async def test_a_failed_setup_gets_the_fixed_error_and_no_ready_frames_during_it_fail(self):
        async def fail(_id, _live):
            return False

        _status, failed = await self.session([self.HELLO, self.SETUP], fail)
        self.assertEqual([f["type"] for f in failed], ["hello", "error"])
        self.assertEqual(failed[1], {"v": 1, "type": "error", "code": "invalid_field"})

        async def until_unwanted(_id, live):
            while live():
                await asyncio.sleep(0.005)
            return True

        _status, during = await self.session(
            [self.HELLO, self.SETUP, {"v": 1, "type": "exec", "id": "x", "argv": ["true"]}], until_unwanted, False)
        self.assertEqual([f["type"] for f in during], ["hello", "error"])

    async def test_losing_the_hosts_input_during_setup_stops_it_with_no_late_ready(self):
        stopped = []

        async def until_unwanted(_id, live):
            while live():
                await asyncio.sleep(0.005)
            stopped.append(True)
            return True

        _status, frames = await self.session([self.HELLO, self.SETUP], until_unwanted)
        self.assertEqual(stopped, [True])
        self.assertEqual([f["type"] for f in frames], ["hello"])


if __name__ == "__main__":
    unittest.main()
