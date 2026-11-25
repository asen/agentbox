"""The pure guest Git command classification, repository grammar and
delivery against acquisitions/git/contract/v1, and the local runner (local.py) on a
stand-in child. No process is started."""

import asyncio
import json
import os
import stat
import time
import unittest
from unittest import mock

from acquisitions.git.jail import local, repository as repo
from acquisitions.git.jail.application import BUNDLE_SIGNATURE, EMPTY_MARKER, UNBORN_HEAD, Application, delivery
from acquisitions.git.jail.command import COMMAND_CODES, DEFAULT_REMOTE, classify_git_command, is_remote_name
from acquisitions.git.jail.local import Clock, Failed, LocalGit, Records, text_input
from guest.src.abort import Abort
from guest.src.artifact_post_protocol import encode_request
from guest.test.deny import deny_processes
from guest.test.post_memory import install_socket_guard

CONTRACTS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "acquisitions", "git", "contract")


def contract(name):
    with open(os.path.join(CONTRACTS, name), encoding="utf-8") as file:
        return json.load(file)


_guards = []


def setUpModule():
    sockets = install_socket_guard()
    _guards.extend([deny_processes(), sockets, sockets.denied])


def tearDownModule():
    processes, sockets, before = _guards
    assert (processes.release(), sockets.denied - before) == (0, 0)


class CommandTest(unittest.TestCase):
    def test_constants_match_the_contract(self):
        spec = contract("v1/contract.json")
        self.assertEqual(spec["command_codes"], list(COMMAND_CODES))
        self.assertEqual(spec["default_remote"], DEFAULT_REMOTE)

    def test_command_forms_follow_the_shared_fixtures(self):
        codes = set()
        for item in contract("v1/command-fixtures.json")["commands"]:
            result = classify_git_command(item["argv"])
            self.assertEqual(result, item["result"], item["name"])
            if result["kind"] == "refused":
                codes.add(result["code"])
        self.assertEqual(sorted(codes), sorted(COMMAND_CODES))

    def test_every_supported_clone_maps_to_an_accepted_submission(self):
        head = {"v": 1, "type": "submit", "session": "0" * 32, "client": "c1", "handler": "git", "operation": "clone"}
        for item in contract("v1/command-fixtures.json")["commands"]:
            result = classify_git_command(item["argv"])
            if result["kind"] == "clone":
                args = {"repository": result["repository"]}
                if "selector" in result:
                    args["selector"] = result["selector"]
                self.assertTrue(encode_request(dict(head, args=args)), item["name"])

    def test_push_is_refused_whatever_follows(self):
        for argv in (["push"], ["push", "--mirror"], ["--git-dir", "x", "push"],
                     ["-C", "a", "-C", "b", "push", "--upload-pack=x"]):
            self.assertEqual(classify_git_command(argv), {"kind": "refused", "code": "git_push_refused"}, argv)

    def test_remote_names_are_ids_never_urls_or_paths(self):
        for name in ("origin", "upstream", "fork-1", "a.b"):
            self.assertTrue(is_remote_name(name), name)
        for name in ("", "-x", ".x", "a..b", "a.lock", "a.", "a/b", "https://github.com/o/r", "git@github.com:o/r",
                     "x" * 65):
            self.assertFalse(is_remote_name(name), name)


class ContractTest(unittest.TestCase):
    def test_constants_match_the_contract(self):
        spec = contract("v1/contract.json")
        self.assertEqual(spec["capability"], "host_exact_image_registry")
        self.assertEqual(spec["repository"], {
            "host": repo.HOST, "url_prefix": repo.URL_PREFIX, "max_url_bytes": repo.MAX_URL_BYTES,
            "max_owner_bytes": repo.MAX_OWNER_BYTES, "max_name_bytes": repo.MAX_NAME_BYTES,
            "max_ref_bytes": repo.MAX_REF_BYTES, "max_selector_bytes": repo.MAX_SELECTOR_BYTES,
            "ref_prefixes": list(repo.REF_PREFIXES), "object_format": repo.OBJECT_FORMAT,
            "oid_hex_bytes": repo.OID_HEX_BYTES,
        })
        d = spec["delivery"]
        self.assertEqual(d["formats"], ["bundle", "empty"])
        self.assertEqual(d["empty_marker"].encode(), EMPTY_MARKER)
        self.assertEqual(BUNDLE_SIGNATURE, b"# v2 git bundle\n")
        self.assertEqual(d["bundle_config"], ["core.warnAmbiguousRefs=false"])
        self.assertEqual(d["bundle_command"], ["bundle", "create", "--version=2", "--quiet", "-", "--glob=refs/heads/*",
                                               "--glob=refs/tags/*"])
        self.assertEqual(spec["semantics"]["unborn_branch"], UNBORN_HEAD)
        for removed in ("manifest", "archive", "upload", "host_upload"):
            self.assertNotIn(removed, spec)

    def test_repository_urls_and_components_follow_the_shared_grammar(self):
        fixtures = contract("v1/repository-fixtures.json")
        for item in fixtures["urls"]["valid"]:
            parsed = repo.parse_repository_url(item["url"])
            self.assertIsNotNone(parsed, item["url"])
            self.assertEqual(repo.repository_id(parsed), item["repository"])
            self.assertEqual(repo.repository_url(parsed), item["canonical_url"])
            self.assertEqual(repo.parse_repository_url(repo.repository_url(parsed)), parsed)
            self.assertEqual(repo.parse_repository(item["repository"]), parsed)
        for item in fixtures["urls"]["invalid"]:
            self.assertIsNone(repo.parse_repository_url(item["url"]), item["why"])
        for text in fixtures["repositories"]["valid"]:
            self.assertEqual(repo.repository_id(repo.parse_repository(text)), text)
        for text in fixtures["repositories"]["invalid"]:
            self.assertIsNone(repo.parse_repository(text), text)
        for key, check in (("selectors", repo.is_selector), ("refs", repo.is_ref), ("oids", repo.is_oid)):
            for text in fixtures[key]["valid"]:
                self.assertTrue(check(text), (key, text))
            for text in fixtures[key]["invalid"]:
                self.assertFalse(check(text), (key, text))


class _Stdin:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        await asyncio.sleep(0)

    def close(self):
        self.closed = True


class Child:
    """A stand-in child: exit and close are separate, as a real one's are."""

    def __init__(self):
        self.returncode = None
        self.stdin = _Stdin()
        self.stdout = asyncio.StreamReader()
        self.stderr = asyncio.StreamReader()
        self.killed = []
        self._closed = asyncio.Event()

    def send_signal(self, number):
        self.killed.append(number)
        asyncio.get_running_loop().call_soon(self.finish, -number)

    def kill(self):
        self.send_signal(9)

    def finish(self, code):
        if self._closed.is_set():
            return
        self.returncode = code
        self.stdout.feed_eof()
        self.stderr.feed_eof()
        self._closed.set()

    async def wait(self):
        await self._closed.wait()
        return self.returncode


class LocalTest(unittest.IsolatedAsyncioTestCase):
    def runner(self, clock=None):
        child = Child()
        calls = []

        async def spawn(program, *args, **options):
            calls.append((program, args, options))
            return child

        original = local._spawn
        local._spawn = spawn
        self.addCleanup(setattr, local, "_spawn", original)
        return child, LocalGit("/guest-private", clock or Clock(time.monotonic() + 10)), calls

    async def test_real_runner_builds_a_closed_invocation_and_waits_for_actual_close(self):
        child, git, calls = self.runner()
        result = asyncio.ensure_future(git.run(["--version"]))
        await asyncio.sleep(0.01)
        program, args, options = calls[0]
        self.assertEqual(program, "/usr/bin/git")
        self.assertNotIn("start_new_session", options)
        self.assertIn("protocol.allow=never", args)
        self.assertIn("core.hooksPath=/dev/null", args)
        env = options["env"]
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "file")
        self.assertEqual(env["HOME"], "/guest-private/home")
        self.assertNotIn("GIT_CONFIG_COUNT", env)
        child.stdout.feed_data(b"git version 2.53.0\n")
        child.returncode = 0
        await asyncio.sleep(0.03)
        self.assertFalse(result.done())
        child.finish(0)
        self.assertEqual(await result, b"git version 2.53.0\n")
        self.assertEqual(child.killed, [])

    async def test_data_is_streamed_without_bulk_caps_diagnostics_are_bounded(self):
        child, git, _ = self.runner()
        count = [0]
        result = asyncio.ensure_future(git.run(["for-each-ref"], data=lambda b: count.__setitem__(0, count[0] + len(b))))
        for _ in range(32):
            child.stdout.feed_data(bytes(65536))
        child.finish(0)
        await result
        self.assertEqual(count[0], 2 * 1048576)
        for stderr in (True, False):
            child, git, _ = self.runner()
            result = asyncio.ensure_future(git.run(["--version"], diagnostics=4096))
            (child.stderr if stderr else child.stdout).feed_data(bytes(4097))
            with self.assertRaisesRegex(Failed, "git_output_exceeded"):
                await result
            self.assertEqual(child.killed, [15])

    async def test_stdin_is_fed_failures_latch_and_a_reaped_child_is_never_signalled(self):
        child, git, _ = self.runner()
        result = asyncio.ensure_future(git.run(["cat-file"], input=text_input(["one\n", "two\n"])))
        await asyncio.sleep(0.01)
        child.finish(0)
        await result
        self.assertEqual(bytes(child.stdin.data), b"one\ntwo\n")
        self.assertTrue(child.stdin.closed)
        stop = Abort()
        child, git, _ = self.runner(Clock(time.monotonic() + 10, stop))
        result = asyncio.ensure_future(git.run(["--version"]))
        await asyncio.sleep(0.01)
        child.returncode = 0
        stop.abort()
        await asyncio.sleep(0.03)
        self.assertEqual(child.killed, [])
        child.finish(0)
        with self.assertRaisesRegex(Failed, "git_cancelled"):
            await result

    async def test_a_quiet_child_is_stopped_by_the_original_deadline(self):
        child, git, _ = self.runner(Clock(time.monotonic() + 0.03))
        with self.assertRaisesRegex(Failed, "git_deadline_expired"):
            await git.run(["--version"])
        self.assertEqual(child.killed, [15])

    async def test_invalid_bindings_are_refused_before_any_filesystem_work(self):
        valid = {"session": "session-1", "request": "request-1", "request_sha256": "a" * 64, "operation": "clone",
                 "repository": "fixture/project", "delivery": {"format": "bundle"}, "size": 1, "sha256": "c" * 64,
                 "local": {"operation": "clone", "destination": "/not-used"}}
        for edit in ({"request_sha256": "x"}, {"size": 0}, {"size": True}, {"request": "../r"}, {"operation": "fetch"},
                     {"repository": "Not A Repo"}, {"selector": "--upload-pack"}, {"delivery": {"format": "archive"}},
                     {"delivery": {"format": "empty", "head": "refs/heads/main"}}):
            outcome = await Application(dict(valid, **edit)).run(1e20, None, local_layout("/not-used"))
            self.assertEqual(outcome, {"ok": False, "code": "git_application_invalid", "changes": "none",
                                       "cleanup": "observed"}, edit)


def local_layout(uploads):
    from acquisitions.git.jail.application import Layout
    return Layout("/", uploads)


class RecordsTest(unittest.TestCase):
    def test_record_parser_bounds_each_record_independent_of_splitting(self):
        text = b"a\nbbbbb\n\ncc\n"
        for split in range(len(text) + 1):
            found = []
            records = Records(10, 5, found.append)
            records.push(text[:split])
            records.push(text[split:])
            records.finish()
            self.assertEqual(found, [b"a", b"bbbbb", b"", b"cc"])
        for split in range(8):
            data = b"123456\n"
            records = Records(10, 5, lambda _record: self.fail("overlong accepted"))
            with self.assertRaises(Failed):
                records.push(data[:split])
                records.push(data[split:])
        count = []
        many = Records(10, 1, count.append)
        for _ in range(100000):
            many.push(b"a\n")
        many.finish()
        self.assertEqual(len(count), 100000)

    def test_the_workers_metadata_is_a_delivery_exactly(self):
        self.assertEqual(delivery({"format": "bundle"}), {"format": "bundle"})
        self.assertEqual(delivery({"format": "bundle", "head": "refs/heads/main"}),
                         {"format": "bundle", "head": "refs/heads/main"})
        self.assertEqual(delivery({"format": "empty"}), {"format": "empty"})
        for metadata in ({}, {"format": "archive"}, {"format": "empty", "head": "refs/heads/main"},
                         {"format": "bundle", "head": "refs/tags/v1"}, {"format": "bundle", "head": "refs/heads/HEAD"},
                         {"format": "bundle", "head": "refs/heads/a..b"}, {"format": "bundle", "head": 1},
                         {"format": "bundle", "extra": 1}, {"manifest_sha256": "a" * 64}):
            self.assertIsNone(delivery(metadata), metadata)

    def test_only_the_sticky_boundary_and_its_ancestors_may_be_sticky_and_other_writable(self):
        me, other = os.geteuid(), os.geteuid() + 1
        clock = Clock(time.monotonic() + 60)

        def entry(mode, uid=0):
            return os.stat_result((mode, 1, 1, 1, uid, 0, 0, 0, 0, 0))

        plain, sticky, open_, link = 0o40755, 0o41777, 0o40777, 0o41777 & ~stat.S_IFDIR | stat.S_IFLNK
        mine = entry(plain, me)
        # /tmp, /tmp/repo, /tmp/repo/sub; the boundary as a clone's parent or a repository's.
        for tmp, repo, sub, boundary, ok in (
                (entry(plain), mine, mine, None, True), (entry(sticky), mine, mine, None, False),
                (entry(sticky), mine, mine, "/tmp", True), (entry(sticky, me), mine, mine, "/tmp", True),
                (entry(sticky, other), mine, mine, "/tmp", False), (entry(plain, other), mine, mine, "/tmp", False),
                (entry(open_), mine, mine, "/tmp", False), (entry(open_, me), mine, mine, "/tmp", False),
                (entry(link), mine, mine, "/tmp", False), (entry(sticky), entry(sticky, me), mine, "/tmp", False),
                (entry(sticky), mine, entry(sticky, me), "/tmp", False),
                (entry(sticky), entry(plain, other), mine, "/tmp", False),
                (entry(sticky), entry(sticky, me), mine, "/tmp/repo", True),
                (entry(sticky), entry(sticky, me), entry(sticky, me), "/tmp/repo", False),
                (entry(sticky), mine, mine, "tmp", False), (entry(sticky), mine, mine, True, False)):
            tree = {"/": entry(plain), "/tmp": tmp, "/tmp/repo": repo, "/tmp/repo/sub": sub}
            with mock.patch.object(local.os, "lstat", tree.__getitem__):
                try:
                    local.directory("/", "/tmp/repo/sub", clock, sticky=boundary)
                    passed = True
                except Failed as error:
                    self.assertEqual(error.code, "git_work_unsafe")
                    passed = False
            self.assertEqual(passed, ok, (oct(tmp.st_mode), tmp.st_uid, oct(repo.st_mode), repo.st_uid,
                                          oct(sub.st_mode), boundary))

    @unittest.skipUnless(os.lstat("/tmp").st_mode & 0o7777 == 0o1777 and os.lstat("/tmp").st_uid == 0,
                         "no root-owned sticky /tmp")
    def test_the_real_tmp_is_accepted_at_or_above_the_sticky_boundary_only(self):
        clock = Clock(time.monotonic() + 60)
        local.directory("/", "/tmp", clock, sticky="/tmp")
        for boundary in (None, "/"):
            with self.assertRaises(Failed):
                local.directory("/", "/tmp", clock, sticky=boundary)

    def test_original_clock_cancellation_stays_fail_closed(self):
        with self.assertRaises(Failed):
            Clock(float("inf"))
        expired = Clock(0)
        with self.assertRaisesRegex(Failed, "git_deadline_expired"):
            expired.check()
        abort = Abort()
        clock = Clock(1e20, abort)
        abort.abort()
        for _ in range(2):
            with self.assertRaisesRegex(Failed, "git_cancelled"):
                clock.check()


if __name__ == "__main__":
    unittest.main()
