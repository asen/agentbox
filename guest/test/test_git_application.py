"""G3 application (application.py) and its fetch adapter `resolve_remote`
with real local Git. Run only under git_fixture_server.py `own`
(git_owned.py): each Git invocation also has that owner and a positive
settlement receipt before product staging removal. All fixture inputs,
captures and receipts are retained. Every test is serial. No process loss,
held owner, live guard removal or external cleanup probe occurs here."""

import hashlib
import os
import tempfile
import time
import unittest
import unittest.mock

from acquisitions.git.jail.application import EMPTY_MARKER, LOCAL_RESULT_CODES, Application, Layout, resolve_remote
from acquisitions.git.jail.local import Clock, LocalGit, Records, text_input
from guest.src.abort import Abort
from guest.test import git_owned

URL = "https://github.com/fixture/project.git"
IDENTITY = ["-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid"]
_serial = [0]
_root = []


def setUpModule():
    if not git_owned.OWNED:
        raise unittest.SkipTest(git_owned.SKIP)
    _root.extend([git_owned.ROOT, git_owned.guard(), LocalGit.run])
    git_owned.install_owned_git(git_owned.ROOT)


def tearDownModule():
    if _root:
        LocalGit.run = _root[2]
        assert _root[1].release() == 0


def until():
    return time.monotonic() + 120


def txt(data):
    return data.decode("utf-8").rstrip()


class Fixture:
    def __init__(self, root):
        self.root = root
        self.uploads = os.path.join(root, "uploads")
        self.upstream = os.path.join(root, "upstream.git")
        self.git = LocalGit(root, Clock(until()))
        self.original = ""
        self.layout = Layout(root, self.uploads)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def exists(path):
    try:
        os.lstat(path)
        return True
    except FileNotFoundError:
        return False


def read(path):
    with open(path, "rb") as file:
        return file.read()


def write(path, data, exclusive=True, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "wb") as file:
        file.write(data.encode() if isinstance(data, str) else data)


def append(path, text):
    with open(path, "a", encoding="utf-8") as file:
        file.write(text)


class GitCase(unittest.IsolatedAsyncioTestCase):
    async def run_git(self, f, path, *args):
        return txt(await f.git.run(["-C", path, *args]))

    async def commit(self, f, text, parent=None):
        script = ("blob\nmark :1\ndata %d\n%s\ncommit refs/heads/main\nmark :2\n"
                  "committer Fixture <fixture@example.invalid> 1700000000 +0000\ndata 7\nfixture\n%sM 100644 :1 file.txt\n\n"
                  % (len(text.encode()), text, "" if parent is None else "from %s\n" % parent))
        await f.git.run(["--git-dir=" + f.upstream, "fast-import", "--quiet"], input=text_input([script]))
        return await self.run_git(f, f.upstream, "rev-parse", "refs/heads/main")

    async def fixture(self, empty=False):
        root = tempfile.mkdtemp(prefix="case-", dir=_root[0])
        for name in ("home", "tmp", "uploads"):
            os.mkdir(os.path.join(root, name), 0o700)
        f = Fixture(root)
        await f.git.run(["init", "--quiet", "--bare", "--template=", "--initial-branch=main", f.upstream])
        if not empty:
            f.original = await self.commit(f, "one\n")
        return f

    async def upload(self, f, local, selector=None, no_head=False, head=None, incremental=False, format=None,
                     edit=None):
        """The host worker's delivery of the upstream, by the real Git: a v2
        bundle of every branch and tag and its usable HEAD, or the empty
        marker. `incremental` needs main~1: what the host never makes."""
        names = []
        listed = Records(10, 1024, lambda line: names.append(line.decode()))
        await f.git.run(["--git-dir=" + f.upstream, "for-each-ref", "--format=%(refname)", "refs/heads/", "refs/tags/"],
                        data=listed.push)
        listed.finish()
        usable = head or "refs/heads/main"
        head = usable if not no_head and usable in names else None
        data = EMPTY_MARKER
        if names:
            parts = []
            revs = ["refs/heads/main~1..refs/heads/main"] if incremental else ["--glob=refs/heads/*", "--glob=refs/tags/*"]
            await f.git.run(["-c", "core.warnAmbiguousRefs=false", "--git-dir=" + f.upstream, "bundle", "create",
                             "--version=2", "--quiet", "-", *revs], data=parts.append)
            data = b"".join(parts)
        if edit is not None:
            data = edit(data)
        format = format or ("empty" if not names else "bundle")
        delivery = {"format": format}
        if format == "bundle" and head is not None:
            delivery["head"] = head
        _serial[0] += 1
        session, request = "session-1", "request-%d" % _serial[0]
        path = os.path.join(f.uploads, "%s-%s.artifact" % (session, request))
        write(path, data)
        given = {"session": session, "request": request,
                 "request_sha256": sha256(("submission %s %s" % (session, request)).encode()),
                 "operation": local["operation"], "repository": "fixture/project"}
        if selector is not None:
            given["selector"] = selector
        given.update(delivery=delivery, size=len(data), sha256=sha256(data), local=local)
        return given, path, data

    async def apply(self, f, given, signal=None):
        result = await Application(given).run(until(), signal, f.layout)
        self.assertEqual(sorted(result), ["changes", "cleanup", "code", "ok"])
        self.assertIn(result["code"], LOCAL_RESULT_CODES)
        return result

    async def clone(self, f, name="work", **options):
        destination = os.path.join(f.root, name)
        given, path, _ = await self.upload(f, {"operation": "clone", "destination": destination}, **options)
        self.assertEqual(await self.apply(f, given), {"ok": True, "code": "git_applied", "changes": "possible",
                                                       "cleanup": "observed"})
        self.assertFalse(exists(path))
        return destination

    async def remote(self, f, work, url=URL):
        await self.run_git(f, work, "config", "remote.origin.url", url)
        await self.run_git(f, work, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")

    async def fetch(self, f, work, **options):
        given, _, _ = await self.upload(f, {"operation": "fetch", "directory": work, "remote": "origin"}, **options)
        return await self.apply(f, given)

    def patch_run(self, wrapper):
        original = LocalGit.run

        async def run(git, args, **options):
            return await wrapper(original, git, args, **options)

        LocalGit.run = run
        self.addCleanup(setattr, LocalGit, "run", original)


class ApplicationTest(GitCase):
    async def test_clone_is_independent_of_removed_staging_canonical_and_single_use(self):
        f = await self.fixture()
        destination = os.path.join(f.root, "work")
        given, _, _ = await self.upload(f, {"operation": "clone", "destination": destination})
        app = Application(given)
        given["local"]["destination"] = os.path.join(f.root, "elsewhere")  # the constructor owns snapshots
        self.assertEqual(await app.run(until(), None, f.layout), {"ok": True, "code": "git_applied",
                                                                   "changes": "possible", "cleanup": "observed"})
        self.assertEqual((await app.run(until(), None, f.layout))["code"], "git_application_used")
        self.assertEqual(read(os.path.join(destination, "file.txt")), b"one\n")
        self.assertEqual(await self.run_git(f, destination, "config", "remote.origin.url"), URL)
        self.assertEqual(await self.run_git(f, destination, "config", "remote.origin.fetch"),
                         "+refs/heads/*:refs/remotes/origin/*")
        self.assertEqual(await self.run_git(f, destination, "symbolic-ref", "refs/remotes/origin/HEAD"),
                         "refs/remotes/origin/main")
        self.assertEqual(await self.run_git(f, destination, "rev-parse", "HEAD"), f.original)
        self.assertEqual(await self.run_git(f, destination, "fsck", "--full", "--strict", "--no-dangling"), "")
        self.assertEqual(os.listdir(f.uploads), [])
        pack = os.path.join(destination, ".git/objects/pack")
        for name in os.listdir(pack):
            self.assertEqual(os.lstat(os.path.join(pack, name)).st_nlink, 1)

    async def test_missing_and_empty_destinations_work_nonempty_and_symlink_do_not(self):
        f = await self.fixture()
        os.mkdir(os.path.join(f.root, "empty"), 0o700)
        await self.clone(f, "empty")
        os.mkdir(os.path.join(f.root, "busy"), 0o700)
        write(os.path.join(f.root, "busy", "keep"), "unchanged")
        given, _, _ = await self.upload(f, {"operation": "clone", "destination": os.path.join(f.root, "busy")})
        self.assertEqual((await self.apply(f, given))["code"], "git_destination_not_empty")
        self.assertEqual(read(os.path.join(f.root, "busy/keep")), b"unchanged")
        os.symlink(os.path.join(f.root, "empty"), os.path.join(f.root, "link"))
        given, _, _ = await self.upload(f, {"operation": "clone", "destination": os.path.join(f.root, "link")})
        self.assertEqual((await self.apply(f, given))["code"], "git_destination_not_empty")

    async def test_branch_wins_over_equal_tag_annotated_and_nested_tags_detach_at_peeled_commits(self):
        f = await self.fixture()
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/release", f.original)
        await self.run_git(f, f.upstream, *IDENTITY, "tag", "-a", "release", "-m", "tag", f.original)
        await self.run_git(f, f.upstream, *IDENTITY, "tag", "-a", "nested", "-m", "nested", "refs/tags/release")
        raw = await self.run_git(f, f.upstream, "rev-parse", "refs/tags/nested")
        branch = await self.clone(f, "branch", selector="release")
        self.assertEqual(await self.run_git(f, branch, "symbolic-ref", "HEAD"), "refs/heads/release")
        tag = await self.clone(f, "tag", selector="nested")
        self.assertEqual(await self.run_git(f, tag, "rev-parse", "HEAD"), f.original)
        self.assertEqual(await self.run_git(f, tag, "rev-parse", "refs/tags/nested"), raw)
        self.assertEqual(txt(await f.git.run(["-C", tag, "symbolic-ref", "-q", "HEAD"], exits=(1,))), "")
        self.assertEqual(await self.run_git(f, tag, "for-each-ref", "refs/heads"), "")
        self.assertEqual(txt(await f.git.run(["-C", tag, "config", "--get-regexp", "^branch\\."], exits=(1,))), "")
        unusual = 'topic/quote";x'
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/" + unusual, f.original)
        quoted = await self.clone(f, "quoted", selector=unusual)
        self.assertEqual(await self.run_git(f, quoted, "symbolic-ref", "HEAD"), "refs/heads/" + unusual)

    async def test_uncheckoutable_and_absent_selectors_refuse_before_publication(self):
        f = await self.fixture()
        tree = await self.run_git(f, f.upstream, "rev-parse", "refs/heads/main^{tree}")
        await self.run_git(f, f.upstream, "update-ref", "refs/tags/tree", tree)
        for selector, code in (("tree", "git_selector_not_checkoutable"), ("absent", "git_selector_not_found")):
            destination = os.path.join(f.root, selector)
            given, _, _ = await self.upload(f, {"operation": "clone", "destination": destination}, selector=selector)
            self.assertEqual((await self.apply(f, given))["code"], code)
            self.assertFalse(exists(destination))

    async def test_empty_and_unusable_head_give_fixed_unborn_main_no_fallback(self):
        for empty in (True, False):
            f = await self.fixture(empty)
            work = await self.clone(f, "work", no_head=True)
            if empty:
                # The marker, nothing else; a fetch of it changes no ref.
                await self.remote(f, work)
                given, _, data = await self.upload(f, {"operation": "fetch", "directory": work, "remote": "origin"})
                self.assertEqual((given["delivery"], data), ({"format": "empty"}, EMPTY_MARKER))
                self.assertTrue((await self.apply(f, given))["ok"])
                self.assertEqual(await self.run_git(f, work, "for-each-ref"), "")
            self.assertEqual(await self.run_git(f, work, "symbolic-ref", "HEAD"), "refs/heads/main")
            self.assertEqual(await self.run_git(f, work, "for-each-ref", "refs/heads"), "")
            self.assertEqual(sorted(os.listdir(work)), [".git"])
            self.assertEqual(txt(await f.git.run(["-C", work, "symbolic-ref", "-q", "refs/remotes/origin/HEAD"],
                                                 exits=(1,))), "")

    async def test_fetch_advances_rewinds_retains_deleted_refs_dirty_index_and_local_commits(self):
        f = await self.fixture()
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/topic", f.original)
        await self.run_git(f, f.upstream, "update-ref", "refs/tags/v1", f.original)
        work = await self.clone(f)
        await self.remote(f, work, "https://github.com/Fixture/Project")
        await self.run_git(f, work, *IDENTITY, "commit", "--quiet", "--allow-empty", "-m", "local")
        local = await self.run_git(f, work, "rev-parse", "HEAD")
        write(os.path.join(work, "file.txt"), "staged\n", exclusive=False)
        await self.run_git(f, work, "add", "file.txt")
        write(os.path.join(work, "file.txt"), "dirty\n", exclusive=False)
        index, config = read(os.path.join(work, ".git/index")), read(os.path.join(work, ".git/config"))
        after = await self.commit(f, "two\n", f.original)
        await self.run_git(f, f.upstream, "update-ref", "-d", "refs/heads/topic")
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/new", after)
        self.assertTrue((await self.fetch(f, work))["ok"])
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/main"), after)
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/topic"), f.original)
        self.assertEqual(await self.run_git(f, work, "rev-parse", "HEAD"), local)
        self.assertEqual(read(os.path.join(work, "file.txt")), b"dirty\n")
        self.assertEqual(read(os.path.join(work, ".git/index")), index)
        self.assertEqual(read(os.path.join(work, ".git/config")), config)
        head = read(os.path.join(work, ".git/FETCH_HEAD")).decode()
        self.assertEqual(head.split("\n")[0], "%s\t\tbranch 'main' of %s" % (after, URL))
        self.assertIn("%s\tnot-for-merge\ttag 'v1' of %s\n" % (f.original, URL), head)
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/main", f.original)
        self.assertTrue((await self.fetch(f, work))["ok"])
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/main"), f.original)
        self.assertEqual(read(os.path.join(work, ".git/index")), index)
        self.assertEqual(await self.run_git(f, work, "fsck", "--full", "--strict", "--no-dangling"), "")

    async def test_tag_and_namespace_conflicts_fail_before_any_change(self):
        f = await self.fixture()
        await self.run_git(f, f.upstream, "update-ref", "refs/tags/v1", f.original)
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/topic", f.original)
        work = await self.clone(f)
        after = await self.commit(f, "two\n", f.original)
        await self.run_git(f, f.upstream, "update-ref", "refs/tags/v1", after)
        before = await self.run_git(f, work, "show-ref")
        failed = await self.fetch(f, work)
        self.assertEqual((failed["code"], failed["changes"]), ("git_tag_conflict", "none"))
        self.assertEqual(await self.run_git(f, work, "show-ref"), before)
        await self.run_git(f, f.upstream, "update-ref", "refs/tags/v1", f.original)
        await self.run_git(f, f.upstream, "update-ref", "-d", "refs/heads/topic")
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/topic/child", after)
        self.assertEqual((await self.fetch(f, work))["code"], "git_ref_conflict")
        self.assertEqual(await self.run_git(f, work, "show-ref"), before)

    async def test_fetch_head_eligibility_follows_configured_upstream(self):
        f = await self.fixture()
        work = await self.clone(f)
        for name in ("elsewhere", "."):
            await self.run_git(f, work, "config", "branch.main.remote", name)
            self.assertTrue((await self.fetch(f, work))["ok"])
            self.assertIn("\tnot-for-merge\t", read(os.path.join(work, ".git/FETCH_HEAD")).decode())
        await self.run_git(f, work, "checkout", "--quiet", "--detach", f.original)
        self.assertTrue((await self.fetch(f, work))["ok"])
        self.assertIn("\tnot-for-merge\t", read(os.path.join(work, ".git/FETCH_HEAD")).decode())
        unborn = os.path.join(f.root, "unborn")
        await f.git.run(["init", "--quiet", "--template=", "--initial-branch=main", unborn])
        await self.remote(f, unborn)
        await self.run_git(f, unborn, "config", "branch.main.remote", "origin")
        await self.run_git(f, unborn, "config", "branch.main.merge", "refs/heads/main")
        self.assertTrue((await self.fetch(f, unborn))["ok"])
        self.assertTrue(read(os.path.join(unborn, ".git/FETCH_HEAD")).decode().startswith(f.original + "\t\t"))
        self.assertEqual(await self.run_git(f, unborn, "for-each-ref", "refs/heads"), "")
        self.assertFalse(exists(os.path.join(unborn, ".git/index")))

    async def test_foreign_config_indirection_and_symbolic_destinations_refuse(self):
        f = await self.fixture()
        work = await self.clone(f)
        tripwire = os.path.join(f.root, "not-a-config")
        write(tripwire, "not valid Git configuration\n")
        config = os.path.join(work, ".git/config")
        original = read(config)
        append(config, "[include]\npath = %s\n" % tripwire)
        self.assertEqual((await self.fetch(f, work))["code"], "git_repository_unsupported")
        write(config, original, exclusive=False)
        await self.run_git(f, work, "symbolic-ref", "refs/remotes/origin/main", "refs/heads/main")
        self.assertEqual((await self.fetch(f, work))["code"], "git_repository_unsupported")
        self.assertEqual(await self.run_git(f, work, "rev-parse", "HEAD"), f.original)

    async def test_digest_truncation_corruption_foreign_files_and_incremental_bundles_refuse(self):
        f = await self.fixture()
        await self.commit(f, "two\n", f.original)

        def unpack(data):
            at = data.index(b"PACK")
            self.assertGreater(at, 0)
            return data[:at] + b"\0" + data[at + 1:]

        def flip(data):
            copy = bytearray(data)
            copy[-30] ^= 0xFF
            return bytes(copy)

        variants = [
            {"edit": lambda data: data[:-1]},
            {"edit": unpack},
            {"edit": flip},
            {"edit": lambda _data: ("gitdir: %s\n" % f.upstream).encode()},
            {"edit": lambda _data: EMPTY_MARKER},
            {"format": "empty"},
            {"incremental": True},
        ]
        for index, variant in enumerate(variants):
            destination = os.path.join(f.root, "bad-%d" % index)
            given, _, _ = await self.upload(f, {"operation": "clone", "destination": destination}, **variant)
            result = await self.apply(f, given)
            self.assertEqual((result["code"], result["changes"]), ("git_bundle_invalid", "none"), index)
            self.assertFalse(exists(destination))
        given, path, data = await self.upload(f, {"operation": "clone",
                                                  "destination": os.path.join(f.root, "bad-digest")})
        write(path, data[:-1] + bytes([data[-1] ^ 1]), exclusive=False)
        self.assertEqual((await self.apply(f, given))["code"], "git_bundle_invalid")

    async def test_tags_of_trees_blobs_and_tags_keep_raw_ids_tracked_links_stay_links(self):
        f = await self.fixture()
        tree = await self.run_git(f, f.upstream, "rev-parse", "refs/heads/main^{tree}")
        blob = await self.run_git(f, f.upstream, "rev-parse", "refs/heads/main:file.txt")
        await self.run_git(f, f.upstream, *IDENTITY, "tag", "lblob", blob)
        await self.run_git(f, f.upstream, *IDENTITY, "tag", "-a", "-m", "t", "atree", tree)
        await self.run_git(f, f.upstream, *IDENTITY, "tag", "-a", "-m", "n", "nested", "refs/tags/atree")
        out, dangling = "/etc/passwd", "../../../../nowhere"
        links = ("blob\nmark :1\ndata %d\n%s\nblob\nmark :2\ndata %d\n%s\ncommit refs/heads/links\nmark :3\n"
                 "committer Fixture <fixture@example.invalid> 1700000000 +0000\ndata 5\nlinks\nfrom %s\n"
                 "M 120000 :1 out\nM 120000 :2 dangling\n\n" % (len(out), out, len(dangling), dangling, f.original))
        await f.git.run(["--git-dir=" + f.upstream, "fast-import", "--quiet"], input=text_input([links]))
        work = await self.clone(f, "work", selector="links")
        for name in ("lblob", "atree", "nested"):
            self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/tags/" + name),
                             await self.run_git(f, f.upstream, "rev-parse", "refs/tags/" + name))
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/tags/nested^{}"), tree)
        for name, target in (("out", out), ("dangling", dangling)):
            self.assertTrue(os.path.islink(os.path.join(work, name)), name)
            self.assertEqual(os.readlink(os.path.join(work, name)), target)
        for selector in ("lblob", "nested"):
            destination = os.path.join(f.root, "sel-" + selector)
            given, _, _ = await self.upload(f, {"operation": "clone", "destination": destination}, selector=selector)
            self.assertEqual((await self.apply(f, given))["code"], "git_selector_not_checkoutable")

    async def test_refs_ambiguous_with_others_keep_their_own_names(self):
        f = await self.fixture()
        other = await self.commit(f, "other\n", f.original)
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/main", f.original)
        for name, oid in (("refs/heads/x", f.original), ("refs/heads/refs/heads/x", other),
                          ("refs/tags/v1", f.original), ("refs/heads/refs/tags/v1", other),
                          ("refs/tags/refs/heads/main", other)):
            await self.run_git(f, f.upstream, "update-ref", name, oid)

        async def upstream():
            return (await self.run_git(f, f.upstream, "for-each-ref", "--format=%(objectname) %(refname)",
                                       "refs/heads/", "refs/tags/")).split("\n")

        async def tracking(work):
            lines = (await self.run_git(f, work, "for-each-ref", "--format=%(objectname) %(refname)",
                                        "refs/remotes/origin/", "refs/tags/")).split("\n")
            lines = [line.replace(" refs/remotes/origin/", " refs/heads/") for line in lines
                     if not line.endswith(" refs/remotes/origin/HEAD")]
            return sorted(lines, key=lambda line: line.split(" ")[1])

        work = await self.clone(f, "work", selector="x")
        self.assertEqual(await tracking(work), await upstream())
        self.assertEqual(await self.run_git(f, work, "symbolic-ref", "HEAD"), "refs/heads/x")
        self.assertEqual(await self.run_git(f, work, "rev-parse", "HEAD"), f.original)
        after = await self.commit(f, "two\n", other)
        await self.run_git(f, f.upstream, "update-ref", "refs/heads/x", after)
        self.assertTrue((await self.fetch(f, work))["ok"])
        self.assertEqual(await tracking(work), await upstream())
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/x"), after)
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/refs/heads/x"), other)

    async def test_a_head_of_every_escaped_byte_is_delivered_and_checked_out(self):
        f = await self.fixture()
        quoted = "refs/heads/" + '"' * 245
        await self.run_git(f, f.upstream, "update-ref", quoted, f.original)
        work = await self.clone(f, "work", head=quoted)
        self.assertEqual(await self.run_git(f, work, "symbolic-ref", "HEAD"), quoted)
        self.assertEqual(await self.run_git(f, work, "symbolic-ref", "refs/remotes/origin/HEAD"),
                         "refs/remotes/origin/" + '"' * 245)
        self.assertEqual(read(os.path.join(work, "file.txt")), b"one\n")

    async def test_upload_hardlinks_are_refused_without_reading_their_contents(self):
        f = await self.fixture()
        given, path, data = await self.upload(f, {"operation": "clone", "destination": os.path.join(f.root, "work")})
        os.link(path, os.path.join(f.root, "second-link"))
        self.assertEqual((await self.apply(f, given))["code"], "git_work_unsafe")
        self.assertEqual(read(path), data)

    async def test_cancellation_and_deadline_refuse_cancellation_after_checkout_cannot_publish(self):
        f = await self.fixture()
        given, _, _ = await self.upload(f, {"operation": "clone", "destination": os.path.join(f.root, "work")})
        stop = Abort()
        stop.abort()
        self.assertEqual((await self.apply(f, given, stop))["code"], "git_cancelled")
        self.assertEqual((await Application(given).run(0, None, f.layout))["code"], "git_deadline_expired")
        later = Abort()

        async def wrapper(original, git, args, **options):
            out = await original(git, args, **options)
            if "reset" in args:
                later.abort()
            return out

        self.patch_run(wrapper)
        result = await self.apply(f, given, later)
        self.assertEqual((result["code"], result["changes"], result["cleanup"]),
                         ("git_cancelled", "none", "retained"))
        self.assertFalse(exists(os.path.join(f.root, "work")))

    async def test_checkout_failure_retains_private_staging_never_a_partial_clone(self):
        f = await self.fixture()
        given, _, _ = await self.upload(f, {"operation": "clone", "destination": os.path.join(f.root, "work")})

        async def wrapper(original, git, args, **options):
            if "reset" in args:
                self.assertEqual(args[0], "-C")
                self.assertTrue(args[1].startswith(f.root + "/.agentbox-clone-"))
                write(os.path.join(args[1], ".git/index.lock"), "fixture checkout conflict")
            return await original(git, args, **options)

        self.patch_run(wrapper)
        result = await self.apply(f, given)
        self.assertEqual(result, {"ok": False, "code": "git_process_failed", "changes": "none",
                                  "cleanup": "retained"})
        self.assertFalse(exists(os.path.join(f.root, "work")))
        # The private directory beside the destination stays, as staging does.
        self.assertEqual(len([name for name in os.listdir(f.root) if name.startswith(".agentbox-clone-")]), 1)

    async def test_a_clone_is_made_beside_its_destination_and_published_by_one_local_rename(self):
        f = await self.fixture()
        destination = os.path.join(f.root, "work")
        given, _, _ = await self.upload(f, {"operation": "clone", "destination": destination})
        targets = []

        async def wrapper(original, git, args, **options):
            if "clone" in args:
                targets.append(args[-1])
            elif args[0] == "-C" and not args[1].startswith(f.uploads + "/"):
                targets.append(args[1])
            return await original(git, args, **options)

        renames = []
        rename = os.rename

        def recording(source, target):
            renames.append((source, target))
            return rename(source, target)

        self.patch_run(wrapper)
        with unittest.mock.patch.object(os, "rename", recording):
            self.assertEqual((await self.apply(f, given))["ok"], True)
        side = os.path.dirname(targets[0])
        self.assertTrue(side.startswith(f.root + "/.agentbox-clone-"))
        self.assertEqual(set(targets), {os.path.join(side, "worktree")})
        self.assertEqual(renames, [(os.path.join(side, "worktree"), destination)])
        self.assertFalse(exists(side))
        self.assertEqual(read(os.path.join(destination, "file.txt")), b"one\n")

    async def test_a_sticky_ancestor_serves_a_clone_destination_and_working_repository_only(self):
        f = await self.fixture()
        sticky = os.path.join(f.root, "sticky")
        os.mkdir(sticky)
        os.chmod(sticky, 0o1777)
        work = await self.clone(f, "sticky/pip-req-build-x")
        self.assertEqual(read(os.path.join(work, "file.txt")), b"one\n")
        self.assertEqual(os.listdir(sticky), ["pip-req-build-x"])
        # Not sticky, a world-writable destination or uploads beneath it: refused.
        shared = os.path.join(f.root, "shared")
        os.mkdir(shared)
        os.chmod(shared, 0o777)
        open_dir = os.path.join(sticky, "open")
        os.mkdir(open_dir)
        os.chmod(open_dir, 0o777)
        for destination in (os.path.join(shared, "x"), open_dir):
            given, _, _ = await self.upload(f, {"operation": "clone", "destination": destination})
            result = await self.apply(f, given)
            self.assertEqual((result["code"], result["changes"]), ("git_work_unsafe", "none"), destination)
        self.assertEqual(os.listdir(shared), [])
        self.assertEqual(os.listdir(open_dir), [])
        given, path, _ = await self.upload(f, {"operation": "clone", "destination": os.path.join(f.root, "y")})
        uploads = os.path.join(sticky, "uploads")
        os.mkdir(uploads, 0o700)
        os.rename(path, os.path.join(uploads, os.path.basename(path)))
        result = await Application(given).run(until(), None, Layout(f.root, uploads))
        self.assertEqual((result["code"], result["changes"]), ("git_work_unsafe", "none"))
        self.assertFalse(exists(os.path.join(f.root, "y")))
        # Fetch and its remote resolution, from the repository or within it, as the clone.
        await self.remote(f, work)
        os.mkdir(os.path.join(work, "sub"))
        for start in (work, os.path.join(work, "sub")):
            self.assertEqual(await resolve_remote(start, "origin", until(), None, f.layout),
                             {"ok": True, "repository": "fixture/project"})
        self.assertTrue((await self.fetch(f, work))["ok"])
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/main"), f.original)
        # Beneath a sticky one, no repository: none found.
        plain = os.path.join(sticky, "plain")
        os.mkdir(plain)
        self.assertEqual((await resolve_remote(plain, "origin", until(), None, f.layout))["code"],
                         "git_repository_unsupported")
        # Not the repository itself, a directory within it, a non-sticky ancestor or a symlink.
        async def unsafe(start, fetched=None):
            self.assertEqual((await resolve_remote(start, "origin", until(), None, f.layout))["code"],
                             "git_work_unsafe", start)
            if fetched is not None:
                result = await self.fetch(f, fetched)
                self.assertEqual((result["code"], result["changes"]), ("git_work_unsafe", "none"), fetched)

        os.chmod(work, 0o1777)
        await unsafe(work, work)
        os.chmod(work, 0o755)
        sub = os.path.join(work, "sub")
        os.chmod(sub, 0o1777)
        await unsafe(sub)
        os.chmod(sub, 0o755)
        nested = os.path.join(open_dir, "work")
        await self.remote(f, await self.clone(f, "nested"))
        os.rename(os.path.join(f.root, "nested"), nested)
        await unsafe(nested, nested)
        os.symlink(sticky, os.path.join(f.root, "link"))
        linked = os.path.join(f.root, "link", "pip-req-build-x")
        await unsafe(linked, linked)
        self.assertTrue((await self.fetch(f, work))["ok"])

    async def test_an_upstream_of_several_packs_is_cloned_self_contained(self):
        f = await self.fixture()
        # Small fast-import batches may be unpacked into loose objects. Pack
        # each batch explicitly; -d without -a leaves the preceding pack.
        await self.run_git(f, f.upstream, "repack", "-d")
        await self.commit(f, "two\n", f.original)
        await self.run_git(f, f.upstream, "repack", "-d")
        packs = [name for name in os.listdir(os.path.join(f.upstream, "objects/pack")) if name.endswith(".pack")]
        self.assertGreaterEqual(len(packs), 2)
        work = await self.clone(f)
        self.assertEqual(read(os.path.join(work, "file.txt")), b"two\n")
        self.assertEqual(await self.run_git(f, work, "fsck", "--full", "--strict", "--no-dangling"), "")

    async def test_ambient_config_is_ignored_and_a_real_reference_hook_never_runs(self):
        f = await self.fixture()
        bad = os.path.join(f.root, "ambient-config")
        write(bad, "not valid Git configuration\n")
        previous = os.environ.get("GIT_CONFIG_GLOBAL")
        os.environ["GIT_CONFIG_GLOBAL"] = bad
        try:
            work = await self.clone(f)
        finally:
            if previous is None:
                del os.environ["GIT_CONFIG_GLOBAL"]
            else:
                os.environ["GIT_CONFIG_GLOBAL"] = previous
        hooks, marker = os.path.join(work, ".git/hooks"), os.path.join(f.root, "hook-ran")
        os.mkdir(hooks, 0o700)
        write(os.path.join(hooks, "reference-transaction"),
              "#!/usr/bin/python3 -ISB\nopen(%r, 'x').write('ran')\n" % marker, mode=0o700)
        await self.commit(f, "two\n", f.original)
        self.assertTrue((await self.fetch(f, work))["ok"])
        self.assertFalse(exists(marker))
        config = os.path.join(work, ".git/config")
        before = read(config)
        append(config, '[url "https://example.invalid/"]\n\tinsteadOf = %s\n' % f.root)
        result = await self.fetch(f, work)
        self.assertEqual((result["code"], result["changes"]), ("git_repository_unsupported", "none"))
        write(config, before, exclusive=False)
        write(os.path.join(work, ".git/refs/heads/broken"), "not-an-object-id\n")
        broken = await self.fetch(f, work)
        self.assertEqual((broken["ok"], broken["changes"]), (False, "none"))

    async def test_failure_after_fetch_reports_possible_changes_and_keeps_prior_fetch_head(self):
        f = await self.fixture()
        work = await self.clone(f)
        after = await self.commit(f, "two\n", f.original)
        write(os.path.join(work, ".git/FETCH_HEAD"), "previous\n")
        write(os.path.join(work, ".git/FETCH_HEAD.lock"), "owned fixture conflict\n")
        result = await self.fetch(f, work)
        self.assertEqual((result["ok"], result["changes"], result["cleanup"]), (False, "possible", "retained"))
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/main"), after)
        self.assertEqual(read(os.path.join(work, ".git/FETCH_HEAD")), b"previous\n")
        self.assertEqual(read(os.path.join(work, ".git/FETCH_HEAD.lock")), b"owned fixture conflict\n")

    async def test_cancellation_after_fetch_never_claims_success_or_rewrites_fetch_head(self):
        f = await self.fixture()
        work = await self.clone(f)
        after = await self.commit(f, "two\n", f.original)
        stop = Abort()

        async def wrapper(original, git, args, **options):
            out = await original(git, args, **options)
            if args[0] == "-C" and "fetch" in args:
                stop.abort()
            return out

        self.patch_run(wrapper)
        given, _, _ = await self.upload(f, {"operation": "fetch", "directory": work, "remote": "origin"})
        result = await self.apply(f, given, stop)
        self.assertEqual((result["code"], result["changes"], result["cleanup"]),
                         ("git_cancelled", "possible", "retained"))
        self.assertEqual(await self.run_git(f, work, "rev-parse", "refs/remotes/origin/main"), after)
        self.assertFalse(exists(os.path.join(work, ".git/FETCH_HEAD")))

    async def test_more_than_4096_acquired_refs_are_accepted_without_a_bulk_cap(self):
        f = await self.fixture()
        await f.git.run(["--git-dir=" + f.upstream, "update-ref", "--stdin"], input=text_input(
            "create refs/heads/topic-%04d %s\n" % (index, f.original) for index in range(5000)))
        work = await self.clone(f)
        count = []
        records = Records(10, 1024, count.append)
        await f.git.run(["-C", work, "for-each-ref", "--format=%(refname)", "refs/remotes/origin"], data=records.push)
        records.finish()
        self.assertEqual(len(count), 5002)  # 5001 branches plus origin/HEAD


class ResolveTest(GitCase):
    async def resolve_fixture(self):
        root = tempfile.mkdtemp(prefix="resolve-", dir=_root[0])
        for name in ("home", "tmp", "uploads"):
            os.mkdir(os.path.join(root, name), 0o700)
        f = Fixture(root)
        f.work = os.path.join(root, "work")
        await f.git.run(["init", "--quiet", "--template=", "--initial-branch=main", f.work])
        return f

    async def config(self, f, *args):
        await f.git.run(["-C", f.work, "config", *args])

    async def resolve(self, f, start, remote="origin"):
        return await resolve_remote(start, remote, until(), None, f.layout)

    async def test_a_remotes_one_github_url_resolves_from_any_subdirectory(self):
        f = await self.resolve_fixture()
        await self.config(f, "remote.origin.url", "https://github.com/Octocat/Hello-World.git")
        await self.config(f, "remote.upstream.url", "https://github.com/rust-lang/rust")
        os.makedirs(os.path.join(f.work, "src", "deep"))
        self.assertEqual(await self.resolve(f, f.work), {"ok": True, "repository": "octocat/hello-world"})
        self.assertEqual(await self.resolve(f, os.path.join(f.work, "src", "deep")),
                         {"ok": True, "repository": "octocat/hello-world"})
        self.assertEqual(await self.resolve(f, f.work, "upstream"), {"ok": True, "repository": "rust-lang/rust"})
        # Its private staging is gone; nothing else was written.
        self.assertEqual(os.listdir(f.uploads), [])

    async def test_other_remotes_urls_and_configurations_refuse_with_fixed_codes(self):
        f = await self.resolve_fixture()

        async def refused(start, remote, code, cleanup="observed"):
            result = await self.resolve(f, start, remote)
            self.assertEqual(result, {"ok": False, "code": code, "cleanup": cleanup}, remote)

        await refused(f.work, "origin", "git_remote_unsupported")
        await self.config(f, "--add", "remote.two.url", "https://github.com/a/b")
        await self.config(f, "--add", "remote.two.url", "https://github.com/c/d")
        await refused(f.work, "two", "git_remote_unsupported")
        for name, url in (("ssh", "git@github.com:a/b.git"), ("other", "https://gitlab.com/a/b"),
                          ("local", "/srv/a/b.git"), ("helper", "ext::sh -c x"),
                          ("port", "https://github.com:443/a/b")):
            await self.config(f, "remote.%s.url" % name, url)
            await refused(f.work, name, "git_remote_unsupported")
        await refused(f.work, "../x", "git_application_invalid")
        # Outside any working repository: refused before any staging.
        outside = os.path.join(f.root, "plain")
        os.mkdir(outside)
        await refused(outside, "origin", "git_repository_unsupported")
        self.assertEqual(os.listdir(f.uploads), [])
        # URL rewriting in the repository's configuration: refused while
        # reading it; that staging is retained, as G3 retains a failure's.
        await self.config(f, "url.https://github.com/.insteadOf", "gh:")
        await refused(f.work, "two", "git_repository_unsupported", "retained")
        left = os.listdir(f.uploads)
        self.assertEqual(len(left), 1)
        self.assertTrue(left[0].startswith(".resolve-"))
        # No private upload directory: refused before any staging.
        g = await self.resolve_fixture()
        await self.config(g, "remote.origin.url", "https://github.com/a/b")
        missing = await resolve_remote(g.work, "origin", until(), None, Layout(g.root, os.path.join(g.root, "absent")))
        self.assertFalse(missing["ok"])


if __name__ == "__main__":
    unittest.main()
