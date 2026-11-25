"""Offline suite of the input staging worker (stage.py) on owned synthetic
trees in private scratch. The worker runs as the host runs it (-I -S -B, the
request on stdin, the spool on stdout, the result on fd 3); its archives are
extracted only by the guest's own GNU tar call, into scratch, never run.

    python3 -I -B -m unittest discover -s inputs -p 'test_*.py'
"""

import json
import os
import resource
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
WORKER = os.path.join(HERE, "stage.py")
sys.dont_write_bytecode = True
sys.path.insert(0, HERE)

import stage  # noqa: E402

TAR = "/usr/bin/tar"
# The guest's extraction (guest/src/inputs.ts `tarArgs`).
TAR_ARGS = ["--extract", "--no-same-owner", "--no-same-permissions", "--no-overwrite-dir"]
DEFAULT_LIMITS = {"archive_bytes": 2 << 30, "entries": 250_000, "depth": 128, "path_bytes": 4096}


def gnu_tar():
    try:
        out = subprocess.run([TAR, "--version"], capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return False
    return out.startswith(b"tar (GNU tar)")


def write(path, data=b"x", mode=0o600):
    with open(path, "wb") as file:
        file.write(data)
    os.chmod(path, mode)


class Scratch:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="agentbox-inputs-")
        os.chmod(self.root, 0o700)
        self.store = os.path.join(self.root, "store")
        os.mkdir(self.store, 0o700)

    def path(self, *parts):
        return os.path.join(self.root, *parts)

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def request(scratch, copies, limits=None, store=None):
    return {
        "schema": stage.REQUEST_SCHEMA,
        "store_hex": os.fsencode(store or scratch.store).hex(),
        "copies": [
            {"source_hex": os.fsencode(source).hex(), "destination": destination, "kind": kind}
            for source, destination, kind in copies
        ],
        "limits": dict(DEFAULT_LIMITS, **(limits or {})),
    }


def run(scratch, body, fsize=None, spool=None, nofile=None):
    """The worker as the host runs it: (exit, result or None, spool bytes);
    `fsize` and `nofile` set those limits (soft, hard) first."""
    spool = spool or scratch.path("spool-%d" % len(os.listdir(scratch.root)))
    fd = os.open(spool, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    read, written = os.pipe()

    def child():
        os.dup2(written, 3)
        if fsize is not None:
            resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
        if nofile is not None:
            resource.setrlimit(resource.RLIMIT_NOFILE, nofile)

    try:
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-B", WORKER],
            stdin=subprocess.PIPE,
            stdout=fd,
            stderr=subprocess.PIPE,
            close_fds=False,
            preexec_fn=child,
            env={},
            cwd="/",
        )
    finally:
        os.close(fd)
        os.close(written)
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    _, err = process.communicate(data, timeout=120)
    with os.fdopen(read, "rb") as file:
        line = file.read()
    result = json.loads(line) if line else None
    with open(spool, "rb") as file:
        archive = file.read()
    if result is not None:
        assert len(line) <= stage.MAX_RESULT_BYTES
        assert result["schema"] == stage.RESULT_SCHEMA, result
    return process.returncode, result, archive, err


def staged(scratch, copies, limits=None, nofile=None):
    code, result, archive, err = run(scratch, request(scratch, copies, limits), nofile=nofile)
    assert code == 0 and result["ok"], (code, result, err)
    assert result["archive_bytes"] == len(archive)
    return result, archive


def refused(scratch, copies, limits=None, store=None, nofile=None):
    code, result, _, err = run(scratch, request(scratch, copies, limits, store), nofile=nofile)
    assert code == 1 and result is not None and not result["ok"], (code, result, err)
    assert err == b"", err
    return result["code"]


def extract(scratch, archive, out=None):
    """The guest's tar call into a fresh directory; returns it."""
    count = len(os.listdir(scratch.root))
    path = scratch.path("archive-%d" % count)
    with open(path, "wb") as file:
        file.write(archive)
    out = out or scratch.path("out-%d" % count)
    os.mkdir(out, 0o700)
    subprocess.run([TAR] + TAR_ARGS[:1] + ["--file", path] + TAR_ARGS[1:], cwd=out, check=True,
                   env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, capture_output=True)
    return out


def members(archive, scratch):
    path = scratch.path("list-%d.tar" % len(os.listdir(scratch.root)))
    with open(path, "wb") as file:
        file.write(archive)
    with tarfile.open(path, "r:", encoding="utf-8", errors="surrogateescape") as tar:
        return tar.getmembers()


def project(scratch):
    """A project tree with everything copy-all keeps."""
    root = scratch.path("project")
    os.makedirs(os.path.join(root, "src", "deep"), 0o700)
    os.makedirs(os.path.join(root, ".git", "objects"), 0o700)
    os.mkdir(os.path.join(root, "empty"), 0o700)
    write(os.path.join(root, "README.md"), b"project v1\n")
    write(os.path.join(root, "src", "run.sh"), b"#!/bin/sh\necho ran\n", 0o755)
    write(os.path.join(root, "src", "deep", "a.txt"), b"a" * 70000)
    write(os.path.join(root, ".git", "HEAD"), b"ref: refs/heads/main\n")
    write(os.path.join(root, ".gitignore"), b"ignored\n")
    write(os.path.join(root, "ignored"), b"still copied\n")
    os.mkdir(os.path.join(root, "worktree"), 0o700)
    write(os.path.join(root, "worktree", ".git"), b"gitdir: /nowhere/.git/worktrees/x\n")
    os.link(os.path.join(root, "README.md"), os.path.join(root, "hard"))
    outside = scratch.path("outside-secret")
    write(outside, b"never read\n")
    os.symlink("README.md", os.path.join(root, "rel-link"))
    os.symlink(outside, os.path.join(root, "abs-link"))
    os.symlink("../../nowhere", os.path.join(root, "dangling"))
    os.symlink("src", os.path.join(root, "dir-link"))
    write(os.fsencode(os.path.join(root, "")) + b"name-\xff\xfe", b"bytes\n")
    return root, outside


class Staging(unittest.TestCase):
    def setUp(self):
        self.scratch = Scratch()

    def tearDown(self):
        self.scratch.close()

    def test_copy_all_keeps_links_dotfiles_git_and_independent_hardlinks(self):
        root, outside = project(self.scratch)
        result, archive = staged(self.scratch, [(root, "work", "directory")])
        names = {os.fsencode(m.name): m for m in members(archive, self.scratch)}
        self.assertEqual(list(names)[:2], [b"plan", b"slots"])
        # Every object: the root and 6 directories, 9 files, 4 links.
        self.assertEqual(
            (result["entries"], result["directories"], result["files"], result["links"]),
            (20, 7, 9, 4),
        )
        self.assertEqual(names[b"slots/0/abs-link"].linkname, outside)
        self.assertEqual(names[b"slots/0/dangling"].linkname, "../../nowhere")
        self.assertTrue(names[b"slots/0/hard"].isreg())
        self.assertTrue(names[b"slots/0/README.md"].isreg())
        self.assertEqual(names[b"slots/0/src/run.sh"].mode, 0o700)
        self.assertEqual(names[b"slots/0/README.md"].mode, 0o600)
        self.assertEqual(names[b"slots/0/src"].mode, 0o700)
        self.assertIn(b"slots/0/name-\xff\xfe", names)
        for member in names.values():
            self.assertEqual((member.mtime, member.uid, member.gid, member.uname, member.gname),
                             (0, 0, 0, "", ""))
        self.assertNotIn(b"never read", archive)

    @unittest.skipUnless(gnu_tar(), "GNU tar")
    def test_the_guest_extraction_gets_the_original_bytes_and_link_texts(self):
        root, outside = project(self.scratch)
        _, archive = staged(self.scratch, [(root, "work", "directory")])
        out = extract(self.scratch, archive)
        self.assertEqual(sorted(os.listdir(out)), ["plan", "slots"])
        with open(os.path.join(out, "plan"), "rb") as file:
            self.assertEqual(file.read(), b"agentbox-inputs-v2\nd work\n")
        copy = os.path.join(out, "slots", "0")
        with open(os.path.join(copy, "src", "deep", "a.txt"), "rb") as file:
            self.assertEqual(file.read(), b"a" * 70000)
        self.assertEqual(os.readlink(os.path.join(copy, "abs-link")), outside)
        self.assertEqual(os.readlink(os.path.join(copy, "dangling")), "../../nowhere")
        self.assertEqual(os.readlink(os.path.join(copy, "dir-link")), "src")
        self.assertTrue(os.path.isfile(os.path.join(copy, "worktree", ".git")))
        self.assertTrue(os.path.isdir(os.path.join(copy, "empty")))
        hard = os.stat(os.path.join(copy, "hard"))
        self.assertNotEqual(hard.st_ino, os.stat(os.path.join(copy, "README.md")).st_ino)
        self.assertEqual(hard.st_nlink, 1)
        self.assertTrue(os.access(os.path.join(copy, "src", "run.sh"), os.X_OK))
        self.assertTrue(os.path.exists(os.fsencode(copy) + b"/name-\xff\xfe"))

    def test_the_archive_is_deterministic(self):
        root, _ = project(self.scratch)
        _, first = staged(self.scratch, [(root, "work", "directory")])
        os.utime(os.path.join(root, "README.md"), (1, 1))
        _, second = staged(self.scratch, [(root, "work", "directory")])
        self.assertEqual(first, second)

    def test_file_and_link_leaves_are_copied_as_themselves(self):
        root, _ = project(self.scratch)
        config = self.scratch.path("tool.conf")
        write(config, b"setting=1\n")
        fifo = self.scratch.path("fifo")
        os.mkfifo(fifo)
        link = self.scratch.path("auth-link")
        os.symlink(fifo, link)
        result, archive = staged(self.scratch, [
            (root, "work", "directory"),
            (config, ".config/tool.conf", "any"),
            (link, ".auth", "any"),
        ])
        listed = {m.name: m for m in members(archive, self.scratch)}
        self.assertTrue(listed["slots/1"].isreg())
        self.assertTrue(listed["slots/2"].issym())
        self.assertEqual(listed["slots/2"].linkname, fifo)
        plan = archive[archive.index(b"agentbox-inputs-v2"):].split(b"\0", 1)[0]
        self.assertEqual(plan, b"agentbox-inputs-v2\nd work\nf .config/tool.conf\nl .auth\n")
        self.assertEqual(result["links"], 5)

    def test_a_workspace_must_be_a_directory_never_through_a_link(self):
        root, _ = project(self.scratch)
        link = self.scratch.path("ws-link")
        os.symlink(root, link)
        self.assertEqual(refused(self.scratch, [(link, "work", "directory")]),
                         "input_source_not_directory")
        self.assertEqual(refused(self.scratch, [(os.path.join(root, "README.md"), "work", "directory")]),
                         "input_source_not_directory")

    def test_symlink_ancestors_and_missing_sources_refuse(self):
        root, _ = project(self.scratch)
        alias = self.scratch.path("alias")
        os.symlink(root, alias)
        self.assertEqual(refused(self.scratch, [(os.path.join(alias, "src"), "work", "any")]),
                         "input_source_symlink_ancestor")
        self.assertEqual(refused(self.scratch, [(self.scratch.path("missing"), "work", "any")]),
                         "input_source_unavailable")
        self.assertEqual(refused(self.scratch, [(os.path.join(root, "README.md", "x"), "w", "any")]),
                         "input_source_unavailable")

    def test_special_files_refuse_without_being_opened(self):
        def bound(path):
            with socket.socket(socket.AF_UNIX) as sock:
                sock.bind(path)

        for make in (os.mkfifo, bound):
            root = self.scratch.path("special-%d" % len(os.listdir(self.scratch.root)))
            os.mkdir(root, 0o700)
            write(os.path.join(root, "a"))
            make(os.path.join(root, "z"))
            self.assertEqual(refused(self.scratch, [(root, "work", "directory")]), "input_special_file")
            self.assertEqual(refused(self.scratch, [(os.path.join(root, "z"), "w", "any")]),
                             "input_special_file")

    def test_the_store_is_never_archived(self):
        root, _ = project(self.scratch)
        inside = os.path.join(self.scratch.store, "runs")
        os.mkdir(inside, 0o700)
        write(os.path.join(inside, "spool"))
        for source in (self.scratch.store, inside, os.path.join(inside, "spool"), self.scratch.root):
            self.assertEqual(refused(self.scratch, [(source, "work", "any")]),
                             "input_source_overlaps_store", source)
        # A bind-free alias by the same identity is the same directory.
        os.symlink(self.scratch.store, os.path.join(root, "store-link"))
        staged(self.scratch, [(root, "work", "directory")])

    def test_limits_admit_exact_values_and_refuse_one_more(self):
        root = self.scratch.path("limits")
        os.makedirs(os.path.join(root, "a", "b"), 0o700)
        write(os.path.join(root, "a", "b", "f"), b"12345")
        result, archive = staged(self.scratch, [(root, "work", "directory")])
        exact = {"entries": 4, "depth": 3, "path_bytes": len("a/b/f"), "archive_bytes": len(archive)}
        self.assertEqual(result["entries"], 4)
        staged(self.scratch, [(root, "work", "directory")], exact)
        for name, code in (("entries", "input_entry_limit"), ("depth", "input_depth_limit"),
                           ("path_bytes", "input_path_limit"), ("archive_bytes", "input_archive_limit")):
            limits = dict(exact, **{name: exact[name] - 1})
            self.assertEqual(refused(self.scratch, [(root, "work", "directory")], limits), code, name)

    def test_the_kernel_file_size_limit_also_bounds_the_spool(self):
        root = self.scratch.path("big")
        os.mkdir(root, 0o700)
        write(os.path.join(root, "f"), b"z" * (1 << 20))
        code, result, archive, _ = run(self.scratch, request(self.scratch, [(root, "w", "directory")]),
                                       fsize=64 * 1024)
        self.assertEqual((code, result["code"]), (1, "input_archive_limit"))
        self.assertLessEqual(len(archive), 64 * 1024)

    def test_requests_and_outputs_are_strict(self):
        root, _ = project(self.scratch)
        good = request(self.scratch, [(root, "work", "directory")])
        bad = [
            b"not json",
            dict(good, schema="other"),
            dict(good, extra=1),
            dict(good, copies=[]),
            dict(good, copies=good["copies"] * 33),
            dict(good, limits=dict(good["limits"], depth=0)),
            dict(good, limits=dict(good["limits"], depth=True)),
            request(self.scratch, [("relative", "work", "directory")]),
            request(self.scratch, [(root + "/../x", "work", "directory")]),
            request(self.scratch, [(root, "work/../x", "directory")]),
            request(self.scratch, [(root, "a\nb", "directory")]),
            request(self.scratch, [(root, "work", "file")]),
            b"{" * (stage.MAX_REQUEST_BYTES + 1),
        ]
        for body in bad:
            code, result, archive, _ = run(self.scratch, body)
            self.assertEqual((code, result["code"], archive), (1, "input_request_invalid", b""), body)

    def test_a_used_spool_and_a_missing_result_channel_refuse(self):
        root, _ = project(self.scratch)
        fd = os.open(self.scratch.path("used"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"old")
        read, written = os.pipe()
        process = subprocess.run(
            [sys.executable, "-I", "-S", "-B", WORKER],
            input=json.dumps(request(self.scratch, [(root, "work", "directory")])).encode(),
            stdout=fd, close_fds=False, preexec_fn=lambda: os.dup2(written, 3), env={},
            capture_output=False, stderr=subprocess.DEVNULL,
        )
        os.close(fd)
        os.close(written)
        with os.fdopen(read, "rb") as file:
            self.assertEqual(json.loads(file.read())["code"], "input_output_invalid")
        self.assertEqual(process.returncode, 1)
        process = subprocess.run([sys.executable, "-I", "-S", "-B", WORKER], input=b"{}",
                                 capture_output=True, env={})
        self.assertEqual((process.returncode, process.stdout), (2, b""))


class Races(unittest.TestCase):
    """In-process seams standing in for concurrent host changes."""

    def setUp(self):
        self.scratch = Scratch()

    def tearDown(self):
        self.scratch.close()

    def stage_in_process(self, copies):
        spool = self.scratch.path("spool-%d" % len(os.listdir(self.scratch.root)))
        fd = os.open(spool, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            body = request(self.scratch, copies)
            return stage.stage(stage.check_request(body), fd), spool
        finally:
            os.close(fd)

    def test_a_file_shrinking_while_copied_fails(self):
        root = self.scratch.path("shrink")
        os.mkdir(root, 0o700)
        write(os.path.join(root, "f"), b"y" * 100000)
        real = os.read

        def shrinking(fd, count):
            os.truncate(os.path.join(root, "f"), 10)
            return real(fd, count)

        with mock.patch.object(stage.os, "read", side_effect=shrinking):
            with self.assertRaises(stage.Refused) as caught:
                self.stage_in_process([(root, "work", "directory")])
        self.assertEqual(caught.exception.code, "input_source_changed")

    def test_entries_swapped_after_listing_are_classified_from_their_own_descriptor(self):
        root = self.scratch.path("swap")
        os.makedirs(os.path.join(root, "d"), 0o700)
        write(os.path.join(root, "d", "inner"), b"inner")
        write(os.path.join(root, "f"), b"file")
        secret = self.scratch.path("secret")
        os.mkdir(secret, 0o700)
        write(os.path.join(secret, "key"), b"never read")
        real = os.listdir

        def swapping(fd):
            names = real(fd)
            if "d" in names:
                shutil.rmtree(os.path.join(root, "d"))
                os.symlink(secret, os.path.join(root, "d"))
            return names

        with mock.patch.object(stage.os, "listdir", side_effect=swapping):
            result, spool = self.stage_in_process([(root, "work", "directory")])
        with open(spool, "rb") as file:
            data = file.read()
        self.assertNotIn(b"never read", data)
        self.assertEqual(result["links"], 1)

        def to_fifo(fd):
            names = real(fd)
            if "f" in names and os.path.isfile(os.path.join(root, "f")):
                os.unlink(os.path.join(root, "f"))
                os.mkfifo(os.path.join(root, "f"))
            return names

        os.unlink(os.path.join(root, "d"))
        with mock.patch.object(stage.os, "listdir", side_effect=to_fifo):
            with self.assertRaises(stage.Refused) as caught:
                self.stage_in_process([(root, "work", "directory")])
        self.assertEqual(caught.exception.code, "input_special_file")

    def test_a_vanished_entry_fails(self):
        root = self.scratch.path("vanish")
        os.mkdir(root, 0o700)
        write(os.path.join(root, "f"))
        real = os.listdir

        def vanishing(fd):
            names = real(fd)
            os.unlink(os.path.join(root, "f"))
            return names

        with mock.patch.object(stage.os, "listdir", side_effect=vanishing):
            with self.assertRaises(stage.Refused) as caught:
                self.stage_in_process([(root, "work", "directory")])
        self.assertEqual(caught.exception.code, "input_source_changed")


class LongPaths(unittest.TestCase):
    """The 4096-byte source-relative path limit through the guest's own
    extraction, at the last slot's prefix (`slots/31/`), into staging whose
    absolute path is long too. Built and read back descriptor-relative."""

    def setUp(self):
        self.scratch = Scratch()

    def tearDown(self):
        self.scratch.close()

    def deep(self, total, leaf):
        """A tree whose one file's relative path is `total` bytes, its last
        component `leaf`; returns the root and the directory names."""
        root = self.scratch.path("deep-%d-%d" % (total, len(leaf)))
        os.mkdir(root, 0o700)
        parent_bytes = total - len(leaf) - 1
        names = []
        while len(b"/".join(names)) < parent_bytes:
            room = parent_bytes - len(b"/".join(names)) - (1 if names else 0)
            names.append(b"d" * min(250, room))
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for name in names:
                os.mkdir(name, 0o700, dir_fd=fd)
                step = os.open(name, os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = step
            out = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
            os.write(out, b"deep\n")
            os.close(out)
        finally:
            os.close(fd)
        self.assertEqual(len(b"/".join(names + [leaf])), total)
        return root, names

    def copies(self, root):
        fillers = []
        for index in range(31):
            path = self.scratch.path("filler-%d" % index)
            if not os.path.exists(path):
                write(path, b"f")
            fillers.append((path, "f%d" % index, "any"))
        return fillers + [(root, "deep", "directory")]

    @unittest.skipUnless(gnu_tar(), "GNU tar")
    def test_a_4096_byte_path_extracts_at_the_last_slot_and_one_more_refuses(self):
        for leaf in (b"x", b"l" * 200):
            root, names = self.deep(4096, leaf)
            _, archive = staged(self.scratch, self.copies(root))
            # Staging beside a long home: its absolute path alone is long.
            home = self.scratch.path("h" * 200)
            base = os.path.join(home, "i" * 200)
            os.makedirs(base, 0o700)
            out = extract(self.scratch, archive, os.path.join(base, "staging"))
            fd = os.open(os.path.join(out, "slots", "31"), os.O_RDONLY | os.O_DIRECTORY)
            try:
                for name in names:
                    step = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = step
                data = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
                self.assertEqual(os.read(data, 16), b"deep\n")
                os.close(data)
            finally:
                os.close(fd)
            shutil.rmtree(home)
        root, _ = self.deep(4097, b"x")
        self.assertEqual(refused(self.scratch, self.copies(root)), "input_path_limit")


def open_fds():
    return len(os.listdir("/proc/self/fd"))


class Depth(unittest.TestCase):
    """Deep trees through the iterative walk: the accepted depth ceiling
    (inputs.rs `DEPTH`, 1024) and the default (128) at their boundaries,
    built and read back descriptor-relative; one open listing per level."""

    MAX_DEPTH = 1024

    def setUp(self):
        self.scratch = Scratch()

    def tearDown(self):
        self.scratch.close()

    def chain(self, levels):
        """`levels` nested directories `d`, the deepest holding the file
        `f`: the file is `levels + 1` deep."""
        root = self.scratch.path("chain-%d" % levels)
        os.mkdir(root, 0o700)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for _ in range(levels):
                os.mkdir("d", 0o700, dir_fd=fd)
                step = os.open("d", os.O_RDONLY | os.O_DIRECTORY, dir_fd=fd)
                os.close(fd)
                fd = step
            out = os.open("f", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=fd)
            os.write(out, b"deepest\n")
            os.close(out)
        finally:
            os.close(fd)
        return root

    def read_back(self, out, levels):
        fd = os.open(os.path.join(out, "slots", "0"), os.O_RDONLY | os.O_DIRECTORY)
        try:
            for _ in range(levels):
                step = os.open("d", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = step
            data = os.open("f", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                return os.read(data, 64)
            finally:
                os.close(data)
        finally:
            os.close(fd)

    def test_the_maximum_depth_stages_and_one_more_refuses(self):
        deepest = self.chain(self.MAX_DEPTH - 1)
        limits = {"depth": self.MAX_DEPTH}
        # A low soft descriptor limit (the hard one kept) is raised for it.
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        result, archive = staged(self.scratch, [(deepest, "work", "directory")], limits,
                                 nofile=(256, hard))
        self.assertEqual(
            (result["entries"], result["directories"], result["files"]),
            (self.MAX_DEPTH + 1, self.MAX_DEPTH, 1),
        )
        listed = members(archive, self.scratch)
        self.assertEqual(listed[-1].name, "slots/0/" + "d/" * (self.MAX_DEPTH - 1) + "f")
        self.assertEqual(len(listed), 2 + self.MAX_DEPTH + 1)
        if gnu_tar():
            out = extract(self.scratch, archive)
            self.assertEqual(self.read_back(out, self.MAX_DEPTH - 1), b"deepest\n")
        # One level more than allowed: a fixed code, no traceback.
        self.assertEqual(refused(self.scratch, [(deepest, "work", "directory")],
                                 {"depth": self.MAX_DEPTH - 1}), "input_depth_limit")
        beyond = self.chain(self.MAX_DEPTH)
        self.assertEqual(refused(self.scratch, [(beyond, "work", "directory")], limits),
                         "input_depth_limit")

    def test_the_default_depth_boundary(self):
        at = self.chain(DEFAULT_LIMITS["depth"] - 1)
        result, _ = staged(self.scratch, [(at, "work", "directory")])
        self.assertEqual(result["directories"], DEFAULT_LIMITS["depth"])
        beyond = self.chain(DEFAULT_LIMITS["depth"])
        self.assertEqual(refused(self.scratch, [(beyond, "work", "directory")]),
                         "input_depth_limit")

    def test_a_hard_descriptor_limit_below_the_depth_fails_with_a_fixed_code(self):
        deepest = self.chain(self.MAX_DEPTH - 1)
        self.assertEqual(refused(self.scratch, [(deepest, "work", "directory")],
                                 {"depth": self.MAX_DEPTH}, nofile=(128, 128)),
                         "input_io_error")

    def test_every_listing_descriptor_is_closed_on_success_and_failure(self):
        deepest = self.chain(self.MAX_DEPTH - 1)
        for limits, code in (({"depth": self.MAX_DEPTH}, None),
                             ({"depth": self.MAX_DEPTH - 1}, "input_depth_limit"),
                             ({"depth": self.MAX_DEPTH, "path_bytes": 1500}, "input_path_limit")):
            spool = self.scratch.path("spool-%d" % len(os.listdir(self.scratch.root)))
            fd = os.open(spool, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                before = open_fds()
                body = request(self.scratch, [(deepest, "work", "directory")], limits)
                try:
                    result = stage.stage(stage.check_request(body), fd)
                    self.assertIsNone(code)
                    self.assertEqual(result["directories"], self.MAX_DEPTH)
                except stage.Refused as refusal:
                    self.assertEqual(refusal.code, code)
                self.assertEqual(open_fds(), before, limits)
            finally:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
