"""The providers' reading of the host's declared storage scopes (common.py):
the cross-language policy fixtures, the limits file's trust checks and
coverage of opened directories. Owned scratch files only.

  python3 -I -m unittest discover -s providers -p 'test_*.py'
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import common  # noqa: E402

with open(os.path.join(HERE, "storage_scopes_fixtures.json")) as _stream:
    FIXTURES = json.load(_stream)


def write(path, data, mode=0o600):
    with open(path, "w") as stream:
        stream.write(data)
    os.chmod(path, mode)


def fixture_bytes(case):
    """A case's file bytes: exact `raw` ASCII, `raw_hex`, or a value."""
    if "raw" in case:
        return case["raw"].encode("ascii")
    if "raw_hex" in case:
        return bytes.fromhex(case["raw_hex"])
    return json.dumps(case["limits"]).encode()


class Policy(unittest.TestCase):
    def test_the_fixtures_agree_with_the_core(self):
        self.assertGreaterEqual(len(FIXTURES["cases"]), 40)
        for case in FIXTURES["cases"]:
            try:
                common.parse_limits(fixture_bytes(case))
                accepted = True
            except common.Failure as failure:
                self.assertEqual(failure.code, "prerequisite")
                accepted = False
            self.assertEqual(accepted, case["valid"], case["name"])


class LimitsFile(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="abs-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.data = os.path.join(self.tmp, "data")
        os.mkdir(self.data, 0o700)
        self.path = os.path.join(self.data, "run-limits.json")
        self.state = os.path.join(self.tmp, "state")
        os.mkdir(self.state, 0o700)
        self.env = {common.SCOPES_ENV: self.path}

    def declare(self, scopes, mode=0o600):
        write(self.path, json.dumps({"max_reserved_bytes": 1, "storage_scopes": scopes}), mode)

    def refused(self, environ=None):
        with self.assertRaises(common.Failure) as raised:
            common.storage_scopes(self.env if environ is None else environ)
        self.assertEqual(raised.exception.code, "prerequisite")

    def test_a_required_file_must_open(self):
        """Required (a mount's protected set): absent refuses; optional
        (every other reader) keeps absent as nothing declared."""
        self.assertEqual(common.storage_scopes(self.env), [])
        with self.assertRaises(common.Failure) as raised:
            common.storage_scopes(self.env, required=True)
        self.assertEqual(raised.exception.code, "prerequisite")
        self.declare([{"path": self.state, "measure": "tree"}])
        self.assertEqual(common.storage_scopes(self.env, required=True), [{"path": self.state, "measure": "tree"}])
        # The other refusals hold in required mode too.
        os.chmod(self.path, 0o644)
        with self.assertRaises(common.Failure):
            common.storage_scopes(self.env, required=True)
        os.unlink(self.path)
        self.assertEqual(common.storage_scopes(self.env), [])

    def test_only_the_named_trusted_file_is_read(self):
        # Absent: nothing declared (every new allocation then refuses).
        self.assertEqual(common.storage_scopes(self.env), [])
        self.declare([{"path": self.state, "measure": "tree"}])
        self.assertEqual(common.storage_scopes(self.env), [{"path": self.state, "measure": "tree"}])
        # No variable, a relative or unplain path: refused, never discovered.
        for environ in ({}, {common.SCOPES_ENV: "run-limits.json"}, {common.SCOPES_ENV: self.path + "/"}):
            self.refused(environ)
        # Another mode, a link, a hard link, oversize, invalid JSON.
        os.chmod(self.path, 0o644)
        self.refused()
        os.chmod(self.path, 0o600)
        link = os.path.join(self.data, "link.json")
        os.symlink(self.path, link)
        self.refused({common.SCOPES_ENV: link})
        hard = os.path.join(self.data, "hard.json")
        os.link(self.path, hard)
        self.refused()
        os.unlink(hard)
        write(self.path, " " * (common.MAX_SCOPES_FILE + 1))
        self.refused()
        write(self.path, "{")
        self.refused()
        # An ancestor writable by others (sticky only counts for root's),
        # or a linked ancestor; group-writable for our own group passes,
        # as in the host's reader (Rust run.rs `trusted_ancestor`).
        self.declare([])
        for mode in (0o777, 0o1777):
            os.chmod(self.data, mode)
            self.refused()
        os.chmod(self.data, 0o770)
        self.assertEqual(common.storage_scopes(self.env), [])
        os.chmod(self.data, 0o700)
        alias = os.path.join(self.tmp, "alias")
        os.symlink(self.data, alias)
        self.refused({common.SCOPES_ENV: os.path.join(alias, "run-limits.json")})

    def test_new_allocation_needs_the_opened_directory_declared(self):
        outside = os.path.join(self.tmp, "outside")
        os.mkdir(outside, 0o700)
        os.symlink(outside, os.path.join(self.state, "escape"))
        self.declare([{"path": self.state, "measure": "tree"}])
        state = common.Dir.root(self.state)
        self.addCleanup(state.close)
        common.require_scopes(self.env, state)
        # Opened through a declared path, it resolves outside: refused.
        fd = os.open(os.path.join(self.state, "escape"), os.O_RDONLY | os.O_DIRECTORY)
        escaped = common.Dir(fd, os.path.join(self.state, "escape"))
        self.addCleanup(escaped.close)
        with self.assertRaises(common.Failure):
            common.require_scopes(self.env, escaped)
        # Nothing declared, or a sibling prefix only: refused.
        self.declare([{"path": self.state + "-other", "measure": "tree"}])
        with self.assertRaises(common.Failure):
            common.require_scopes(self.env, state)
        os.unlink(self.path)
        with self.assertRaises(common.Failure):
            common.require_scopes(self.env, state)


class Coverage(unittest.TestCase):
    """Actual filesystem membership, as the host measures it: a fake
    topology (fstat's device faked for owned scratch inodes) and the host's
    existing read-only mounts; no mount is made."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="abc-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.srv = os.path.join(self.tmp, "srv")
        for sub in ("state/images", "state/volumes/v"):
            os.makedirs(os.path.join(self.srv, sub), 0o700)
        for sub in ("", "state", "state/volumes"):
            os.chmod(os.path.join(self.srv, sub), 0o700)

    def covered(self, scopes, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            return common.covered(scopes, os.readlink(f"/proc/self/fd/{fd}"), os.fstat(fd))
        finally:
            os.close(fd)

    def mounted(self, path, dev):
        """Every inode under `path` reports `dev`: a stand-in mount."""
        inodes = {os.lstat(path).st_ino}
        for top, dirs, files in os.walk(path):
            inodes.update(os.lstat(os.path.join(top, name)).st_ino for name in dirs + files)
        real = os.fstat

        def fstat(fd):
            st = real(fd)
            if st.st_ino not in inodes:
                return st
            fields = list(st)
            fields[2] = dev
            return os.stat_result(fields)
        patcher = unittest.mock.patch.object(os, "fstat", fstat)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_a_measured_filesystem_never_covers_another_mounted_below(self):
        # filesystem srv, tree srv/state, a "tmpfs" at srv/state/volumes.
        self.mounted(os.path.join(self.srv, "state/volumes"), 2 ** 40)
        fs = {"path": self.srv, "measure": "filesystem"}
        scopes = [fs, {"path": os.path.join(self.srv, "state"), "measure": "tree"}]
        self.assertTrue(self.covered(scopes, os.path.join(self.srv, "state/images")))
        for sub in ("state/volumes", "state/volumes/v"):
            self.assertFalse(self.covered(scopes, os.path.join(self.srv, sub)), sub)
            self.assertFalse(self.covered([fs], os.path.join(self.srv, sub)), sub)
        # Measured too: reached, and its own.
        scopes.append({"path": os.path.join(self.srv, "state/volumes"), "measure": "filesystem"})
        self.assertTrue(self.covered(scopes, os.path.join(self.srv, "state/volumes/v")))

    def test_every_allocation_directory_is_checked(self):
        self.mounted(os.path.join(self.srv, "state/volumes"), 2 ** 40)
        path = os.path.join(self.tmp, "run-limits.json")
        write(path, json.dumps({"max_reserved_bytes": 1, "storage_scopes": [
            {"path": os.path.join(self.srv, "state"), "measure": "tree"}]}))
        env = {common.SCOPES_ENV: path}
        state = common.Dir.root(os.path.join(self.srv, "state"))
        self.addCleanup(state.close)
        volumes = state.sub("volumes")
        self.addCleanup(volumes.close)
        common.require_scopes(env, state)
        with self.assertRaises(common.Failure):
            common.require_scopes(env, state, volumes)

    def test_existing_mounts_are_not_covered_by_a_lexical_parent(self):
        outer, inner = "/sys/fs", "/sys/fs/cgroup"
        try:
            if os.stat(outer).st_dev == os.stat(inner).st_dev:
                self.skipTest("one filesystem")
        except OSError:
            self.skipTest("no such mounts")
        for measure in ("filesystem", "tree"):
            self.assertFalse(self.covered([{"path": outer, "measure": measure}], inner), measure)
        self.assertTrue(self.covered([{"path": inner, "measure": "filesystem"}], inner))


if __name__ == "__main__":
    unittest.main()
