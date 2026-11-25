"""Offline end-to-end cases of `git pull` through the `git` shim, against stock
Git pulling the same upstream from a local path.

Each Git command runs the literal shim's dispatch (acquisitions/git/jail/
dispatch.py) from a test entry on PATH (this file, `git-shim`), with a
request context and one stand-in seam, the request client: it writes the
host's request file and runs the real host worker against the loopback HTTPS
fixture server (test_git_handler.py), then gives the delivery to the real G3
`Application`, which runs stock `git pull` with the staged remote helper.
The artifact POST, controller and broker are not exercised; their own suites
cover them. No real network, GitHub or credential; not a native trial.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_git_pull.py'
"""

import asyncio
import fcntl
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import unittest
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.dont_write_bytecode = True
for _path in (HERE, ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import handler_testing as testing  # noqa: E402
from handler_testing import Scratch  # noqa: E402
import test_git_handler as fixture  # noqa: E402
from test_git_handler import GIT, PYTHON, Server, Tls  # noqa: E402

CONFIG_ENV = "AGENTBOX_TEST_GIT_PULL"
REPOSITORY = "fixture/project"
URL = "https://github.com/fixture/project.git"
SHOWN = "https://github.com/fixture/project"
SESSION = "0123456789abcdef" * 2
DATES = {"GIT_AUTHOR_DATE": "1700001000 +0000", "GIT_COMMITTER_DATE": "1700001000 +0000"}
IDENTITY = "[user]\n\tname = Fixture User\n\temail = user@example.invalid\n"


def lines(*items):
    return "".join(item + "\n" for item in items)


class PullCase(unittest.TestCase):
    """One fixture server, an upstream at `one`, a template clone of it through
    the shim, then the upstream one commit ahead (`two`)."""

    def setUp(self):
        os.umask(0o022)
        self.scratch = Scratch()
        self.addCleanup(self.scratch.remove)
        at = self.scratch.at
        self.tls = Tls(self.scratch)
        stream = (fixture.blob(1, lines("a", "b", "c").encode()) + fixture.blob(2, b"v1\n")
                  + fixture.commit("refs/heads/main", 3, "one", [("100644", ":1", "shared.txt"),
                                                                 ("100644", ":2", "up.txt")])
                  + b"reset refs/tags/v1\nfrom :3\n\n")
        self.upstream, marks = fixture.repository(self.scratch, REPOSITORY, stream)
        self.one = marks[3]
        self.server = Server(self.scratch, "backend", "github", self.tls)
        self.addCleanup(self.server.kill)
        for name in ("bin", "work", "requests", "sentinels"):
            os.mkdir(at(name), 0o700)
        with open(at("home", ".gitconfig"), "w") as stream:
            stream.write(IDENTITY)
        with open(at("bin", "git"), "w") as stream:
            stream.write('#!/bin/sh\nexec %s -I -B %s git-shim "$@"\n' % (PYTHON, os.path.abspath(__file__)))
        os.chmod(at("bin", "git"), 0o700)
        self.config = {"root": self.scratch.path, "requests": at("requests"), "port": self.server.port,
                       "ca": self.tls.ca, "policy": dict(fixture.POLICY, repositories=[REPOSITORY])}
        code, out = self.shim(["clone", "--quiet", URL, "template"], at("work"))
        self.assertEqual(code, 0, out)
        self.advance("two", {"shared.txt": lines("a", "B upstream", "c"), "up.txt": "v2\n"})

    def advance(self, message, files):
        script = ("commit refs/heads/main\ncommitter Up <up@example.invalid> 1700000500 +0000\ndata %d\n%s\n"
                  "from %s\n" % (len(message), message, self.one)).encode()
        for path, text in files.items():
            script += b"M 100644 inline %s\ndata %d\n%s\n" % (path.encode(), len(text.encode()), text.encode())
        self.scratch.run([GIT, "--git-dir=" + self.upstream, "fast-import", "--quiet"], script)
        self.two = self.scratch.run([GIT, "--git-dir=" + self.upstream, "rev-parse", "main"]).decode().strip()

    def env(self, **extra):
        at = self.scratch.at
        env = {"PATH": at("bin") + ":/usr/bin:/bin", "HOME": at("home"), "TMPDIR": at("tmp"), "LC_ALL": "C",
               "GIT_CONFIG_NOSYSTEM": "1", "AGENTBOX_REQUEST_SESSION": SESSION,
               "AGENTBOX_WORK_ROOT": at("work"), CONFIG_ENV: json.dumps(self.config)}
        env.update(extra)
        return env

    def shim(self, argv, cwd, **extra):
        done = subprocess.run(["git", *argv], cwd=cwd, env=self.env(**extra), stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=300)
        return done.returncode, done.stdout.decode(errors="replace")

    def stock(self, path, *argv, check=True):
        done = subprocess.run([GIT, "-C", path, *argv], env=dict(self.env(PATH="/usr/bin:/bin"), **DATES),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        if check and done.returncode != 0:
            raise AssertionError("%s: %s" % (argv, done.stdout.decode(errors="replace")))
        return done.returncode, done.stdout.decode(errors="replace")

    def requests(self):
        try:
            with open(self.scratch.at("requests.log")) as stream:
                return [json.loads(line) for line in stream]
        except FileNotFoundError:
            return []

    def pair(self, name, prepare=None):
        """Two copies of the template, prepared alike: one pulls through the
        shim, the baseline from the upstream's path with stock Git."""
        at = self.scratch.at
        pulled, baseline = at("work", name), at("work", name + "-baseline")
        for path in (pulled, baseline):
            shutil.copytree(at("work", "template"), path, symlinks=True)
            if prepare is not None:
                prepare(path)
        self.stock(baseline, "remote", "set-url", "origin", self.upstream)
        return pulled, baseline

    def write(self, path, name, text):
        with open(os.path.join(path, name), "w") as stream:
            stream.write(text)

    def commit_local(self, path, name, text):
        self.write(path, name, text)
        self.stock(path, "add", name)
        self.stock(path, "commit", "--quiet", "-m", "local " + name)

    def state(self, path, code):
        """What stock Git leaves, independent of new commit ids and the remote's spelling."""
        def out(*argv):
            return self.stock(path, *argv, check=False)[1].replace(self.upstream[:-len(".git")], SHOWN)

        files = {}
        for directory, dirnames, names in os.walk(path):
            dirnames[:] = [name for name in dirnames if name != ".git"]
            for name in names:
                with open(os.path.join(directory, name), "rb") as stream:
                    files[os.path.relpath(os.path.join(directory, name), path)] = stream.read()
        git_dir = os.path.join(path, ".git")
        return {
            "exit": code, "status": out("status", "--porcelain=v1"), "index": out("ls-files", "-s"),
            "head": out("symbolic-ref", "-q", "HEAD"),
            "shape": [(line.split("|")[0], len(line.split("|")[1].split())) for line in
                      out("log", "--topo-order", "--format=%T %s|%P", "HEAD").splitlines()],
            "refs": out("for-each-ref", "--format=%(refname) %(objectname)", "refs/remotes", "refs/tags"),
            "merge_head": os.path.exists(os.path.join(git_dir, "MERGE_HEAD")),
            "rebasing": os.path.exists(os.path.join(git_dir, "rebase-merge")),
            "files": files,
        }

    def compare(self, name, argv, prepare=None, **extra):
        """Pull both; their states, the shim's output and the pulled path."""
        pulled, baseline = self.pair(name, prepare)
        with open(os.path.join(pulled, ".git", "config"), "rb") as stream:
            config = stream.read()
        before = len(self.requests())
        marked = self.marked(pulled)
        code, out = self.shim(["pull", *argv], pulled, **extra)
        expected, stock_out = self.stock(baseline, "pull", *argv, check=False)
        self.assertEqual(self.state(pulled, code), self.state(baseline, expected), (name, out, stock_out))
        self.assertEqual(self.requests()[before:], [{"repository": REPOSITORY, "operation": "fetch",
                                                     "worker": "ok"}])
        with open(os.path.join(pulled, ".git", "config"), "rb") as stream:
            self.assertEqual(stream.read(), config)
        self.provenance(pulled, marked)
        self.assertEqual(os.listdir(self.scratch.at("work", ".agentbox-requests")), [])
        return code, out, pulled

    def marked(self, path):
        """Each metadata line (objects aside) naming the scratch or staging, by file."""
        marks = (b".agentbox-requests", b".apply-", self.scratch.path.encode())
        git_dir = os.path.join(path, ".git")
        found = set()
        for directory, dirnames, names in os.walk(git_dir):
            dirnames[:] = [name for name in dirnames if os.path.join(directory, name) != os.path.join(git_dir,
                                                                                                       "objects")]
            for name in names:
                with open(os.path.join(directory, name), "rb") as stream:
                    for line in stream:
                        if any(mark in line for mark in marks):
                            found.add((os.path.relpath(os.path.join(directory, name), git_dir), line))
        return found

    def provenance(self, path, before):
        """The pull added no staging path to the repository's metadata or history.
        (The clone's own reflog line `clone: from <staging>` predates it.)"""
        self.assertEqual(self.marked(path) - before, set())
        _, history = self.stock(path, "log", "--all", "--format=%B")
        for mark in (".agentbox-requests", ".apply-", self.scratch.path):
            self.assertNotIn(mark, history)

    def refused(self, path, argv, code, **extra):
        before = len(self.requests())
        status, out = self.shim(["pull", *argv], path, **extra)
        self.assertEqual(status, 3, out)
        # Repository configuration refused while reading it retains that staging, as a fetch's.
        cleanup = "retained" if code == "git_repository_unsupported" else "observed"
        self.assertIn('agentbox-request: git {"ok":false,"code":"%s","changes":"none","cleanup":"%s"}'
                      % (code, cleanup), out)
        self.assertEqual(self.requests()[before:], [])
        uploads = self.scratch.at("work", ".agentbox-requests")
        left = os.listdir(uploads)
        self.assertEqual(len(left), 1 if cleanup == "retained" else 0, left)
        for name in left:
            self.assertTrue(name.startswith(".resolve-"), name)
            shutil.rmtree(os.path.join(uploads, name))


class PullTest(PullCase):
    def test_fast_forward_merge_and_rebase_match_stock_git(self):
        code, out, pulled = self.compare("ff", [])
        self.assertEqual(code, 0, out)
        self.assertIn('agentbox-request: git {"ok":true,"code":"git_applied"', out)
        self.assertIn("Fast-forward", out)
        self.assertEqual(self.stock(pulled, "rev-parse", "HEAD")[1].strip(), self.two)
        with open(os.path.join(pulled, ".git", "FETCH_HEAD")) as stream:
            self.assertEqual(stream.read(), "%s\t\tbranch 'main' of %s\n" % (self.two, SHOWN))

        def diverged(path):
            self.commit_local(path, "local.txt", "mine\n")

        # Diverged without a strategy, or --ff-only: Git refuses, nothing integrated.
        for name, argv in (("diverged", []), ("ff-only", ["--ff-only"])):
            code, out, pulled = self.compare(name, argv, diverged)
            self.assertEqual(code, 128, out)
            self.assertIn('"code":"git_pull_failed"', out)
        code, out, pulled = self.compare("merge", ["--no-rebase"], diverged)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stock(pulled, "log", "-1", "--format=%s|%an|%cn")[1].strip(),
                         "Merge branch 'main' of %s|Fixture User|Fixture User" % SHOWN)
        code, out, pulled = self.compare("rebase", ["--rebase"], diverged)
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stock(pulled, "rev-parse", "HEAD~1")[1].strip(), self.two)

    def test_configured_strategies_apply_with_local_precedence_and_unsupported_ones_refuse(self):
        def diverged(*config):
            def prepare(path):
                self.commit_local(path, "local.txt", "mine\n")
                for key, value in config:
                    self.stock(path, "config", key, value)
            return prepare

        code, out, pulled = self.compare("local-rebase", [], diverged(("pull.rebase", "true")))
        self.assertEqual((code, self.stock(pulled, "rev-parse", "HEAD~1")[1].strip()), (0, self.two), out)
        code, out, pulled = self.compare("branch-rebase", [], diverged(("pull.rebase", "false"),
                                                                       ("branch.main.rebase", "yes")))
        self.assertEqual((code, self.stock(pulled, "rev-parse", "HEAD~1")[1].strip()), (0, self.two), out)
        # A global value, through an include.
        with open(self.scratch.at("home", "strategy.cfg"), "w") as stream:
            stream.write("[pull]\n\trebase = true\n")
        with open(self.scratch.at("home", ".gitconfig"), "a") as stream:
            stream.write("[include]\n\tpath = strategy.cfg\n")
        code, out, pulled = self.compare("global-rebase", [], diverged())
        self.assertEqual((code, self.stock(pulled, "rev-parse", "HEAD~1")[1].strip()), (0, self.two), out)
        # The repository's values precede the global ones.
        code, out, pulled = self.compare("local-merge", [], diverged(("pull.rebase", "false"),
                                                                     ("user.name", "Local Name")))
        self.assertEqual((code, self.stock(pulled, "log", "-1", "--format=%an|%cn|%P")[1].strip().count(" ")),
                         (0, 3), out)
        self.assertTrue(self.stock(pulled, "log", "-1", "--format=%an|%cn")[1].startswith("Local Name|Local Name"))
        # Not plain booleans, a filter or a global merge strategy: refused before any request.
        for key, value in (("pull.rebase", "merges"), ("pull.rebase", "interactive"),
                           ("branch.main.rebase", "m"), ("pull.ff", "sometimes"),
                           ("filter.x.smudge", "touch %s" % self.scratch.at("sentinels", "filter")),
                           ("pull.twohead", "octopus"), ("merge.ff", "false")):
            pulled, _ = self.pair("refused-" + key + value, diverged((key, value)))
            self.refused(pulled, [], "git_pull_unsupported" if key.startswith(("pull.r", "pull.f", "branch"))
                         else "git_repository_unsupported")
        with open(self.scratch.at("home", ".gitconfig"), "w") as stream:
            stream.write(IDENTITY + "[pull]\n\trebase = merges\n")
        pulled, _ = self.pair("refused-global", diverged())
        self.refused(pulled, [], "git_pull_unsupported")
        # The repository's value precedes an unsupported global one.
        code, out, _ = self.compare("local-over-global", ["--no-rebase"], diverged(("pull.rebase", "false")))
        self.assertEqual(code, 0, out)
        self.assertEqual(os.listdir(self.scratch.at("sentinels")), [])

    def test_dirty_worktrees_and_conflicts_keep_gits_state_and_status(self):
        code, out, pulled = self.compare("unrelated", ["--no-rebase"],
                                         lambda path: self.write(path, "local.txt", "dirty\n"))
        self.assertEqual(code, 0, out)
        with open(os.path.join(pulled, "local.txt")) as stream:
            self.assertEqual(stream.read(), "dirty\n")
        code, out, pulled = self.compare("overlapping", ["--no-rebase"],
                                         lambda path: self.write(path, "up.txt", "dirty\n"))
        self.assertNotEqual(code, 0, out)
        self.assertEqual(self.stock(pulled, "rev-parse", "HEAD")[1].strip(), self.one)

        def conflicting(path):
            self.commit_local(path, "shared.txt", lines("a", "B local", "c"))

        code, out, pulled = self.compare("conflict-merge", ["--no-rebase"], conflicting)
        self.assertEqual(code, 1, out)
        self.assertTrue(os.path.exists(os.path.join(pulled, ".git", "MERGE_HEAD")))
        self.assertIn("CONFLICT (content)", out)
        self.assertIn('{"ok":false,"code":"git_pull_failed","changes":"possible","cleanup":"observed"}', out)
        code, out, pulled = self.compare("conflict-rebase", ["--rebase"], conflicting)
        self.assertEqual(code, 1, out)
        self.assertTrue(os.path.isdir(os.path.join(pulled, ".git", "rebase-merge")))
        # A merge in progress: stock Git refuses before integrating.
        code, out, pulled = self.compare("unconcluded", [], lambda path: (
            conflicting(path), self.stock(path, "merge", "--no-ff", "origin/main", check=False)))
        self.assertEqual(code, 128, out)

    def test_an_unread_full_stdout_and_stderr_bound_a_pull_and_its_report(self):
        pulled, _ = self.pair("unread")
        read, write = full_pipe()
        self.addCleanup(os.close, read)
        started = time.monotonic()
        process = subprocess.Popen(["git", "pull"], cwd=pulled, env=self.env(), stdin=subprocess.DEVNULL,
                                   stdout=write, stderr=write)
        os.close(write)
        try:
            code = process.wait(timeout=120)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        self.assertEqual(code, 0)
        self.assertLess(time.monotonic() - started, 60)
        self.assertEqual(drain(read), b"x" * full_pipe.size)
        self.assertEqual(self.stock(pulled, "rev-parse", "HEAD")[1].strip(), self.two)
        self.assertEqual(os.listdir(self.scratch.at("work", ".agentbox-requests")), [])

    def test_no_upstream_detached_head_and_other_forms_never_request(self):
        pulled, _ = self.pair("no-upstream", lambda path: self.stock(path, "checkout", "--quiet", "-b", "topic"))
        self.refused(pulled, [], "git_remote_unsupported")
        pulled, _ = self.pair("detached", lambda path: self.stock(path, "checkout", "--quiet", "--detach"))
        self.refused(pulled, [], "git_remote_unsupported")
        pulled, _ = self.pair("local-upstream", lambda path: self.stock(path, "config", "branch.main.remote", "."))
        self.refused(pulled, [], "git_remote_unsupported")
        for argv, code in ((["origin"], "git_arguments_invalid"), (["--rebase=merges"], "git_option_unsupported")):
            status, out = self.shim(["pull", *argv], self.scratch.at("work", "template"))
            self.assertEqual(status, 1, out)
            self.assertIn('"code":"%s"' % code, out)
        self.assertEqual(len(self.requests()), 1)

    def test_a_clone_beneath_a_sticky_directory_is_fetched_and_pulled_but_not_a_sticky_repository(self):
        sticky = self.scratch.at("work", "sticky")
        os.mkdir(sticky)
        os.chmod(sticky, 0o1777)
        code, out = self.shim(["clone", "--quiet", URL, "repo"], sticky)
        self.assertEqual(code, 0, out)
        repo = os.path.join(sticky, "repo")
        self.stock(repo, "reset", "--quiet", "--hard", self.one)
        os.mkdir(os.path.join(repo, "sub"))
        before = len(self.requests())
        for argv, cwd in ((["fetch"], os.path.join(repo, "sub")), (["pull"], repo)):
            code, out = self.shim(argv, cwd)
            self.assertEqual(code, 0, (argv, out))
        self.assertEqual(self.requests()[before:], [{"repository": REPOSITORY, "operation": "fetch",
                                                     "worker": "ok"}] * 2)
        self.assertEqual(self.stock(repo, "rev-parse", "HEAD")[1].strip(), self.two)
        os.chmod(repo, 0o1777)
        self.refused(repo, [], "git_work_unsafe")

    def test_ambient_overrides_reach_no_other_transport_hook_or_editor(self):
        at = self.scratch.at
        hooks = at("hooks")
        os.mkdir(hooks, 0o700)
        for name in ("post-merge", "pre-merge-commit", "post-checkout", "reference-transaction"):
            path = os.path.join(hooks, name)
            with open(path, "w") as stream:
                stream.write("#!/bin/sh\ntouch %s\n" % at("sentinels", name))
            os.chmod(path, 0o700)
        for name in ("git-remote-https", "git-remote-evil", "git-remote-ext"):
            with open(at("bin", name), "w") as stream:
                stream.write("#!/bin/sh\ntouch %s\nexit 1\n" % at("sentinels", name))
            os.chmod(at("bin", name), 0o700)

        def prepare(path):
            self.commit_local(path, "local.txt", "mine\n")
            shutil.copytree(hooks, os.path.join(path, ".git", "hooks"), dirs_exist_ok=True)

        pulled, _ = self.pair("ambient", prepare)
        with open(at("home", ".gitconfig"), "a") as stream:
            stream.write('[core]\n\thooksPath = %s\n[protocol]\n\tallow = always\n'
                         '[url "file://%s"]\n\tinsteadOf = %s\n' % (hooks, self.upstream, URL))
        before = len(self.requests())
        marked = self.marked(pulled)
        code, out = self.shim(["pull", "--no-rebase"], pulled, GIT_ALLOW_PROTOCOL="https:ext:file:evil",
                              GIT_CONFIG_PARAMETERS="'remote.origin.vcs'='evil' 'protocol.allow'='always'",
                              GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="url.ext::false.insteadOf",
                              GIT_CONFIG_VALUE_0="https://", GIT_EDITOR="touch %s" % at("sentinels", "editor"),
                              GIT_SSH_COMMAND="touch %s" % at("sentinels", "ssh"))
        self.assertEqual(code, 0, out)
        self.assertEqual(self.stock(pulled, "log", "-1", "--format=%s")[1].strip(),
                         "Merge branch 'main' of %s" % SHOWN)
        self.assertEqual(self.requests()[before:], [{"repository": REPOSITORY, "operation": "fetch",
                                                     "worker": "ok"}])
        self.assertEqual(os.listdir(at("sentinels")), [])
        self.provenance(pulled, marked)
        fixture.contained(self, self.server.stop())


class RunnerTest(unittest.TestCase):
    """pull.py's runner and helper alone, with stand-in programs."""

    def setUp(self):
        self.scratch = Scratch()
        self.addCleanup(self.scratch.remove)

    def run_pull(self, script, abort_after=None, outputs=None):
        from acquisitions.git.jail.local import Clock
        from acquisitions.git.jail.pull import run_pull
        from guest.src.abort import Abort

        program = self.scratch.at("program")
        with open(program, "w") as stream:
            stream.write("#!/bin/sh\n" + script)
        os.chmod(program, 0o700)
        out = None
        if outputs is None:
            out = os.open(self.scratch.at("out"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            outputs = (out, out)
        abort = Abort()

        async def main():
            if abort_after is not None:
                asyncio.get_running_loop().call_later(abort_after, abort.abort)
            return await run_pull([program], {"PATH": "/usr/bin:/bin"}, Clock(time.monotonic() + 60, abort),
                                  outputs)

        try:
            return asyncio.run(main())
        finally:
            if out is not None:
                os.close(out)

    def output(self):
        with open(self.scratch.at("out")) as stream:
            return stream.read()

    def alive(self, name):
        with open(self.scratch.at(name)) as stream:
            pid = int(stream.read())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return False
            # A zombie of init's is gone for this purpose.
            with open("/proc/%d/stat" % pid) as stream:
                if stream.read().rsplit(")", 1)[1].split()[0] == "Z":
                    return False
            time.sleep(0.02)
        return True

    def test_a_normal_exit_relays_output_and_returns_its_status(self):
        self.assertEqual(self.run_pull("echo out; echo err >&2; read x; exit 3\n"), 3)
        self.assertEqual(sorted(self.output().split()), ["err", "out"])

    def test_an_unread_full_output_bounds_cancellation_and_the_final_report(self):
        from acquisitions.git.jail.local import Failed
        from acquisitions.git.jail.output import REPORT_TIMEOUT_MS, report_line
        from acquisitions.git.jail.pull import KILL_GRACE_MS, STREAM_EOF_MS

        read, write = full_pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        threads = threading.active_count()
        flags = fcntl.fcntl(write, fcntl.F_GETFL)
        bound = (KILL_GRACE_MS + STREAM_EOF_MS + REPORT_TIMEOUT_MS) / 1000 + 3
        # Git blocked writing to the relay, the relay unable to write: cancellation still ends it.
        started = time.monotonic()
        with self.assertRaises(Failed) as raised:
            self.run_pull("head -c 4000000 /dev/zero >&2; head -c 4000000 /dev/zero; sleep 60\n", 0.3,
                          (write, write))
        self.assertEqual(raised.exception.code, "git_cancelled")
        report_line('agentbox-request: git {"ok":false,"code":"git_cancelled"}', write)
        self.assertLess(time.monotonic() - started, bound)
        # No thread left, the shared descriptor's flags untouched, nothing written past the full pipe.
        self.assertEqual(threading.active_count(), threads)
        self.assertEqual(fcntl.fcntl(write, fcntl.F_GETFL), flags)
        self.assertEqual(drain(read), b"x" * full_pipe.size)
        # A normal end whose small output cannot be written: its status, in bounded time.
        read, write = full_pipe()
        self.addCleanup(os.close, read)
        self.addCleanup(os.close, write)
        started = time.monotonic()
        self.assertEqual(self.run_pull("echo out; echo err >&2; exit 5\n", None, (write, write)), 5)
        self.assertLess(time.monotonic() - started, STREAM_EOF_MS / 1000 + 3)
        self.assertEqual(drain(read), b"x" * full_pipe.size)

    def test_cancellation_signals_the_whole_group_and_keeps_staging(self):
        from acquisitions.git.jail.local import Failed

        started = time.monotonic()
        with self.assertRaises(Failed) as raised:
            self.run_pull("sleep 60 & echo $! > %s; trap '' TERM; wait\n" % self.scratch.at("child"), 0.3)
        self.assertEqual(raised.exception.code, "git_cancelled")
        self.assertLess(time.monotonic() - started, 10)
        self.assertFalse(self.alive("child"))

    def test_a_descendant_holding_the_streams_is_uncertain_and_killed_before_the_reap(self):
        from acquisitions.git.jail.local import Failed

        with self.assertRaises(Failed) as raised:
            self.run_pull("sleep 60 & echo $! > %s; exit 0\n" % self.scratch.at("child"))
        self.assertEqual(raised.exception.code, "git_cleanup_incomplete")
        self.assertFalse(self.alive("child"))

    def test_the_helper_serves_only_its_bound_remote_and_upload_pack(self):
        entry = os.path.join(ROOT, "acquisitions", "git", "jail", "git.py")
        source = self.scratch.at("source.git")
        self.scratch.run([GIT, "init", "--quiet", "--bare", source])
        env = {"PATH": "/usr/bin:/bin", "AGENTBOX_GIT_PULL_SOURCE": source, "AGENTBOX_GIT_PULL_REMOTE": "origin",
               "AGENTBOX_GIT_PULL_URL": URL}

        def helper(args, data, **extra):
            done = subprocess.run([PYTHON, "-I", "-S", "-B", entry, "shim", "git-remote-agentbox", *args],
                                  input=data, env=dict(env, **extra), capture_output=True, timeout=60)
            return done.returncode, done.stdout

        self.assertEqual(helper(["origin", URL], b"capabilities\n\n"), (0, b"connect\n\n"))
        for args in (["upstream", URL], ["origin", "https://github.com/other/project.git"], ["origin"]):
            self.assertEqual(helper(args, b"capabilities\n"), (128, b""))
        self.assertEqual(helper(["origin", URL], b"capabilities\n", AGENTBOX_GIT_PULL_SOURCE=""), (128, b""))
        for line in (b"connect git-receive-pack\n", b"fetch 0 refs/heads/main\n", b"list\n", b"option x y\n"):
            self.assertEqual(helper(["origin", URL], line)[0], 128, line)
        code, out = helper(["origin", URL], b"connect git-upload-pack\n0000")
        self.assertEqual((code, out[:1]), (0, b"\n"))


def full_pipe():
    """A pipe whose buffer is full and which nobody reads; its write end blocking."""
    read, write = os.pipe()
    os.set_blocking(write, False)
    try:
        while True:
            os.write(write, b"x" * 4096)
    except BlockingIOError:
        pass
    os.set_blocking(write, True)
    full_pipe.size = fcntl.fcntl(write, getattr(fcntl, "F_GETPIPE_SZ", 1032))
    return read, write


def drain(read):
    """What a full pipe holds, read without blocking."""
    os.set_blocking(read, False)
    data = bytearray()
    try:
        while True:
            chunk = os.read(read, 65536)
            if not chunk:
                break
            data += chunk
    except BlockingIOError:
        pass
    return bytes(data)


def shim(argv):
    """The `git` on PATH: the shim's dispatch with a request context, its
    request client standing in for the artifact POST lane (module docstring)."""
    from acquisitions.git.jail.application import Application, Layout, delivery, resolve_remote, resolve_upstream
    from acquisitions.git.jail.dispatch import DispatchSeams, run_git_command_with
    from acquisitions.git.jail.main import pass_through
    from acquisitions.git.jail.output import report_line
    from guest.src.artifact_post_context import context_from_environment, prepare_upload_dir, upload_dir
    from guest.src.request_status import EXIT_OK, EXIT_RUNTIME

    config = json.loads(os.environ[CONFIG_ENV])
    context = context_from_environment(os.environ)
    layout = Layout(config["root"], upload_dir(context))

    async def resolve(start, remote, deadline, abort, _layout):
        return await resolve_remote(start, remote, deadline, abort, layout)

    async def upstream(start, deadline, abort, _layout, environ):
        return await resolve_upstream(start, deadline, abort, layout, environ)

    async def client(operation, repository, local, context, report, deadline, abort, selector=None):
        # As the request client: the upload directory first.
        assert prepare_upload_dir(context) == layout.uploads
        number = len(os.listdir(config["requests"])) + 1
        stage = os.path.join(config["requests"], "request-%032x" % number)
        os.mkdir(stage, 0o700)
        path = fixture.request(stage, config["port"], SimpleNamespace(ca=config["ca"]), repository=repository,
                               selector=selector, policy=config["policy"], operation=operation)
        code, found = fixture.acquire(path)
        value = json.loads(found[0]) if code == 0 and len(found) == 1 else {}
        with open(os.path.join(config["root"], "requests.log"), "a") as stream:
            stream.write(json.dumps({"repository": repository, "operation": operation,
                                     "worker": value.get("code", value.get("outcome"))}) + "\n")
        if value.get("outcome") != "ok":
            report({"ok": False, "code": "git_request_denied", "changes": "none", "cleanup": "observed"})
            return EXIT_RUNTIME
        request = "r-%d" % number
        os.rename(os.path.join(stage, testing.handler.ARTIFACT_FILE),
                  os.path.join(layout.uploads, "%s-%s.artifact" % (context.session, request)))
        given = {"session": context.session, "request": request, "request_sha256": "b" * 64,
                 "operation": operation, "repository": repository}
        if selector is not None:
            given["selector"] = selector
        given.update(delivery=delivery(value["metadata"]), size=value["size"], sha256=value["sha256"], local=local)
        outcome = await Application(given).run(deadline.local_until, abort, layout)
        report({key: outcome[key] for key in ("ok", "code", "changes", "cleanup")})
        return EXIT_OK if outcome["ok"] else (outcome.get("exit") or EXIT_RUNTIME)

    return asyncio.run(run_git_command_with(DispatchSeams(client, resolve, upstream), argv, os.getcwd(), context,
                                            report_line, pass_through, environ=os.environ))


if __name__ == "__main__" and sys.argv[1:2] == ["git-shim"]:
    sys.exit(shim(sys.argv[2:]))
