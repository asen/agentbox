"""Owned real-Git campaign for the G3 tests (test_git_application.py).

Only the explicitly owned campaign runs real local Git: the whole suite runs
under git_fixture_server.py `own` with AGENTBOX_G3_FIXTURE_ROOT set to a fresh
private scratch root; otherwise those tests skip. The environment variable is
a fixture gate, not proof of process custody: the outer owner's retained
report supplies it.

Each Git invocation is also placed under that owner, with a positive
settlement receipt before any product staging removal. Receipts and captures
live outside product staging and are all retained. The owner is never
signalled: force is a control message.
"""

import asyncio
import json
import os
import tempfile

from acquisitions.git.jail.local import DIAGNOSTIC_BYTES, LOCAL_CONFIG, Failed, LocalGit, open_regular
from guest.test.deny import deny_processes

HERE = os.path.dirname(os.path.abspath(__file__))
OWNER = os.path.join(os.path.dirname(HERE), "..", "acquisitions", "git_fixture_server.py")
OWNER = os.path.normpath(OWNER)
EXEC = os.path.join(HERE, "git-owned-exec.py")
PYTHON = "/usr/bin/python3"
ROOT = os.environ.get("AGENTBOX_G3_FIXTURE_ROOT")
OWNED = ROOT is not None and ROOT.startswith("/") and "\0" not in ROOT
SKIP = "G3 fixtures require the outer owner and an explicit fresh scratch root (AGENTBOX_G3_FIXTURE_ROOT)"


def guard():
    """Every child but the owner's Python is refused."""
    return deny_processes(lambda program: OWNED and program == PYTHON)


def _inspect(path, consume):
    fd = open_regular(path)
    try:
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return
            consume(chunk)
    finally:
        os.close(fd)


def install_owned_git(root):
    """Replaces LocalGit.run with the owned runner; calls live under `root/calls`."""
    calls = os.path.join(root, "calls")
    os.mkdir(calls, 0o700)

    async def run(self, args, cwd=None, input=None, data=None, exits=(0,), reject_stderr=False,
                  diagnostics=DIAGNOSTIC_BYTES):
        self.clock.check()
        call = tempfile.mkdtemp(prefix="call-", dir=calls)
        stdin = os.path.join(call, "stdin")
        fd = os.open(stdin, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            for chunk in input or ():
                view = memoryview(chunk)
                while view:
                    self.clock.check()
                    view = view[os.write(fd, view[:65536]):]
        finally:
            os.close(fd)
        self.clock.check()
        report, stdout, stderr = (os.path.join(call, name) for name in ("owner.json", "stdout", "stderr"))
        config = [item for value in LOCAL_CONFIG for item in ("-c", value)]
        owner = await asyncio.create_subprocess_exec(
            PYTHON, "-ISB", OWNER, "own", "--report", report, "--stdin", stdin, "--graceful", "1", "--",
            PYTHON, "-ISB", EXEC, stdout, stderr, "/usr/bin/git", *config, *args,
            cwd=cwd or self.stage, env=self.env, start_new_session=True, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        state = {"error": None, "forcing": False}

        def force():
            if state["forcing"]:
                return
            state["forcing"] = True
            try:
                owner.stdin.write(b"force\n")
                owner.stdin.close()
            except Exception:
                pass  # The report and actual owner close decide.

        def check():
            try:
                self.clock.check()
            except Exception as error:
                state["error"] = state["error"] or error
                force()

        async def tick():
            while True:
                check()
                await asyncio.sleep(0.01)

        ticker = asyncio.ensure_future(tick())
        if self.clock.signal is not None:
            self.clock.signal.add_listener(check)
        try:
            status = await owner.wait()
        finally:
            ticker.cancel()
            if self.clock.signal is not None:
                self.clock.signal.remove_listener(check)
        # No signal or removal after this close. A missing or bad report fails
        # and all material stays; test exit is never substituted for accounting.
        raw = bytearray()

        def bounded(chunk):
            if len(raw) + len(chunk) > 16384:
                raise RuntimeError("fixture accounting oversized")
            raw.extend(chunk)

        _inspect(report, bounded)
        receipt = json.loads(raw.decode("utf-8"))
        if (status != 0 or receipt.get("echild") is not True or receipt.get("group_killed") is not True
                or receipt.get("owner_error") is not None or not isinstance(receipt.get("reaped"), int)
                or receipt["reaped"] < 1 or receipt.get("held_output") is not False
                or receipt.get("relay_failed") is not False or receipt.get("output_over_bound") is not False
                or receipt.get("line_truncated") is not False or receipt.get("partial_line") is not False
                or receipt.get("graceful_timeout") is not False):
            raise RuntimeError("fixture owner settlement unconfirmed")
        if state["error"] is not None:
            raise state["error"]
        exit_ = receipt.get("child_exit") or {}
        if receipt.get("forced") is not False or "code" not in exit_ or exit_["code"] not in exits:
            raise Failed("git_process_failed")
        self.clock.check()
        kept = bytearray()
        count = [0]

        def capture(chunk):
            count[0] += len(chunk)
            if count[0] > diagnostics:
                raise Failed("git_output_exceeded")

        def on_stderr(chunk):
            if reject_stderr:
                raise Failed("git_repository_unsupported")
            capture(chunk)

        def on_stdout(chunk):
            self.clock.check()
            if data is not None:
                data(chunk)
            else:
                capture(chunk)
                kept.extend(chunk)

        _inspect(stderr, on_stderr)
        _inspect(stdout, on_stdout)
        self.clock.check()
        return bytes(kept)

    LocalGit.run = run
