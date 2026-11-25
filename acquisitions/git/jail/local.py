"""Local helpers of the git application (application.py). No inherited Git
configuration or environment, shell, network transport or background
maintenance. Not host authority."""

import asyncio
import os
import signal
import stat
import time

# The local application's own bound, clipped by the request's cutoff.
GIT_APPLICATION_TIMEOUT_MS = 600000

DIAGNOSTIC_BYTES = 65536
CHUNK_BYTES = 65536
APPLICATION_CODES = (
    "git_application_invalid", "git_application_used", "git_cancelled", "git_deadline_expired",
    "git_bundle_invalid", "git_repository_inconsistent", "git_repository_unsupported",
    "git_work_unsafe", "git_work_changed", "git_process_failed", "git_output_exceeded",
    "git_application_failed", "git_cleanup_incomplete",
)


class Failed(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def fail(code):
    raise Failed(code)


def _finite(value):
    return isinstance(value, (int, float)) and value == value and abs(value) != float("inf")


class Clock:
    """One original monotonic deadline (time.monotonic() seconds). Cleanup is
    awaited, not raced or abandoned."""

    def __init__(self, deadline, signal=None):
        if not _finite(deadline):
            fail("git_application_invalid")
        self.until = min(deadline, time.monotonic() + GIT_APPLICATION_TIMEOUT_MS / 1000)
        self.signal = signal
        self._failure = None

    def check(self):
        if self.signal is not None and self.signal.aborted and self._failure is None:
            self._failure = "git_cancelled"
        if time.monotonic() >= self.until and self._failure is None:
            self._failure = "git_deadline_expired"
        if self._failure is not None:
            fail(self._failure)


def same(a, b):
    return a.st_dev == b.st_dev and a.st_ino == b.st_ino


def regular(info):
    return stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()


def below(root, path):
    if not isinstance(path, str) or "\0" in path:
        return False
    if not os.path.isabs(root) or os.path.normpath(root) != root or not os.path.isabs(path) \
            or os.path.normpath(path) != path:
        return False
    rel = os.path.relpath(path, root)
    return rel != ".." and not rel.startswith(".." + os.sep) and not os.path.isabs(rel)


def directory(root, path, clock, sticky=None):
    """Guest-side cooperative pathname checks, NOT openat2 or a filesystem
    sandbox. Root is / in the guest; tests use an explicitly owned scratch root.
    `sticky` (a path: a clone destination's parent, a working repository's
    parent) and its ancestors may also be a sticky other-writable directory
    of root or this user, such as /tmp: another user cannot rename or remove
    what this user puts there. Components below it have no such exception."""
    if not below(root, path) or (sticky is not None and not below(root, sticky)):
        fail("git_work_unsafe")
    rel = os.path.relpath(path, root)
    parts = [part for part in rel.split(os.sep) if part and part != "."]
    for count in range(len(parts) + 1):
        clock.check()
        current = os.path.join(root, *parts[:count])
        info = os.lstat(current)
        clock.check()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or \
                ((info.st_mode & 0o002) != 0
                 and not (sticky is not None and below(current, sticky) and info.st_mode & stat.S_ISVTX)):
            fail("git_work_unsafe")


def open_regular(path):
    """A descriptor of the regular single-link file of this user at `path`."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if not regular(os.fstat(fd)):
            fail("git_work_unsafe")
        return fd
    except BaseException:
        os.close(fd)
        raise


def repository_tree(path, clock):
    """Inspect metadata, not contents. Worktree symlinks are not visited."""
    pending = [path]
    while pending:
        clock.check()
        current = pending.pop()
        info = os.lstat(current)
        clock.check()
        if info.st_uid != os.geteuid() or (info.st_mode & 0o002) != 0:
            fail("git_repository_unsupported")
        if stat.S_ISDIR(info.st_mode):
            pending.extend(os.path.join(current, name) for name in os.listdir(current))
        elif not regular(info):
            fail("git_repository_unsupported")


class Records:
    """Bounded individual records; no limit on their total bytes or count."""

    def __init__(self, delimiter, maximum, accept):
        self._pending = b""
        self.delimiter = bytes([delimiter])
        self.max = maximum
        self.accept = accept

    def push(self, chunk):
        at = 0
        while at < len(chunk):
            end = chunk.find(self.delimiter, at)
            part = chunk[at:len(chunk) if end < 0 else end]
            if len(self._pending) + len(part) > self.max:
                fail("git_repository_unsupported")
            record = self._pending + part if self._pending else part
            if end < 0:
                self._pending = bytes(record)
                break
            self._pending = b""
            self.accept(bytes(record))
            at = end + 1

    def finish(self):
        if self._pending:
            fail("git_repository_inconsistent")


LOCAL_CONFIG = (
    "protocol.allow=never", "protocol.file.allow=always", "protocol.ext.allow=never",
    "core.hooksPath=/dev/null", "core.fsmonitor=false", "core.untrackedCache=false",
    "core.attributesFile=/dev/null", "credential.helper=", "credential.interactive=false",
    "submodule.recurse=false", "fetch.recurseSubmodules=false", "fetch.parallel=1",
    "gc.auto=0", "maintenance.auto=false", "fetch.writeCommitGraph=false",
    "transfer.bundleURI=false", "clone.rejectShallow=true", "checkout.workers=1",
    "init.defaultBranch=main", "init.templateDir=", "core.pager=",
)

GIT = "/usr/bin/git"
# Library tests only: the child launcher.
_spawn = asyncio.create_subprocess_exec


class LocalGit:
    """Trusted stock Git only. Children stay in the caller's group. On stop,
    the unreaped direct child is signalled through its own handle, then its
    actual close is awaited. No PID or group signalling after reap, owner
    timeout or detached cleanup. This accounts direct children and their
    pipes, not escaped descendants."""

    def __init__(self, stage, clock):
        self.stage = stage
        self.clock = clock
        home = os.path.join(stage, "home")
        self.env = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": home, "XDG_CONFIG_HOME": home,
            "TMPDIR": os.path.join(stage, "tmp"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_PROTOCOL_FROM_USER": "0",
            "GIT_ALLOW_PROTOCOL": "file", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
            "GIT_ATTR_NOSYSTEM": "1", "GIT_LFS_SKIP_SMUDGE": "1", "GIT_PAGER": "", "GIT_CEILING_DIRECTORIES": stage,
        }

    async def run(self, args, cwd=None, input=None, data=None, exits=(0,), reject_stderr=False,
                  diagnostics=DIAGNOSTIC_BYTES):
        """Git with the fixed configuration and `args`: its kept stdout, or
        Failed. `input` is a list of bytes fed with backpressure; `data`
        streams stdout apart from the bounded diagnostic budget."""
        self.clock.check()
        loop = asyncio.get_running_loop()
        argv = [item for pair in (("-c", config) for config in LOCAL_CONFIG) for item in pair] + list(args)
        try:
            child = await _spawn(
                GIT, *argv, cwd=cwd or self.stage, env=self.env,
                stdin=asyncio.subprocess.DEVNULL if input is None else asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except Exception:
            fail("git_process_failed")
        state = {"failure": None, "diagnostic": 0, "ended": False, "kill": None}
        kept = bytearray()

        def alive():
            return child.returncode is None

        def stop(error):
            if state["failure"] is None:
                state["failure"] = error
            if alive():
                try:
                    child.send_signal(signal.SIGTERM)
                except ProcessLookupError:
                    pass
                if state["kill"] is None:
                    state["kill"] = loop.call_later(0.2, lambda: alive() and child.kill())

        def check():
            try:
                self.clock.check()
            except Failed as error:
                stop(error)

        async def pump(stream, is_data):
            while True:
                try:
                    chunk = await stream.read(65536)
                except Exception:
                    stop(Failed("git_process_failed"))
                    return
                if not chunk:
                    return
                if state["failure"] is not None:
                    continue
                try:
                    self.clock.check()
                    if not is_data and reject_stderr:
                        fail("git_repository_unsupported")
                    if is_data and data is not None:
                        data(chunk)
                    else:
                        state["diagnostic"] += len(chunk)
                        if state["diagnostic"] > diagnostics:
                            fail("git_output_exceeded")
                        if is_data:
                            kept.extend(chunk)
                except Exception as error:
                    stop(error)

        async def feed():
            # With backpressure: never a whole ref listing queued in a pipe.
            if input is None:
                return
            try:
                for chunk in input:
                    self.clock.check()
                    if state["failure"] is not None or state["ended"]:
                        break
                    for at in range(0, len(chunk), CHUNK_BYTES):
                        if state["failure"] is not None or state["ended"]:
                            break
                        child.stdin.write(chunk[at:at + CHUNK_BYTES])
                        await child.stdin.drain()
                        self.clock.check()
                child.stdin.close()
            except Exception as error:
                stop(error if isinstance(error, Failed) else Failed("git_process_failed"))

        async def closed():
            returncode = await child.wait()
            state["ended"] = True
            if returncode < 0 or returncode not in exits:
                if state["failure"] is None:
                    state["failure"] = Failed("git_process_failed")

        ticker = {"handle": None}

        def tick():
            check()
            ticker["handle"] = loop.call_later(0.01, tick)

        tick()
        if self.clock.signal is not None:
            self.clock.signal.add_listener(check)
        try:
            check()
            await asyncio.gather(pump(child.stdout, True), pump(child.stderr, False), feed(), closed())
            self.clock.check()
            if state["failure"] is not None:
                raise state["failure"]
            return bytes(kept)
        finally:
            ticker["handle"].cancel()
            if state["kill"] is not None:
                state["kill"].cancel()
            if self.clock.signal is not None:
                self.clock.signal.remove_listener(check)


def text_input(lines):
    return [line.encode("utf-8", "surrogatepass") for line in lines]
