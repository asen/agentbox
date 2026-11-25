"""A helper session on owned pipes, driven from the test's own loop, and stand-in
anchors. Commands are owned synthetic fixtures run in an owned temporary
working directory."""

import asyncio
import base64
import fcntl
import os
import shutil
import tempfile
import time

from guest.src import execution
from guest.src.execution import Session, SessionOptions
from guest.src.protocol import FrameSplitter, decode_guest_frame, encode_host_frame


def scratch(test):
    directory = tempfile.mkdtemp(prefix="agentbox-guest-test-")
    test.addCleanup(shutil.rmtree, directory, True)
    return directory


class Harness:
    """`held` starts with the host not reading; `small` shrinks the output pipe
    to one page so a withheld host fills it at once."""

    def __init__(self, directory, held=False, small=False, abort=None, grace=200, wrapper_bin=None):
        self.loop = asyncio.get_running_loop()
        self.input_r, self.input_w = os.pipe2(os.O_CLOEXEC)
        self.output_r, self.output_w = os.pipe2(os.O_CLOEXEC)
        if small:
            fcntl.fcntl(self.output_w, fcntl.F_SETPIPE_SZ, 4096)
        self.frames = []
        self.data = bytearray()
        self.splitter = FrameSplitter()
        self.reading = False
        self.input_closed = False
        self.output_closed = False
        self.session = Session(SessionOptions(self.input_r, self.output_w, os.path.join(directory, "work"), directory,
                                              kill_grace_ms=grace, abort=abort, wrapper_bin=wrapper_bin))
        self.task = self.loop.create_task(self.session.run())
        os.set_blocking(self.output_r, False)
        if not held:
            self.release()

    def _read(self):
        try:
            chunk = os.read(self.output_r, 65536)
        except BlockingIOError:
            return
        if not chunk:
            self.hold()
            return
        for line in self.splitter.push(chunk):
            # The test's own filler (`fill`), never a frame.
            if line.strip(b" "):
                self.frames.append(decode_guest_frame(line))

    def fill(self):
        """Fills the host's one-page pipe with a filler line the reader skips."""
        os.write(self.output_w, b" " * 4095 + b"\n")

    def _drained(self):
        """Reads what is there; False once nothing is left."""
        try:
            chunk = os.read(self.output_r, 65536)
        except BlockingIOError:
            return False
        if not chunk:
            return False
        for line in self.splitter.push(chunk):
            if line.strip(b" "):
                self.frames.append(decode_guest_frame(line))
        return True

    def hold(self):
        """The host stops reading."""
        if self.reading:
            self.loop.remove_reader(self.output_r)
            self.reading = False

    def release(self):
        """The host reads again."""
        if not self.reading and not self.output_closed:
            self.loop.add_reader(self.output_r, self._read)
            self.reading = True

    def send(self, frame):
        self.raw(encode_host_frame(frame) + b"\n")

    def raw(self, data):
        os.write(self.input_w, data.encode() if isinstance(data, str) else data)

    def end(self):
        """The end of the host's input."""
        if not self.input_closed:
            self.input_closed = True
            os.close(self.input_w)

    def close_output(self):
        """The host's output is gone."""
        self.hold()
        if not self.output_closed:
            self.output_closed = True
            os.close(self.output_r)

    async def status(self, timeout=20):
        try:
            return await asyncio.wait_for(asyncio.shield(self.task), timeout)
        finally:
            if self.task.done():
                self.close()

    def close(self):
        self.end()
        # What the session wrote before its end is still the host's to read.
        while self.reading and not self.output_closed and self._drained():
            pass
        self.close_output()
        for fd in (self.input_r, self.output_w):
            try:
                os.close(fd)
            except OSError:
                pass
        self.input_r = self.output_w = -1

    async def until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            for frame in self.frames:
                if predicate(frame):
                    return frame
            assert time.monotonic() < deadline, "timed out waiting for a frame"
            await asyncio.sleep(0.01)

    async def within(self, seconds, predicate):
        deadline = time.monotonic() + seconds
        while True:
            for frame in self.frames:
                if predicate(frame):
                    return frame
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(0.005)

    async def hello(self):
        self.send({"v": 1, "type": "hello", "session": "nonce-1"})
        hello = await self.until(lambda frame: frame["type"] == "hello")
        assert hello == {"v": 1, "type": "hello", "session": "nonce-1", "guest_version": execution.GUEST_VERSION}

    async def exec(self, argv):
        await self.hello()
        self.send({"v": 1, "type": "exec", "id": "e-1", "argv": argv})
        return await self.until(lambda frame: frame["type"] == "exit")

    def output(self, stream):
        return b"".join(base64.b64decode(frame["data"]) for frame in self.frames
                        if frame["type"] == "output" and frame["stream"] == stream)


async def wait_for(check, timeout=10):
    deadline = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < deadline, "timed out waiting"
        await asyncio.sleep(0.01)


class FakeAnchor:
    """A stand-in anchor, no process: what the session sees of anchor.py. It
    holds its own copies of the child ends; its control input records the
    session's stop requests."""

    def __init__(self, argv, control_in, control_out, pass_fds, env):
        self.loop = asyncio.get_running_loop()
        self.argv = list(argv)
        self.env = env
        self.pass_fds = pass_fds
        self.stops = bytearray()
        self.control_in = os.dup(control_in)
        self.control_out = os.dup(control_out)
        words = self.argv[self.argv.index(execution.ANCHOR) + 1:]
        self.flags = {}
        while words and words[0].startswith("--"):
            name, _, value = words.pop(0).partition("=")
            self.flags[name] = os.dup(int(value))
        self.streams = {"stdout": os.dup(int(words[0])), "stderr": os.dup(int(words[1]))}
        self.words = words
        self.config = bytearray()
        self.input = bytearray()
        self.done = self.loop.create_future()
        os.set_blocking(self.control_in, False)
        self.loop.add_reader(self.control_in, self._stop)
        for flag, sink in (("--env", self.config), ("--stdin", self.input)):
            if flag in self.flags:
                os.set_blocking(self.flags[flag], False)
                self.loop.add_reader(self.flags[flag], self._drain, flag, sink)

    def _stop(self):
        try:
            chunk = os.read(self.control_in, 64)
        except BlockingIOError:
            return
        if not chunk:
            self.loop.remove_reader(self.control_in)
            return
        self.stops += chunk

    def _drain(self, flag, sink):
        try:
            chunk = os.read(self.flags[flag], 65536)
        except BlockingIOError:
            return
        if not chunk:
            self.loop.remove_reader(self.flags[flag])
            return
        sink += chunk

    def write(self, stream, data):
        os.write(self.streams[stream], data)

    def finish(self, lines):
        """The anchor's last lines, the end of the output, its own SIGKILL."""
        os.write(self.control_out, lines.encode())
        for fd in [self.control_out, *self.streams.values()]:
            os.close(fd)
        self.streams = {}
        self.control_out = -1
        if not self.done.done():
            self.done.set_result(-9)

    async def wait(self):
        return await self.done

    def close(self):
        for fd in [self.control_in, self.control_out, *self.streams.values(), *self.flags.values()]:
            if fd >= 0:
                try:
                    self.loop.remove_reader(fd)
                except Exception:
                    pass
                try:
                    os.close(fd)
                except OSError:
                    pass


def fake_anchors(test, after=None):
    """Replaces the anchor's spawn for one test; returns the anchors started.
    `after(anchor)` runs on each, as its own behaviour."""
    anchors = []
    original = execution.spawn_anchor

    async def spawn(argv, control_in, control_out, pass_fds, _cwd, env):
        anchor = FakeAnchor(argv, control_in, control_out, pass_fds, env)
        anchors.append(anchor)
        if after is not None:
            after(anchor)
        return anchor

    execution.spawn_anchor = spawn

    def restore():
        execution.spawn_anchor = original
        for anchor in anchors:
            anchor.close()

    test.addCleanup(restore)
    return anchors


async def fake_exec(session, anchors, argv=("/bin/true",)):
    """Runs the exec and returns the anchor it started."""
    before = len(anchors)
    await session.hello()
    session.send({"v": 1, "type": "exec", "id": "e-1", "argv": list(argv)})
    await wait_for(lambda: len(anchors) == before + 1)
    return anchors[before]
