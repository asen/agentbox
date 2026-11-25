"""One approved CONNECT tunnel's payload in its own `agentbox-relay` child
(crates/agentbox-relay/src/main.rs), started by the broker (broker.py) at
each tunnel's commit.

```text
spawn    socketpair; the child: its end as stdin, stdout and stderr
         /dev/null, the client and upstream sockets inherited at their own
         numbers (pass_fds) and named as its two arguments, nothing else
         (close_fds), env {}, cwd /, its own session
start    the frame, then START, counted byte by byte, each piece and START
         itself only while the caller's `go()` still allows it; then this
         process's copies of both sockets closed
revoke   one byte, never waiting
read     its lines, without waiting: "opened", "closed REASON UP DOWN",
         "refused REASON"; at most MAX_LINE bytes each
finish   waits for its end of stream and exit until a deadline, then
         SIGKILL; reaped
```

START is the ownership boundary. Until its byte is written the child has
not touched either socket (it only drops its copies) and the caller may
still answer the client: a failure first kills and reaps the child, then
raises `RelayError` with `answerable` true; a stop or end the caller's
`go()` reports meanwhile (its spawn included) raises `RelayStopped`, the
same, with that end as its code. Once START is written only the
child writes to the client. A failure that leaves it unknown whether START
went out closes both copies here and raises with `answerable` false: the
caller must not answer. This process's end of stream, its exit included,
ends the child, before START or after.
"""
import select
import signal
import socket
import struct
import subprocess
import time

MAGIC = b"ABR1"
START = b"G"
MAX_PREFIX = 16 * 1024
MAX_MILLIS = 24 * 3600 * 1000
# The child's own handoff bound; the frame's send uses it too.
HANDOFF_WAIT = 2.0
MAX_LINE = 128
REVOKE = {"topology_revoked": b"R", "topology_unavailable": b"U", "broker_stopped": b"S"}


class RelayError(Exception):
    """A fixed code; `answerable`: whether the caller may still answer the
    client (the child never saw START and is reaped)."""

    def __init__(self, code, answerable=True):
        super().__init__(code)
        self.code = code
        self.answerable = answerable


class RelayStopped(RelayError):
    """The caller's own end, seen before START: the child is reaped and
    the client still the caller's."""


def frame(prefix, idle, lifetime):
    """The handoff frame without START; idle and lifetime in seconds."""
    millis = [int(value * 1000) for value in (idle, lifetime)]
    if len(prefix) > MAX_PREFIX or not all(1 <= value <= MAX_MILLIS for value in millis):
        raise RelayError("handoff_invalid")
    return MAGIC + struct.pack(">IIH", millis[0], millis[1], len(prefix)) + bytes(prefix)


class Relay:
    """One child, its control socket and what it said."""

    def __init__(self, popen, control):
        self.popen = popen
        self.control = control
        self.buffer = b""
        self.ended = False
        self.opened = False
        # ("closed", reason, up, down) or ("refused", reason); None while
        # it said neither, or never will.
        self.result = None

    @classmethod
    def start(cls, binary, client, upstream, prefix=b"", idle=120, lifetime=3600, go=None):
        """A child given `client` and `upstream` (connected sockets) and the
        bytes read past the head; both copies here closed once it started.
        `go()`: None while the caller still commits, else its end. Raises
        `RelayError` otherwise (see `answerable`)."""
        data = frame(prefix, idle, lifetime) + START
        relay = cls.spawn(binary, client, upstream)
        relay.begin(data, client, upstream, go)
        return relay

    @classmethod
    def spawn(cls, binary, client, upstream):
        """The child, holding both sockets but not started: the caller's
        still. `RelayError` (answerable) if it cannot be spawned."""
        numbers = (client.fileno(), upstream.fileno())
        if min(numbers) <= 2 or numbers[0] == numbers[1]:
            raise RelayError("handoff_invalid")
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            popen = subprocess.Popen(
                [binary, str(numbers[0]), str(numbers[1])], stdin=child.fileno(),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={}, cwd="/", close_fds=True,
                pass_fds=numbers, start_new_session=True)
        except (OSError, subprocess.SubprocessError):
            parent.close()
            raise RelayError("spawn_failed") from None
        finally:
            child.close()
        return cls(popen, parent)

    def begin(self, data, client, upstream, go=None):
        """Writes `data` (the frame, START last) by `HANDOFF_WAIT`, each
        piece and START itself only while `go()` allows, then closes this
        process's copies of both sockets."""
        go = go or (lambda: None)
        try:
            sent, end = self._send(data, time.monotonic() + HANDOFF_WAIT, go)
        except Exception:
            # Whether START went out is unknown: never answer.
            self.kill()
            client.close()
            upstream.close()
            self.finish(0)
            raise RelayError("handoff_unknown", answerable=False) from None
        if sent < len(data):
            # START never went out: the child touched nothing. Reaped
            # before the caller may answer.
            self.kill()
            self.finish(0)
            if end is not None:
                raise RelayStopped(end)
            raise RelayError("handoff_failed")
        client.close()
        upstream.close()
        self.control.setblocking(False)

    def _send(self, data, deadline, go):
        """(how many bytes of `data` went out by `deadline`, the end `go()`
        reported, if any): exact, as each send either says what it wrote or
        raises having written nothing. START, the last byte, goes alone,
        right after its own check."""
        sent = 0
        while sent < len(data):
            end = go()
            if end is not None:
                return sent, end
            left = deadline - time.monotonic()
            if left <= 0:
                break
            self.control.settimeout(left)
            upto = len(data) - 1 if sent < len(data) - 1 else len(data)
            try:
                sent += self.control.send(data[sent:upto])
            except OSError:
                break
        return sent, None

    def fileno(self):
        return self.control.fileno()

    def revoke(self, reason="broker_stopped"):
        """Ends its tunnel, before its 200 when heard first."""
        try:
            self.control.send(REVOKE[reason], socket.MSG_DONTWAIT)
        except OSError:
            pass

    def read(self):
        """Takes what it said, without waiting; True at its end of stream."""
        while not self.ended:
            try:
                data = self.control.recv(MAX_LINE)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                data = b""
            if not data:
                self.ended = True
                break
            self.buffer += data
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                self._said(line.decode("ascii", "replace").split(" "))
            if len(self.buffer) > MAX_LINE:
                self.ended = True
        return self.ended

    def _said(self, words):
        if words == ["opened"]:
            self.opened = True
        elif len(words) == 4 and words[0] == "closed" and words[2].isdigit() and words[3].isdigit():
            self.result = ("closed", words[1], int(words[2]), int(words[3]))
        elif len(words) == 2 and words[0] == "refused":
            self.result = ("refused", words[1])

    def kill(self):
        """SIGKILL, only while unreaped."""
        if self.popen.returncode is None:
            try:
                self.popen.send_signal(signal.SIGKILL)
            except ProcessLookupError:
                pass

    def finish(self, timeout):
        """Waits up to `timeout` seconds for its end of stream and exit,
        then kills it; reaps it and closes the control socket. Returns its
        exit status (negative: a signal)."""
        deadline = time.monotonic() + timeout
        while not self.read():
            left = deadline - time.monotonic()
            if left <= 0:
                break
            select.select([self.control], [], [], left)
        try:
            self.popen.wait(max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.kill()
            self.popen.wait()
        self.control.close()
        return self.popen.returncode

    @property
    def pid(self):
        return self.popen.pid
