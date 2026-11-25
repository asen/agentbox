"""The host side of contracts/provider/v1 for one execution: a
`capabilities` invocation, then the `start` owner session in a leaf of the
instance's domain, held until `stop`.

```text
INTERPRETER -I ENTRY control STATE        stdin/stdout control frames
env: the captured host environment, AGENTBOX_CUSTODY=D (start only),
     AGENTBOX_STORAGE_SCOPES=DATA/run-limits.json
start -> started (instance live) ... stop -> stopped | failed
timeout_ms -> cancel -> CANCEL_GRACE -> lost (the caller kills D)
```

Framing, canonical encoding and every exchange check are the providers'
own module (providers/protocol.py `encode`, `decode_response`,
`Exchange`): one implementation for both sides. stderr is kept to 64 KiB
and never parsed.
"""
import selectors
import time

from .assets import provider_protocol as protocol
from .host import Child, Drain, HostError, capture_host, read_some, write_some

CANCEL_GRACE = 30.0
CAPABILITIES_TIMEOUT_MS = 30000
START_TIMEOUT_MS = 600000
STOP_TIMEOUT_MS = 300000
CUSTODY_ENV = "AGENTBOX_CUSTODY"
SCOPES_ENV = "AGENTBOX_STORAGE_SCOPES"


def environment(scopes, custody=None):
    env = dict(capture_host())
    env[SCOPES_ENV] = scopes
    if custody is not None:
        env[CUSTODY_ENV] = custody
    return env


def control_argv(config):
    return [config["interpreter"], "-I", config["entry"]] + protocol.control_argv(config["state"])


def connect_words(config, run, execution, instance):
    """A stdio transport's ProxyCommand words (provider_client.rs
    `connect_words`)."""
    return [config["interpreter"], "-I", config["entry"]] + protocol.connect_argv(
        config["state"], run, execution, instance)


class Channel:
    """One control invocation's pipes on the loop: frames out, frames in
    (each refused frame final for its exchange), stderr drained."""

    def __init__(self, loop, child):
        self.loop, self.child = loop, child
        self.inbox = []
        self.buffer = b""
        self.outgoing = b""
        self.ended = False
        self.broken = None
        self.stdin = child.popen.stdin.fileno()
        self.stdout = child.popen.stdout.fileno()
        self.stderr = Drain(loop, child.popen.stderr.fileno())
        loop.watch(self.stdout, selectors.EVENT_READ, self._read)

    def _read(self, _mask):
        data = read_some(self.stdout)
        if data is None:
            return
        if not data:
            self.ended = True
            self.loop.unwatch(self.stdout)
            if self.buffer:
                self.broken = "truncated_frame"
            return
        self.buffer += data
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            if len(line) > protocol.MAX_FRAME_BYTES:
                self.broken = "frame_too_large"
                return
            try:
                self.inbox.append(protocol.decode_response(line))
            except protocol.ProtocolError as error:
                self.broken = error.code
                return
        if len(self.buffer) > protocol.MAX_FRAME_BYTES:
            self.broken = "frame_too_large"

    def send(self, frame):
        self.outgoing += protocol.encode(frame) + b"\n"
        self._flush(None)

    def _flush(self, _mask):
        while self.outgoing:
            written = write_some(self.stdin, self.outgoing)
            if written is None:
                self.outgoing = b""
                break
            if written == 0:
                self.loop.watch(self.stdin, selectors.EVENT_WRITE, self._flush)
                return
            self.outgoing = self.outgoing[written:]
        self.loop.unwatch(self.stdin)

    def close_input(self):
        self.loop.unwatch(self.stdin)
        try:
            self.child.popen.stdin.close()
        except OSError:
            pass

    def close(self):
        self.loop.unwatch(self.stdout)
        self.stderr.close()


class Invocation:
    """One exchange (providers' `Exchange`) on one `Channel`."""

    def __init__(self, loop, config, scopes, request, described=None, worker_sha256=None,
                 leaf=None, custody=None):
        self.loop = loop
        self.exchange = protocol.Exchange(request, described, worker_sha256)
        self.request = request
        self.child = Child(control_argv(config), environment(scopes, custody), leaf=leaf)
        self.channel = Channel(loop, self.child)
        self.channel.send(request)
        # Per in-flight operation: one cancel, one grace, never renewed.
        self.cancel_sent = False
        self.grace_until = None
        self.error = None
        # The exchange keeps no copy of `started`: kept here once accepted.
        self.started = None

    def pump(self):
        """Feeds received frames to the exchange; a refusal is final."""
        if self.error is not None:
            return
        if self.channel.broken is not None:
            self.error = self.channel.broken
            self.exchange.frame_error()
            return
        while self.channel.inbox:
            frame = self.channel.inbox.pop(0)
            try:
                self.exchange.provider(frame)
            except protocol.ProtocolError as error:
                self.error = error.code
                return
            if frame["type"] == "started":
                self.started = frame

    def host(self, frame):
        self.exchange.host(frame)
        if frame["type"] == "stop":
            self.cancel_sent, self.grace_until = False, None
        self.channel.send(frame)

    def cancel(self):
        if self.cancel_sent or self.exchange.inflight is None or self.exchange.result is not None:
            return
        self.cancel_sent = True
        self.grace_until = time.monotonic() + CANCEL_GRACE
        try:
            self.host({"v": 1, "type": "cancel", "operation": self.exchange.inflight["operation"]})
        except protocol.ProtocolError:
            pass

    def settled_answer(self):
        """The exchange's outcome, else None while pending."""
        self.pump()
        if self.exchange.result is None and (self.channel.ended or self.child.exited()):
            self.pump()
            if self.exchange.result is None:
                self.exchange.exit()
        return self.exchange.outcome()

    def wait(self, done, timeout_ms, stop=None, force=None):
        """Runs the loop until `done()`. At `timeout_ms` or once `stop()`
        holds, the in-flight operation is cancelled (once); its grace,
        counted from that cancel and never renewed by a later wait, ends
        the wait. `force()` ends it at once. Returns whether `done()`
        held."""
        deadline = time.monotonic() + timeout_ms / 1000.0

        def check():
            self.pump()
            return done() or self.error is not None

        while not check():
            now = time.monotonic()
            if force is not None and force():
                return False
            if now >= deadline or (stop is not None and stop()):
                self.cancel()
                if self.grace_until is None:
                    # Nothing in flight to cancel: nothing more to await.
                    return False
            if self.grace_until is not None and now >= self.grace_until:
                return False
            if self.channel.ended and self.child.exited():
                self.pump()
                return check()
            self.loop.step(0.05)
        return done()

    def end(self):
        """The invocation's process ended and reaped (killed if needed)."""
        self.channel.close_input()
        self.channel.close()
        if not self.child.exited():
            self.child.kill_group()
        self.child.finish()


def capabilities(loop, config, scopes, operation, stop=None, force=None):
    request = {"v": 1, "type": "capabilities", "operation": operation,
               "timeout_ms": CAPABILITIES_TIMEOUT_MS}
    invocation = Invocation(loop, config, scopes, request)
    try:
        invocation.wait(lambda: invocation.settled_answer() is not None, CAPABILITIES_TIMEOUT_MS, stop, force)
        outcome = invocation.settled_answer()
    finally:
        invocation.end()
    result = invocation.exchange.result
    if invocation.error is not None or outcome is None or not isinstance(result, dict) \
            or result.get("type") != "described":
        raise HostError("provider_capabilities_failed")
    return result
