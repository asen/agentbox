"""The controller's side of docs/server-protocol.md: one `agentbox-server`
per execution, in its own leaf of the domain, on two private pipes.

```text
configure [post {nonce, delivery}] [grants] -> ready {broker port}
events (broker records) -> the capture, continuously drained
post.request, post.ended -> bounded queues, taken by the acquisition lane
deliver / respond / revoke -> one `result` each, by command id
end of input (close stdin) -> stopped -> exit (its own 5 s cutoff)
```

Every queue is bounded: at most MAX_QUEUED inbound POST messages and
MAX_OUTSTANDING commands awaiting their result; more is a server fault
(`server_queue_full`), never growth.

The pipes are this process's alone (close-on-exec; the server's other
children never get them). Frames are u32 big-endian length plus one JSON
object, at most 1 MiB, refused otherwise; any refusal, a frame after
`stopped` or a late frame after the end counts the server lost.
"""
import json
import selectors
import struct
import time

from .host import Child, Drain, HostError, read_some, write_some

MAX_FRAME_BYTES = 1 << 20
MAX_QUEUED = 64
MAX_OUTSTANDING = 8
READY_TIMEOUT = 15.0
STOP_TIMEOUT = 5.0 + 2.0
VERSION = 1


class Server:
    def __init__(self, loop, program, leaf, env, record_event):
        self.loop = loop
        self.record_event = record_event
        self.child = Child([program], env, leaf=leaf)
        self.stdin = self.child.popen.stdin.fileno()
        self.stdout = self.child.popen.stdout.fileno()
        self.stderr = Drain(loop, self.child.popen.stderr.fileno(), limit=4096)
        self.buffer = b""
        self.outgoing = b""
        self.messages = []
        self.ready = None
        self.stopped = None
        self.broken = None
        self.ended = False
        self.input_closed = False
        self.next_id = 0
        self.posts = []
        self.outstanding = {}
        self.results = {}
        self.post_closed = False
        loop.watch(self.stdout, selectors.EVENT_READ, self._read)

    def _read(self, _mask):
        data = read_some(self.stdout)
        if data is None:
            return
        if not data:
            self.ended = True
            self.loop.unwatch(self.stdout)
            if self.buffer:
                self.broken = self.broken or "server_truncated"
            return
        self.buffer += data
        while len(self.buffer) >= 4:
            (length,) = struct.unpack(">I", self.buffer[:4])
            if length == 0 or length > MAX_FRAME_BYTES:
                self.broken = self.broken or "server_frame_invalid"
                self.buffer = b""
                return
            if len(self.buffer) < 4 + length:
                return
            body, self.buffer = self.buffer[4:4 + length], self.buffer[4 + length:]
            try:
                message = json.loads(body)
            except ValueError:
                message = None
            if not isinstance(message, dict) or not isinstance(message.get("type"), str):
                self.broken = self.broken or "server_frame_invalid"
                continue
            self._message(message)

    def _message(self, message):
        kind = message["type"]
        if self.stopped is not None:
            self.broken = self.broken or "server_frame_after_stop"
        elif kind == "event":
            if message.get("event") == "post.closed":
                self.post_closed = True
            self.record_event(message)
        elif kind == "ready" and self.ready is None:
            self.ready = message
        elif kind == "stopped":
            self.stopped = message
        elif kind in ("post.request", "post.ended") and self.ready is not None \
                and self.ready.get("post") is True:
            if len(self.posts) >= MAX_QUEUED:
                self.broken = self.broken or "server_queue_full"
                return
            self.posts.append(message)
        elif kind == "result" and message.get("id") in self.outstanding \
                and isinstance(message.get("ok"), bool):
            self.outstanding.pop(message["id"])
            self.results[message["id"]] = message
        else:
            self.broken = self.broken or "server_unexpected"

    def _send(self, message):
        body = json.dumps(message, separators=(",", ":")).encode()
        if len(body) > MAX_FRAME_BYTES:
            raise HostError("server_frame_invalid")
        self.outgoing += struct.pack(">I", len(body)) + body
        self._flush(None)

    def _flush(self, _mask):
        while self.outgoing:
            written = write_some(self.stdin, self.outgoing)
            if written is None:
                self.outgoing = b""
                self.broken = self.broken or "server_lost"
                break
            if written == 0:
                self.loop.watch(self.stdin, selectors.EVENT_WRITE, self._flush)
                return
            self.outgoing = self.outgoing[written:]
        self.loop.unwatch(self.stdin)

    def configure(self, session, run_id, execution_id, lifetime_ms, policy, stop=None, post=None, grants=(),
                  proxy=None):
        """`post`: None (POST unconfigured) or {nonce, delivery}. `grants`:
        the invocation's `--allow-connect` endpoints, sent only if any.
        `proxy`: the configured `connect_proxy`, sent only if set."""
        self.next_id += 1
        message = {"type": "configure", "id": self.next_id, "v": VERSION, "session": session,
                   "run_id": run_id, "execution_id": execution_id, "lifetime_ms": lifetime_ms,
                   "policy": policy, "post": post}
        if grants:
            message["grants"] = list(grants)
        if proxy is not None:
            message["connect_proxy"] = proxy
        self._send(message)
        ok = self.loop.run(lambda: self.ready is not None or self.failed() or (stop is not None and stop()),
                           time.monotonic() + READY_TIMEOUT)
        if not ok or self.ready is None or self.failed() or self.ready.get("session") != session \
                or self.ready.get("id") != self.next_id or self.ready.get("v") != VERSION:
            raise HostError("server_not_ready")
        broker = self.ready.get("broker")
        port = broker.get("port") if isinstance(broker, dict) else None
        if port is None or broker.get("host") != "127.0.0.1" or type(port) is not int \
                or not 1024 <= port <= 65535 or self.ready.get("post") is not (post is not None) \
                or self.ready.get("delivery") is not (post is not None and post["delivery"] is not None):
            raise HostError("server_not_ready")
        return port

    def command(self, kind, **fields):
        """Sends one command; returns its id (its `result` arrives later)."""
        if len(self.outstanding) >= MAX_OUTSTANDING or self.input_closed:
            raise HostError("server_queue_full")
        self.next_id += 1
        self.outstanding[self.next_id] = kind
        self._send(dict(fields, type=kind, id=self.next_id))
        return self.next_id

    def take_result(self, ident):
        """The command's result once it came, else None."""
        return self.results.pop(ident, None)

    def take_posts(self):
        taken, self.posts = self.posts, []
        return taken

    def failed(self):
        return self.broken is not None or self.stopped is not None or self.ended or self.child.exited()

    def shutdown(self, force=None):
        """End of input, then `stopped` and the exit within the server's own
        bound (`force()` ends the wait at once); else its group killed.
        Returns whether it stopped clean."""
        if not self.input_closed:
            self.input_closed = True
            self.outgoing = b""
            self.loop.unwatch(self.stdin)
            try:
                self.child.popen.stdin.close()
            except OSError:
                pass
        self.loop.run(lambda: (self.ended and self.child.exited()) or (force is not None and force()),
                      time.monotonic() + STOP_TIMEOUT)
        clean = (self.ended and self.child.exited() and self.broken is None
                 and isinstance(self.stopped, dict) and self.stopped.get("clean") is True)
        self.loop.unwatch(self.stdout)
        self.stderr.close()
        if not self.child.exited():
            self.child.kill_group()
        code = self.child.finish()
        return clean and code == 0
