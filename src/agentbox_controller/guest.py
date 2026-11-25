"""The host side of the guest protocol (contracts/v1 `agentbox.guest`) on
one ssh session: hello, one exec, its output, task input by credit, exit.

```text
host hello(session) -> guest hello(session, version)
  [-> inputs_setup(execution_id) -> guest inputs_ready]   copied inputs, once asked
  -> exec(id, argv[, env][, stdin])
guest output(id, stream, data) ... stdin_ready(id, n) -> host stdin(id, n, data) | stdin_eof
guest exit(id, outcome[, code])      a cancel crosses it: cancel(id) once
```

Serving (`argv` None, `jail serve`): no exec; the session holds at
guest-ready until the host closes it. Any guest frame then is refused.

The codec is the guest package's own (guest/src/protocol.py): one rule set,
both directions. Guest frames are untrusted reports: recorded with fixed
event types, the output as data; anything refused ends the session
(`protocol_rejected`). Each `stdin` frame and its LF is one write of at
most 2860 bytes, so nothing interleaves with it.
"""
import base64
import selectors

from .assets import guest_protocol as gp
from .host import Drain, read_some, write_some

MAX_SSH_STDERR = 65536


class Guest:
    def __init__(self, loop, child, capture, surfaces, nonce, exec_id, argv, env, task_input, inputs=None):
        self.loop, self.child, self.capture = loop, child, capture
        self.surfaces = surfaces
        self.nonce, self.exec_id = nonce, exec_id
        self.exec_frame = None
        if argv is not None:
            self.exec_frame = {"type": "exec", "id": exec_id, "argv": list(argv)}
            if env:
                self.exec_frame["env"] = tuple(sorted(env.items()))
            if task_input is not None:
                self.exec_frame["stdin"] = True
            gp.encode_host_frame(self.exec_frame)
        self.task_input = task_input
        self.splitter = gp.FrameSplitter()
        self.stdin = child.popen.stdin.fileno()
        self.stdout = child.popen.stdout.fileno()
        self.stderr = Drain(loop, child.popen.stderr.fileno(), MAX_SSH_STDERR)
        self.outgoing = b""
        self.phase = "hello"
        self.inputs = inputs
        self.inputs_ready = False
        self.ready = False
        self.exit = None
        self.failure = None
        self.cancel_sent = False
        self.ended = False
        self.credit = None
        self.input_done = task_input is None
        loop.watch(self.stdout, selectors.EVENT_READ, self._read)
        self._send({"type": "hello", "session": nonce})

    def _send(self, frame):
        if self.failure is not None:
            return
        self.outgoing += gp.encode_host_frame(frame) + b"\n"
        self._flush(None)

    def _flush(self, _mask):
        while self.outgoing:
            written = write_some(self.stdin, self.outgoing)
            if written is None:
                self.outgoing = b""
                self._fail("transport_lost")
                break
            if written == 0:
                self.loop.watch(self.stdin, selectors.EVENT_WRITE, self._flush)
                return
            self.outgoing = self.outgoing[written:]
        self.loop.unwatch(self.stdin)
        self._pump_input()

    def _fail(self, code):
        if self.failure is None and self.exit is None:
            self.failure = code

    def _read(self, _mask):
        data = read_some(self.stdout)
        if data is None:
            return
        if not data:
            self.ended = True
            self.loop.unwatch(self.stdout)
            try:
                self.splitter.end()
            except gp.Refused as error:
                self._reject(error.code)
            self._fail("transport_lost")
            return
        try:
            frames = self.splitter.push(data)
        except gp.Refused as error:
            self._reject(error.code)
            return
        for raw in frames:
            try:
                frame = gp.decode_guest_frame(raw)
            except gp.Refused as error:
                self._reject(error.code)
                return
            self._handle(frame)

    def _reject(self, code):
        self.capture.record("host.supervisor", "host.protocol.rejected", "warn", {"code": code})
        self._fail("protocol_rejected")

    def _handle(self, frame):
        kind = frame["type"]
        if self.exit is not None or self.failure is not None:
            # After the terminal frame nothing more is accepted.
            self._reject("unexpected_frame")
            return
        if self.phase == "hello":
            if kind != "hello" or frame["session"] != self.nonce:
                self._reject("invalid_field")
                return
            self.capture.record("guest", "guest.hello", "info", {"guest_version": frame["guest_version"]})
            self.capture.record("host.supervisor", "host.execution.guest_ready")
            if self.inputs is not None:
                self.phase = "inputs"
                self._send({"type": "inputs_setup", "execution_id": self.inputs})
                return
            self._exec()
            return
        if self.phase == "inputs":
            if kind == "inputs_ready":
                self.inputs_ready = True
                self.capture.record("guest", "guest.inputs_ready", "info", {})
                self._exec()
            elif kind == "error":
                self.capture.record("guest", "guest.protocol_error", "warn", {"code": frame["code"]})
                self._fail("inputs_setup_failed")
            else:
                self._reject("unexpected_frame")
            return
        if self.phase == "serving":
            self._reject("unexpected_frame")
            return
        if kind == "error":
            self.capture.record("guest", "guest.protocol_error", "warn", {"code": frame["code"]})
            self._fail("guest_protocol_error")
            return
        if frame.get("id") != self.exec_id or kind in ("hello", "inputs_ready"):
            self._reject("invalid_field")
            return
        if kind == "output":
            # Canonical base64, checked by the codec.
            data = base64.b64decode(frame["data"])
            self.capture.record("guest", "guest.output", "info",
                                {"request_id": self.exec_id, "stream": frame["stream"], "bytes": len(data)},
                                body=data)
            self.surfaces[frame["stream"]].show(data)
        elif kind == "exit":
            self.exit = frame
            attributes = {"request_id": self.exec_id, "outcome": frame["outcome"]}
            if "code" in frame:
                attributes["code"] = frame["code"]
            self.capture.record("guest", "guest.exit", "info", attributes)
        elif kind == "stdin_ready":
            if self.input_done or self.credit is not None or frame["seq"] != self._next_seq():
                self._reject("invalid_field")
                return
            self.credit = frame["seq"]
            self.capture.record("guest", "guest.stdin_ready", "info",
                                {"request_id": self.exec_id, "seq": frame["seq"]})
            self._pump_input()
        elif kind == "stdin_closed":
            if self.task_input is None or self.input_done:
                self._reject("invalid_field")
                return
            self.capture.record("guest", "guest.stdin_closed", "info", {"request_id": self.exec_id})
            self._end_input()

    def _exec(self):
        self.ready = True
        if self.exec_frame is None:
            self.phase = "serving"
            self.capture.record("host.supervisor", "host.serve.ready")
            return
        self.phase = "running"
        self._send(self.exec_frame)

    def _next_seq(self):
        return 0 if not hasattr(self, "_sent_seq") else self._sent_seq + 1

    def _pump_input(self, _mask=None):
        """One chunk per credit, read only once credited and the outgoing
        queue is empty; the end of input on the outstanding credit."""
        if self.input_done or self.credit is None or self.outgoing or self.failure is not None:
            if self.task_input is not None and self.task_input.fd is not None:
                self.loop.unwatch(self.task_input.fd)
            return
        data = self.task_input.read()
        if data is None:
            self.loop.watch(self.task_input.fd, selectors.EVENT_READ, self._pump_input)
            return
        seq = self.credit
        self.credit = None
        self._sent_seq = seq
        if data:
            self._send({"type": "stdin", "id": self.exec_id, "seq": seq,
                        "data": base64.b64encode(data).decode()})
        else:
            self._send({"type": "stdin_eof", "id": self.exec_id, "seq": seq})
            self._end_input()

    def _end_input(self):
        self.input_done = True
        self.credit = None
        if self.task_input is not None:
            if self.task_input.fd is not None:
                self.loop.unwatch(self.task_input.fd)
            self.task_input.close()

    def cancel(self):
        """Asks the command to stop, once; only after `exec` was sent."""
        if self.cancel_sent or not self.ready or self.exec_frame is None or self.exit is not None \
                or self.failure is not None:
            return
        self.cancel_sent = True
        self._send({"type": "cancel", "id": self.exec_id})

    def done(self):
        return self.exit is not None or self.failure is not None

    def close(self):
        """Ends the session: input closed, the reader unwatched; the caller
        reaps the ssh process (or kills its group)."""
        self._end_input()
        self.loop.unwatch(self.stdin)
        self.loop.unwatch(self.stdout)
        try:
            self.child.popen.stdin.close()
        except OSError:
            pass
