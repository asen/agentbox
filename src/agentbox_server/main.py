"""`agentbox-server`: one session's transport, for one trusted controller
on its private stdio (docs/server-protocol.md); the packaged default of
the controller configuration's `server`.

```text
controller --stdin frames--> reader (in the loop) --bounded queue--> commands
controller <-stdout frames-- whole frames, each by its deadline
loop: configure -> Broker (CONNECT policy + POST ingress) -> relay children
      POST inbox events -> post.request / post.ended
      deliver -> activate + one scp (spool fd as its fd 3), driven by the loop
      respond / revoke -> the inbox, the active request
stderr: fixed codes only, best effort
```

One selectors loop does everything but the bounded lookup threads. Every
stop takes one path within one cutoff (`SHUTDOWN_WAIT`) never renewed: the
end of input (the controller's close or death), a violation, SIGINT,
SIGTERM or SIGHUP, lost output, a failed broker, the session's lifetime.
Each revokes the POST ingress and the active request, stops the broker
(every relay child revoked, then killed if late) and kills the delivery's
`scp` group. A SIGKILL of this process skips all of it; its relay children
then see their control socket's end and exit, its `scp` group does not.
"""
import errno
import fcntl
import os
import selectors
import signal
import stat
import time

from . import broker as broker_mod, codec, ingress as ingress_mod, tools, transport, wire
from .wire import Violation

MAX_PENDING_COMMANDS = 64
OUTPUT_WAIT = 2.0
SHUTDOWN_WAIT = 5.0
STARTUP_WAIT = 10.0
FINAL_WAIT = 0.25
SLICE = 0.01
MAX_UPLOAD_OUTPUT = 4096
SOURCE = "/dev/fd/3"
TERMINATING = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


def clock():
    return time.monotonic()


class Loop:
    def __init__(self):
        self.selector = selectors.DefaultSelector()

    def watch(self, fd, events, callback):
        try:
            self.selector.modify(fd, events, callback)
        except KeyError:
            self.selector.register(fd, events, callback)

    def unwatch(self, fd):
        try:
            self.selector.unregister(fd)
        except (KeyError, ValueError):
            pass

    def step(self, timeout):
        for key, mask in self.selector.select(max(0.0, timeout)):
            key.data(mask)


class Server:
    def __init__(self, relay_path):
        self.relay_path = relay_path
        self.loop = Loop()
        self.cause = None
        self.signalled = False
        self.output_failed = False
        self.broker_failed = False
        self.reader = wire.Reader()
        self.commands = []
        self.input_open = True
        self.last_id = 0
        self.session = None
        self.cutoff = None
        self.broker = None
        self.post = None
        self.exchanges = {}
        self.next_exchange = 0
        self.next_token = 0
        self.active = None
        self.delivery = None
        self.running = None
        self.finished = []
        self.wake = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.loop.watch(self.wake[0], selectors.EVENT_READ, self._woken)
        self.loop.watch(0, selectors.EVENT_READ, lambda _mask: self.service_input())

    # Stops.

    def request_stop(self, cause):
        if self.cause is None:
            self.cause = cause

    def stopping(self):
        return self.cause is not None or self.signalled

    def halted(self):
        if self.cause is not None:
            return self.cause
        if self.signalled:
            return "signal"
        if self.output_failed:
            return "output_failed"
        if self.broker_failed:
            return "broker_failed"
        if self.cutoff is not None and clock() >= self.cutoff:
            return "lifetime"
        return None

    def stop_seen(self):
        """Any stop already known, before `serve` gets to it: the broker
        reads it at each commit boundary (an end of input or a signal can
        arrive mid-batch or during a required write)."""
        return self.halted() is not None

    def on_signal(self, _number, _frame):
        self.signalled = True
        try:
            os.write(self.wake[1], b"s")
        except OSError:
            pass

    def _woken(self, _mask):
        try:
            os.read(self.wake[0], 256)
        except OSError:
            pass

    # Control input.

    def service_input(self):
        """Reads what the controller sent: frames into the bounded queue; a
        violation or the end stops at once."""
        while self.input_open:
            try:
                data = os.read(0, 65536)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self.input_open = False
                self.loop.unwatch(0)
                return self.request_stop("control_failed")
            if not data:
                self.input_open = False
                self.loop.unwatch(0)
                return self.request_stop(self.reader.end())
            try:
                commands = self.reader.feed(data)
            except Violation as violation:
                self.input_open = False
                self.loop.unwatch(0)
                return self.request_stop(violation.code)
            self.commands.extend(commands)
            if len(self.commands) > MAX_PENDING_COMMANDS:
                self.input_open = False
                self.loop.unwatch(0)
                return self.request_stop("control_overflow")

    # Output.

    def write(self, message, deadline, abort):
        """One whole frame by `deadline`: "ok", "aborted" (a stop before its
        first byte: the stream intact) or "lost" (for good)."""
        if self.output_failed:
            return "lost"
        data = wire.frame(message)
        if data is None:
            self.output_failed = True
            return "lost"
        sent = 0
        while True:
            if clock() >= deadline:
                self.output_failed = True
                return "lost"
            if abort():
                if sent:
                    self.output_failed = True
                    return "lost"
                return "aborted"
            try:
                sent += os.write(1, data[sent:])
            except (BlockingIOError, InterruptedError):
                pass
            except OSError:
                self.output_failed = True
                return "lost"
            if sent == len(data):
                # Written only if its last byte went out before any stop.
                if clock() >= deadline or abort():
                    self.output_failed = True
                    return "lost"
                return "ok"
            # Wait for room, still reading the controller's input.
            selector = selectors.DefaultSelector()
            try:
                selector.register(1, selectors.EVENT_WRITE)
                if self.input_open:
                    selector.register(0, selectors.EVENT_READ)
                selector.register(self.wake[0], selectors.EVENT_READ)
                ready = selector.select(min(0.02, max(0.0, deadline - clock())))
            finally:
                selector.close()
            for key, _mask in ready:
                if key.fd == 0:
                    self.service_input()
                elif key.fd == self.wake[0]:
                    self._woken(0)

    def send(self, message):
        """A loop message, by OUTPUT_WAIT, aborted by a stop; an error
        stops the server."""
        outcome = self.write(message, clock() + OUTPUT_WAIT, self.stopping)
        if outcome == "aborted":
            raise Halt("stopping")
        if outcome == "lost":
            raise Halt("output_failed")

    def record(self, event, deadline):
        """The broker's required sink: an `event` written by `deadline`,
        never aborted."""
        return self.write(dict(event, type="event"), deadline, lambda: False) == "ok"

    def result(self, ident, code=None):
        self.send(wire.message("result", id=ident, ok=code is None, code=code))

    # The loop.

    def serve(self):
        while True:
            reason = self.halted()
            if reason is not None:
                return reason
            try:
                if self.commands:
                    self.command(self.commands.pop(0))
                else:
                    self.loop.step(SLICE)
                if self.broker is not None:
                    self.broker.tick()
                self.pump()
            except Halt as halt:
                return self.halted() or halt.reason

    def command(self, value):
        ident, kind, fields = self._validated(value)
        self.last_id = ident
        if kind == "configure":
            return self.configure(ident, fields)
        if kind == "deliver":
            code = self.deliver(ident, **fields)
            if code is not None:
                self.result(ident, code)
            return
        if kind == "respond":
            return self.result(ident, self.respond(fields["exchange"], fields["body"]))
        return self.result(ident, self.revoke(fields["request"]))

    def _validated(self, value):
        try:
            return wire.command(value, self.session is not None, self.last_id)
        except Violation as violation:
            raise Halt(violation.code) from None

    # configure.

    def configure(self, ident, fields):
        now = clock()
        cutoff = None if fields["lifetime"] is None else now + fields["lifetime"]
        post = fields["post"]
        if post is not None and post["delivery"] is not None:
            self.delivery = Delivery.open(post["delivery"], fields["run_id"], post["nonce"])
        if not relay_trusted(self.relay_path):
            raise Halt("relay_missing")
        if post is not None:
            if cutoff is not None and now >= cutoff:
                raise Halt("configure_invalid")
            self.post = ingress_mod.Ingress(now, cutoff)
            self.post.arm(post["nonce"])
        broker = broker_mod.Broker(
            self.loop, fields["policy"], broker_mod.Limits(), self.post, self.relay_path, self.record,
            self._broker_failed, clock, stopped=self.stop_seen, proxy=fields["connect_proxy"])
        until = now + STARTUP_WAIT if cutoff is None else min(now + STARTUP_WAIT, cutoff)
        try:
            address = broker.start(until, self.stopping)
        except broker_mod.BrokerStartError:
            if self.post is not None:
                self.post.stop()
            broker.close_unstarted()
            raise Halt("broker_start_failed") from None
        self.broker = broker
        self.session = fields["session"]
        self.cutoff = cutoff
        if self.halted() is not None:
            raise Halt(self.halted())
        self.send(wire.message("ready", v=wire.VERSION, id=ident, session=fields["session"],
                               broker={"host": address[0], "port": address[1]}, post=self.post is not None,
                               delivery=self.delivery is not None))

    def _broker_failed(self):
        self.broker_failed = True

    # respond, deliver, revoke.

    def respond(self, exchange, body):
        if self.post is None:
            return "post_unconfigured"
        if exchange not in self.exchanges:
            return "stale"
        ident = self.exchanges[exchange][0]
        try:
            response = codec.decode_response(body.encode("utf-8", "surrogatepass"))
        except codec.CodecError:
            return "response_invalid"
        if response["type"] == "ready":
            active = self.active
            if active is None:
                return "ready_unbound"
            if active["cancel"].is_cancelled():
                return "cancelled"
            if active["request"] != response["request"] \
                    or active["delivered"] != (response["size"], response["sha256"]):
                return "ready_unbound"
        return self.post.respond(ident, response)

    def deliver(self, ident, exchange, request, deadline, name, size, sha256):
        if self.delivery is None or self.post is None:
            return "delivery_unconfigured"
        if exchange not in self.exchanges:
            return "stale"
        exchange_id, admitted = self.exchanges[exchange]
        if self.active is not None or self.running is not None:
            return "busy"
        deadline = admitted + deadline
        activated = self.post.activate(exchange_id, deadline)
        if isinstance(activated, str):
            return activated
        token, cancel = activated
        self.next_token += 1
        own = self.next_token
        upload = min(clock() + ingress_mod.UPLOAD_CEILING, deadline)
        if self.cutoff is not None:
            upload = min(upload, self.cutoff)
        self.active = {"request": request, "token": own, "ingress_token": token, "cancel": cancel,
                       "delivered": None}
        job = {"id": ident, "token": own, "size": size, "sha256": sha256}
        try:
            run = self.delivery.start(request, name, size, upload)
        except DeliveryError as error:
            self.finished.append(dict(job, outcome=error.code))
            self.running = None
            return None
        self.running = dict(job, run=run, cancel=cancel)
        self.loop.watch(run.fileno(), selectors.EVENT_READ, lambda _mask: run.readable())
        return None

    def revoke(self, request):
        active = self.active
        if active is None or active["request"] != request:
            return "not_active"
        active["cancel"].cancel()
        self.active = None
        self.post.retire(active["ingress_token"])
        return None

    def _retire(self):
        if self.active is not None:
            self.active["cancel"].cancel()
            self.post.retire(self.active["ingress_token"])
            self.active = None

    def pump(self):
        """The delivery ends seen before, then the POST inbox's events, in
        order; a delivery ending now is reported next pass (as the Rust
        server's delivery thread: a peer's `post.ended` before its
        cancelled upload's result)."""
        while self.finished:
            done = self.finished.pop(0)
            outcome = done["outcome"]
            active = self.active
            if outcome is None:
                if active is not None and active["token"] == done["token"] and not active["cancel"].is_cancelled():
                    active["delivered"] = (done["size"], done["sha256"])
                else:
                    outcome = "request_ended"
            self.result(done["id"], outcome)
        if self.post is not None:
            self._post_events()
        running = self.running
        if running is not None:
            run = running["run"]
            if running["cancel"].is_cancelled() or self.stopping():
                outcome = run.cancel()
            else:
                outcome = run.poll(clock())
            if outcome is not None:
                self.loop.unwatch(run.fileno())
                run.close()
                self.running = None
                self.finished.append(dict(running, outcome=_upload_outcome(outcome)))

    def _post_events(self):
        while True:
            event = self.post.poll()
            if event is None:
                return
            if event[0] == "request":
                _, exchange, request, replay, received, admitted_at = event
                self.next_exchange += 1
                self.exchanges[self.next_exchange] = (exchange, admitted_at)
                body = codec.render_request(request)
                self.send(wire.message("post.request", exchange=self.next_exchange, replay=replay,
                                       bytes=received, body=body))
            elif event[0] == "ended":
                _, exchange, end = event
                number = next((n for n, (e, _) in self.exchanges.items() if e == exchange), None)
                if number is None:
                    continue
                del self.exchanges[number]
                self.send(wire.message("post.ended", exchange=number, end=end))
            else:
                self.send(wire.message("event", event="post.closed", severity="warn",
                                       attributes={"closure": event[1]}))

    # The stop.

    def shutdown(self, reason):
        self.request_stop(reason)
        cutoff = clock() + SHUTDOWN_WAIT
        if self.active is not None:
            self.active["cancel"].cancel()
            self._retire()
        if self.post is not None:
            self.post.close()
        report = None
        if self.broker is not None:
            report = self.broker.stop_until(cutoff, self.loop.step)
        outstanding = False
        if self.running is not None:
            run = self.running["run"]
            run.cancel()
            self.loop.unwatch(run.fileno())
            run.close()
            self.running = None
        clean = (report is None or report["clean"]) and not outstanding
        if not self.output_failed:
            broker = None
            if report is not None:
                broker = {key: report[key] for key in (
                    "state", "clean", "connections_outstanding", "posts_outstanding",
                    "resolutions_outstanding", "recorder_outstanding")}
            message = wire.message("stopped", reason=reason, clean=clean, broker=broker,
                                   delivery_outstanding=outstanding)
            self.write(message, min(clock() + FINAL_WAIT, cutoff), lambda: False)
        note(reason)
        return 0 if reason == "control_eof" and clean else 1


class Halt(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _upload_outcome(outcome):
    if outcome[0] == "ok":
        return None if outcome[1] == 0 else "transfer_failed"
    return {"tool_cancelled": "cancelled", "tool_timeout": "timeout",
            "tool_output_too_large": "transfer_output"}.get(outcome[1], "transfer_start_failed")


class DeliveryError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class Delivery:
    """The configured spool (opened once, never by name again) and pinned
    target: one `scp` per delivered request, its source the opened spool
    entry as fd 3."""

    def __init__(self, spool, scp, ssh, connection, work, nonce):
        self.spool, self.scp, self.ssh = spool, scp, ssh
        self.connection, self.work, self.nonce = connection, work, nonce

    @classmethod
    def open(cls, config, run_id, nonce):
        try:
            spool = os.open(config["spool_root"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise Halt("spool_invalid") from None
        try:
            scp = tools.resolve("scp")
            ssh = tools.resolve("ssh")
        except tools.ToolError:
            raise Halt("transfer_tools_missing") from None
        if scp == ssh:
            raise Halt("transfer_tools_missing")
        if not (run_id.startswith("r-") and len(run_id) == 34):
            raise Halt("target_invalid")
        return cls(spool, scp, ssh, config["connection"], config["work_dir"], nonce)

    def start(self, request, name, size, deadline):
        try:
            destination = f"{self.work}/{transport.DELIVERY_DIR}/{transport.upload_name(self.nonce, request)}"
            argv = self.connection.scp_argv(self.scp, self.ssh, SOURCE, destination)
        except transport.Invalid:
            raise DeliveryError("target_invalid") from None
        if not codec.is_id(name):
            raise DeliveryError("source_invalid")
        try:
            source = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY,
                             dir_fd=self.spool)
        except OSError as error:
            raise DeliveryError("source_missing" if error.errno == errno.ENOENT else "source_invalid") from None
        try:
            st = os.fstat(source)
            if not stat.S_ISREG(st.st_mode):
                raise DeliveryError("source_invalid")
            if st.st_size != size:
                raise DeliveryError("size_mismatch")
            if deadline <= clock():
                raise DeliveryError("timeout")
            env = self.connection.env(tools.tool_env(), tools.capture_host())
            try:
                return tools.Run(argv[0], argv[1:], env, deadline, MAX_UPLOAD_OUTPUT, forwarded=source)
            except tools.ToolError:
                raise DeliveryError("transfer_start_failed") from None
        finally:
            os.close(source)


def relay_trusted(path):
    """The relay beside this program, accepting the user's umask 0002."""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    uid = os.geteuid()
    writable = 0o002 if st.st_uid == uid else 0o022
    return (stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and not st.st_mode & writable
            and st.st_uid in (0, uid))


def note(code):
    """A best-effort fixed code on stderr: written only if it fits now."""
    try:
        flags = fcntl.fcntl(2, fcntl.F_GETFL)
        fcntl.fcntl(2, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        try:
            os.write(2, f"agentbox-server: {code}\n".encode())
        finally:
            fcntl.fcntl(2, fcntl.F_SETFL, flags)
    except OSError:
        pass


def _control_stream(fd):
    try:
        mode = os.fstat(fd).st_mode
    except OSError:
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


def _inherited_cloexec():
    """Every inherited descriptor above stderr close-on-exec."""
    try:
        for name in os.listdir("/proc/self/fd"):
            fd = int(name)
            if fd > 2:
                try:
                    os.set_inheritable(fd, False)
                except OSError:
                    pass
    except OSError:
        return False
    return True


def main(relay_path):
    tools.capture_host()
    try:
        os.chdir("/")
    except OSError:
        pass
    if not _control_stream(0) or not _control_stream(1) or not _inherited_cloexec():
        note("control_streams_invalid")
        return 2
    try:
        os.set_blocking(0, False)
        os.set_blocking(1, False)
    except OSError:
        note("control_streams_invalid")
        return 2
    server = Server(relay_path)
    try:
        signal.set_wakeup_fd(server.wake[1], warn_on_full_buffer=False)
        for number in TERMINATING:
            signal.signal(number, server.on_signal)
    except (OSError, ValueError):
        note("signals_failed")
        return 2
    try:
        reason = server.serve()
    except Halt as halt:
        reason = server.halted() or halt.reason
    return server.shutdown(reason)
