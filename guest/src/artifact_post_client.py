"""The guest's artifact request POST client (acquisitions/contracts/artifacts/post-v1): one
bounded exchange per POST over the fixed loopback proxy endpoint, and the one
request flow every handler's client (request_main.py's generic lane, the pip,
npm and git request clients) runs.

    submit --ready--> local application --> result --closed recorded--> ok
       |                    |  abort
       |                    +-----------> cancel (one terminal action)
       +--rejected/closed/error/refused/lost--> fails, nothing retried

Transport: numeric 127.0.0.1:18080 only, the guest end of the session's
reverse forward to the host broker; no proxy, DNS, redirect, retry or
keep-alive. One TCP connection per POST: the canonical head and body
(artifact_post_protocol.py) written once, the write side kept open until the
complete response AND the server's close (a client half-close cancels on the
host), then the connection is destroyed. The response is the bounded
`ResponseReader`'s: a canonical body whose status fits it, or the host's
empty 503 (`refused`), a transport refusal apart from every logical answer.
Bounds are absolute and never renewed: the request's original cutoff; the
connection and write within the control cap (10 s) from the exchange's
start; a submit's answer until the original cutoff, a cancel's or result's
within the control cap. The cutoff and the abort are read again on
readiness, before the write, after it, at every read and at completion; a
late event changes nothing once the exchange settled.

Flow: one fresh `client` per submission. A `ready` must name this session,
client, handler and operation and the request digest recomputed here, before
any local application; the `result` echoes `ready`'s request, request digest
and artifact digest. One terminal action after `ready`: the result, or one
cancel; a ready this side refuses is cancelled too. Success needs the
matching `closed` `recorded`. Once a submit byte may have left, a host upload
may exist (`Run.upload`): no later answer proves it gone, so only the
handler's own confirmed removal settles it. An abort before `ready` destroys
the submit, which cancels on the host; after `ready` the local application is
aborted and awaited, then one cancel. A submission, once sent, is spent: no
resubmission, and no result retry on a lost response.

Nothing here is host authority. `ready` is not installation and `recorded`
acknowledges an untrusted claim.

Clocks: nanoseconds of the injected clock (`time.monotonic_ns()` in
production). A cutoff is absolute; a time at or past it has expired.
"""

import asyncio
import os
import socket
import time

from guest.src.abort import Abort
from guest.src.artifact_post_protocol import (
    decode_http_response, encode_http_request, encode_request, request_sha256, ResponseReader,
)
from guest.src.protocol import Refused, is_id

# The fixed endpoint: numeric, never resolved.
ENDPOINT_HOST = "127.0.0.1"
ENDPOINT_PORT = 18080
# A POST's connection and write, and a cancel's or result's answer.
CONTROL_TIMEOUT_MS = 10000

MS_NS = 1_000_000
CONTROL_NS = CONTROL_TIMEOUT_MS * MS_NS
UNKNOWN = "unknown"


class _Connection(asyncio.Protocol):
    """One connection to the fixed endpoint: reports each event at most once
    and never after `destroy`; never half-closed by this side."""

    def __init__(self, events):
        self.events = events
        self.transport = None
        self.destroyed = False
        self.task = None
        self.pending = []

    # asyncio.Protocol
    def connection_made(self, transport):
        if self.destroyed:
            transport.abort()
            return
        self.transport = transport
        transport.set_write_buffer_limits(high=0)
        self.events.connect()

    def data_received(self, data):
        if not self.destroyed:
            self.events.data(data)

    def eof_received(self):
        if not self.destroyed:
            self.events.end()
        # Keep this side's write half open.
        return True

    def connection_lost(self, _exc):
        self._done(False)
        if not self.destroyed:
            self.destroyed = True
            self.events.close()

    def resume_writing(self):
        self._done(True)

    # Channel
    def write(self, data, done):
        if self.transport is None or self.destroyed:
            asyncio.get_running_loop().call_soon(done, False)
            return
        self.transport.write(data)
        self.pending.append(done)
        if self.transport.get_write_buffer_size() == 0:
            self._done(True)

    def _done(self, ok):
        pending, self.pending = self.pending, []
        for done in pending:
            asyncio.get_running_loop().call_soon(done, ok)

    def destroy(self):
        self.destroyed = True
        if self.task is not None and not self.task.done():
            self.task.cancel()
        if self.transport is not None:
            self.transport.abort()


def dial_fixed_endpoint(events):
    """The production connection: numeric 127.0.0.1:18080, no lookup."""
    loop = asyncio.get_running_loop()
    connection = _Connection(events)

    async def connect():
        try:
            await loop.create_connection(lambda: connection, host=ENDPOINT_HOST, port=ENDPOINT_PORT,
                                         family=socket.AF_INET)
        except asyncio.CancelledError:
            raise
        except Exception:
            if not connection.destroyed:
                connection.destroyed = True
                events.close()

    connection.task = loop.create_task(connect())
    return connection


class MonotonicClock:
    """The production clock: `time.monotonic_ns()`; timers only wake."""

    def now(self):
        return time.monotonic_ns()

    def wake(self, at_ns, fire):
        loop = asyncio.get_running_loop()
        state = {"handle": None, "cancelled": False}

        def arm():
            remaining = at_ns - time.monotonic_ns()
            if remaining <= 0:
                state["cancelled"] = True
                fire()
                return
            state["handle"] = loop.call_later(-(-remaining // MS_NS) / 1000, lambda: None if state["cancelled"] else arm())

        def cancel():
            state["cancelled"] = True
            if state["handle"] is not None:
                state["handle"].cancel()

        arm()
        return cancel


class Seams:
    """The client's effects on the world; tests replace them with memory doubles."""

    def __init__(self, dial, clock, client_id):
        self.dial = dial
        self.clock = clock
        self.client_id = client_id


PRODUCTION_SEAMS = Seams(dial_fixed_endpoint, MonotonicClock(), lambda: "c-" + os.urandom(16).hex())


class _Events:
    def __init__(self, connect, data, end, close):
        self.connect = connect
        self.data = data
        self.end = end
        self.close = close


def exchange(request, until_ns, answer_until_ns, seams, signal=None):
    """One POST: its connection, write, complete response and the server's
    close. A future of the result dict: `response` (response), `refused`,
    `malformed` (code), `lost` / `expired` / `aborted` (sent: whether a
    request byte may have reached the host) or `invalid`."""
    return _Exchange(request, until_ns, answer_until_ns, seams, signal).run()


def _earliest(first, second):
    return first if first < second else second


class _Exchange:
    def __init__(self, request, until_ns, answer_until_ns, seams, signal):
        try:
            self.data = encode_http_request(encode_request(request))
        except Refused:
            self.data = None
        self.seams = seams
        self.signal = signal
        start = seams.clock.now()
        self.write_until = _earliest(start + CONTROL_NS, until_ns)
        self.answer_until = _earliest(answer_until_ns, until_ns)
        self.reader = ResponseReader()
        self.cancels = []
        self.channel = None
        self.sent = False
        self.written = False
        self.settled = False
        self.future = None

    def _on_abort(self):
        self._settle({"kind": "aborted", "sent": self.sent})

    def run(self):
        self.future = asyncio.get_running_loop().create_future()
        data = self.data
        if data is None:
            self._settle({"kind": "invalid"})
            return self.future
        if not self._live(self.write_until):
            return self.future
        clock = self.seams.clock
        if self.signal is not None:
            self.signal.add_listener(self._on_abort)
        self.cancels.append(clock.wake(self.write_until, lambda: None if self.written else self._expire()))
        self.cancels.append(clock.wake(self.answer_until, self._expire))
        # A wake may fire at once; the listener is released by the settle.
        if self.settled:
            return self.future
        connected = [False]

        def connect():
            # A connect reported before the dial returned writes once it did.
            if self.channel is None:
                connected[0] = True
            else:
                self._connected(data)

        try:
            self.channel = self.seams.dial(_Events(connect, self._data, self._end,
                                                   lambda: self._settle({"kind": "lost", "sent": self.sent})))
        except Exception:
            self._settle({"kind": "lost", "sent": False})
        # A dial that reported synchronously and settled is destroyed now.
        if self.settled:
            if self.channel is not None:
                self.channel.destroy()
        elif connected[0]:
            self._connected(data)
        return self.future

    def _connected(self, data):
        if self.settled or not self._live(self.write_until):
            return
        self.sent = True

        def done(ok):
            if self.settled:
                return
            if not ok:
                self._settle({"kind": "lost", "sent": True})
                return
            if not self._live(self.write_until):
                return
            self.written = True

        self.channel.write(data, done)

    def _data(self, chunk):
        if self.settled or not self._live(self.answer_until):
            return
        state = self.reader.push(chunk)
        if state["state"] == "failed":
            self._settle({"kind": "malformed", "code": state["code"]})

    def _end(self):
        """The server's close: only now is a response complete."""
        if self.settled or not self._live(self.answer_until):
            return
        state = self.reader.end()
        if state["state"] == "failed":
            self._settle({"kind": "malformed", "code": state["code"]})
            return
        if state["state"] == "refused":
            self._settle({"kind": "refused"})
            return
        if state["state"] != "complete" or not self.written:
            # An answer before this side's whole request was written answers nothing of it.
            self._settle({"kind": "lost", "sent": self.sent})
            return
        try:
            response = decode_http_response(state["status"], state["body"])
        except Refused as error:
            self._settle({"kind": "malformed", "code": error.code})
            return
        # Completion is checked again: a response complete only at or after a bound is not delivered.
        if not self._live(self.answer_until):
            return
        self._settle({"kind": "response", "response": response})

    def _expire(self):
        self._settle({"kind": "expired", "sent": self.sent})

    def _live(self, until):
        """Before `until` and not aborted; otherwise the exchange settles. The abort is read first."""
        if self.settled:
            return False
        if self.signal is not None and self.signal.aborted:
            self._settle({"kind": "aborted", "sent": self.sent})
            return False
        if self.seams.clock.now() >= until:
            self._expire()
            return False
        return True

    def _settle(self, result):
        """Once: timers and the listener released, the connection destroyed."""
        if self.settled:
            return
        self.settled = True
        for cancel in self.cancels:
            cancel()
        if self.signal is not None:
            self.signal.remove_listener(self._on_abort)
        if self.channel is not None:
            self.channel.destroy()
        if not self.future.done():
            self.future.set_result(result)


class Lane:
    """One handler's side of the flow: its submission; `accept(ready)`, the
    handler's checks of a ready already bound to this submission, before any
    application; `apply(ready, signal)`, the local application, a coroutine
    that ends only once all its owned work ended; `applied(outcome)`, whether
    the outcome may be claimed `applied`."""

    def __init__(self, submission, accept, apply, applied):
        self.submission = submission
        self.accept = accept
        self.apply = apply
        self.applied = applied


class Run:
    """How one request ended. `terminal` is a dict by `kind`: `recorded`
    (status), `invalid`, `unavailable`, `refused`, `rejected` (code), `closed`
    (request, outcome, reason?), `error` (code), `lost`, `protocol`,
    `cancelled` or `expired`. `upload` says whether a host upload for this
    submission may exist: `possible` from before the submit's first write
    attempt, `none` only when this side proved that no submit byte left it.
    `outcome` is the application's, UNKNOWN if it raised."""

    __slots__ = ("terminal", "upload", "ready", "outcome")

    def __init__(self, terminal, upload, ready=None, outcome=None):
        self.terminal = terminal
        self.upload = upload
        self.ready = ready
        self.outcome = outcome


async def run_request(context, lane, until_ns, seams, signal=None):
    """One submission to its end under the original cutoff `until_ns`; returns
    only once the application and every exchange ended."""
    clock = seams.clock

    def aborted():
        # Read afresh each time; never narrowed by an earlier read.
        return signal is not None and signal.aborted

    client = seams.client_id()
    digest = None
    if is_id(client):
        try:
            digest = request_sha256(client, lane.submission)
        except Refused:
            digest = None
    # Before the submit: nothing was sent, locally proven.
    if digest is None:
        return Run({"kind": "invalid"}, "none")
    head = {"v": 1, "session": context.session, "client": client}
    if aborted():
        return Run({"kind": "cancelled"}, "none")
    if clock.now() >= until_ns:
        return Run({"kind": "expired"}, "none")

    submit = dict(head, type="submit", **lane.submission)
    submitted = await exchange(submit, until_ns, until_ns, seams, signal)
    # Possible unless the exchange proved that it never attempted a write.
    unsent = submitted["kind"] == "invalid" or (
        submitted["kind"] in ("lost", "expired", "aborted") and not submitted["sent"])
    upload = "none" if unsent else "possible"
    if submitted["kind"] != "response":
        return Run(_failed(submitted), upload)
    answer = submitted["response"]
    handler = lane.submission["handler"]

    def ours(response):
        return response["session"] == context.session and response["client"] == client

    if answer["type"] == "error":
        return Run({"kind": "error", "code": answer["code"]}, upload)
    if answer["type"] == "rejected":
        return Run({"kind": "rejected", "code": answer["code"]} if ours(answer) else {"kind": "protocol"}, upload)
    if answer["type"] == "closed":
        bound = ours(answer) and answer["handler"] == handler and answer["request_sha256"] == digest
        if not bound or answer["outcome"] == "recorded":
            return Run({"kind": "protocol"}, upload)
        return Run(_closed(answer), upload)
    ready = answer

    async def cancel(terminal):
        now = clock.now()
        # The cancel is this side's answer to an abort: no signal of its own.
        if now < until_ns:
            await exchange(dict(head, type="cancel"), until_ns, now + CONTROL_NS, seams)
        return terminal

    if (not ours(ready) or ready["handler"] != handler or ready["operation"] != lane.submission["operation"]
            or ready["request_sha256"] != digest or not lane.accept(ready)):
        return Run(await cancel({"kind": "protocol"}), upload)

    # The application: aborted by the caller's signal or the original cutoff, always awaited.
    internal = Abort()
    if signal is not None:
        signal.add_listener(internal.abort)
    stop_wake = clock.wake(until_ns, internal.abort)
    if aborted() or clock.now() >= until_ns:
        internal.abort()
    try:
        outcome = await lane.apply(ready, internal)
    except Exception:
        outcome = UNKNOWN
    stop_wake()
    if signal is not None:
        signal.remove_listener(internal.abort)
    if aborted():
        return Run(await cancel({"kind": "cancelled"}), upload, ready, outcome)
    now = clock.now()
    if now >= until_ns:
        return Run({"kind": "expired"}, upload, ready, outcome)

    status = "applied" if outcome is not UNKNOWN and lane.applied(outcome) else "failed"
    result = dict(head, type="result", request=ready["request"], request_sha256=ready["request_sha256"],
                  sha256=ready["sha256"], status=status)
    resulted = await exchange(result, until_ns, now + CONTROL_NS, seams, signal)
    # An abort before any result byte left: the cancel is then the one terminal action.
    if resulted["kind"] == "aborted" and not resulted["sent"]:
        return Run(await cancel({"kind": "cancelled"}), upload, ready, outcome)
    if resulted["kind"] != "response":
        return Run(_failed(resulted, True), upload, ready, outcome)
    end = resulted["response"]
    if end["type"] == "error":
        return Run({"kind": "error", "code": end["code"]}, upload, ready, outcome)
    bound = (end["type"] == "closed" and ours(end) and end["handler"] == handler and end["request"] == ready["request"]
             and end["request_sha256"] == ready["request_sha256"])
    if not bound:
        return Run({"kind": "protocol"}, upload, ready, outcome)
    terminal = {"kind": "recorded", "status": status} if end["outcome"] == "recorded" else _closed(end)
    return Run(terminal, upload, ready, outcome)


def _failed(result, resulting=False):
    """An exchange that brought no response. A lost result was sent once and is never repeated."""
    kind = result["kind"]
    if kind == "malformed":
        return {"kind": "protocol"}
    if kind == "aborted":
        return {"kind": "cancelled"}
    if kind == "lost":
        return {"kind": "lost"} if result["sent"] or resulting else {"kind": "unavailable"}
    return {"kind": kind}


def _closed(response):
    terminal = {"kind": "closed", "request": response["request"], "outcome": response["outcome"]}
    if "reason" in response:
        terminal["reason"] = response["reason"]
    return terminal
