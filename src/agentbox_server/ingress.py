"""The host side of the artifact POST, transport only: one execution's
bounded ingress, to which the broker's POST connections submit decoded
bodies, and its inbox, which the server's command loop drains and answers.
Every caller runs on the broker's loop; latches need no locks.

Slots: one submit exchange and one control exchange; no queue, no retry.
Binding: one execution, its original cutoff (if any) and one armed session
nonce. Ledger: one execution ledger of control messages and body bytes,
both directions, bounded from the request grant; a body that does not fit
ends the ingress (`limit`). Cancellation: a submit's request has one
irreversible latch; the ingress's end cancels every request at once.
Ordering: the loop sees every end of an exchange it has seen before any
further request, and no request while a response's write is unknown.
"""
from . import codec

REQUEST_TIMEOUT = 1800.0
EXCHANGE_CEILING = REQUEST_TIMEOUT
WRITE_TIMEOUT = 10.0
UPLOAD_CEILING = 60.0
MAX_REQUESTS = 256
REQUEST_MESSAGES = 4
SLACK_MESSAGES = 64
MAX_MESSAGES = REQUEST_MESSAGES * MAX_REQUESTS + SLACK_MESSAGES
MAX_TERMINAL_BYTES = 1024
CREDIT = codec.MAX_BODY_BYTES
MAX_METADATA_BYTES = codec.MAX_BODY_BYTES - codec.MAX_READY_OVERHEAD_BYTES
MAX_READY_BYTES = MAX_METADATA_BYTES + codec.MAX_READY_OVERHEAD_BYTES
REQUEST_BYTES = CREDIT + MAX_READY_BYTES + 2 * MAX_TERMINAL_BYTES
MAX_EXCHANGES = 2
MAX_CONTROL_BYTES = MAX_REQUESTS * REQUEST_BYTES + MAX_EXCHANGES * 3 * CREDIT + SLACK_MESSAGES * CREDIT
SUBMIT, CONTROL = 0, 1


class Cancellation:
    """One request's irreversible latch, or its ingress's end."""

    def __init__(self, ingress):
        self.ingress = ingress
        self.own = False

    def cancel(self):
        self.own = True

    def is_cancelled(self):
        return self.own or self.ingress.closure is not None


class Ledger:
    def __init__(self):
        self.messages = self.bytes = self.held_messages = self.held_bytes = 0

    def room(self, messages, size):
        return (self.messages + self.held_messages + messages <= MAX_MESSAGES
                and self.bytes + self.held_bytes + size <= MAX_CONTROL_BYTES)

    def charge(self, size):
        self.messages += 1
        self.bytes += size

    def hold(self, messages, size):
        self.held_messages += messages
        self.held_bytes += size

    def release(self, messages, size):
        self.held_messages = max(0, self.held_messages - messages)
        self.held_bytes = max(0, self.held_bytes - size)


class Exchange:
    def __init__(self, ident, kind, replay, request, length, admitted_at, cancel, deadline):
        self.id, self.kind, self.replay, self.request = ident, kind, replay, request
        self.received = length
        self.admitted_at = admitted_at
        self.polled = False
        self.cancel = cancel
        self.wake = False
        self.deadline = deadline
        self.held = True
        self.responded = False
        self.response = None
        self.delivers = None
        self.end = None
        self.reported = False
        self.worker = True

    def registers(self):
        return self.kind == "submit" and not self.replay


class Client:
    def __init__(self, name, cancel):
        self.name, self.cancel, self.terminal = name, cancel, True


class Ingress:
    """One execution's POST ingress and its inbox (`poll`, `respond`,
    `activate`, `close`)."""

    def __init__(self, now, cutoff):
        self.cutoff = cutoff
        self.closure = None
        self.closure_reported = False
        self.session = None
        self.permits = 0
        self.slots = [None, None]
        self.next = 1
        self.ledger = Ledger()
        self.clients = []
        self.active = None

    # The broker's side.

    def ended(self):
        return self.closure is not None

    def clip(self, at):
        return at if self.cutoff is None else min(at, self.cutoff)

    def past(self, now):
        return self.cutoff is not None and now >= self.cutoff

    def bound(self, now):
        return self.clip(now + EXCHANGE_CEILING)

    def end(self, closure):
        if self.closure is None:
            self.closure = closure

    def stop(self):
        self.end("stopped")

    def arm(self, session):
        if not codec.is_session(session) or self.session is not None:
            raise ValueError("arm")
        self.session = session

    def permit(self):
        """A POST connection's permit: None, or the refusal code."""
        if self.closure is not None or self.session is None:
            return "post_closed"
        if self.permits >= MAX_EXCHANGES:
            return "post_capacity"
        self.permits += 1
        return None

    def release_permit(self):
        self.permits -= 1

    def _slot(self, ident):
        for at, exchange in enumerate(self.slots):
            if exchange is not None and exchange.id == ident:
                return at, exchange
        return None, None

    def _release_terminal(self, client):
        for entry in self.clients:
            if entry.name == client and entry.terminal:
                entry.terminal = False
                self.ledger.release(2, 2 * CREDIT)

    def _answer(self, code, length, until):
        body = codec.encode_response({"type": "error", "code": code})
        if not self.ledger.room(2, length + len(body)):
            self.end("limit")
            return ("refused", "post_closed")
        self.ledger.charge(length)
        self.ledger.charge(len(body))
        return ("answer", codec.fault_status(code), body, until)

    def admit(self, body, now):
        """A complete body, once: ("answer", status, body, until),
        ("refused", code) or ("dispatched", exchange id)."""
        if self.closure is not None or self.past(now):
            return ("refused", "post_closed")
        until = self.bound(now)
        try:
            request = codec.decode_request(body)
        except codec.CodecError as error:
            request, fault = None, error.code
        if self.session is None:
            return ("refused", "post_closed")
        length = len(body)
        if request is None:
            return self._answer(fault, length, until)
        if request["session"] != self.session:
            return self._answer("session_mismatch", length, until)
        client = request["client"]
        named = next((at for at, entry in enumerate(self.clients) if entry.name == client), None)
        kind = request["type"]
        replay = kind == "submit" and named is not None
        if kind == "submit" and self.slots[SUBMIT] is None:
            at = SUBMIT
        elif self.slots[CONTROL] is None:
            at = CONTROL
        else:
            if not self.ledger.room(1, length):
                self.end("limit")
                return ("refused", "post_closed")
            self.ledger.charge(length)
            return ("refused", "post_capacity")
        inherits = kind in ("cancel", "result") and named is not None and self.clients[named].terminal
        registers = kind == "submit" and not replay
        if registers:
            fits = self.ledger.room(4, length + 3 * CREDIT)
        else:
            fits = inherits or self.ledger.room(2, length + CREDIT)
        if not fits:
            self.end("limit")
            return ("refused", "post_closed")
        if inherits:
            self.clients[named].terminal = False
            self.ledger.release(2, 2 * CREDIT)
        self.ledger.charge(length)
        self.ledger.hold(1, CREDIT)
        cancel = Cancellation(self)
        if registers:
            self.ledger.hold(2, 2 * CREDIT)
            self.clients.append(Client(client, cancel))
        bound = None if kind == "submit" or named is None else self.clients[named].cancel
        ident = self.next
        self.next += 1
        exchange = Exchange(ident, kind, replay, request, length, now, cancel, until)
        exchange.bound = bound
        self.slots[at] = exchange
        return ("dispatched", ident)

    def exchange(self, ident):
        return self._slot(ident)[1]

    def next_step(self, ident):
        """A waiting connection's next step: ("closed",), ("wait",
        deadline) or ("respond", status, body, until)."""
        if self.closure is not None:
            return ("closed",)
        _, exchange = self._slot(ident)
        if exchange is None:
            return ("closed",)
        exchange.wake = False
        if exchange.response is not None:
            status, body = exchange.response
            exchange.response = None
            return ("respond", status, body, exchange.deadline)
        return ("wait", exchange.deadline)

    def finish(self, ident, end):
        """The exchange's HTTP side ended with `end`; all but `written`
        cancel its request (and a cancel's or result's named one)."""
        _, exchange = self._slot(ident)
        if end != "written" and exchange is not None:
            exchange.cancel.cancel()
            if exchange.bound is not None:
                exchange.bound.cancel()
        at, exchange = self._slot(ident)
        if exchange is None:
            return end
        exchange.worker = False
        if exchange.end is None:
            exchange.end = end
        delivers = exchange.delivers if end == "written" else None
        active = self.active["exchange"] if self.active is not None else None
        unanswered, exchange.held = exchange.held, False
        terminal = exchange.registers() and not exchange.responded and active != ident
        client = exchange.request["client"]
        if unanswered:
            self.ledger.release(1, CREDIT)
        if terminal:
            self._release_terminal(client)
        if delivers is not None and self.active is not None and self.active["exchange"] == ident:
            self.active["delivered"] = delivers
        if exchange.reported:
            self.slots[at] = None
        return end

    # The command loop's side.

    def _oldest(self, pick):
        candidates = [at for at in range(MAX_EXCHANGES)
                      if self.slots[at] is not None and pick(self.slots[at])]
        return min(candidates, key=lambda at: self.slots[at].id) if candidates else None

    def poll(self):
        """The next event, in order: ("request", id, request, replay, bytes,
        admitted_at), ("ended", id, end) or ("closed", closure); None."""
        at = self._oldest(lambda e: e.polled and e.end is not None and not e.reported)
        if at is not None:
            exchange = self.slots[at]
            exchange.reported = True
            event = ("ended", exchange.id, exchange.end)
            if not exchange.worker:
                self.slots[at] = None
            return event
        if self.closure is not None:
            if self.closure_reported:
                return None
            self.closure_reported = True
            return ("closed", self.closure)
        if any(e is not None and e.responded and e.end is None for e in self.slots):
            return None
        at = self._oldest(lambda e: not e.polled)
        if at is None:
            return None
        exchange = self.slots[at]
        if exchange.received is None:
            return None
        received, exchange.received = exchange.received, None
        exchange.polled = True
        return ("request", exchange.id, exchange.request, exchange.replay, received, exchange.admitted_at)

    def respond(self, ident, response):
        """Answers a seen, waiting exchange once; None or `stale`,
        `mismatch`, `response_invalid`."""
        try:
            body = codec.encode_response(response)
        except codec.CodecError:
            return "response_invalid"
        _, waiting = self._slot(ident)
        if waiting is None or not waiting.polled or waiting.responded or waiting.end is not None:
            return "stale"
        active = self.active["exchange"] if self.active is not None else None
        if not _answers(waiting.request, self.session or "", response, active == ident):
            return "mismatch"
        ready = None
        if response["type"] == "ready":
            ready = (response["request"], response["request_sha256"], response["sha256"])
        terminal = waiting.registers() and ready is None
        client = waiting.request["client"]
        waiting.responded = True
        waiting.held = False
        waiting.delivers = ready
        waiting.response = (codec.response_status(response), body)
        waiting.wake = True
        self.ledger.release(1, CREDIT)
        self.ledger.charge(len(body))
        if terminal:
            self._release_terminal(client)
        return None

    def activate(self, ident, deadline):
        """Makes a seen, waiting, non-replay submit the one active request:
        (token, cancellation) or an error code."""
        if self.closure is not None:
            return "closed"
        if self.active is not None:
            return "busy"
        token = self.next
        _, waiting = self._slot(ident)
        if waiting is None:
            return "stale"
        if waiting.kind == "submit" and waiting.replay:
            return "replay"
        if waiting.kind != "submit" or not waiting.polled or waiting.responded or waiting.end is not None:
            return "stale"
        if waiting.cancel.is_cancelled():
            return "cancelled"
        waiting.deadline = min(waiting.deadline, deadline)
        waiting.wake = True
        self.next += 1
        self.active = {"token": token, "exchange": ident, "delivered": None,
                       "client": waiting.request["client"], "cancel": waiting.cancel}
        return (token, waiting.cancel)

    def retire(self, token):
        """Drops the active request `token`: its latch set, its unused
        terminal credits released."""
        if self.active is not None and self.active["token"] == token:
            self.active["cancel"].cancel()
            client = self.active["client"]
            self.active = None
            self._release_terminal(client)

    def close(self):
        self.stop()


def _answers(request, session, response, active):
    """Whether `response` answers `request` of `session`; a `ready` only
    for the active request's own submit."""
    kind = response["type"]
    if kind == "error":
        return True

    def same():
        return response["session"] == session and response["client"] == request["client"]

    if request["type"] == "submit":
        digest = codec.request_sha256(request["client"], request["handler"], request["operation"], request["args"])
        if kind == "rejected":
            return same()
        if kind == "ready":
            return (active and same() and response["handler"] == request["handler"]
                    and response["operation"] == request["operation"] and response["request_sha256"] == digest)
        if kind == "closed":
            return same() and response["handler"] == request["handler"] and response["request_sha256"] == digest
        return False
    if request["type"] == "cancel":
        return kind == "closed" and same()
    return (kind == "closed" and same() and response["request"] == request["request"]
            and response["request_sha256"] == request["request_sha256"])
