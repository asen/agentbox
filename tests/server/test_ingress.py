"""The artifact POST ingress and inbox (agentbox_server/ingress.py), in
memory with explicit instants: no socket, thread or clock. Every admitted
body and every answer is charged. The timing profile
(acquisitions/contracts/artifacts/v1/timing.json) is checked here too.

  python3 -I -B -m unittest discover -s tests/server -t . -p test_ingress.py
"""
import json
import os
import unittest

from tests import support
from agentbox_controller import acquisition, handlers
from agentbox_server import broker, codec, ingress
from agentbox_server.ingress import CREDIT, MAX_CONTROL_BYTES, MAX_MESSAGES, Ingress

SESSION = "0123456789abcdef0123456789abcdef"
OTHER = "fedcba9876543210fedcba9876543210"
ARTIFACT_SHA = "ab" * 32
T0 = 1000.0
CUTOFF = T0 + 3600.0
ARGS = {"text": "a1"}


def digest(client):
    return codec.request_sha256(client, "echo", "say", ARGS)


def submit(client, session=SESSION, handler="echo", operation="say", args=None):
    return codec.encode_request({"type": "submit", "session": session, "client": client, "handler": handler,
                                 "operation": operation, "args": ARGS if args is None else args})


def cancel(client, session=SESSION):
    return codec.encode_request({"type": "cancel", "session": session, "client": client})


def result(client, request="req-1"):
    return codec.encode_request({"type": "result", "session": SESSION, "client": client, "request": request,
                                 "request_sha256": digest(client), "sha256": ARTIFACT_SHA, "status": "applied"})


def ready(client):
    return {"type": "ready", "session": SESSION, "client": client, "request": "req-1",
            "request_sha256": digest(client), "handler": "echo", "operation": "say", "size": 3,
            "sha256": ARTIFACT_SHA, "metadata": {}}


def rejected(client, session=SESSION):
    return {"type": "rejected", "session": session, "client": client, "code": "busy"}


def closed(client, outcome, request="req-1"):
    response = {"type": "closed", "session": SESSION, "client": client, "request": request,
                "request_sha256": digest(client), "handler": "echo", "outcome": outcome}
    if outcome == "denied":
        response["reason"] = "worker_failed"
    return response


def ledger(post):
    held = post.ledger
    return (held.messages, held.bytes, held.held_messages, held.held_bytes)


class Base(unittest.TestCase):

    def armed(self, cutoff=CUTOFF):
        post = Ingress(T0, cutoff)
        post.arm(SESSION)
        return post

    def admit(self, post, body, now=T0):
        """A permit, then one body: the admission."""
        self.assertIsNone(post.permit())
        try:
            return post.admit(body, now)
        finally:
            post.release_permit()

    def dispatch(self, post, body, now=T0):
        admission = self.admit(post, body, now)
        self.assertEqual(admission[0], "dispatched", admission)
        return admission[1]

    def seen(self, post):
        event = post.poll()
        self.assertEqual(event[0], "request", event)
        return event[1], event[3]

    def active(self, post, client):
        """A seen, activated submit: (exchange, token, cancellation)."""
        exchange = self.dispatch(post, submit(client))
        self.assertEqual(self.seen(post), (exchange, False))
        token, latch = post.activate(exchange, CUTOFF)
        return exchange, token, latch

    def write(self, post, exchange):
        """The worker takes its response: (status, body)."""
        step = post.next_step(exchange)
        self.assertEqual(step[0], "respond", step)
        return step[1], step[2]

    def answered(self, admission):
        self.assertEqual(admission[0], "answer", admission)
        return len(admission[2]), admission[1], codec.decode_response(admission[2])


class Bounds(Base):

    def test_the_timing_profile_is_the_contract(self):
        """The server, lane and handler ceilings match the shared timing profile."""
        contracts = os.path.join(support.REPO, "acquisitions", "contracts")
        with open(os.path.join(contracts, "artifacts", "v1", "timing.json")) as stream:
            spec = json.load(stream)
        self.assertEqual((spec["schema"], spec["profiles"]), ("agentbox.artifact.timing.v1", ["agentbox.handlers.v1"]))
        for name, seconds in (("acquisition_timeout_ms", handlers.CEILINGS["acquisition_seconds"]),
                              ("upload_timeout_ms", ingress.UPLOAD_CEILING),
                              ("request_timeout_ms", ingress.REQUEST_TIMEOUT),
                              ("request_timeout_ms", acquisition.REQUEST_TIMEOUT),
                              ("control_write_timeout_ms", ingress.WRITE_TIMEOUT),
                              ("cleanup_reserve_ms", broker.RECORD_WAIT)):
            self.assertEqual(spec[name], int(seconds * 1000), name)
        self.assertEqual((spec["acquisition_timeout_ms"], spec["upload_timeout_ms"], spec["request_timeout_ms"],
                          spec["cleanup_reserve_ms"]), (600000, 60000, 1800000, 250))
        # The handler contract's acquisition ceiling is this one.
        with open(os.path.join(contracts, "handlers", "v1", "contract.json")) as stream:
            ceilings = json.load(stream)["limits"]["ceilings"]
        self.assertEqual(ceilings["acquisition_seconds"] * 1000, spec["acquisition_timeout_ms"])

    def test_bounds_derive_from_the_request_grant(self):
        self.assertEqual(MAX_MESSAGES, 4 * ingress.MAX_REQUESTS + 64)
        self.assertEqual(MAX_MESSAGES, 1088)
        self.assertEqual(ingress.MAX_READY_BYTES, 63488 + 2048)
        self.assertEqual(ingress.MAX_READY_BYTES, CREDIT)
        self.assertEqual(ingress.REQUEST_BYTES, 65536 + 65536 + 2 * 1024)
        self.assertEqual(MAX_CONTROL_BYTES, 256 * ingress.REQUEST_BYTES + 2 * 3 * CREDIT + 64 * CREDIT)
        self.assertEqual((ingress.WRITE_TIMEOUT, ingress.MAX_EXCHANGES), (10.0, 2))
        self.assertEqual(CREDIT, codec.MAX_BODY_BYTES)

    def test_the_whole_grant_at_its_largest_fits_the_ledger(self):
        held = ingress.Ledger()
        for _ in range(ingress.MAX_REQUESTS):
            self.assertTrue(held.room(4, CREDIT + 3 * CREDIT))
            held.charge(CREDIT)
            held.hold(3, 3 * CREDIT)
            self.assertTrue(held.room(4, CREDIT + 3 * CREDIT))
            held.release(3, 3 * CREDIT)
            held.charge(ingress.MAX_READY_BYTES)
            held.charge(ingress.MAX_TERMINAL_BYTES)
            held.charge(ingress.MAX_TERMINAL_BYTES)
        self.assertEqual(held.messages, 4 * ingress.MAX_REQUESTS)
        self.assertLessEqual(held.bytes, MAX_CONTROL_BYTES)
        self.assertTrue(held.room(ingress.SLACK_MESSAGES, ingress.SLACK_MESSAGES * CREDIT))


class Admission(Base):

    def test_permits_are_bounded_and_released(self):
        post = self.armed()
        self.assertEqual((post.permit(), post.permit(), post.permit()), (None, None, "post_capacity"))
        post.release_permit()
        self.assertIsNone(post.permit())
        post.release_permit()
        post.release_permit()
        self.assertEqual(post.permits, 0)
        post.stop()
        self.assertEqual(post.permit(), "post_closed")

    def test_arming_is_once_and_exact(self):
        post = Ingress(T0, CUTOFF)
        for bad in ("", SESSION[:-1], SESSION + "0", "0123456789ABCDEF0123456789abcdef", SESSION[:-1] + "g"):
            with self.assertRaises(ValueError):
                post.arm(bad)
        post.arm(SESSION)
        for again in (SESSION, OTHER):
            with self.assertRaises(ValueError):
                post.arm(again)

    def test_an_unarmed_ingress_admits_nothing_and_a_foreign_session_is_charged(self):
        post = Ingress(T0, CUTOFF)
        self.assertEqual(post.permit(), "post_closed")
        self.assertEqual(ledger(post), (0, 0, 0, 0))
        post.arm(SESSION)
        expected = [0, 0]
        for body in (submit("c1", session=OTHER), cancel("c1", session=OTHER)):
            length, status, response = self.answered(self.admit(post, body))
            self.assertEqual((status, response), (403, {"type": "error", "code": "session_mismatch"}))
            expected[0] += 2
            expected[1] += len(body) + length
            self.assertEqual(ledger(post), (expected[0], expected[1], 0, 0))
        self.assertIsNone(post.poll())
        self.dispatch(post, submit("c1"))
        self.assertEqual(self.seen(post)[1], False, "a refused submit records no client")

    def test_codec_errors_are_answered_and_charged_at_actual_sizes(self):
        post = self.armed()
        canonical = submit("c1")
        expected = [0, 0]
        for body in (b"{}", b"[]", b"", canonical[:1] + b" " + canonical[1:], b" " + canonical,
                     b"\xef\xbb\xbf" + canonical, b"x" * codec.MAX_BODY_BYTES):
            length, status, response = self.answered(self.admit(post, body))
            self.assertEqual((status, response["type"]), (400, "error"), body[:20])
            expected[0] += 2
            expected[1] += len(body) + length
            self.assertEqual(ledger(post), (expected[0], expected[1], 0, 0))
        self.assertIsNone(post.poll())

    def test_refusals_before_admission_charge_nothing(self):
        # Past the cutoff, even a malformed body: nothing charged.
        post = self.armed()
        for body in (b"{}", submit("c1")):
            self.assertEqual(self.admit(post, body, CUTOFF), ("refused", "post_closed"))
        self.assertEqual(ledger(post), (0, 0, 0, 0))
        # Both slots taken: a third body is charged alone, nothing held.
        post = self.armed()
        self.dispatch(post, submit("c1"))
        self.dispatch(post, cancel("c1"))
        before = ledger(post)
        body = cancel("c2")
        self.assertEqual(self.admit(post, body), ("refused", "post_capacity"))
        self.assertEqual(ledger(post), (before[0] + 1, before[1] + len(body), before[2], before[3]))

    def test_a_submit_is_charged_once_with_its_holds(self):
        post = self.armed()
        body = submit("c1")
        exchange = self.dispatch(post, body)
        self.assertEqual(ledger(post), (1, len(body), 3, 3 * CREDIT))
        event = post.poll()
        self.assertEqual((event[0], event[2], event[3], event[4], event[5]),
                         ("request", codec.decode_request(body), False, len(body), T0))
        self.assertIsNone(post.poll(), "no event twice")
        # Its own ceiling from admission, within the execution's cutoff.
        self.assertEqual(post.next_step(exchange), ("wait", T0 + ingress.EXCHANGE_CEILING))

    def test_every_admitted_body_is_charged_once_whatever_follows(self):
        post = self.armed()
        body = submit("c0", handler="pip", operation="files", args={"projects": ["example"]})
        exchange = self.dispatch(post, body)
        self.assertEqual(ledger(post), (1, len(body), 3, 3 * CREDIT))
        self.assertEqual(self.seen(post), (exchange, False))
        self.assertIsNone(post.respond(exchange, rejected("c0")))
        _, written = self.write(post, exchange)
        self.assertEqual(ledger(post)[:2], (2, len(body) + len(written)))
        post.finish(exchange, "written")
        post.poll()
        self.assertEqual(ledger(post)[2:], (0, 0))

    def test_a_cancel_or_result_never_takes_the_submit_slot(self):
        post = self.armed()
        self.dispatch(post, cancel("c1"))
        for body in (cancel("c2"), result("c2")):
            self.assertEqual(self.admit(post, body), ("refused", "post_capacity"))
        self.dispatch(post, submit("c3"))

    def test_a_busy_submit_takes_the_control_slot_and_nothing_queues(self):
        post = self.armed()
        _, _, latch = self.active(post, "c1")
        busy = self.dispatch(post, submit("c2"))
        self.assertEqual(self.seen(post), (busy, False))
        self.assertEqual(post.activate(busy, CUTOFF), "busy")
        before = list(ledger(post))
        for body in (submit("c3"), cancel("c1"), result("c1")):
            self.assertEqual(self.admit(post, body), ("refused", "post_capacity"))
            before[0] += 1
            before[1] += len(body)
            self.assertEqual(list(ledger(post)), before)
        self.assertIsNone(post.respond(busy, rejected("c2")))
        status, body = self.write(post, busy)
        self.assertEqual(status, 200)
        self.assertEqual(ledger(post), (before[0] + 1, before[1] + len(body), before[2] - 3, before[3] - 3 * CREDIT))
        self.assertEqual(post.finish(busy, "written"), "written")
        self.assertEqual(post.poll(), ("ended", busy, "written"))
        # The control slot is free again; the submit slot is not.
        self.dispatch(post, cancel("c1"))
        self.assertEqual(self.admit(post, cancel("c1")), ("refused", "post_capacity"))
        self.assertFalse(latch.is_cancelled())

    def test_a_replayed_client_is_marked_and_never_activated(self):
        post = self.armed()
        first = self.dispatch(post, submit("c1"))
        self.seen(post)
        self.assertIsNone(post.respond(first, closed("c1", "denied")))
        self.write(post, first)
        post.finish(first, "written")
        self.assertIsNotNone(post.poll())
        spent = ledger(post)
        body = submit("c1")
        replayed = self.dispatch(post, body)
        self.assertEqual(self.seen(post), (replayed, True))
        # Only its response credit is held: no terminal credits.
        self.assertEqual(ledger(post), (spent[0] + 1, spent[1] + len(body), spent[2] + 1, spent[3] + CREDIT))
        self.assertEqual(post.activate(replayed, CUTOFF), "replay")
        self.assertEqual(post.respond(replayed, ready("c1")), "mismatch")
        self.assertIsNone(post.respond(replayed, rejected("c1")))
        self.write(post, replayed)
        self.assertEqual(ledger(post)[2], spent[2])

    def test_responses_must_answer_their_request(self):
        post = self.armed()
        waiting = self.dispatch(post, submit("c1"))
        self.assertEqual(post.respond(waiting, rejected("c1")), "stale", "unseen")
        self.assertEqual(self.seen(post), (waiting, False))
        wrong_digest = dict(closed("c1", "denied"), request_sha256=digest("c2"))
        wrong_handler = dict(closed("c1", "denied"), handler="pip")
        for response in (rejected("c2"), rejected("c1", session=OTHER), ready("c1"), wrong_digest, wrong_handler):
            self.assertEqual(post.respond(waiting, response), "mismatch", response)
        self.assertEqual(ledger(post)[0], 1, "nothing charged")
        error = {"type": "error", "code": "not_active"}
        self.assertIsNone(post.respond(waiting, error))
        self.assertEqual(post.respond(waiting, error), "stale")
        self.assertEqual(self.write(post, waiting)[0], 409)
        # A result's closed names its own request and digest.
        post = self.armed()
        waiting = self.dispatch(post, result("c1"))
        self.seen(post)
        self.assertEqual(post.respond(waiting, closed("c1", "recorded", request="req-2")), "mismatch")
        self.assertEqual(post.respond(waiting, rejected("c1")), "mismatch")
        self.assertIsNone(post.respond(waiting, closed("c1", "recorded")))


class Ledger(Base):

    def fits(self, seeded, body):
        """`body` admitted against a seeded ledger: whether it fit (charged
        once), else the ingress ended (`limit`), nothing charged."""
        post = self.armed()
        post.ledger.messages, post.ledger.bytes = seeded
        admission = self.admit(post, body)
        if admission == ("refused", "post_closed"):
            self.assertEqual(post.poll(), ("closed", "limit"))
            self.assertEqual(post.permit(), "post_closed")
            self.assertEqual(ledger(post)[:2], seeded, "not charged")
            return False
        answer = len(admission[2]) if admission[0] == "answer" else 0
        self.assertEqual(post.ledger.bytes, seeded[1] + len(body) + answer)
        return True

    def test_the_ledger_charges_actual_sizes_and_ends_past_its_bounds(self):
        for body, holds in ((submit("c1"), 3), (cancel("c9"), 1)):
            exact = MAX_CONTROL_BYTES - len(body) - holds * CREDIT
            self.assertEqual((self.fits((0, exact), body), self.fits((0, exact + 1), body)), (True, False))
        self.assertEqual((self.fits((MAX_MESSAGES - 4, 0), submit("c1")),
                          self.fits((MAX_MESSAGES - 3, 0), submit("c1"))), (True, False))
        post = self.armed()
        code = codec.decode_response(self.admit(post, b"{}")[2])["code"]
        answer = codec.encode_response({"type": "error", "code": code})
        exact = MAX_CONTROL_BYTES - (2 + len(answer))
        self.assertEqual((self.fits((0, exact), b"{}"), self.fits((0, exact + 1), b"{}")), (True, False))
        self.assertEqual((self.fits((MAX_MESSAGES - 2, 0), b"{}"), self.fits((MAX_MESSAGES - 1, 0), b"{}")),
                         (True, False))

    def test_terminal_credits_keep_the_result_room_and_end_the_ingress_otherwise(self):
        post = self.armed()
        exchange, token, _ = self.active(post, "c1")
        self.assertIsNone(post.respond(exchange, ready("c1")))
        self.write(post, exchange)
        post.finish(exchange, "written")
        post.poll()
        self.assertEqual(ledger(post)[2:], (2, 2 * CREDIT))
        spent = (MAX_MESSAGES - 2, MAX_CONTROL_BYTES - 2 * CREDIT)
        post.ledger.messages, post.ledger.bytes = spent
        # An unrelated request no longer fits and ends its ingress...
        other = self.armed()
        other.ledger.messages, other.ledger.bytes = spent
        other.ledger.held_messages, other.ledger.held_bytes = 2, 2 * CREDIT
        self.assertEqual(self.admit(other, cancel("c9")), ("refused", "post_closed"))
        # ...while the active request's result still does, and its answer.
        body = result("c1")
        claim = self.dispatch(post, body)
        self.seen(post)
        self.assertIsNone(post.respond(claim, closed("c1", "recorded")))
        _, answer = self.write(post, claim)
        self.assertEqual(ledger(post), (MAX_MESSAGES, spent[1] + len(body) + len(answer), 0, 0))
        post.finish(claim, "written")
        before = ledger(post)
        post.retire(token)
        self.assertEqual(ledger(post), before, "retiring releases and refunds nothing more")

    def test_retiring_releases_only_unused_terminal_credits(self):
        post = self.armed()
        exchange, token, _ = self.active(post, "c1")
        self.assertIsNone(post.respond(exchange, ready("c1")))
        self.write(post, exchange)
        post.finish(exchange, "written")
        before = ledger(post)
        post.retire(token)
        self.assertEqual(ledger(post), (before[0], before[1], before[2] - 2, before[3] - 2 * CREDIT))
        self.assertIsNone(post.active)

    def test_an_unanswered_submit_releases_its_holds_and_keeps_its_charge(self):
        post = self.armed()
        body = submit("c1")
        exchange = self.dispatch(post, body)
        self.seen(post)
        post.finish(exchange, "peer_eof")
        self.assertEqual(ledger(post), (1, len(body), 0, 0))

    def test_the_first_end_wins(self):
        post = self.armed()
        post.ledger.messages = MAX_MESSAGES
        self.assertEqual(self.admit(post, submit("c1")), ("refused", "post_closed"))
        post.stop()
        self.assertEqual((post.poll(), post.poll()), (("closed", "limit"), None))
        post = self.armed()
        self.assertIsNone(post.permit())
        post.stop()
        post.ledger.messages = MAX_MESSAGES
        self.assertEqual(post.admit(submit("c1"), T0), ("refused", "post_closed"))
        self.assertEqual(post.poll(), ("closed", "stopped"))


class Revocation(Base):
    """Acquisition's revocation: peer loss, failed writes, a control
    exchange's loss, retirement; each cancellation irreversible."""

    def test_peer_loss_before_the_response_cancels_the_request(self):
        for end in ("peer_eof", "peer_reset", "extra_input", "exchange_expired"):
            post = self.armed()
            exchange, token, latch = self.active(post, "c1")
            self.assertEqual(post.finish(exchange, end), end)
            self.assertTrue(latch.is_cancelled())
            self.assertEqual(post.poll(), ("ended", exchange, end))
            self.assertEqual(post.respond(exchange, ready("c1")), "stale")
            # The active request stays the loop's until it retires it, and
            # its latch never clears.
            self.assertIsNotNone(post.active)
            post.retire(token)
            self.assertTrue(latch.is_cancelled())
            self.assertIsNone(post.active)

    def test_a_failed_write_cancels_even_after_the_response_began(self):
        for end in ("write_failed", "write_timeout", "post_stopped"):
            post = self.armed()
            exchange, _, latch = self.active(post, "c1")
            self.assertIsNone(post.respond(exchange, ready("c1")))
            self.write(post, exchange)
            post.finish(exchange, end)
            self.assertTrue(latch.is_cancelled())
            self.assertIsNone(post.active["delivered"], "never delivered")
            self.assertEqual(post.poll(), ("ended", exchange, end))

    def test_a_control_exchange_loss_cancels_the_request_it_names(self):
        post = self.armed()
        _, _, latch = self.active(post, "c1")
        lost = self.dispatch(post, cancel("c1"))
        self.seen(post)
        self.assertFalse(latch.is_cancelled())
        post.finish(lost, "peer_reset")
        self.assertTrue(latch.is_cancelled())
        # A cancel naming another client cancels nothing of this request.
        post = self.armed()
        _, _, latch = self.active(post, "c1")
        other = self.dispatch(post, cancel("c9"))
        post.finish(other, "peer_eof")
        self.assertFalse(latch.is_cancelled())
        # The loop's own cancellation latches the same way, for good.
        latch.cancel()
        self.assertTrue(latch.is_cancelled())

    def test_a_written_ready_frees_the_exchange_not_the_request(self):
        post = self.armed()
        exchange, _, latch = self.active(post, "c1")
        self.assertIsNone(post.respond(exchange, ready("c1")))
        self.assertIsNone(post.active["delivered"], "not before its write")
        status, body = self.write(post, exchange)
        self.assertEqual((status, codec.decode_response(body)), (200, ready("c1")))
        self.assertIsNone(post.active["delivered"], "not while written")
        self.assertEqual(post.finish(exchange, "written"), "written")
        self.assertFalse(latch.is_cancelled())
        self.assertEqual(post.active["delivered"], ("req-1", digest("c1"), ARTIFACT_SHA))
        self.assertEqual(post.poll(), ("ended", exchange, "written"))
        self.assertEqual(post.slots, [None, None])
        self.assertIsNotNone(post.active, "the application phase goes on")
        self.assertEqual(ledger(post)[2:], (2, 2 * CREDIT), "its result's credits")
        self.dispatch(post, submit("c2"))
        self.assertFalse(latch.is_cancelled())

    def test_a_result_right_after_ready_waits_for_its_write(self):
        post = self.armed()
        exchange, _, _ = self.active(post, "c1")
        self.assertIsNone(post.respond(exchange, ready("c1")))
        held = ledger(post)
        body = result("c1")
        self.dispatch(post, body)
        # The result takes over the terminal credits: no new hold.
        self.assertEqual(ledger(post), (held[0] + 1, held[1] + len(body), held[2] - 1, held[3] - CREDIT))
        self.assertIsNone(post.poll(), "held while the ready's write is unknown")
        self.write(post, exchange)
        self.assertIsNone(post.poll(), "held while written")
        post.finish(exchange, "written")
        self.assertEqual(post.poll(), ("ended", exchange, "written"), "the write's end first")
        self.assertIsNotNone(post.active["delivered"])
        claim, _ = self.seen(post)
        self.assertIsNone(post.respond(claim, closed("c1", "recorded")))

    def test_a_result_after_a_failed_ready_write_sees_the_loss_first(self):
        post = self.armed()
        exchange, _, latch = self.active(post, "c1")
        self.assertIsNone(post.respond(exchange, ready("c1")))
        self.dispatch(post, result("c1"))
        self.write(post, exchange)
        post.finish(exchange, "peer_reset")
        self.assertEqual(post.poll(), ("ended", exchange, "peer_reset"))
        self.assertTrue(latch.is_cancelled())
        self.assertIsNone(post.active["delivered"])
        self.seen(post)

    def test_activation_tightens_the_wait_to_the_request_deadline(self):
        post = self.armed()
        exchange = self.dispatch(post, submit("c1"))
        self.seen(post)
        self.assertEqual(post.next_step(exchange), ("wait", T0 + ingress.EXCHANGE_CEILING))
        deadline = T0 + 1700.0
        post.activate(exchange, deadline)
        self.assertTrue(post.exchange(exchange).wake, "the worker rereads its bound")
        self.assertEqual(post.next_step(exchange), ("wait", deadline))
        self.assertIsNone(post.respond(exchange, ready("c1")))
        step = post.next_step(exchange)
        self.assertEqual((step[0], step[3]), ("respond", deadline))
        # A later request deadline never extends the exchange's own bound.
        post = self.armed()
        exchange = self.dispatch(post, submit("c1"))
        self.seen(post)
        post.activate(exchange, CUTOFF + 1.0)
        self.assertEqual(post.next_step(exchange), ("wait", T0 + ingress.EXCHANGE_CEILING))

    def test_an_exchange_is_bounded_by_its_ceiling_and_the_cutoff_if_any(self):
        # Untimed: each exchange waits its ceiling from its own admission.
        post = self.armed(cutoff=None)
        late = T0 + 400 * 24 * 3600
        exchange = self.dispatch(post, submit("c1"), late)
        self.assertEqual(post.next_step(exchange), ("wait", late + ingress.EXCHANGE_CEILING))
        self.assertEqual(self.admit(post, b"{}", late)[3], late + ingress.EXCHANGE_CEILING)
        self.seen(post)
        post.activate(exchange, late + ingress.EXCHANGE_CEILING + 1.0)
        self.assertEqual(post.next_step(exchange), ("wait", late + ingress.EXCHANGE_CEILING))
        # A finite cutoff before the ceiling caps the exchange and its answers.
        post = self.armed(cutoff=T0 + 60.0)
        exchange = self.dispatch(post, submit("c1"))
        self.assertEqual(post.next_step(exchange), ("wait", T0 + 60.0))
        self.assertEqual(self.admit(post, b"{}")[3], T0 + 60.0)

    def test_activation_refuses_what_cannot_be_the_active_request(self):
        post = self.armed()
        lost = self.dispatch(post, submit("c1"))
        self.seen(post)
        post.exchange(lost).cancel.cancel()
        self.assertEqual(post.activate(lost, CUTOFF), "cancelled")
        post.finish(lost, "peer_eof")
        self.assertEqual(post.activate(lost, CUTOFF), "stale")
        self.assertEqual(post.poll()[0], "ended")
        control = self.dispatch(post, cancel("c1"))
        self.seen(post)
        self.assertEqual(post.activate(control, CUTOFF), "stale")


class Shutdown(Base):

    def test_past_the_cutoff_nothing_is_admitted(self):
        post = self.armed()
        self.assertEqual(self.admit(post, submit("c1"), CUTOFF), ("refused", "post_closed"))
        self.assertEqual(ledger(post), (0, 0, 0, 0))

    def test_stop_cancels_everything_and_reports_what_remains(self):
        post = self.armed()
        exchange, token, latch = self.active(post, "c1")
        control = self.dispatch(post, cancel("c1"))
        self.assertIsNone(post.permit())
        post.close()
        self.assertEqual(post.closure, "stopped")
        self.assertEqual(len([e for e in post.slots if e is not None]), 2, "outstanding, not settled")
        self.assertEqual(post.permits, 1)
        self.assertTrue(latch.is_cancelled())
        self.assertEqual((post.next_step(exchange), post.next_step(control)), (("closed",), ("closed",)))
        self.assertEqual(post.permit(), "post_closed")
        post.finish(exchange, "post_stopped")
        post.finish(control, "post_stopped")
        self.assertEqual(post.poll()[0], "ended")
        self.assertEqual(post.poll(), ("closed", "stopped"))
        self.assertIsNone(post.poll())
        post.release_permit()
        self.assertEqual(post.permits, 0)
        post.retire(token)
        # Irreversible: a second stop changes nothing.
        post.stop()
        self.assertTrue(latch.is_cancelled())
        self.assertEqual(post.closure, "stopped")

    def test_a_stopped_ingress_refuses_a_response_write(self):
        post = self.armed()
        exchange, _, _ = self.active(post, "c1")
        self.assertIsNone(post.respond(exchange, ready("c1")))
        post.stop()
        self.assertEqual(post.next_step(exchange), ("closed",))
        self.assertEqual(post.activate(exchange, CUTOFF), "closed")

    def test_nothing_is_answered_after_the_end_or_at_the_cutoff(self):
        post = self.armed()
        for body in (b"{}", submit("c1", session=OTHER)):
            self.assertEqual(self.admit(post, body)[3], T0 + ingress.EXCHANGE_CEILING)
        self.assertEqual(Ingress(T0, CUTOFF).permit(), "post_closed")
        for body in (b"{}", b"", submit("c1", session=OTHER)):
            post = self.armed()
            self.assertIsNone(post.permit())
            post.stop()
            self.assertEqual(post.admit(body, T0), ("refused", "post_closed"))
            post = self.armed()
            self.assertEqual(self.admit(post, body, CUTOFF), ("refused", "post_closed"))


if __name__ == "__main__":
    unittest.main()
