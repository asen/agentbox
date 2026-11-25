"""The artifact POST client's transport, request flow, context and generic save
client with memory doubles only (post_memory.py): no socket, server, process
or lookup, and the socket guard counts only the production dial's own
refused attempt. Owned roots are kept."""

import asyncio
import hashlib
import json
import os
import re
import shutil
import unittest

from guest.src import artifact_post_protocol as post
from guest.src import artifact_save_client
from guest.src.abort import Abort
from guest.src.artifact_post_client import (
    CONTROL_TIMEOUT_MS, ENDPOINT_HOST, ENDPOINT_PORT, PRODUCTION_SEAMS, UNKNOWN, Lane, Seams, dial_fixed_endpoint,
    exchange, run_request,
)
from guest.src.artifact_post_context import (
    CONTEXT_ENV, MOUNT_ENV, SESSION_ENV, UPLOAD_DIR_NAME, WORK_ROOT_ENV, RequestContext, context_environment,
    context_from_environment, prepare_upload_dir, request_context, upload_dir, upload_name,
)
from guest.src.artifact_save_client import SAVED_NAME, SaveSeams, run_save_client_with
from guest.src.protocol import RESERVED_ENV
from guest.src.request_status import EXIT_INPUT_LOST, EXIT_OK, EXIT_RUNTIME
from guest.test.post_memory import (
    MS_NS, SESSION, ManualClock, MemoryHost, closed_for, descriptors, install_socket_guard, owned_context, ready,
    response_bytes, seams_of, settle, upload,
)

SOCKETS = install_socket_guard()
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATA = b"synthetic echo bytes\n"
SUBMISSION = {"handler": "echo", "operation": "say", "args": {"text": "hi"}}
FAR = 3_600_000 * MS_NS
METADATA = {"length": len(DATA), "operation": "say"}


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fixture_ready(client="c-1", request="req-1", data=DATA):
    return ready(SUBMISSION, client, request, {"handler": "echo", "operation": "say", "size": len(data),
                                                "sha256": sha256(data), "metadata": METADATA})


def submit(client="c-1"):
    return dict({"v": 1, "type": "submit", "session": SESSION, "client": client}, **SUBMISSION)


def bounds(clock, answer=FAR):
    return clock.now() + FAR, clock.now() + answer


def run(coroutine):
    return asyncio.run(coroutine)


class Recorded:
    """An echo-shaped lane whose application the test controls."""

    def __init__(self, apply=None, accept=True):
        self.events = []

        async def default(_ready, _signal):
            return True

        inner = apply or default

        async def applying(ready_, signal):
            self.events.append("apply " + ready_["request"])
            try:
                return await inner(ready_, signal)
            finally:
                self.events.append("applied")

        self.lane = Lane(SUBMISSION, lambda _ready: accept, applying, lambda outcome: outcome)


def scripted(events, answers):
    """A host answering by request type from a table; records each request's type in `events`."""

    def answer(connection, request):
        assert request is not None, "canonical request"
        events.append(request["type"])
        handler = answers.get(request["type"])
        if handler is not None:
            handler(connection, request)

    return MemoryHost(answer)


class Context(unittest.TestCase):
    def test_the_context_is_exactly_a_session_nonce_and_a_plain_absolute_working_root(self):
        self.assertEqual(request_context(SESSION, "/home/agentbox/work"), RequestContext(SESSION, "/home/agentbox/work"))
        for session, root in (("0123456789ABCDEF0123456789abcdef", "/w"), ("0123456789abcdef", "/w"), ("s1", "/w"),
                              (SESSION, "w"), (SESSION, "/"), (SESSION, "/a/../b"), (SESSION, "/a b"), (SESSION, "/a/"),
                              (None, "/w"), (SESSION, 1), (SESSION + "\n", "/w")):
            self.assertIsNone(request_context(session, root), "%r %r" % (session, root))
        self.assertEqual(context_from_environment({SESSION_ENV: SESSION, WORK_ROOT_ENV: "/w"}),
                         RequestContext(SESSION, "/w"))
        self.assertIsNone(context_from_environment({SESSION_ENV: SESSION}))
        self.assertIsNone(context_from_environment({WORK_ROOT_ENV: "/w"}))
        self.assertEqual(context_environment(RequestContext(SESSION, "/w")),
                         {"AGENTBOX_REQUEST_SESSION": SESSION, "AGENTBOX_WORK_ROOT": "/w"})
        self.assertEqual(UPLOAD_DIR_NAME, ".agentbox-requests")
        self.assertEqual(upload_dir(RequestContext(SESSION, "/srv/x/home/work")), "/srv/x/home/work/.agentbox-requests")
        self.assertEqual(upload_name(SESSION, "req-1"), SESSION + "-req-1.artifact")
        self.assertIsNone(upload_name(SESSION, "../x"))

    def test_a_mount_root_is_plain_absolute_and_holds_the_working_root(self):
        self.assertEqual(MOUNT_ENV, "AGENTBOX_WORK_MOUNT")
        for mount in ("/h/src/app", "/h/src/app/sub"):
            self.assertEqual(request_context(SESSION, "/h/src/app/sub", mount),
                             RequestContext(SESSION, "/h/src/app/sub", mount))
        for mount in ("/h/src/ap", "/h/src/app/sub/x", "relative", "/h/../h/src", "", "/", 1):
            self.assertIsNone(request_context(SESSION, "/h/src/app/sub", mount), repr(mount))
        env = {SESSION_ENV: SESSION, WORK_ROOT_ENV: "/h/src/app"}
        self.assertEqual(context_from_environment(dict(env, **{MOUNT_ENV: "/h/src"})),
                         RequestContext(SESSION, "/h/src/app", "/h/src"))
        # A malformed or inconsistent root refuses: never the unmounted rule.
        for bad in ("", "/h/other", "h/src"):
            self.assertIsNone(context_from_environment(dict(env, **{MOUNT_ENV: bad})), bad)
        self.assertEqual(context_environment(RequestContext(SESSION, "/h/src/app", "/h/src")),
                         {"AGENTBOX_REQUEST_SESSION": SESSION, "AGENTBOX_WORK_ROOT": "/h/src/app",
                          "AGENTBOX_WORK_MOUNT": "/h/src"})

    def test_a_mounted_working_root_admits_the_hosts_modes_the_upload_directory_stays_private(self):
        for mode in (0o755, 0o775, 0o700):
            _root, work, context = owned_context()
            os.chmod(work, mode)
            mounted = RequestContext(context.session, context.work_root, context.work_root)
            directory = prepare_upload_dir(mounted)
            self.assertEqual(directory, os.path.join(work, ".agentbox-requests"), oct(mode))
            self.assertEqual(os.lstat(directory).st_mode & 0o777, 0o700)
            if mode != 0o700:
                # The same root unmounted refuses, as ever.
                shutil.rmtree(directory)
                self.assertIsNone(prepare_upload_dir(context))
        # Other-writable, a link, or a permissive upload directory refuses.
        _root, work, context = owned_context()
        mounted = RequestContext(context.session, context.work_root, context.work_root)
        os.chmod(work, 0o777)
        self.assertIsNone(prepare_upload_dir(mounted))
        self.assertFalse(os.path.exists(os.path.join(work, ".agentbox-requests")))
        os.chmod(work, 0o755)
        os.mkdir(os.path.join(work, ".agentbox-requests"), 0o755)
        self.assertIsNone(prepare_upload_dir(mounted))
        _root, linked, context = owned_context()
        target = os.path.join(linked, "real")
        os.mkdir(target, 0o755)
        link = os.path.join(linked, "link")
        os.symlink(target, link)
        self.assertIsNone(prepare_upload_dir(RequestContext(context.session, link, link)))
        self.assertFalse(os.path.exists(os.path.join(target, ".agentbox-requests")))

    def test_both_context_names_are_reserved_in_the_contract(self):
        for name in CONTEXT_ENV:
            self.assertIn(name, RESERVED_ENV)
        with open(os.path.join(REPO, "contracts", "v1", "protocol.json"), encoding="utf-8") as stream:
            self.assertEqual(json.load(stream)["reserved_env"], list(RESERVED_ENV))

    def test_upload_directories_are_made_private_before_a_submit_never_adopted_otherwise(self):
        _root, work, context = owned_context()
        directory = prepare_upload_dir(context)
        self.assertEqual(directory, os.path.join(work, ".agentbox-requests"))
        self.assertEqual(os.lstat(directory).st_mode & 0o777, 0o700)
        self.assertEqual(prepare_upload_dir(context), directory)
        # Group access, a link or a file in its place is refused, never repaired.
        os.chmod(directory, 0o750)
        self.assertIsNone(prepare_upload_dir(context))
        self.assertEqual(os.lstat(directory).st_mode & 0o777, 0o750)
        _root, linked, linked_context = owned_context()
        os.mkdir(os.path.join(linked, "elsewhere"), 0o700)
        os.symlink(os.path.join(linked, "elsewhere"), os.path.join(linked, ".agentbox-requests"))
        self.assertIsNone(prepare_upload_dir(linked_context))
        self.assertTrue(os.path.islink(os.path.join(linked, ".agentbox-requests")))
        open_root, opened, open_context = owned_context()
        os.chmod(opened, 0o755)
        self.assertIsNone(prepare_upload_dir(open_context))
        self.assertFalse(os.path.exists(os.path.join(opened, ".agentbox-requests")))
        missing = request_context(SESSION, os.path.join(open_root, "absent"))
        self.assertIsNone(prepare_upload_dir(missing))
        self.assertFalse(os.path.exists(os.path.join(open_root, "absent")))


class Exchange(unittest.TestCase):
    def test_one_exchange_writes_once_and_keeps_its_write_side_until_the_response_and_close(self):
        async def body():
            clock = ManualClock()
            held = []
            host = MemoryHost(lambda connection, _request: held.append(connection))
            pending = asyncio.ensure_future(exchange(submit(), *bounds(clock), seams_of(host, clock)))
            await settle()
            self.assertEqual(len(held), 1)
            self.assertEqual(len(host.connections), 1)
            connection = held[0]
            self.assertEqual(connection.raw, post.encode_http_request(post.encode_request(submit())))
            self.assertEqual(len(connection.writes), 1)
            # The whole response without the close completes nothing.
            response = fixture_ready()
            connection.data(response_bytes(response))
            await settle()
            self.assertEqual(connection.destroyed, 0)
            connection.end()
            self.assertEqual(await pending, {"kind": "response", "response": response})
            self.assertEqual(connection.destroyed, 1)
            connection.data("x")
            connection.close()
            self.assertEqual(connection.destroyed, 1)

        run(body())

    def test_the_hosts_empty_503_is_a_distinct_refusal_other_empty_statuses_are_malformed(self):
        async def body():
            for split in (1, 7, 1 << 20):
                clock = ManualClock()

                def answer(connection, _request, split=split):
                    data = post.REFUSAL_HEAD.encode("latin-1")
                    for at in range(0, len(data), split):
                        connection.data(data[at:at + split])
                    connection.end()

                host = MemoryHost(answer)
                self.assertEqual(await exchange(submit(), *bounds(clock), seams_of(host, clock)), {"kind": "refused"})
                self.assertEqual(len(host.connections), 1)
            refusal = post.REFUSAL_HEAD
            for text, code in (
                    (refusal + "x", "response_trailing"),
                    (refusal.replace("503 Service Unavailable", "405 Method Not Allowed"), "response_malformed"),
                    (refusal.replace("503 Service Unavailable", "503 Busy"), "response_malformed"),
                    ("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                     "response_malformed"),
                    ("﻿" + refusal, "response_malformed"),
                    (refusal[:-2], "response_truncated")):
                clock = ManualClock()

                def answer(connection, _request, text=text):
                    connection.data(text.encode("utf-8"))
                    connection.end()

                host = MemoryHost(answer)
                self.assertEqual(await exchange(submit(), *bounds(clock), seams_of(host, clock)),
                                 {"kind": "malformed", "code": code}, repr(text))

        run(body())

    def test_a_response_is_complete_only_with_the_servers_close(self):
        async def body():
            clock = ManualClock()

            def lose(connection, _request):
                connection.data(response_bytes(fixture_ready()))
                connection.close()

            self.assertEqual(await exchange(submit(), *bounds(clock), seams_of(MemoryHost(lose), clock)),
                             {"kind": "lost", "sent": True})
            # A connection refused before connecting sent nothing.
            refused = MemoryHost(lambda *_: None, connect=False)
            pending = asyncio.ensure_future(exchange(submit(), *bounds(clock), seams_of(refused, clock)))
            await settle()
            refused.connections[0].close()
            self.assertEqual(await pending, {"kind": "lost", "sent": False})
            self.assertEqual(refused.connections[0].writes, [])

            class Failing:
                def write(self, _data, done):
                    asyncio.get_running_loop().call_soon(done, False)

                def destroy(self):
                    pass

            def failing_dial(events):
                asyncio.get_running_loop().call_soon(events.connect)
                return Failing()

            self.assertEqual(await exchange(submit(), *bounds(clock), Seams(failing_dial, clock, lambda: "c-1")),
                             {"kind": "lost", "sent": True})
            # An answer before this side's write completed answers nothing of it.
            early = []

            class Silent:
                def write(self, _data, _done):
                    pass

                def destroy(self):
                    pass

            def silent_dial(events):
                def answer():
                    events.data(response_bytes(fixture_ready()))
                    events.end()

                early.append(answer)
                asyncio.get_running_loop().call_soon(events.connect)
                return Silent()

            unwritten = asyncio.ensure_future(exchange(submit(), *bounds(clock), Seams(silent_dial, clock, lambda: "c-1")))
            await settle()
            early[0]()
            self.assertEqual(await unwritten, {"kind": "lost", "sent": True})

        run(body())

    def test_the_cutoff_the_control_cap_and_the_abort_bound_every_step(self):
        async def body():
            clock = ManualClock()
            host = MemoryHost(lambda *_: None, connect=False)
            pending = asyncio.ensure_future(exchange(submit(), *bounds(clock), seams_of(host, clock)))
            await settle()
            clock.advance(CONTROL_TIMEOUT_MS * MS_NS - 1)
            await settle()
            self.assertEqual(host.connections[0].destroyed, 0)
            clock.advance(1)
            self.assertEqual(await pending, {"kind": "expired", "sent": False})
            self.assertEqual(host.connections[0].destroyed, 1)
            host.connections[0].connect()
            self.assertEqual(host.connections[0].writes, [])

            # A submit's answer waits until the original cutoff only.
            clock = ManualClock()
            host = MemoryHost(lambda *_: None)
            until = clock.now() + 60_000 * MS_NS
            pending = asyncio.ensure_future(exchange(submit(), until, until, seams_of(host, clock)))
            await settle()
            clock.advance(30_000 * MS_NS)
            await settle()
            self.assertEqual(host.connections[0].destroyed, 0)
            clock.advance(30_000 * MS_NS)
            self.assertEqual(await pending, {"kind": "expired", "sent": True})
            host.connections[0].respond(fixture_ready())
            self.assertEqual(host.connections[0].destroyed, 1)

            # A result's answer within the control cap, clipped by the original cutoff.
            clock = ManualClock()
            host = MemoryHost(lambda *_: None)
            pending = asyncio.ensure_future(exchange(submit(), clock.now() + 5_000 * MS_NS,
                                                     clock.now() + 10_000 * MS_NS, seams_of(host, clock)))
            await settle()
            clock.advance(5_000 * MS_NS)
            self.assertEqual(await pending, {"kind": "expired", "sent": True})

            # Already past the cutoff: nothing is dialled.
            clock = ManualClock()
            host = MemoryHost(lambda *_: None)
            self.assertEqual(await exchange(submit(), clock.now(), clock.now(), seams_of(host, clock)),
                             {"kind": "expired", "sent": False})
            self.assertEqual(host.connections, [])

            before = Abort()
            before.abort()
            self.assertEqual(await exchange(submit(), *bounds(clock), seams_of(host, clock), before),
                             {"kind": "aborted", "sent": False})
            self.assertEqual(host.connections, [])
            after = Abort()
            pending = asyncio.ensure_future(exchange(submit(), *bounds(clock), seams_of(host, clock), after))
            await settle()
            after.abort()
            self.assertEqual(await pending, {"kind": "aborted", "sent": True})
            self.assertEqual(host.connections[0].destroyed, 1)
            host.connections[0].respond(fixture_ready())
            self.assertEqual(host.connections[0].destroyed, 1)
            self.assertEqual(clock.pending, 0, "every wake released")

        run(body())

    def test_the_production_dial_is_the_fixed_numeric_endpoint_refused_here_by_the_guard(self):
        self.assertEqual(ENDPOINT_HOST, "127.0.0.1")
        self.assertEqual(ENDPOINT_PORT, 18080)
        self.assertIs(PRODUCTION_SEAMS.dial, dial_fixed_endpoint)
        self.assertRegex(PRODUCTION_SEAMS.client_id(), r"\Ac-[0-9a-f]{32}\Z")
        before = SOCKETS.denied

        async def body():
            clock = ManualClock()
            return await exchange(submit(), *bounds(clock), Seams(dial_fixed_endpoint, clock, lambda: "c-1"))

        self.assertEqual(run(body()), {"kind": "lost", "sent": False})
        self.assertEqual(SOCKETS.denied, before + 1, "only the production dial's own refused attempt")


class Flow(unittest.TestCase):
    def test_ready_application_result_and_recorded_run_in_order_bound_to_one_client(self):
        async def body():
            clock = ManualClock()
            _root, _work, context = owned_context()
            recorded = Recorded()
            host = scripted(recorded.events, {
                "submit": lambda c, _r: c.respond(fixture_ready()),
                "result": lambda c, _r: c.respond(closed_for(SUBMISSION, "c-1", "req-1", "recorded"))})
            result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock))
            self.assertEqual(result.terminal, {"kind": "recorded", "status": "applied"})
            self.assertEqual(recorded.events, ["submit", "apply req-1", "applied", "result"])
            first, second = host.requests
            expected = fixture_ready()
            self.assertEqual(first, submit())
            self.assertEqual(second, {"v": 1, "type": "result", "session": SESSION, "client": "c-1", "request": "req-1",
                                      "request_sha256": expected["request_sha256"], "sha256": expected["sha256"],
                                      "status": "applied"})
            self.assertEqual([c.destroyed for c in host.connections], [1, 1])
            self.assertEqual(clock.pending, 0)

        run(body())

    def test_a_ready_not_bound_to_this_submission_is_never_applied_and_gets_one_cancel(self):
        other = fixture_ready()
        variants = (
            ("session", dict(other, session="f" * 32), True),
            ("client", dict(other, client="c-9"), True),
            ("digest", dict(other, request_sha256="0" * 64), True),
            ("handler", dict(other, handler="pip"), True),
            ("operation", dict(other, operation="refuse"), True),
            ("other submission", ready(dict(SUBMISSION, args={"text": "ho"}), "c-1", "req-1",
                                       {"handler": "echo", "operation": "say", "size": 1, "sha256": other["sha256"],
                                        "metadata": {}}), True),
            ("lane", other, False),
        )

        async def body():
            for name, response, accept in variants:
                clock = ManualClock()
                _root, _work, context = owned_context()
                recorded = Recorded(accept=accept)
                host = scripted(recorded.events, {
                    "submit": lambda c, _r, response=response: c.respond(response),
                    "cancel": lambda c, _r: c.respond({"v": 1, "type": "error", "code": "not_active"})})
                result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock))
                self.assertEqual(result.terminal, {"kind": "protocol"}, name)
                self.assertEqual(recorded.events, ["submit", "cancel"], name)
                self.assertEqual(host.requests[1], {"v": 1, "type": "cancel", "session": SESSION, "client": "c-1"}, name)

        run(body())

    def test_answers_before_ready_end_the_request_without_application_or_retry(self):
        cases = (
            ("rejected", {"v": 1, "type": "rejected", "session": SESSION, "client": "c-1", "code": "busy"},
             {"kind": "rejected", "code": "busy"}),
            ("foreign rejected", {"v": 1, "type": "rejected", "session": SESSION, "client": "c-2", "code": "busy"},
             {"kind": "protocol"}),
            ("denied", closed_for(SUBMISSION, "c-1", "req-1", "denied"),
             {"kind": "closed", "request": "req-1", "outcome": "denied", "reason": "fake_denied"}),
            ("recorded before ready", closed_for(SUBMISSION, "c-1", "req-1", "recorded"), {"kind": "protocol"}),
            ("foreign closed", closed_for(SUBMISSION, "c-2", "req-1", "expired"), {"kind": "protocol"}),
            ("error", {"v": 1, "type": "error", "code": "session_mismatch"}, {"kind": "error", "code": "session_mismatch"}),
            ("refused", "refuse", {"kind": "refused"}),
            ("lost", "close", {"kind": "lost"}),
        )

        async def body():
            for name, answer, terminal in cases:
                clock = ManualClock()
                _root, _work, context = owned_context()
                recorded = Recorded()

                def respond(connection, _request, answer=answer):
                    if answer == "refuse":
                        connection.refuse()
                    elif answer == "close":
                        connection.close()
                    else:
                        connection.respond(answer)

                host = scripted(recorded.events, {"submit": respond})
                result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock))
                self.assertEqual(result.terminal, terminal, name)
                self.assertEqual(recorded.events, ["submit"], name)
                self.assertEqual(len(host.connections), 1, name)

        run(body())

    def test_an_abort_before_ready_destroys_the_submit_which_is_the_only_post(self):
        async def body():
            clock = ManualClock()
            _root, _work, context = owned_context()
            recorded = Recorded()
            host = scripted(recorded.events, {})
            abort = Abort()
            pending = asyncio.ensure_future(run_request(context, recorded.lane, clock.now() + FAR,
                                                        seams_of(host, clock), abort))
            await settle()
            abort.abort()
            self.assertEqual((await pending).terminal, {"kind": "cancelled"})
            self.assertEqual(recorded.events, ["submit"])
            self.assertEqual(host.connections[0].destroyed, 1)
            host.connections[0].respond(fixture_ready())
            await settle()
            self.assertEqual(recorded.events, ["submit"])
            none = scripted([], {})
            result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(none, clock), abort)
            self.assertEqual(result.terminal, {"kind": "cancelled"})
            self.assertEqual(none.connections, [])

        run(body())

    def test_an_abort_after_ready_aborts_and_awaits_the_application_then_one_cancel(self):
        async def body():
            clock = ManualClock()
            _root, _work, context = owned_context()
            abort = Abort()
            seen = []

            async def apply(_ready, signal):
                seen.append(signal)
                future = asyncio.get_running_loop().create_future()
                signal.add_listener(lambda: asyncio.get_running_loop().call_soon(future.set_result, False))
                return await future

            recorded = Recorded(apply)

            def on_submit(connection, _request):
                connection.respond(fixture_ready())
                asyncio.get_running_loop().call_soon(abort.abort)

            host = scripted(recorded.events, {
                "submit": on_submit,
                "cancel": lambda c, _r: c.respond(closed_for(SUBMISSION, "c-1", "req-1", "cancelled"))})
            result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock), abort)
            self.assertEqual(result.terminal, {"kind": "cancelled"})
            self.assertTrue(seen[0].aborted)
            self.assertEqual(recorded.events, ["submit", "apply req-1", "applied", "cancel"])
            self.assertEqual(host.requests[1], {"v": 1, "type": "cancel", "session": SESSION, "client": "c-1"})

        run(body())

    def test_the_original_cutoff_during_application_aborts_it_nothing_is_sent_after(self):
        async def body():
            clock = ManualClock()
            _root, _work, context = owned_context()

            async def apply(_ready, signal):
                future = asyncio.get_running_loop().create_future()
                signal.add_listener(lambda: future.set_result(True))
                return await future

            recorded = Recorded(apply)
            host = scripted(recorded.events, {"submit": lambda c, _r: c.respond(fixture_ready())})
            until = clock.now() + 60_000 * MS_NS
            pending = asyncio.ensure_future(run_request(context, recorded.lane, until, seams_of(host, clock)))
            await settle()
            self.assertEqual(recorded.events, ["submit", "apply req-1"])
            clock.advance(60_000 * MS_NS)
            result = await pending
            self.assertEqual(result.terminal, {"kind": "expired"})
            self.assertEqual(recorded.events, ["submit", "apply req-1", "applied"])
            self.assertEqual(len(host.connections), 1)

        run(body())

    def test_one_result_never_retried(self):
        cases = (
            ("lost", lambda c, _r: c.close(), {"kind": "lost"}),
            ("refused", lambda c, _r: c.refuse(), {"kind": "refused"}),
            ("not active", lambda c, _r: c.respond({"v": 1, "type": "error", "code": "not_active"}),
             {"kind": "error", "code": "not_active"}),
            ("expired", lambda c, _r: c.respond(closed_for(SUBMISSION, "c-1", "req-1", "expired")),
             {"kind": "closed", "request": "req-1", "outcome": "expired"}),
            ("other request", lambda c, _r: c.respond(closed_for(SUBMISSION, "c-1", "req-2", "recorded")),
             {"kind": "protocol"}),
            ("other client", lambda c, _r: c.respond(closed_for(SUBMISSION, "c-2", "req-1", "recorded")),
             {"kind": "protocol"}),
            ("a ready", lambda c, _r: c.respond(fixture_ready()), {"kind": "protocol"}),
        )

        async def body():
            for name, answer, terminal in cases:
                clock = ManualClock()
                _root, _work, context = owned_context()
                recorded = Recorded()
                host = scripted(recorded.events, {"submit": lambda c, _r: c.respond(fixture_ready()), "result": answer})
                result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock))
                self.assertEqual(result.terminal, terminal, name)
                self.assertEqual(recorded.events, ["submit", "apply req-1", "applied", "result"], name)

        run(body())

    def test_a_failed_or_raising_application_is_claimed_failed_an_abort_during_the_result_ends_it(self):
        async def failed(_ready, _signal):
            return False

        async def raises(_ready, _signal):
            raise RuntimeError("boom")

        async def body():
            for name, apply in (("failed", failed), ("raises", raises)):
                clock = ManualClock()
                _root, _work, context = owned_context()
                recorded = Recorded(apply)
                host = scripted(recorded.events, {
                    "submit": lambda c, _r: c.respond(fixture_ready()),
                    "result": lambda c, _r: c.respond(closed_for(SUBMISSION, "c-1", "req-1", "recorded"))})
                result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock))
                self.assertEqual(result.terminal, {"kind": "recorded", "status": "failed"}, name)
                self.assertEqual(host.requests[1]["status"], "failed", name)
                if name == "raises":
                    self.assertIs(result.outcome, UNKNOWN)
            clock = ManualClock()
            _root, _work, context = owned_context()
            abort = Abort()
            recorded = Recorded()
            host = scripted(recorded.events, {"submit": lambda c, _r: c.respond(fixture_ready()),
                                              "result": lambda _c, _r: abort.abort()})
            result = await run_request(context, recorded.lane, clock.now() + FAR, seams_of(host, clock), abort)
            self.assertEqual(result.terminal, {"kind": "cancelled"})
            self.assertEqual(recorded.events, ["submit", "apply req-1", "applied", "result"])
            self.assertEqual(host.connections[1].destroyed, 1)

        run(body())

    def test_a_host_upload_is_possible_from_the_first_write_attempt_only_an_unsent_submit_is_none(self):
        _root, _work, context = owned_context()

        async def attempt(host, signal=None):
            clock = ManualClock()
            return await run_request(context, Recorded().lane, clock.now() + FAR, seams_of(host, clock), signal)

        async def body():
            aborted = Abort()
            aborted.abort()
            result = await attempt(MemoryHost(lambda *_: None), aborted)
            self.assertEqual((result.terminal, result.upload), ({"kind": "cancelled"}, "none"))
            unconnected = MemoryHost(lambda *_: None, connect=False)
            pending = asyncio.ensure_future(attempt(unconnected))
            await settle()
            unconnected.connections[0].close()
            result = await pending
            self.assertEqual((result.terminal, result.upload), ({"kind": "unavailable"}, "none"))
            for name, answer in (
                    ("refused", lambda c: c.refuse()),
                    ("rejected", lambda c: c.respond({"v": 1, "type": "rejected", "session": SESSION, "client": "c-1",
                                                      "code": "busy"})),
                    ("lost", lambda c: c.close()),
                    ("denied", lambda c: c.respond(closed_for(SUBMISSION, "c-1", "req-1", "denied"))),
                    ("error", lambda c: c.respond({"v": 1, "type": "error", "code": "session_mismatch"}))):
                result = await attempt(MemoryHost(lambda c, _r, answer=answer: answer(c)))
                self.assertEqual(result.upload, "possible", name)
            abort = Abort()
            late = await attempt(MemoryHost(lambda *_: asyncio.get_running_loop().call_soon(abort.abort)), abort)
            self.assertEqual((late.terminal, late.upload), ({"kind": "cancelled"}, "possible"))

            def foreign_answer(connection, request):
                if request["type"] == "submit":
                    connection.respond(dict(fixture_ready(), client="c-9"))
                else:
                    connection.respond(closed_for(SUBMISSION, "c-1", "req-1", "cancelled"))

            foreign = await attempt(MemoryHost(foreign_answer))
            self.assertEqual((foreign.terminal, foreign.upload), ({"kind": "protocol"}, "possible"))

        run(body())


def save_seams(host, clock, until=FAR):
    class Deadline:
        started_ns = clock.now()
        until_ns = clock.now() + until
        local_until = float("inf")

    return SaveSeams(seams_of(host, clock), lambda: Deadline)


async def save_once(data, place=None):
    """One save of `data` (None: none) uploaded under the announced DATA; its report and status."""
    clock = ManualClock()
    _root, work, context = owned_context()
    reports = []

    def answer(connection, request):
        if request is not None and request["type"] == "submit":
            directory = os.path.join(work, ".agentbox-requests")
            name = upload_name(SESSION, "req-1")
            if place is not None:
                place(directory, name)
            elif data is not None:
                upload(directory, name, data)
            connection.respond(fixture_ready())
        else:
            connection.respond(closed_for(SUBMISSION, "c-1", "req-1", "recorded"))

    host = MemoryHost(answer)
    status = await run_save_client_with(save_seams(host, clock), SUBMISSION, context, reports.append)
    return status, reports, work, host


def artifacts(work):
    return [entry for entry in os.listdir(work) if entry.startswith("agentbox-artifact-")]


class SaveClient(unittest.TestCase):
    def test_the_generic_client_copies_its_upload_into_a_fresh_private_directory(self):
        async def body():
            clock = ManualClock()
            _root, work, context = owned_context()
            reports = []
            prepared = []

            def answer(connection, request):
                if request["type"] == "submit":
                    prepared.append(os.path.isdir(os.path.join(work, ".agentbox-requests")))
                    upload(os.path.join(work, ".agentbox-requests"), upload_name(SESSION, "req-1"), DATA)
                    connection.respond(fixture_ready())
                elif request["type"] == "result":
                    connection.respond(closed_for(SUBMISSION, "c-1", "req-1", "recorded"))

            host = MemoryHost(answer)
            status = await run_save_client_with(save_seams(host, clock), SUBMISSION, context, reports.append)
            self.assertEqual(status, EXIT_OK)
            self.assertEqual(prepared, [True])
            [entry] = artifacts(work)
            path = os.path.join(work, entry, SAVED_NAME)
            with open(path, "rb") as stream:
                self.assertEqual(stream.read(), DATA)
            self.assertEqual(os.lstat(path).st_mode & 0o777, 0o600)
            self.assertEqual(os.lstat(os.path.join(work, entry)).st_mode & 0o777, 0o700)
            self.assertEqual(reports, [{"ok": True, "path": path, "size": len(DATA), "sha256": sha256(DATA),
                                        "metadata": METADATA, "cleanup": "observed"}])
            self.assertEqual(host.requests[1]["status"], "applied")
            self.assertEqual(os.listdir(os.path.join(work, ".agentbox-requests")), [])

        run(body())

    def test_an_upload_of_another_size_or_digest_or_none_is_never_kept(self):
        corrupt = bytes([DATA[0] ^ 1]) + DATA[1:]

        async def body():
            for label, data, code in (("short", DATA[1:], "artifact_mismatch"), ("corrupt", corrupt, "artifact_mismatch"),
                                      ("missing", None, "artifact_missing")):
                status, reports, work, host = await save_once(data)
                self.assertEqual(status, EXIT_RUNTIME, label)
                self.assertEqual(host.requests[1]["status"], "failed", label)
                self.assertEqual(reports, [{"ok": False, "code": code, "cleanup": "incomplete"}], label)
                self.assertEqual(artifacts(work), [], label)

        run(body())

    def test_an_upload_of_the_wrong_size_or_no_regular_file_leaves_no_descriptor_open(self):
        async def body():
            before = descriptors()
            for label, args, code in (
                    ("wrong size", (DATA + DATA,), "artifact_mismatch"),
                    ("directory", (None, lambda d, n: os.mkdir(os.path.join(d, n), 0o700)), "artifact_missing"),
                    ("short", (DATA[1:],), "artifact_mismatch")):
                status, reports, work, _host = await save_once(*args)
                self.assertEqual(status, EXIT_RUNTIME, label)
                self.assertEqual(reports, [{"ok": False, "code": code, "cleanup": "incomplete"}], label)
                self.assertEqual(artifacts(work), [], label)
                self.assertEqual(descriptors(), before, label)
            status, _reports, _work, _host = await save_once(DATA)
            self.assertEqual(status, EXIT_OK)
            self.assertEqual(descriptors(), before)

        asyncio.run(body())

    def test_short_writes_are_continued_a_write_making_no_progress_fails_the_copy(self):
        original = artifact_save_client._pwrite
        calls = []

        def three(fd, data, position):
            calls.append(position)
            return original(fd, data[:3], position)

        async def body():
            artifact_save_client._pwrite = three
            status, reports, _work, host = await save_once(DATA)
            self.assertEqual(status, EXIT_OK)
            with open(reports[0]["path"], "rb") as stream:
                self.assertEqual(stream.read(), DATA)
            self.assertEqual(len(calls), -(-len(DATA) // 3))
            self.assertEqual(host.requests[1]["status"], "applied")
            before = descriptors()
            artifact_save_client._pwrite = lambda *_: 0
            status, reports, work, host = await save_once(DATA)
            self.assertEqual(status, EXIT_RUNTIME)
            self.assertEqual(reports, [{"ok": False, "code": "artifact_save_failed", "cleanup": "incomplete"}])
            self.assertEqual(host.requests[1]["status"], "failed")
            self.assertEqual(artifacts(work), [])
            self.assertEqual(descriptors(), before)

        try:
            run(body())
        finally:
            artifact_save_client._pwrite = original

    def late_copy(self, crossing, until=FAR, abort=None):
        """One save whose first write runs `crossing(clock)`, its writes 3
        bytes each: the report, the host's requests, the work root."""
        original = artifact_save_client._pwrite

        async def body():
            clock = ManualClock()
            _root, work, context = owned_context()
            reports = []

            def answer(connection, request):
                if request["type"] == "submit":
                    upload(os.path.join(work, ".agentbox-requests"), upload_name(SESSION, "req-1"), DATA)
                    connection.respond(fixture_ready())
                else:
                    connection.respond(closed_for(SUBMISSION, "c-1", "req-1", "recorded"))

            def write(fd, data, position):
                if position == 0:
                    crossing(clock)
                return original(fd, data[:3], position)

            artifact_save_client._pwrite = write
            host = MemoryHost(answer)
            status = await run_save_client_with(save_seams(host, clock, until), SUBMISSION, context,
                                                reports.append, abort)
            return status, reports, host, work

        try:
            return run(body())
        finally:
            artifact_save_client._pwrite = original

    def assert_upload_kept_copy_gone(self, work):
        self.assertEqual(artifacts(work), [])
        self.assertEqual(os.listdir(os.path.join(work, ".agentbox-requests")), [upload_name(SESSION, "req-1")])

    def test_the_requests_original_cutoff_bounds_the_copy(self):
        """Well inside the delivery's 60 s, the request's own cutoff passes
        during the copy (its wake not yet run): never kept, nothing applied."""
        def cross(clock):
            clock._now += 2 * MS_NS * 1000

        status, reports, host, work = self.late_copy(cross, until=1000 * MS_NS)
        self.assertEqual(status, EXIT_RUNTIME)
        self.assertEqual(reports, [{"ok": False, "code": "request_expired", "cleanup": "incomplete"}])
        self.assertEqual([request["type"] for request in host.requests], ["submit"])
        self.assert_upload_kept_copy_gone(work)

    def test_a_cancellation_scheduled_during_the_copy_runs_before_it_is_kept(self):
        """The abort is only scheduled on the event loop: the copy yields, so
        it runs and stops the copy before anything is kept."""
        abort = Abort()

        def cancel(_clock):
            asyncio.get_running_loop().call_soon(abort.abort)

        status, reports, host, work = self.late_copy(cancel, abort=abort)
        self.assertEqual(status, EXIT_INPUT_LOST)
        self.assertEqual(reports, [{"ok": False, "code": "request_cancelled", "cleanup": "incomplete"}])
        self.assertNotIn("result", [request["type"] for request in host.requests])
        self.assert_upload_kept_copy_gone(work)

    def test_a_denial_reports_the_hosts_reason_no_context_sends_nothing(self):
        async def body():
            clock = ManualClock()
            _root, _work, context = owned_context()
            reports = []
            host = MemoryHost(lambda c, _r: c.respond(closed_for(SUBMISSION, "c-1", "req-1", "denied", SESSION,
                                                                 "echo_refused")))
            status = await run_save_client_with(save_seams(host, clock), SUBMISSION, context, reports.append)
            self.assertEqual(status, EXIT_RUNTIME)
            self.assertEqual(reports, [{"ok": False, "code": "request_denied", "reason": "echo_refused",
                                        "cleanup": "incomplete"}])
            self.assertEqual(len(host.connections), 1)
            host = MemoryHost(lambda *_: None)
            reports = []
            status = await run_save_client_with(save_seams(host, clock), SUBMISSION, None, reports.append)
            self.assertEqual(status, EXIT_RUNTIME)
            self.assertEqual(reports, [{"ok": False, "code": "request_unavailable", "cleanup": "observed"}])
            self.assertEqual(host.connections, [])
            host = MemoryHost(lambda c, _r: c.refuse())
            reports = []
            await run_save_client_with(save_seams(host, clock), SUBMISSION, context, reports.append)
            self.assertEqual(reports, [{"ok": False, "code": "request_refused", "cleanup": "incomplete"}])
            self.assertEqual(len(host.connections), 1)

        run(body())


if __name__ == "__main__":
    unittest.main()
