"""The Git lane's guest client and command dispatch over the artifact POST,
process-free and socket-free: memory doubles of the host (post_memory.py),
stand-ins for the G3 application, the remote resolution and the real Git, and
owned working roots that are kept. The test plays the host. No Git, network,
upload, fixed guest path or VM."""

import asyncio
import os
import unittest

from acquisitions.git.jail.application import Layout
from acquisitions.git.jail.dispatch import DispatchSeams, git_report_line, run_git_command_with
from acquisitions.git.jail.request_client import GitClientSeams, git_layout, run_git_client_with
from guest.src.abort import Abort
from guest.src.artifact_post_clock import RequestDeadline
from guest.src.request_status import EXIT_OK
from guest.test.deny import deny_processes
from guest.test.post_memory import (
    SESSION, ManualClock, MemoryHost, closed_for, install_socket_guard, owned_context, ready, seams_of,
)

S = 1_000_000_000
APPLIED = {"ok": True, "code": "git_applied", "changes": "possible", "cleanup": "observed"}
CLONE = {"handler": "git", "operation": "clone", "args": {"repository": "octocat/hello-world", "selector": "dev"}}
DELIVERY = {"handler": "git", "operation": "clone", "size": 4096, "sha256": "b" * 64,
            "metadata": {"format": "bundle", "head": "refs/heads/main"}}
_guards = []


def setUpModule():
    sockets = install_socket_guard()
    _guards.extend([deny_processes(), sockets, sockets.denied])


def tearDownModule():
    processes, sockets, before = _guards
    assert (processes.release(), sockets.denied - before) == (0, 0)


def applier(result):
    """An applier stand-in: records each input and its context, and answers
    `result` or, for "await-abort", waits for its abort."""
    seen = []

    def factory(context):
        async def apply(given, _deadline, signal):
            seen.append({"input": given, "signal": signal, "context": context})
            if result != "await-abort":
                return result
            done = asyncio.get_running_loop().create_future()
            signal.add_listener(lambda: done.done() or done.set_result(None))
            await done
            return {"ok": False, "code": "git_cancelled", "changes": "none", "cleanup": "observed"}

        return apply

    return factory, seen


def deadline(clock):
    """A deadline on the manual clock, far enough for every test."""
    return RequestDeadline(clock.now(), clock.now() + 1800 * S, float(2 ** 53))


class Client:
    def __init__(self, memory, clock, factory, **options):
        self.reports = []
        _root, self.work, self.context = owned_context()
        arguments = {"operation": "clone", "repository": "octocat/hello-world", "selector": "dev",
                     "local": {"operation": "clone", "destination": "/nowhere/hello-world"},
                     "context": self.context, "report": self.reports.append, "deadline": deadline(clock)}
        arguments.update(options)
        self.status = asyncio.ensure_future(
            run_git_client_with(GitClientSeams(seams_of(memory, clock), factory), **arguments))


def host(**answers):
    """A host answering by request type; records each request."""
    def answer(connection, request):
        assert request is not None, "canonical request"
        if request["type"] in answers:
            answers[request["type"]](connection, request)

    return MemoryHost(answer)


def soon(action):
    asyncio.get_running_loop().call_soon(action)


class LaneTest(unittest.IsolatedAsyncioTestCase):
    async def test_a_clone_is_applied_from_its_submission_and_bound_ready(self):
        clock = ManualClock()
        factory, seen = applier(APPLIED)
        memory = host(submit=lambda c, _r: c.respond(ready(CLONE, "c-1", "req-1", DELIVERY)),
                      result=lambda c, _r: c.respond(closed_for(CLONE, "c-1", "req-1", "recorded")))
        run = Client(memory, clock, factory)
        self.assertEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports, [APPLIED])
        # The POST submit: only the operation, canonical repository and selector.
        self.assertEqual(memory.requests[0], dict({"v": 1, "type": "submit", "session": SESSION, "client": "c-1"},
                                                  **CLONE))
        (applied,) = seen
        bound = ready(CLONE, "c-1", "req-1", DELIVERY)
        self.assertEqual(applied["input"], {
            "session": SESSION, "request": "req-1", "request_sha256": bound["request_sha256"], "operation": "clone",
            "repository": "octocat/hello-world", "selector": "dev",
            "delivery": {"format": "bundle", "head": "refs/heads/main"}, "size": DELIVERY["size"],
            "sha256": DELIVERY["sha256"], "local": {"operation": "clone", "destination": "/nowhere/hello-world"},
        })
        # The dynamic layout: the context's upload directory, prepared before the submit.
        self.assertEqual(applied["context"], run.context)
        layout = git_layout(applied["context"])
        self.assertEqual((layout.root, layout.uploads), ("/", os.path.join(run.work, ".agentbox-requests")))
        self.assertEqual(os.lstat(layout.uploads).st_mode & 0o777, 0o700)
        # The result echoes the ready's bindings.
        self.assertEqual(memory.requests[1], {"v": 1, "type": "result", "session": SESSION, "client": "c-1",
                                              "request": "req-1", "request_sha256": bound["request_sha256"],
                                              "sha256": DELIVERY["sha256"], "status": "applied"})

    async def test_a_fetch_submits_no_selector_denials_and_failures_report_their_codes(self):
        clock = ManualClock()
        fetch = {"handler": "git", "operation": "fetch", "args": {"repository": "octocat/hello-world"}}
        factory, seen = applier(APPLIED)
        memory = host(submit=lambda c, _r: c.respond(ready(fetch, "c-1", "req-2", dict(DELIVERY, operation="fetch"))),
                      result=lambda c, _r: c.respond(closed_for(fetch, "c-1", "req-2", "recorded")))
        run = Client(memory, clock, factory, operation="fetch", selector=None,
                     local={"operation": "fetch", "directory": "/nowhere/hello-world", "remote": "origin"})
        self.assertEqual(await run.status, EXIT_OK)
        self.assertEqual(memory.requests[0], dict({"v": 1, "type": "submit", "session": SESSION, "client": "c-1"},
                                                  **fetch))
        self.assertEqual(seen[0]["input"]["local"]["operation"], "fetch")
        # Denied: nothing applied.
        factory, seen = applier(APPLIED)
        memory = host(submit=lambda c, _r: c.respond(closed_for(CLONE, "c-1", "req-1", "denied")))
        run = Client(memory, clock, factory)
        self.assertNotEqual(await run.status, EXIT_OK)
        # Sent, then closed: no proof the host's upload is gone, so retained.
        self.assertEqual(run.reports, [{"ok": False, "code": "git_request_denied", "reason": "fake_denied",
                                        "changes": "none", "cleanup": "retained"}])
        self.assertEqual(seen, [])
        # Busy: nothing applied.
        memory = host(submit=lambda c, _r: c.respond({"v": 1, "type": "rejected", "session": SESSION,
                                                      "client": "c-1", "code": "busy"}))
        run = Client(memory, clock, factory)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports[0]["code"], "git_request_busy")
        # A failed application claims failed and reports its own fields.
        failing = {"ok": False, "code": "git_tag_conflict", "changes": "none", "cleanup": "observed"}
        factory, seen = applier(failing)
        memory = host(submit=lambda c, _r: c.respond(ready(CLONE, "c-1", "req-1", DELIVERY)),
                      result=lambda c, _r: c.respond(closed_for(CLONE, "c-1", "req-1", "recorded")))
        run = Client(memory, clock, factory)
        self.assertNotEqual(await run.status, EXIT_OK)
        # G3 removes the upload only on its own success: after its failure it may remain.
        self.assertEqual(run.reports, [dict(failing, cleanup="retained")])
        self.assertEqual(memory.requests[1]["status"], "failed")

    async def test_a_pull_is_a_fetch_whose_failing_exit_is_gits_own_status(self):
        clock = ManualClock()
        fetch = {"handler": "git", "operation": "fetch", "args": {"repository": "octocat/hello-world"}}
        local = {"operation": "pull", "directory": "/nowhere/hello-world", "remote": "origin",
                 "branch": "refs/heads/main", "flag": None, "global": {}}
        for outcome, status, report, result in (
                (dict(APPLIED, exit=0), EXIT_OK, APPLIED, "applied"),
                # A conflict: Git's own status; the upload consumed by an observed end.
                ({"ok": False, "code": "git_pull_failed", "changes": "possible", "cleanup": "observed", "exit": 1},
                 1, {"ok": False, "code": "git_pull_failed", "changes": "possible", "cleanup": "observed"}, "failed"),
                # An uncertain end: no exit, staging kept.
                ({"ok": False, "code": "git_cleanup_incomplete", "changes": "possible", "cleanup": "retained"},
                 3, {"ok": False, "code": "git_cleanup_incomplete", "changes": "possible", "cleanup": "retained"},
                 "failed")):
            factory, seen = applier(outcome)
            memory = host(submit=lambda c, _r: c.respond(ready(fetch, "c-1", "req-2",
                                                               dict(DELIVERY, operation="fetch"))),
                          result=lambda c, _r: c.respond(closed_for(fetch, "c-1", "req-2", "recorded")))
            run = Client(memory, clock, factory, operation="fetch", selector=None, local=local)
            self.assertEqual(await run.status, status)
            self.assertEqual(run.reports, [report])
            self.assertEqual(memory.requests[0]["operation"], "fetch")
            self.assertEqual((seen[0]["input"]["operation"], seen[0]["input"]["local"]), ("fetch", local))
            self.assertEqual(memory.requests[1]["status"], result)
        # Only a fetch carries a pull.
        factory, seen = applier(APPLIED)
        run = Client(host(), clock, factory, local=local)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports[0]["code"], "git_client_invalid")

    async def test_cancelling_during_application_aborts_awaits_and_sends_one_cancel(self):
        clock = ManualClock()
        factory, seen = applier("await-abort")
        abort = Abort()

        def submit(connection, _request):
            connection.respond(ready(CLONE, "c-1", "req-1", DELIVERY))
            soon(abort.abort)

        memory = host(submit=submit,
                      cancel=lambda c, _r: c.respond(closed_for(CLONE, "c-1", "req-1", "cancelled")))
        run = Client(memory, clock, factory, abort=abort)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports[0]["code"], "git_cancelled")
        self.assertTrue(seen[0]["signal"].aborted)
        self.assertEqual([request["type"] for request in memory.requests], ["submit", "cancel"])

    async def test_a_lost_ready_or_an_aborted_sent_submit_never_applies_and_retains(self):
        clock = ManualClock()
        factory, seen = applier(APPLIED)
        # The connection is lost after the submit: any completed upload stays unclaimed.
        memory = host(submit=lambda c, _r: c.close())
        run = Client(memory, clock, factory)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports, [{"ok": False, "code": "git_client_lost", "changes": "none",
                                        "cleanup": "retained"}])
        self.assertEqual(len(memory.connections), 1)
        # Aborted after the submit was sent, before any ready: no cancel POST, retained.
        abort = Abort()
        memory = host(submit=lambda _c, _r: soon(abort.abort))
        run = Client(memory, clock, factory, abort=abort)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports, [{"ok": False, "code": "git_cancelled", "changes": "none",
                                        "cleanup": "retained"}])
        self.assertEqual(len(memory.connections), 1)
        # Aborted before anything was sent: locally proven unsent, observed.
        before = Abort()
        before.abort()
        memory = host()
        run = Client(memory, clock, factory, abort=before)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports, [{"ok": False, "code": "git_cancelled", "changes": "none",
                                        "cleanup": "observed"}])
        self.assertEqual(len(memory.connections), 0)
        self.assertEqual(seen, [])

    async def test_a_refusal_a_foreign_ready_or_no_context_never_applies_or_retries(self):
        clock = ManualClock()
        factory, seen = applier(APPLIED)
        memory = host(submit=lambda c, _r: c.refuse())
        run = Client(memory, clock, factory)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports[0]["code"], "git_client_refused")
        self.assertEqual(len(memory.connections), 1)
        # A ready digested for another selector is not this submission's.
        other = dict(CLONE, args={"repository": "octocat/hello-world", "selector": "main"})
        memory = host(submit=lambda c, _r: c.respond(ready(other, "c-1", "req-1", DELIVERY)),
                      cancel=lambda c, _r: c.respond({"v": 1, "type": "error", "code": "not_active"}))
        run = Client(memory, clock, factory)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports[0]["code"], "git_client_protocol")
        self.assertEqual(seen, [])
        self.assertEqual([request["type"] for request in memory.requests], ["submit", "cancel"])
        # No context: nothing is sent.
        memory = host()
        run = Client(memory, clock, factory, context=None)
        self.assertNotEqual(await run.status, EXIT_OK)
        self.assertEqual(run.reports, [{"ok": False, "code": "git_client_unavailable", "changes": "none",
                                        "cleanup": "observed"}])
        self.assertEqual(len(memory.connections), 0)


async def dispatch(context, args, resolved="octocat/hello-world", environ=None, upstream=None):
    """The dispatch with `context` and recording stand-ins: (status, calls)."""
    calls = {"pass_through": [], "resolve": [], "upstream": [], "client": [], "lines": []}

    async def resolve(_start, _remote, _deadline, _signal, layout):
        calls["resolve"].append(layout)
        return {"ok": True, "repository": resolved}

    async def resolve_upstream(start, _deadline, _signal, layout, given):
        calls["upstream"].append((start, layout, given))
        return upstream or {"ok": True, "repository": resolved, "remote": "upstream", "branch": "refs/heads/dev",
                            "global": {"user.name": "Fixture"}}

    async def client(**options):
        calls["client"].append(options)
        return EXIT_OK

    async def pass_through(items):
        calls["pass_through"].append(items)
        return 7

    status = await run_git_command_with(DispatchSeams(client, resolve, resolve_upstream), args, "/work", context,
                                        calls["lines"].append, pass_through, environ=environ)
    return status, calls


class DispatchTest(unittest.IsolatedAsyncioTestCase):
    async def test_push_and_unsupported_remote_forms_refuse_with_no_request(self):
        for context in (None, owned_context()[2]):
            for args, code in ((["push"], "git_push_refused"),
                               (["-C", "repo", "push", "origin", "main"], "git_push_refused"),
                               (["send-pack", "x"], "git_push_refused"), (["lfs", "push"], "git_push_refused"),
                               (["pull", "origin"], "git_arguments_invalid"), (["pull", "-r"], "git_option_unsupported"),
                               (["ls-remote", "origin"], "git_command_unsupported"),
                               (["remote", "update"], "git_command_unsupported"),
                               (["fetch", "--all"], "git_option_unsupported"),
                               (["-c", "x=y", "fetch"], "git_option_unsupported"),
                               (["fetch", "origin", "main"], "git_arguments_invalid"),
                               (["fetch", "https://github.com/a/b"], "git_remote_unsupported"),
                               (["clone", "git@github.com:a/b.git"], "git_url_unsupported"),
                               (["clone", "https://gitlab.com/a/b"], "git_url_unsupported"),
                               (["clone", "--depth", "1", "https://github.com/a/b"], "git_option_unsupported"),
                               (["clone", "-b", "-x", "https://github.com/a/b"], "git_selector_invalid")):
                status, calls = await dispatch(context, args)
                self.assertEqual(status, 1, args)
                self.assertEqual(calls["lines"], [git_report_line({"ok": False, "code": code, "changes": "none",
                                                                   "cleanup": "observed"})])
                self.assertEqual((calls["pass_through"], calls["resolve"], calls["upstream"], calls["client"]),
                                 ([], [], [], []), args)

    async def test_local_commands_pass_through_clone_and_fetch_submit_only_canonical_data(self):
        _root, work, context = owned_context()
        for args in (["status"], ["-C", "x", "log", "--oneline"], ["remote", "add", "origin", "https://github.com/a/b"],
                     ["--version"], []):
            for each in (context, None):
                status, calls = await dispatch(each, args)
                self.assertEqual(status, 7)
                self.assertEqual(calls["pass_through"], [args])
                self.assertEqual((len(calls["resolve"]), len(calls["client"]), calls["lines"]), (0, 0, []))
        # A clone: repository and selector to the client; its destination local.
        status, calls = await dispatch(context, ["-C", "src", "clone", "--branch", "v1",
                                                 "https://github.com/Octocat/Hello-World.git"])
        self.assertEqual(status, EXIT_OK)
        (options,) = calls["client"]
        self.assertEqual((options["operation"], options["repository"], options["selector"], options["local"],
                          options["context"]),
                         ("clone", "octocat/hello-world", "v1",
                          {"operation": "clone", "destination": "/work/src/Hello-World"}, context))
        self.assertEqual(calls["resolve"], [])
        # A fetch: the remote resolved locally in the context's upload directory, only its repository submitted.
        status, calls = await dispatch(context, ["-C", "src/hello", "fetch", "upstream"], "rust-lang/rust")
        self.assertEqual(status, EXIT_OK)
        (fetched,) = calls["client"]
        self.assertEqual((fetched["operation"], fetched["repository"], fetched.get("selector"), fetched["local"]),
                         ("fetch", "rust-lang/rust", None,
                          {"operation": "fetch", "directory": "/work/src/hello", "remote": "upstream"}))
        (layout,) = calls["resolve"]
        self.assertIsInstance(layout, Layout)
        self.assertEqual((layout.root, layout.uploads), ("/", os.path.join(work, ".agentbox-requests")))
        self.assertTrue(os.path.isdir(os.path.join(work, ".agentbox-requests")))
        # Without a context, a fetch neither reads the repository nor submits.
        status, calls = await dispatch(None, ["fetch"])
        self.assertEqual(status, 3)
        self.assertEqual((len(calls["resolve"]), len(calls["client"])), (0, 0))
        self.assertEqual(calls["lines"], [git_report_line({"ok": False, "code": "git_client_unavailable",
                                                           "changes": "none", "cleanup": "observed"})])
        # A clone without one goes to the client, which sends nothing.
        status, calls = await dispatch(None, ["clone", "https://github.com/a/b"])
        self.assertEqual(status, EXIT_OK)
        self.assertIsNone(calls["client"][0]["context"])

    async def test_a_pull_submits_its_upstreams_repository_as_a_fetch(self):
        _root, work, context = owned_context()
        environ = {"HOME": "/home/x", "PATH": "/bin"}
        status, calls = await dispatch(context, ["-C", "src", "pull", "--rebase"], "rust-lang/rust", environ)
        self.assertEqual(status, EXIT_OK)
        (pulled,) = calls["client"]
        self.assertEqual((pulled["operation"], pulled["repository"], pulled.get("selector"), pulled["local"]),
                         ("fetch", "rust-lang/rust", None,
                          {"operation": "pull", "directory": "/work/src", "remote": "upstream",
                           "branch": "refs/heads/dev", "flag": "--rebase", "global": {"user.name": "Fixture"}}))
        ((start, layout, given),) = calls["upstream"]
        self.assertEqual((start, layout.uploads, given), ("/work/src", os.path.join(work, ".agentbox-requests"),
                                                          environ))
        self.assertEqual(calls["resolve"], [])
        # An unresolved upstream submits nothing.
        status, calls = await dispatch(context, ["pull"], upstream={"ok": False, "code": "git_remote_unsupported",
                                                                    "cleanup": "observed"})
        self.assertEqual((status, calls["client"]), (3, []))
        self.assertEqual(calls["lines"], [git_report_line({"ok": False, "code": "git_remote_unsupported",
                                                           "changes": "none", "cleanup": "observed"})])
        # Without a context nothing is read.
        status, calls = await dispatch(None, ["pull"])
        self.assertEqual((status, calls["upstream"], calls["client"]), (3, [], []))


if __name__ == "__main__":
    unittest.main()
