"""The git handler's jail client (git.py): one clone or fetch submission over
the artifact POST (artifact_post_client.py), then the guest-local G3
application (application.py) of what the host delivered. It is always this
role.

One submission, no retry and no fallback to network Git. The request clock is
captured on entry and only ever shortened: the application gets the same
cutoff in its own clock domain, so G3's 600 s is a ceiling clipped by the
request, never an extension. Without the task's request context
(artifact_post_context.py) nothing is sent. The upload directory
`<work_root>/.agentbox-requests` is prepared before the submit. The client
submits only an operation and its arguments: a canonical repository and an
optional clone selector. A `ready` bound to this submission (its request
digest recomputed here) and its worker metadata (the delivery: a stock bundle
and the source's HEAD, or the empty marker) go to one fresh G3 `Application`
on the context's upload directory, which imports the upload with stock local
Git, checks the repository and applies the frozen clone or fetch plan with
local Git only. One status-only `result`: `applied` only after the
application's success, `failed` otherwise. Success needs a `closed`
`recorded` for it. Cancellation aborts the application, awaits it and sends
one cancel; nothing is ever resubmitted or sent twice.

Nothing here is host authority, and success is an untrusted guest claim.
Paths, remote names, refs and Git diagnostics stay local; the report has G3's
four fixed fields only. G3 removes the upload file only on its own success,
or a pull's that ended with Git's own failing exit; this side never removes it. So whenever a submit byte may have left
(`Run.upload`) and no G3 application succeeded, the host's upload may remain
and `cleanup` is `retained`, whatever G3 or any later answer, a recorded
cancel included, says. Guest cleanup is never host settlement.
"""

from acquisitions.git.jail.application import Application, Layout, delivery
from guest.src.artifact_post_client import PRODUCTION_SEAMS, UNKNOWN, Lane, run_request
from guest.src.artifact_post_clock import capture_request_deadline
from guest.src.artifact_post_context import prepare_upload_dir, upload_dir, upload_name
from guest.src.request_status import EXIT_INPUT_LOST, EXIT_OK, EXIT_PROTOCOL, EXIT_RUNTIME

# The git handler; upstream read operations only, there is no push. A pull
# submits a fetch; its local operation is `pull`.
HANDLER = "git"
GIT_OPERATIONS = ("clone", "fetch")

# The client's own fixed codes, beside G3's result codes.
CLIENT_CODES = (
    "git_client_invalid", "git_client_unavailable", "git_client_refused", "git_client_lost", "git_client_protocol",
    "git_client_failed", "git_request_busy", "git_request_submission_limit", "git_request_cancelled",
    "git_request_expired", "git_request_denied", "git_cancelled", "git_deadline_expired",
)


class GitClientSeams:
    """Library tests only: the transport and the application, `applier(context)`
    returning a coroutine function `(given, deadline, signal)`."""

    def __init__(self, post, applier):
        self.post = post
        self.applier = applier


def git_layout(context):
    """G3's layout on the context's upload directory."""
    return Layout("/", upload_dir(context))


def _production_applier(context):
    async def apply(given, deadline, signal):
        return await Application(given).run(deadline, signal, git_layout(context))

    return apply


PRODUCTION = GitClientSeams(PRODUCTION_SEAMS, _production_applier)


async def run_git_client(**options):
    """One submission with the production transport and G3 application; returns its exit status."""
    return await run_git_client_with(PRODUCTION, **options)


async def run_git_client_with(seams, operation, repository, local, context, report, selector=None, abort=None,
                              deadline=None):
    """Library tests only: the same client on other seams. `local` is the
    guest-local operation, never sent; `report` gets one dict; `deadline` is
    the caller's, captured before any local work."""
    # First: before anything else, unless the caller's own.
    deadline = deadline or capture_request_deadline()
    valid = (operation in GIT_OPERATIONS and isinstance(repository, str)
             and (selector is None or (operation == "clone" and isinstance(selector, str)))
             and isinstance(local, dict) and callable(report)
             and (local.get("operation") == operation or (operation, local.get("operation")) == ("fetch", "pull")))
    if not valid:
        try:
            if callable(report):
                report({"ok": False, "code": "git_client_invalid", "changes": "none", "cleanup": "observed"})
        except Exception:
            pass
        return EXIT_RUNTIME
    clock = seams.post.clock

    def finish(code, status):
        # Before the submit nothing was sent: no upload can exist.
        return _say(report, _failure((code, status, None), None, False))

    if context is None:
        return finish("git_client_unavailable", EXIT_RUNTIME)
    if abort is not None and abort.aborted:
        return finish("git_cancelled", EXIT_INPUT_LOST)
    if clock.now() >= deadline.until_ns:
        return finish("git_deadline_expired", EXIT_RUNTIME)
    if prepare_upload_dir(context) is None:
        return finish("git_client_unavailable", EXIT_RUNTIME)

    applier = seams.applier(context)
    args = {"repository": repository}
    if operation == "clone" and selector is not None:
        args["selector"] = selector

    def accept(ready):
        return delivery(ready["metadata"]) is not None and upload_name(context.session, ready["request"]) is not None

    async def apply(ready, signal):
        delivered = delivery(ready["metadata"])
        # Never applied: the upload stays.
        if delivered is None:
            return {"ok": False, "code": "git_application_invalid", "changes": "none", "cleanup": "retained"}
        # The ready's digest is this submission's, recomputed by the flow before any application.
        given = {"session": context.session, "request": ready["request"], "request_sha256": ready["request_sha256"],
                 "operation": operation, "repository": repository}
        if selector is not None:
            given["selector"] = selector
        given.update(delivery=delivered, size=ready["size"], sha256=ready["sha256"], local=local)
        return await applier(given, deadline.local_until, signal)

    lane = Lane({"handler": HANDLER, "operation": operation, "args": args}, accept, apply,
                lambda result: result["ok"])
    run = await run_request(context, lane, deadline.until_ns, seams.post, abort)
    outcome = run.outcome
    # Only a G3 success, or a pull's observed end, consumed the upload; otherwise
    # one may remain once a submit byte may have left.
    consumed = outcome is not None and outcome is not UNKNOWN and (
        outcome["ok"] or ("exit" in outcome and outcome["cleanup"] == "observed"))
    retained = run.upload == "possible" and not consumed
    terminal = run.terminal
    if terminal["kind"] == "recorded" and terminal["status"] == "applied" and consumed:
        return _say(report, {"ok": True, "code": outcome["code"], "changes": outcome["changes"],
                             "cleanup": "retained" if retained else outcome["cleanup"]})
    return _say(report, _failure(_reason(terminal, outcome), outcome, retained))


def _reason(terminal, outcome):
    """The first reason stands: the application's failure before the result,
    then the request's end. (code, status, reason); a pull's status is Git's
    own when it exited."""
    kind = terminal["kind"]
    if outcome is UNKNOWN:
        return "git_client_failed", EXIT_RUNTIME, None
    if outcome is not None and not outcome["ok"] and kind not in ("cancelled", "expired"):
        return outcome["code"], outcome.get("exit") or EXIT_RUNTIME, None
    if kind == "closed":
        code = {"denied": "git_request_denied", "cancelled": "git_request_cancelled"}.get(
            terminal["outcome"], "git_request_expired")
        return code, EXIT_RUNTIME, terminal.get("reason")
    if kind == "rejected":
        return ("git_request_busy" if terminal["code"] == "busy" else "git_request_submission_limit"), EXIT_RUNTIME, None
    return {
        "recorded": ("git_client_failed", EXIT_RUNTIME),
        "refused": ("git_client_refused", EXIT_RUNTIME),
        "invalid": ("git_client_unavailable", EXIT_RUNTIME),
        "unavailable": ("git_client_unavailable", EXIT_RUNTIME),
        "lost": ("git_client_lost", EXIT_INPUT_LOST),
        "error": ("git_client_protocol", EXIT_PROTOCOL),
        "protocol": ("git_client_protocol", EXIT_PROTOCOL),
        "cancelled": ("git_cancelled", EXIT_INPUT_LOST),
        "expired": ("git_deadline_expired", EXIT_RUNTIME),
    }[kind] + (None,)


def _failure(reason, outcome, retained):
    """The application's own fields when it ran, its cleanup downgraded to `retained` when an upload may remain."""
    code, status, why = reason
    changes = "none"
    cleanup = "retained" if retained else "observed"
    if outcome is UNKNOWN:
        changes, cleanup = "possible", "retained"
    elif outcome is not None:
        changes = outcome["changes"]
        if outcome["cleanup"] == "retained":
            cleanup = "retained"
    fields = {"ok": False, "code": code}
    if why is not None:
        fields["reason"] = why
    fields["changes"] = changes
    fields["cleanup"] = cleanup
    return fields, EXIT_RUNTIME if status == EXIT_OK else status


def _say(report, outcome):
    """Reports once; a raising report fails the status."""
    fields, status = outcome if isinstance(outcome, tuple) else (outcome, EXIT_OK)
    try:
        report(fields)
    except Exception:
        return EXIT_RUNTIME
    return status
