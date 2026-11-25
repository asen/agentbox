"""The generic jail client of a handler without a jail module: one
`agentbox-request HANDLER OPERATION [ARGS]` submission over the artifact POST
(artifact_post_client.py), and the delivered artifact saved as is.

    submit --ready--> copy upload to WORK/agentbox-artifact-XXXXXX/artifact
                      (size and SHA-256 of the ready) --> result applied

The client knows no handler's semantics: the host's handler validates the
arguments and its worker produced the artifact and its metadata. The upload
directory `<work_root>/.agentbox-requests` is prepared before the submit.
After a `ready` bound to this submission, the one file its ids name,
`<session>-<request>.artifact`, is copied once from one open handle into a
fresh private directory under the working root, counted and hashed on the
way, within 60 s of the `ready` and never past the request's original cutoff,
both read before every chunk and once more before the copy is kept. The copy
yields to the event loop between chunks, so the request's cancellation and
cutoff timers run during it; a blocked disk call itself is not interrupted.
Only a copy of exactly the announced size and digest is kept; then the upload
is removed while its name still holds the inode read. `applied` claims only
that copy. One report names the copy's path, size, digest and the worker's
metadata, or a fixed code; a denial carries the host's reason, the lane's or
the handler worker's code.

Nothing here is host authority; the checks are transfer integrity against the
host's announcement, not protection from this guest. Cleanup is sticky
`incomplete` whenever a host upload may remain: a submit byte may have left
and this side did not confirm removing that file.
"""

import asyncio
import hashlib
import os
import shutil
import stat
import tempfile

from guest.src.artifact_post_client import PRODUCTION_SEAMS, UNKNOWN, Lane, run_request
from guest.src.artifact_post_clock import capture_request_deadline
from guest.src.artifact_post_context import prepare_upload_dir, upload_name
from guest.src.request_status import EXIT_INPUT_LOST, EXIT_OK, EXIT_PROTOCOL, EXIT_RUNTIME

# The copy's read and checks, from its `ready`; never renewed.
DELIVERY_TIMEOUT_MS = 60000
# The saved artifact's name within its fresh directory.
SAVED_NAME = "artifact"
SAVE_PREFIX = "agentbox-artifact-"
CHUNK_BYTES = 1048576
MS_NS = 1_000_000

# The writes the copy makes; library tests replace it.
_pwrite = os.pwrite


class SaveSeams:
    """Library tests only: the transport and the request clock."""

    def __init__(self, post, deadline):
        self.post = post
        self.deadline = deadline


PRODUCTION = SaveSeams(PRODUCTION_SEAMS, capture_request_deadline)


async def run_save_client(submission, context, report, abort=None):
    """One submission with the production transport; returns its exit status."""
    return await run_save_client_with(PRODUCTION, submission, context, report, abort)


class _Saved:
    __slots__ = ("ok", "path", "code", "removed", "file")

    def __init__(self, ok, removed, path=None, code=None, file=None):
        self.ok = ok
        self.removed = removed
        self.path = path
        self.code = code
        self.file = file


async def run_save_client_with(seams, submission, context, report, abort=None):
    """Library tests only: the same client on other seams. `report` gets one dict."""
    deadline = seams.deadline()
    clock = seams.post.clock

    def finish(code, status, cleanup="observed", reason=None):
        return _say(report, _failure(code, status, cleanup, reason))

    if context is None:
        return finish("request_unavailable", EXIT_RUNTIME)
    if abort is not None and abort.aborted:
        return finish("request_cancelled", EXIT_INPUT_LOST)
    if clock.now() >= deadline.until_ns:
        return finish("request_expired", EXIT_RUNTIME)
    directory = prepare_upload_dir(context)
    if directory is None:
        return finish("request_unavailable", EXIT_RUNTIME)

    async def apply(ready, signal):
        # The delivery's own bound, never past the request's original cutoff.
        until = min(deadline.until_ns, clock.now() + DELIVERY_TIMEOUT_MS * MS_NS)

        def late():
            return signal.aborted or clock.now() >= until

        name = upload_name(context.session, ready["request"]) or ""
        return await save_upload(os.path.join(directory, name), context.work_root, ready, late)

    lane = Lane(submission, lambda ready: upload_name(context.session, ready["request"]) is not None, apply,
                lambda saved: saved.ok)
    run = await run_request(context, lane, deadline.until_ns, seams.post, abort)
    outcome = run.outcome
    removed = outcome is not None and outcome is not UNKNOWN and outcome.removed
    cleanup = "observed" if run.upload == "none" or removed else "incomplete"
    terminal = run.terminal
    if (terminal["kind"] == "recorded" and terminal["status"] == "applied" and outcome is not None
            and outcome is not UNKNOWN and outcome.ok and run.ready is not None):
        ready = run.ready
        return _say(report, {"ok": True, "path": outcome.path, "size": ready["size"], "sha256": ready["sha256"],
                             "metadata": ready["metadata"], "cleanup": cleanup})
    code, status, reason = _reason(terminal, outcome)
    return finish(code, status, cleanup, reason)


async def save_upload(upload, parent, ready, late, prefix=SAVE_PREFIX):
    """Copies the upload into a fresh private directory beneath `parent`
    (`prefix` its name's start), then removes the upload by the inode read. Every write is looped to its end; a write that
    makes no progress fails. The copy is kept only when its own size, after
    the last write, is the announced one and it is not late. Both handles
    are closed on every path; a failed or cancelled copy's directory is
    removed; its upload stays."""
    source = target = None
    saved = None
    code = None
    identity = None
    closed = True
    try:
        try:
            try:
                source = os.open(upload, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError:
                code = "artifact_expired" if late() else "artifact_missing"
            if source is not None:
                info = os.fstat(source)
                if not stat.S_ISREG(info.st_mode):
                    code = "artifact_missing"
                elif info.st_size != ready["size"]:
                    code = "artifact_mismatch"
                else:
                    identity = (info.st_dev, info.st_ino)
                    saved = tempfile.mkdtemp(prefix=prefix, dir=parent)
                    target = os.open(os.path.join(saved, SAVED_NAME),
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                    code = await _copy(source, target, ready, late)
        except Exception:
            code = code or "artifact_save_failed"
        finally:
            for fd in (target, source):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        closed = False
    except BaseException:
        # Cancelled mid-copy: the partial copy goes, the upload stays.
        if saved is not None:
            shutil.rmtree(saved, ignore_errors=True)
        raise
    # The last check before the copy is kept and the upload removed.
    if code is None and late():
        code = "artifact_expired"
    if code is not None or not closed:
        if saved is not None:
            shutil.rmtree(saved, ignore_errors=True)
        return _Saved(False, False, code=code or "artifact_save_failed")
    removed = identity is not None and _remove_identity(upload, identity)
    return _Saved(True, removed, path=os.path.join(saved, SAVED_NAME))


async def save_upload_unnamed(upload, parent, ready, late):
    """save_upload's copy into a new unnamed file in `parent` (None: TMPDIR;
    tempfile.TemporaryFile: O_TMPFILE, else a fresh name unlinked at once,
    before any byte is written), kept open: `file` of the result, the
    caller's to close. Kept and the upload removed exactly as save_upload
    keeps a copy; any other end, a cancellation included, closes the file
    (nothing of it stays) and the upload stays."""
    source = None
    target = None
    code = None
    identity = None
    kept = False
    try:
        try:
            try:
                source = os.open(upload, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
            except OSError:
                code = "artifact_expired" if late() else "artifact_missing"
            if source is not None:
                info = os.fstat(source)
                if not stat.S_ISREG(info.st_mode):
                    code = "artifact_missing"
                elif info.st_size != ready["size"]:
                    code = "artifact_mismatch"
                else:
                    identity = (info.st_dev, info.st_ino)
                    target = tempfile.TemporaryFile(dir=parent, buffering=0)
                    code = await _copy(source, target.fileno(), ready, late)
        except Exception:
            code = code or "artifact_save_failed"
        finally:
            if source is not None:
                try:
                    os.close(source)
                except OSError:
                    code = code or "artifact_save_failed"
        # The last check before the copy is kept and the upload removed.
        if code is None and late():
            code = "artifact_expired"
        kept = code is None
    finally:
        if not kept and target is not None:
            target.close()
    if not kept:
        return _Saved(False, False, code=code)
    return _Saved(True, _remove_identity(upload, identity), file=target)


async def _copy(source, target, ready, late):
    """The failure's code, or None once the copy is exactly the announced
    bytes. Yields to the event loop before every chunk."""
    digest = hashlib.sha256()
    total = 0
    while True:
        await asyncio.sleep(0)
        if late():
            return "artifact_expired"
        data = os.pread(source, CHUNK_BYTES, total)
        if not data:
            break
        total += len(data)
        if total > ready["size"]:
            return "artifact_mismatch"
        digest.update(data)
        at = 0
        while at < len(data):
            if late():
                return "artifact_expired"
            written = _pwrite(target, data[at:], total - len(data) + at)
            if written <= 0:
                return "artifact_save_failed"
            at += written
    if total != ready["size"] or digest.hexdigest() != ready["sha256"]:
        return "artifact_mismatch"
    return None if os.fstat(target).st_size == ready["size"] else "artifact_save_failed"


def _remove_identity(path, identity):
    """Removes `path` only while it still names the inode read."""
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or (info.st_dev, info.st_ino) != identity:
            return False
        os.unlink(path)
        return True
    except OSError:
        return False


def _reason(terminal, outcome):
    """The first reason stands: a local failure before the result, then the request's end."""
    if outcome is UNKNOWN:
        return "request_failed", EXIT_RUNTIME, None
    kind = terminal["kind"]
    if outcome is not None and not outcome.ok and kind not in ("cancelled", "expired"):
        return outcome.code, EXIT_RUNTIME, None
    if kind == "closed":
        if terminal["outcome"] == "denied":
            return "request_denied", EXIT_RUNTIME, terminal.get("reason")
        return ("request_cancelled" if terminal["outcome"] == "cancelled" else "request_expired"), EXIT_RUNTIME, None
    if kind == "rejected":
        return ("request_busy" if terminal["code"] == "busy" else "request_submission_limit"), EXIT_RUNTIME, None
    return {
        "recorded": ("request_failed", EXIT_RUNTIME),
        "refused": ("request_refused", EXIT_RUNTIME),
        "invalid": ("request_invalid", EXIT_RUNTIME),
        "unavailable": ("request_unavailable", EXIT_RUNTIME),
        "lost": ("request_lost", EXIT_INPUT_LOST),
        "error": ("request_protocol", EXIT_PROTOCOL),
        "protocol": ("request_protocol", EXIT_PROTOCOL),
        "cancelled": ("request_cancelled", EXIT_INPUT_LOST),
        "expired": ("request_expired", EXIT_RUNTIME),
    }[kind] + (None,)


def _failure(code, status, cleanup, reason):
    fields = {"ok": False, "code": code}
    if reason is not None:
        fields["reason"] = reason
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
