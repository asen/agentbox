"""The mediated acquisition lane of one execution (docs/artifact-requests.md,
acquisitions/contracts/handlers/v1, acquisitions/contracts/artifacts/post-v1), over the server's four
commands (docs/server-protocol.md): the Python owner of what the Rust
lane, driver and handler caller decided in the old CLI.

```text
server post.request  submit  grant (256, every attributable one) -> busy |
                             handler/operation/args/byte checks -> closed denied
                             -> claim: req-N, the whole remaining http allowance
                                reserved, one worker:
                     INTERPRETER -I -B ENTRY acquire STAGE/request.json
                     (own group; managed: a fresh leaf of D)
                     exit 0 and one result line: `acquired` settles the
                     charge, provenance recorded; ok: STAGE/artifact private
                     regular of the stated size -> renamed SPOOL/req-N.artifact
                     (0400); any other exit: worker_failed, charge kept
                     -> deliver(exchange, req-N, name, size, sha256)
                     result ok -> respond ready; else closed denied upload_failed
                     the spool file removed after the deliver result
                     cancel  -> worker killed, closed cancelled (both exchanges)
                     result  -> bound to the ready post.ended `written` proved
                                -> closed recorded
server post.ended    the waiting submit's peer gone: worker killed; a ready's
                     write outcome (written | lost)
every terminal end   revoke(req-N): the server's active request freed
deadline             admission + 1800 s, capped by the execution's cutoff
                     (untimed: none, the 1800 s alone; the server bounds
                     each exchange the same): closed expired; acquisition:
                     the manifest's seconds
```

One active request; no queue, no retry. A never-started worker refunds its
reservation (spawn refused: proof); one that started and did not exit 0
with a valid line keeps it. A worker's stage is removed once its group is
reaped and (managed) its leaf read empty; an unsettled leaf keeps it.
Git (`none` metering) is outside the allowance. Workers get their
allowance and deadline in the request file, so they keep both if this
controller dies; only Git's helpers have no independent deadline and may
outlive an attached execution's worker group (a managed one's die with D).
No artifact byte is hashed here: the worker's digest is its trusted claim,
the guest checks content. Capture: ordinary records keep LANE_RESERVE free
for the lane; a lane record that no longer fits closes the lane
(`capture_full`): its active request cancelled, later submissions
`rejected submission_limit`, cancels and results still answered.

```text
teardown  close    no new request, the active one ended (worker reaped,
                   revoke), results awaited <= 2 s (not after a forced stop)
          ... server shutdown, managed: D killed ...
          dispose  late results taken; the spool removed only if nothing can
                   still use it: no upload without its result unless the
                   server stopped clean, no unsettled leaf; or D read empty.
                   Else kept: its reservation stays in the execution record
```
"""
import json
import os
import re
import secrets
import selectors
import shutil
import stat
import time

from .assets import post_codec
from .host import Child, Drain, HostError, read_some, tool_env
from .store import absent

REQUEST_TIMEOUT = 1800.0
REQUEST_TIMEOUT_MS = 1800000
MAX_REQUESTS = 256
MAX_ACQUIRED_BYTES = 2 << 30
MAX_WORKER_OUTPUT = 256 * 1024
MAX_REQUEST_FILE = 256 * 1024
MAX_PROVENANCE = 256
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_ARTIFACT_BYTES = 2 << 30
# The capture kept for the lane's records (Rust: 64 KiB lifecycle +
# 288 records x 1 KiB + one worst-case provenance record).
LANE_RESERVE = 506112
CLOSE_TIMEOUT = 2.0
REQUEST_SCHEMA = "agentbox.handler-request.v1"
RESULT_SCHEMA = "agentbox.handler-result.v1"
# Test builds only (tests/controller/launch.py): the request file's `test` object.
TEST_SEAM = None
_SHA = re.compile(r"[0-9a-f]{64}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]*")
# A package's version, or (pip) a file's name.
_VERSION = re.compile(r"[A-Za-z0-9.+!_-]{1,256}")


def _integrity(text):
    for prefix, length in (("sha512-", 88), ("sha256-", 44), ("sha1-", 28)):
        if isinstance(text, str) and text.startswith(prefix):
            body = text[len(prefix):]
            padding = len(body) - len(body.rstrip("="))
            return len(body) == length and padding <= 2 \
                and re.fullmatch(r"[A-Za-z0-9+/]*", body[:length - padding]) is not None
    return False


def _package(name):
    if not isinstance(name, str) or not name or len(name) > 214:
        return False
    if name.startswith("@"):
        scope, sep, rest = name[1:].partition("/")
        return bool(sep) and bool(_PART.fullmatch(scope)) and bool(_PART.fullmatch(rest))
    return bool(_PART.fullmatch(name))


def result_line(output, metadata_bytes, allowance):
    """The worker's one line (acquisition/effects/worker.rs `result_line`):
    (outcome dict, acquired or None, provenance lines), else None."""
    from .handlers import strict_object
    if len(output) > MAX_WORKER_OUTPUT or not output.endswith(b"\n") or output.count(b"\n") != 1:
        return None
    try:
        value = strict_object(output[:-1], MAX_WORKER_OUTPUT)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    acquired = value.pop("acquired", None)
    if allowance is not None:
        if type(acquired) is not int or not 0 <= acquired <= allowance:
            return None
    elif "acquired" in value or acquired is not None:
        return None
    provenance = value.pop("provenance", [])
    if not isinstance(provenance, list) or len(provenance) > MAX_PROVENANCE:
        return None
    lines = []
    for entry in provenance:
        if not isinstance(entry, dict) or set(entry) != {"name", "version", "integrity"} \
                or not _package(entry["name"]) or not isinstance(entry["version"], str) \
                or not _VERSION.fullmatch(entry["version"]) or not _integrity(entry["integrity"]):
            return None
        lines.append(f"{entry['name']} {entry['version']} {entry['integrity']}")
    if value.get("schema") != RESULT_SCHEMA:
        return None
    if value.get("outcome") == "ok" and set(value) == {"schema", "outcome", "size", "sha256", "metadata"}:
        size, sha, metadata = value["size"], value["sha256"], value["metadata"]
        if type(size) is not int or not 1 <= size <= MAX_SAFE_INTEGER or not isinstance(sha, str) \
                or not _SHA.fullmatch(sha) or not isinstance(metadata, dict) \
                or not post_codec.keys_valid(metadata) \
                or len(post_codec.canonical_value(metadata).encode()) > metadata_bytes:
            return None
        return value, acquired, lines
    if value.get("outcome") == "error" and set(value) == {"schema", "outcome", "code"} and not provenance \
            and isinstance(value["code"], str) and _CODE.fullmatch(value["code"]):
        return value, acquired, lines
    return None


class Request:
    def __init__(self, ident, client, submission, request_sha256, exchange, admitted, deadline):
        self.id, self.client, self.request_sha256 = ident, client, request_sha256
        self.handler, self.operation = submission["handler"], submission["operation"]
        self.args = submission["args"]
        self.exchange, self.admitted, self.deadline = exchange, admitted, deadline
        self.answered = False
        self.attempted = False
        self.reserved = None
        self.acquired = 0
        self.worker = None
        self.leaf = None
        self.stage = None
        self.output = bytearray()
        self.output_ended = False
        self.drain = None
        self.work_deadline = None
        self.artifact = None
        self.deliver = None
        self.delivery_done = False
        self.spool_name = None
        self.ready_written = None
        self.status = None
        self.end = None
        self.reason = None
        self.uploaded = False
        self.guest = None


class Lane:
    """One execution's lane. `ctx`: the execution (loop, server, capture,
    run/execution ids, cutoff, `leaf()`/`kill_leaf(name)`)."""

    def __init__(self, ctx, selection, nonce, spool):
        self.ctx, self.selection, self.nonce, self.spool = ctx, selection, nonce, spool
        self.submissions = 0
        self.attempts = 0
        self.charged = 0
        self.records = []
        self.active = None
        self.closing = None
        self.commands = {}
        self.retained = []
        self.provenance = 0
        self.uploads = 0
        # A lane step that could not be carried out (no answer sendable).
        self.failed = False
        # The spool confirmed removed (dispose).
        self.released = False

    # -- capture ----------------------------------------------------------

    def note(self, kind, severity="info", closing=False, **attributes):
        """A lane record; one that does not fit closes the lane."""
        kept = self.ctx.capture.record("host.supervisor", kind, severity, attributes, closing=closing, lane=True)
        if not kept and not closing and self.closing is None:
            self.close_lane("capture_full")
        return kept

    # -- answers ----------------------------------------------------------

    def respond(self, exchange, response, then=None):
        try:
            body = post_codec.encode_response(dict(response, v=1)).decode("utf-8", "surrogatepass")
        except post_codec.Refused:
            raise HostError("internal") from None
        ident = self.ctx.server.command("respond", exchange=exchange, body=body)
        self.commands[ident] = then
        return ident

    def rejected(self, exchange, client, code):
        self.respond(exchange, {"type": "rejected", "session": self.nonce, "client": client, "code": code})

    def closed(self, request, exchange, outcome, reason=None):
        response = {"type": "closed", "session": self.nonce, "client": request.client, "request": request.id,
                    "request_sha256": request.request_sha256, "handler": request.handler, "outcome": outcome}
        if reason is not None:
            response["reason"] = reason
        self.respond(exchange, response)

    def error(self, exchange, code):
        self.respond(exchange, {"type": "error", "code": code})

    # -- the loop's pass --------------------------------------------------

    def pump(self):
        server = self.ctx.server
        if server.post_closed and self.closing is None:
            self.close_lane("post_closed")
        for message in server.take_posts():
            if message["type"] == "post.request":
                self.post(message)
            else:
                self.ended(message)
        for ident in list(self.commands):
            result = server.take_result(ident)
            if result is not None:
                then = self.commands.pop(ident)
                if then is not None:
                    then(result)
        request = self.active
        if request is not None:
            self.progress(request)

    def post(self, message):
        try:
            body = post_codec.decode_request(message.get("body", "").encode("utf-8", "surrogatepass"))
        except (post_codec.Refused, AttributeError):
            # The server decoded it already: its canonical body or a fault.
            raise HostError("server_unexpected") from None
        exchange = message.get("exchange")
        if type(exchange) is not int or body["session"] != self.nonce:
            raise HostError("server_unexpected")
        kind = body["type"]
        if kind == "submit":
            self.submit(exchange, body, message.get("replay") is True)
        elif kind == "cancel":
            self.cancel(exchange, body["client"])
        else:
            self.result(exchange, body)

    def submit(self, exchange, body, replay):
        client = body["client"]
        submission = {"handler": body["handler"], "operation": body["operation"], "args": body["args"]}
        if self.closing is not None or self.submissions >= MAX_REQUESTS:
            return self.rejected(exchange, client, "submission_limit")
        self.submissions += 1
        if replay or self.active is not None:
            return self.rejected(exchange, client, "busy")
        now = time.monotonic()
        request = Request(f"req-{len(self.records) + 1}", client, submission,
                          post_codec.request_sha256(client, submission), exchange, now,
                          min(now + REQUEST_TIMEOUT, self.ctx.deadline))
        self.records.append(request)
        handler = self.selection.handlers.get(request.handler)
        reason = None
        if handler is None:
            reason = "handler_unknown"
        elif request.operation not in handler.operations:
            reason = "operation_unknown"
        elif request.operation not in handler.permitted:
            reason = "operation_denied"
        elif len(post_codec.canonical_value(request.args).encode()) > handler.limits["args_bytes"]:
            reason = "args_too_large"
        elif handler.metering == "http" and MAX_ACQUIRED_BYTES - self.charged <= 0:
            reason = "byte_limit"
        if reason is not None:
            return self.finish(request, "denied", reason)
        self.active = request
        self.start(request, handler)

    def start(self, request, handler):
        """Counted before any effect; the reservation charged at once."""
        self.attempts += 1
        request.attempted = True
        if handler.metering == "http":
            request.reserved = MAX_ACQUIRED_BYTES - self.charged
            self.charged += request.reserved
        now = time.monotonic()
        request.work_deadline = min(now + handler.limits["acquisition_seconds"], request.deadline)
        try:
            stage = os.path.join(self.spool, f"stage-{request.id}-{secrets.token_hex(8)}")
            os.mkdir(stage, 0o700)
            request.stage = stage
            file = {"schema": REQUEST_SCHEMA, "handler": handler.id, "version": handler.version,
                    "operation": request.operation, "args": request.args, "policy": handler.policy,
                    "ids": {"run": self.ctx.run_id, "execution": self.ctx.execution_id, "session": self.nonce,
                            "request": request.id, "request_sha256": request.request_sha256},
                    "stage": stage, "artifact": f"{stage}/artifact",
                    "remaining_ms": max(0, int((request.work_deadline - now) * 1000)),
                    "tools": dict(handler.tools), "limits": {"metadata_bytes": handler.limits["metadata_bytes"]}}
            if request.reserved is not None:
                file["limits"]["acquire_bytes"] = request.reserved
            if TEST_SEAM is not None:
                file["test"] = TEST_SEAM
            data = json.dumps(file, separators=(",", ":")).encode()
            if len(data) > MAX_REQUEST_FILE:
                raise HostError("handler_request_invalid")
            fd = os.open(f"{stage}/request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600)
            try:
                os.write(fd, data)
            finally:
                os.close(fd)
        except OSError:
            return self.never_started(request, "staging_failed")
        except HostError as error:
            return self.never_started(request, error.code)
        leaf = self.ctx.leaf()
        try:
            request.worker = Child([self.selection.interpreter, "-I", "-B", self.selection.entry(handler),
                                    "acquire", f"{stage}/request.json"], tool_env(),
                                   leaf=None if leaf is None else leaf[0], stdin=False)
        except HostError:
            return self.never_started(request, "worker_failed")
        finally:
            if leaf is not None:
                os.close(leaf[0])
        request.leaf = None if leaf is None else leaf[1]
        stdout = request.worker.popen.stdout.fileno()
        request.drain = Drain(self.ctx.loop, request.worker.popen.stderr.fileno(), 65536)

        def read(_mask):
            chunk = read_some(stdout)
            if chunk is None:
                return
            if not chunk:
                request.output_ended = True
                self.ctx.loop.unwatch(stdout)
                return
            request.output += chunk[:MAX_WORKER_OUTPUT + 1 - len(request.output)]

        self.ctx.loop.watch(stdout, selectors.EVENT_READ, read)
        self.note("host.handler.started", request=request.id, handler=request.handler,
                  operation=request.operation)

    def never_started(self, request, reason):
        """No worker ran: its reservation refunded."""
        if request.reserved is not None:
            self.charged -= request.reserved
            request.reserved = None
        self.remove_stage(request)
        self.finish(request, "denied", reason)

    # -- progress ---------------------------------------------------------

    def progress(self, request):
        now = time.monotonic()
        if request.worker is not None:
            if request.output_ended and request.worker.exited():
                self.collect(request)
            elif now >= request.work_deadline or now >= request.deadline:
                self.stop_worker(request)
                self.finish(request, "expired" if now >= request.deadline else "denied",
                            None if now >= request.deadline else "acquisition_expired")
        elif request.end is None and now >= request.deadline:
            self.finish(request, "expired")

    def stop_worker(self, request, keep_stage=False):
        """Its group killed and reaped (its status kept), its leaf killed
        (managed: unsettled, the request is `retained`); its stage removed
        unless kept for the handoff; a started worker without a line keeps
        its charge."""
        worker = request.worker
        if worker is None:
            return
        self.ctx.loop.unwatch(worker.popen.stdout.fileno())
        request.drain.close()
        if not worker.exited():
            worker.kill_group()
        request.status = worker.finish()
        request.worker = None
        if request.leaf is not None:
            if not self.ctx.kill_leaf(request.leaf):
                self.retained.append(request.id)
        if not keep_stage:
            self.remove_stage(request)

    def collect(self, request):
        handler = self.selection.handlers[request.handler]
        output = bytes(request.output)
        self.stop_worker(request, keep_stage=True)
        if request.id in self.retained:
            # A process of its leaf may still write the stage.
            return self.finish(request, "denied", "worker_unsettled")
        line = None
        if request.status == 0:
            line = result_line(output, handler.limits["metadata_bytes"], request.reserved)
        if line is None:
            self.remove_stage(request)
            return self.finish(request, "denied", "worker_failed")
        value, acquired, provenance = line
        if request.reserved is not None:
            self.charged -= request.reserved - acquired
            request.acquired = acquired
            request.reserved = None
        if provenance:
            self.provenance += 1
            self.note("host.handler.provenance", request=request.id, handler=request.handler,
                      packages="\n".join(provenance))
        if value["outcome"] == "error":
            self.remove_stage(request)
            return self.finish(request, "denied", value["code"])
        request.artifact = value
        self.handoff(request)

    def handoff(self, request):
        """The artifact checked (private regular of this user, the stated
        size, one link), renamed into the spool as one name, then
        delivered; it stays unchanged until the deliver result."""
        artifact = request.artifact
        name = f"{request.id}.artifact"
        try:
            fd = os.open(f"{request.stage}/artifact", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        except OSError:
            self.remove_stage(request)
            return self.finish(request, "denied", "artifact_invalid")
        try:
            st = os.fstat(fd)
            ok = stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600 \
                and st.st_nlink == 1 and st.st_size == artifact["size"] and st.st_size <= MAX_ARTIFACT_BYTES
            if ok:
                os.fchmod(fd, 0o400)
                os.rename(f"{request.stage}/artifact", f"{self.spool}/{name}")
        except OSError:
            ok = False
        finally:
            os.close(fd)
        self.remove_stage(request)
        if not ok:
            return self.finish(request, "denied", "artifact_invalid")
        request.spool_name = name
        request.deliver = self.ctx.server.command(
            "deliver", exchange=request.exchange, request=request.id, deadline_ms=REQUEST_TIMEOUT_MS, name=name,
            size=artifact["size"], sha256=artifact["sha256"])
        self.commands[request.deliver] = lambda result: self.delivered(request, result)

    def delivered(self, request, result):
        request.delivery_done = True
        self.remove_spool(request)
        if request.end is not None:
            return
        if result.get("ok") is not True:
            return self.finish(request, "denied", "upload_failed")
        request.uploaded = True
        self.uploads += 1
        artifact = request.artifact
        request.answered = True
        self.respond(request.exchange, {
            "type": "ready", "session": self.nonce, "client": request.client, "request": request.id,
            "request_sha256": request.request_sha256, "handler": request.handler, "operation": request.operation,
            "size": artifact["size"], "sha256": artifact["sha256"], "metadata": artifact["metadata"]},
            then=lambda answer: self.ready_sent(request, answer))

    def ready_sent(self, request, answer):
        if answer.get("ok") is not True and request.end is None:
            request.ready_written = False
            self.end_request(request, "lost")

    def ended(self, message):
        exchange, end = message.get("exchange"), message.get("end")
        request = self.active
        if request is None or exchange != request.exchange:
            return
        if request.uploaded and request.answered:
            # The ready's own write outcome.
            request.ready_written = end == "written"
            if not request.ready_written:
                self.end_request(request, "lost")
            return
        if not request.answered:
            # The waiting submit's peer is gone: nothing more is answered.
            request.answered = True
            self.stop_worker(request)
            self.end_request(request, "cancelled")

    def cancel(self, exchange, client):
        request = self.active
        if request is None or request.client != client:
            return self.error(exchange, "not_active")
        self.stop_worker(request)
        if not request.answered:
            request.answered = True
            self.closed(request, request.exchange, "cancelled")
        self.closed(request, exchange, "cancelled")
        self.end_request(request, "cancelled")

    def result(self, exchange, body):
        request = self.active
        if request is None or request.client != body["client"] or request.ready_written is not True:
            return self.error(exchange, "not_active")
        if (body["request"], body["request_sha256"], body["sha256"]) != \
                (request.id, request.request_sha256, request.artifact["sha256"]):
            return self.error(exchange, "binding_mismatch")
        request.guest = body["status"]
        self.closed(request, exchange, "recorded")
        self.end_request(request, "recorded")

    # -- ends -------------------------------------------------------------

    def finish(self, request, outcome, reason=None):
        """Answers a waiting submit `closed`, then ends the request."""
        self.stop_worker(request)
        if not request.answered:
            request.answered = True
            self.closed(request, request.exchange, outcome, reason)
        self.end_request(request, outcome, reason)

    def end_request(self, request, end, reason=None):
        if request.end is not None:
            return
        request.end, request.reason = end, reason
        if request.deliver is None or request.delivery_done:
            # Never under an upload still running: its result removes it.
            self.remove_spool(request)
        if request.deliver is not None:
            # The server's active request, if it is still that one.
            ident = self.ctx.server.command("revoke", request=request.id)
            self.commands[ident] = None
        if self.active is request:
            self.active = None
        attributes = {"request": request.id, "handler": request.handler, "operation": request.operation,
                      "end": end, "attempted": request.attempted, "acquired": request.acquired,
                      "uploaded": request.uploaded}
        if reason is not None:
            attributes["reason"] = reason
        if request.guest is not None:
            attributes["guest_claim"] = request.guest
        self.note("host.handler.request", **attributes)

    # -- files ------------------------------------------------------------

    def remove_stage(self, request):
        """Never under an unsettled leaf (dispose decides)."""
        if request.stage is not None and request.id not in self.retained:
            shutil.rmtree(request.stage, ignore_errors=True)
            request.stage = None

    def remove_spool(self, request):
        name = request.spool_name
        if name is not None:
            try:
                os.unlink(f"{self.spool}/{name}")
            except FileNotFoundError:
                pass
            request.spool_name = None

    # -- the end ----------------------------------------------------------

    def close_lane(self, reason):
        """No new request; the active one cancelled."""
        self.closing = reason
        request = self.active
        if request is not None:
            self.finish(request, "cancelled")
        if reason == "capture_full":
            self.note("host.handler.lane_note", "warn", closing=True, note="capture_full")

    def close(self, force):
        """At the execution's end, before the server's shutdown: the lane
        closed, its commands' results awaited (bounded, never renewed; not
        after a forced stop). Nothing under an upload still running is
        removed here (`dispose`)."""
        try:
            if self.closing is None:
                self.close_lane("stopped")
        except HostError:
            # No answer could be sent (the server gone or its queue full):
            # the active request still ends, its upload's file kept.
            self.failed = True
            request = self.active
            if request is not None:
                self.stop_worker(request)
                request.end = request.end or "cancelled"
                self.active = None
                if request.deliver is None or request.delivery_done:
                    self.remove_spool(request)
        until = time.monotonic() + CLOSE_TIMEOUT
        server = self.ctx.server
        self.ctx.loop.run(lambda: not any(i in server.outstanding for i in self.commands) or server.failed()
                          or force(), until)
        self.take_results()

    def take_results(self):
        """The results already in: their continuations (no answer is sent
        after the end: each request has ended)."""
        server = self.ctx.server
        for ident in list(self.commands):
            result = server.take_result(ident)
            if result is None:
                continue
            then = self.commands.pop(ident)
            if then is not None:
                try:
                    then(result)
                except HostError:
                    self.failed = True

    def dispose(self, server_clean, domain_settled):
        """After the server's shutdown (`server_clean`: it stopped clean, its
        transfer group ended) and, managed, the domain's kill
        (`domain_settled`: read empty). The spool is removed only when
        nothing can still use it; True only once it is gone and every lane
        step was carried out. Otherwise it stays, and so does its
        reservation (the execution record)."""
        self.take_results()
        uploading = any(r.deliver is not None and not r.delivery_done for r in self.records)
        if domain_settled or (not self.retained and (server_clean or not uploading)):
            shutil.rmtree(self.spool, ignore_errors=True)
        self.released = absent(self.spool)
        clean = self.released and not self.failed
        self.note("host.handler.lane_closed", "info" if clean else "warn", closing=True,
                  requests=self.submissions, attempts=self.attempts, acquired=self.charged,
                  uploads=self.uploads, reason=self.closing, cleanup_confirmed=clean,
                  spool_released=self.released, max_requests=MAX_REQUESTS,
                  max_acquired_bytes=MAX_ACQUIRED_BYTES)
        return clean
