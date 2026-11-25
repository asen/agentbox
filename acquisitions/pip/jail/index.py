"""The jail-local Python package index of one command (pip.py): a
standard-library HTTP server on 127.0.0.1 (an ephemeral port, this jail's
loopback only; a thread per connection, at most MAX_CONNECTIONS) that
native pip uses as its index (PEP 691 JSON). Best effort, a convenience,
not a boundary: the host authorizes, meters and verifies every request. It
resolves nothing: pip asks for project pages and files, the adapter fetches
them from the host's `pip` handler in batches and serves what was
delivered, as delivered.

    pip GET /simple/NAME/                 -> key (files, NORMALIZED)
        the host's rebuilt page: `application/vnd.pypi.simple.v1+json`,
        each file's URL /files/NAME/SHA256/FILENAME
    pip GET /files/NAME/SHA256/FILENAME   -> key (fetch, NAME, SHA256, FILENAME)
        FILENAME.metadata: that file's core metadata sidecar
    anything else                          -> 404; any other method -> 405

    keys -> bounded local queue (MAX_PENDING) -> batches, one host request at
    a time: a short window, then up to 64 keys of one operation whose
    arguments fit 60 KiB -> `pip files|fetch` over the artifact POST
    -> the delivered batch copied into a new unnamed file (size and SHA-256
    of the ready, the upload removed by its inode), its index checked
    against the bytes -> each key served from its slice, `missing` as 404

Each batch's file is tempfile.TemporaryFile's in TMPDIR (O_TMPFILE; on a
file system without it a fresh name unlinked at once, before any byte is
written: only a death in that instant leaves an empty file), open for the
adapter's life: one descriptor per delivered batch, at most the execution's
256 requests. No name stays however this process ends (a container removed
at the command's exit kills it mid-close); the kernel frees the files with
their descriptors.

A GET waits for its key at most KEY_WAIT (the host's whole-request clock,
its queue included), then 504. A failed host request fails its own keys
(424, the code in the reason phrase, which pip shows: a lane busy with
another handler's request is `request_busy`); later keys get new requests.
Neither status is one pip retries. Nothing is
retried here, and pip is told not to retry (pip.py): every submission
counts against the execution's request allowance. `close()` stops the listener, aborts an
active request (its one cancel) and closes every batch. The adapter
authorizes nothing: any jail process could submit the same requests, and
the host checks each one under the operator's policy.
"""

import asyncio
import json
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from guest.src.abort import Abort
from guest.src.artifact_post_client import PRODUCTION_SEAMS, UNKNOWN, Lane, run_request
from guest.src.artifact_post_clock import capture_request_deadline
from guest.src.artifact_post_context import prepare_upload_dir, upload_name
from guest.src.artifact_post_protocol import REQUEST_TIMEOUT_MS, canonical_value
from guest.src.artifact_save_client import save_upload_unnamed

HANDLER = "pip"
BATCH_SCHEMA = "agentbox.pip.batch.v1"
TRAILER_PREFIX = b"\nagentbox.pip.batch.v1 "
TRAILER_BYTES = len(TRAILER_PREFIX) + 20 + 1
MAX_INDEX_BYTES = 1 << 20
MAX_ITEMS = 64
# The host's argument ceiling (handlers.py CEILINGS args_bytes).
MAX_ARGS_BYTES = 61440
MAX_PENDING = 4096
BATCH_WINDOW = 0.05
MAX_CONNECTIONS = 32
IDLE_TIMEOUT = 30
# A key's whole wait from the GET that asked: the host's whole-request clock.
KEY_WAIT = REQUEST_TIMEOUT_MS / 1000
CLOSE_WAIT = 15
DELIVERY_TIMEOUT_MS = 60000
MS_NS = 1_000_000
CHUNK = 1 << 16
PAGE = "application/vnd.pypi.simple.v1+json"
# A failed host request's status: Failed Dependency.
FAILED = 424

NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?")
PROJECT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,254}")
SHA256 = re.compile(r"[0-9a-f]{64}")


def normalized(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def route(path):
    """The key a GET of `path` asks for, or None (404)."""
    parts = path.split("?", 1)[0].split("/")
    if len(parts) == 4 and parts[:2] == ["", "simple"] and parts[3] == "":
        name = unquote(parts[2])
        return ("files", normalized(name)) if NAME.fullmatch(name) else None
    if len(parts) == 5 and parts[:2] == ["", "files"]:
        project, digest, filename = parts[2], parts[3], unquote(parts[4])
        if (len(project) <= 128 and PROJECT.fullmatch(project) and SHA256.fullmatch(digest)
                and FILENAME.fullmatch(filename)):
            return ("fetch", project, digest, filename)
    return None


class Batch:
    """One delivered batch: its unnamed file, open until `close()`, read in
    slices from any thread. Reads and the close share a lock, so a reply
    that outlives the close fails instead of reading whatever reuses the
    descriptor."""

    def __init__(self, file):
        self.file = file
        self.lock = threading.Lock()
        self.closed = False

    def pread(self, size, offset):
        with self.lock:
            if self.closed:
                raise ConnectionError("batch closed")
            return os.pread(self.file.fileno(), size, offset)

    def close(self):
        with self.lock:
            if not self.closed:
                self.closed = True
                self.file.close()


class Delivered:
    """One key's answer: a slice of a delivered batch."""

    __slots__ = ("batch", "offset", "size")

    def __init__(self, batch, offset, size):
        self.batch = batch
        self.offset = offset
        self.size = size


MISSING = "missing"


class BatchFailed(Exception):
    """A host request that delivered nothing: its fixed code and reason."""

    def __init__(self, code, reason=None):
        super().__init__(code)
        self.code = code
        self.reason = reason


def item_of(key):
    """The index item fields a key's answer must carry."""
    if key[0] == "files":
        return {"name": key[1]}
    return {"name": key[1], "sha256": key[2], "filename": key[3]}


def read_exact(batch, size, offset, short):
    """`size` bytes of `batch` at `offset`; `short` raised when it ends first."""
    data = b""
    while len(data) < size:
        try:
            chunk = batch.pread(size - len(data), offset + len(data))
        except OSError:
            raise short from None
        if not chunk:
            raise short
        data += chunk
    return data


def read_batch(batch, size, operation, keys):
    """The delivered `batch` (`size` bytes) checked against the `keys`
    requested: a list of Delivered or MISSING, in key order."""
    invalid = BatchFailed("pip_batch_invalid")
    if size < TRAILER_BYTES:
        raise invalid
    trailer = read_exact(batch, TRAILER_BYTES, size - TRAILER_BYTES, invalid)
    if not trailer.startswith(TRAILER_PREFIX) or not trailer.endswith(b"\n"):
        raise invalid
    digits = trailer[len(TRAILER_PREFIX):-1]
    if not digits.isdigit():
        raise invalid
    length = int(digits)
    start = size - TRAILER_BYTES - length
    if length > MAX_INDEX_BYTES or start < 0:
        raise invalid
    try:
        index = json.loads(read_exact(batch, length, start, invalid).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise invalid from None
    items = index.get("items") if isinstance(index, dict) else None
    if (index.get("schema") != BATCH_SCHEMA or index.get("operation") != operation
            or not isinstance(items, list) or len(items) != len(keys)):
        raise invalid
    answers, offset = [], 0
    for item, key in zip(items, keys):
        if not isinstance(item, dict) or any(item.get(name) != value for name, value in item_of(key).items()):
            raise invalid
        count = item.get("bytes")
        if type(count) is not int or count < 0:
            raise invalid
        if item.get("status") == "ok":
            answers.append(Delivered(batch, offset, count))
        elif item.get("status") == "missing" and count == 0:
            answers.append(MISSING)
        else:
            raise invalid
        offset += count
    if offset != start:
        raise invalid
    return answers


def args_for(keys):
    if keys[0][0] == "files":
        return {"projects": [key[1] for key in keys]}
    return {"files": [{"project": key[1], "filename": key[3], "sha256": key[2]} for key in keys]}


def take_batch(pending):
    """The next batch from the ordered `pending` keys: the first key's
    operation, at most MAX_ITEMS keys whose arguments fit."""
    operation = pending[0][0]
    batch = []
    for key in pending:
        if key[0] != operation:
            continue
        if len(batch) == MAX_ITEMS or len(canonical_value(args_for(batch + [key])).encode()) > MAX_ARGS_BYTES:
            break
        batch.append(key)
    return batch


async def fetch_batch(context, spool, operation, args, abort, seams=PRODUCTION_SEAMS):
    """One host request of `operation` with `args`; the delivered batch in a
    new unnamed file in `spool` (a directory; None: TMPDIR): (Batch, size).
    Raises BatchFailed."""
    deadline = capture_request_deadline()
    clock = seams.clock
    directory = prepare_upload_dir(context)
    if directory is None:
        raise BatchFailed("request_unavailable")
    kept = []

    async def apply(ready, signal):
        until = min(deadline.until_ns, clock.now() + DELIVERY_TIMEOUT_MS * MS_NS)

        def late():
            return signal.aborted or clock.now() >= until

        name = upload_name(context.session, ready["request"]) or ""
        saved = await save_upload_unnamed(os.path.join(directory, name), spool, ready, late)
        if saved.ok:
            kept.append(saved.file)
        return saved

    lane = Lane({"handler": HANDLER, "operation": operation, "args": args},
                lambda ready: upload_name(context.session, ready["request"]) is not None, apply,
                lambda saved: saved.ok)
    try:
        run = await run_request(context, lane, deadline.until_ns, seams, abort)
    except BaseException:
        for file in kept:
            file.close()
        raise
    terminal, outcome = run.terminal, run.outcome
    if (terminal["kind"] == "recorded" and terminal["status"] == "applied" and outcome is not None
            and outcome is not UNKNOWN and outcome.ok and run.ready is not None):
        return Batch(outcome.file), run.ready["size"]
    for file in kept:
        file.close()
    if terminal["kind"] == "closed":
        raise BatchFailed("request_" + terminal["outcome"], terminal.get("reason"))
    if terminal["kind"] == "rejected":
        raise BatchFailed("request_" + terminal["code"])
    if outcome is not None and outcome is not UNKNOWN and not outcome.ok:
        raise BatchFailed(outcome.code)
    raise BatchFailed("request_" + terminal["kind"])


class Adapter:
    """One command's index (module documentation). `fetch(operation, args,
    abort)` (tests replace it) is `fetch_batch` bound to the request
    context and `spool`, the directory of the batches' unnamed files (None:
    TMPDIR); every batch it returns stays open until `close()`."""

    def __init__(self, fetch, spool=None):
        self.fetch = fetch
        self.spool = spool
        self.delivered = []
        self.cache = {}
        self.waiting = {}
        self.pending = []
        self.wake = asyncio.Event()
        self.abort = Abort()
        self.server = None
        self.batcher = None
        self.closing = False
        self.loop = None
        self.port = None

    @property
    def url(self):
        return "http://127.0.0.1:%d/" % self.port

    async def start(self):
        self.loop = asyncio.get_running_loop()
        self.server = Server(self)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, name="agentbox-pip", daemon=True).start()
        self.batcher = self.loop.create_task(self.batches())

    async def close(self):
        """Stops listening, aborts an active host request and awaits it
        (its one cancel, bounded by `CLOSE_WAIT`), fails every waiting key
        and closes every batch."""
        self.closing = True
        if self.server is not None:
            await asyncio.to_thread(self.server.shutdown)
            self.server.server_close()
        self.abort.abort()
        self.wake.set()
        if self.batcher is not None:
            try:
                await asyncio.wait_for(asyncio.shield(self.batcher), CLOSE_WAIT)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                self.batcher.cancel()
                try:
                    await self.batcher
                except asyncio.CancelledError:
                    pass
        for future in self.waiting.values():
            future.cancel()
        self.waiting.clear()
        for batch in self.delivered:
            batch.close()

    async def answer(self, key):
        """A key's Delivered or MISSING; raises BatchFailed."""
        known = self.cache.get(key)
        if known is not None:
            return known
        future = self.waiting.get(key)
        if future is None:
            if len(self.pending) >= MAX_PENDING:
                raise BatchFailed("adapter_queue_full")
            future = asyncio.get_running_loop().create_future()
            # Its failure may outlive every client that waited for it.
            future.add_done_callback(lambda done: done.cancelled() or done.exception())
            self.waiting[key] = future
            self.pending.append(key)
            self.wake.set()
        return await asyncio.shield(future)

    async def batches(self):
        """One host request at a time, never retried; a failure fails that
        batch's keys only."""
        while not self.closing:
            await self.wake.wait()
            if not self.closing:
                await asyncio.sleep(BATCH_WINDOW)
            self.wake.clear()
            while self.pending and not self.closing:
                keys = take_batch(self.pending)
                chosen = set(keys)
                self.pending = [key for key in self.pending if key not in chosen]
                try:
                    batch, size = await self.fetch(keys[0][0], args_for(keys), self.abort)
                    try:
                        answers = read_batch(batch, size, keys[0][0], keys)
                    except BatchFailed:
                        batch.close()
                        raise
                    self.delivered.append(batch)
                except BatchFailed as failed:
                    for key in keys:
                        future = self.waiting.pop(key, None)
                        if future is not None and not future.done():
                            if self.closing:
                                future.cancel()
                            else:
                                future.set_exception(failed)
                    continue
                for key, answer in zip(keys, answers):
                    self.cache[key] = answer
                    future = self.waiting.pop(key, None)
                    if future is not None and not future.done():
                        future.set_result(answer)

    def resolve(self, key, timeout=KEY_WAIT):
        """`answer(key)` on the adapter's loop, from a connection thread;
        TimeoutError after `timeout` seconds (its batch goes on)."""
        future = asyncio.run_coroutine_threadsafe(self.answer(key), self.loop)
        try:
            return future.result(timeout)
        except TimeoutError:
            future.cancel()
            raise


class Handler(BaseHTTPRequestHandler):
    """One connection: GET and HEAD served, other methods refused."""

    protocol_version = "HTTP/1.1"
    server_version = "agentbox-pip"
    timeout = IDLE_TIMEOUT

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.serve(head=False)

    def do_HEAD(self):
        self.serve(head=True)

    def refuse(self):
        self.close_connection = True
        self.reply(405, "Method Not Allowed")

    do_PUT = do_POST = do_DELETE = do_PATCH = refuse

    def serve(self, head):
        key = route(self.path)
        if key is None:
            return self.reply(404, "Not Found", head=head)
        try:
            answer = self.server.adapter.resolve(key)
        except BatchFailed as failed:
            # pip shows the reason phrase; a 500, 502 or 503 it would retry,
            # or with no retries left report by its status alone.
            reason = "agentbox index request failed (%s%s)" % (
                failed.code, "" if failed.reason is None else " reason=%s" % failed.reason)
            return self.reply(FAILED, reason, head=head)
        except TimeoutError:
            self.close_connection = True
            return self.reply(504, "agentbox index request timed out", head=head)
        except Exception:
            # The adapter closed under it.
            self.close_connection = True
            return self.reply(FAILED, "agentbox index closed", head=head)
        if answer is MISSING:
            return self.reply(404, "Not Found", head=head)
        kind = PAGE if key[0] == "files" else "application/octet-stream"
        self.reply(200, "OK", kind=kind, answer=answer, head=head)

    def reply(self, status, reason, kind="text/plain", answer=None, head=False):
        body = b"" if answer is not None else (reason + "\n").encode()
        self.send_response(status, reason)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(answer.size if answer is not None else len(body)))
        self.end_headers()
        if head:
            return
        if answer is None:
            self.wfile.write(body)
            return
        offset, left = answer.offset, answer.size
        while left:
            data = answer.batch.pread(min(CHUNK, left), offset)
            if not data:
                raise ConnectionError("batch truncated")
            self.wfile.write(data)
            offset += len(data)
            left -= len(data)


class Server(ThreadingHTTPServer):
    """A thread per connection, at most MAX_CONNECTIONS at once; errors
    end their connection quietly."""

    daemon_threads = True

    def __init__(self, adapter):
        self.adapter = adapter
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(("127.0.0.1", 0), Handler)

    def process_request(self, request, address):
        if not self.slots.acquire(timeout=IDLE_TIMEOUT):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        pass
