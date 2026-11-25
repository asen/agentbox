"""The jail-local npm registry adapter of one outer npm process (npm.py):
a standard-library HTTP server on 127.0.0.1 (an ephemeral port, this
jail's loopback only; a thread per connection, at most MAX_CONNECTIONS)
that native npm uses as its registry. Best effort, a convenience, not a
boundary: the host authorizes, meters and verifies every request. It resolves nothing: npm asks
for documents and tarballs, the adapter fetches them from the host's `npm`
handler in batches and serves what was delivered.

    npm GET /NAME | /@SCOPE%2fNAME     -> key (metadata, FORMAT, NAME)
        Accept install-v1+json: abbreviated, else full (a cached full
        document also answers an abbreviated request)
    npm GET .../NAME/-/BASE-VERSION.tgz -> key (tarball, NAME, VERSION)
        whatever host and path prefix the lock or document named
        (replace-registry-host=always routes them all here)
    anything else                        -> 404 (audit, search, ...);
        any other method                 -> 405 (publish, login, ...)

    keys -> bounded local queue (MAX_PENDING) -> batches, one host request at
    a time: a short window, then up to 256 keys of one operation (and
    format) whose arguments fit 60 KiB -> `npm metadata|tarballs` over the
    artifact POST -> the delivered batch copied into this adapter's private
    spool (size and SHA-256 of the ready, the upload removed by its inode),
    its index checked against the bytes -> each key served from its slice,
    `missing` as 404

Bodies are served as delivered: documents keep their upstream tarball
URLs, so lockfiles keep them too. A GET waits for its key at most KEY_WAIT (the host's whole-request
clock, its queue included), then 504. Nothing is retried: the first failed
host request makes every later miss a 503 without another submission.
Keys, batches and host requests live on the shim's asyncio loop; the
connection threads wait on it (`resolve`). `close()` stops the listener,
aborts an active request (its one cancel) and removes the spool. The adapter authorizes nothing: any jail process
could submit the same requests, and the host checks each one under the
operator's policy.
"""

import asyncio
import json
import os
import re
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from guest.src.abort import Abort
from guest.src.artifact_post_client import PRODUCTION_SEAMS, UNKNOWN, Lane, run_request
from guest.src.artifact_post_clock import capture_request_deadline
from guest.src.artifact_post_context import prepare_upload_dir, upload_name
from guest.src.artifact_post_protocol import REQUEST_TIMEOUT_MS, canonical_value
from guest.src.artifact_save_client import save_upload

HANDLER = "npm"
BATCH_SCHEMA = "agentbox.npm.batch.v1"
TRAILER_PREFIX = b"\nagentbox.npm.batch.v1 "
TRAILER_BYTES = len(TRAILER_PREFIX) + 20 + 1
MAX_INDEX_BYTES = 1 << 20
MAX_ITEMS = 256
# The host's argument ceiling (handlers.rs MAX_ARGS_BYTES).
MAX_ARGS_BYTES = 61440
# Keys waiting for a batch, at most: more are answered 503 at once.
MAX_PENDING = 4096
# After the first key of a batch, how long others may join it.
BATCH_WINDOW = 0.05
# Connection threads at once; a connection idle this long, or a request
# or response stalled this long on its socket, ends.
MAX_CONNECTIONS = 32
IDLE_TIMEOUT = 30
# A key's whole wait, its queue included, from the GET that asked: the
# host's whole-request clock, never renewed. Then 504; npm's own
# fetch-timeout (npm.py) is longer.
KEY_WAIT = REQUEST_TIMEOUT_MS / 1000
# At close, how long an aborted host request may take to end (its cancel's
# own exchange is bounded by the 10 s control cap).
CLOSE_WAIT = 15
# The delivered copy's own bound from its ready (artifact_save_client.py).
DELIVERY_TIMEOUT_MS = 60000
MS_NS = 1_000_000
CHUNK = 1 << 16
SPOOL_PREFIX = "agentbox-npm-"
ABBREVIATED = "application/vnd.npm.install-v1+json"

NAME_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]*")
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")


def package_name(text):
    """The host worker's name grammar (acquisitions/npm/host/worker.py)."""
    if not 0 < len(text) <= 214:
        return False
    if text.startswith("@"):
        scope, slash, name = text[1:].partition("/")
        return bool(slash) and NAME_PART.fullmatch(scope) is not None and NAME_PART.fullmatch(name) is not None
    return NAME_PART.fullmatch(text) is not None


def package_version(text):
    return 0 < len(text) <= 256 and SEMVER.fullmatch(text) is not None


def route(path, accept):
    """The key a GET of `path` asks for, or None (404)."""
    path = path.split("?", 1)[0]
    if not path.startswith("/") or "\\" in path:
        return None
    if "/-/" in path:
        before, _, file = path[1:].rpartition("/-/")
        parts = [unquote(part) for part in before.split("/")]
        if any("/" in part for part in parts[:-1]):
            return None
        # A prefix of the registry's own path may precede the name.
        last = parts[-1]
        if "/" in last:
            name = last
        elif len(parts) >= 2 and parts[-2].startswith("@"):
            name = parts[-2] + "/" + last
        else:
            name = last
        base = name.rsplit("/", 1)[-1]
        if not package_name(name) or not file.startswith(base + "-") or not file.endswith(".tgz"):
            return None
        version = file[len(base) + 1:-len(".tgz")]
        return ("tarballs", name, version) if package_version(version) else None
    name = unquote(path[1:])
    if not package_name(name):
        return None
    return ("metadata", "abbreviated" if ABBREVIATED in accept else "full", name)


class Delivered:
    """One key's answer: a slice of a spool file, or missing."""

    __slots__ = ("path", "offset", "size")

    def __init__(self, path, offset, size):
        self.path = path
        self.offset = offset
        self.size = size


MISSING = "missing"


class BatchFailed(Exception):
    """A host request that delivered nothing: its fixed code and reason."""

    def __init__(self, code, reason=None):
        super().__init__(code)
        self.code = code
        self.reason = reason


def read_batch(path, size, operation, keys):
    """The delivered batch at `path` (`size` bytes) checked against the
    `keys` requested: a list of Delivered or MISSING, in key order."""
    invalid = BatchFailed("npm_batch_invalid")
    if size < TRAILER_BYTES:
        raise invalid
    with open(path, "rb") as stream:
        stream.seek(size - TRAILER_BYTES)
        trailer = stream.read(TRAILER_BYTES)
        if not trailer.startswith(TRAILER_PREFIX) or not trailer.endswith(b"\n"):
            raise invalid
        digits = trailer[len(TRAILER_PREFIX):-1]
        if not digits.isdigit():
            raise invalid
        length = int(digits)
        start = size - TRAILER_BYTES - length
        if length > MAX_INDEX_BYTES or start < 0:
            raise invalid
        stream.seek(start)
        try:
            index = json.loads(stream.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            raise invalid from None
    items = index.get("items") if isinstance(index, dict) else None
    if (index.get("schema") != BATCH_SCHEMA or index.get("operation") != operation
            or not isinstance(items, list) or len(items) != len(keys)):
        raise invalid
    answers, offset = [], 0
    for item, key in zip(items, keys):
        if not isinstance(item, dict) or item.get("name") != key[-2 if operation == "tarballs" else -1]:
            raise invalid
        if operation == "tarballs" and item.get("version") != key[-1]:
            raise invalid
        count = item.get("bytes")
        if type(count) is not int or count < 0:
            raise invalid
        if item.get("status") == "ok":
            answers.append(Delivered(path, offset, count))
        elif item.get("status") == "missing" and count == 0:
            answers.append(MISSING)
        else:
            raise invalid
        offset += count
    if offset != start:
        raise invalid
    return answers


def canonical_size(value):
    return len(canonical_value(value).encode("utf-8", "surrogatepass"))


def args_for(keys):
    if keys[0][0] == "metadata":
        return {"names": [key[2] for key in keys], "format": keys[0][1]}
    return {"packages": [{"name": key[1], "version": key[2]} for key in keys]}


def take_batch(pending):
    """The next batch from the ordered `pending` keys: the first key's
    operation and format, at most MAX_ITEMS keys whose arguments fit."""
    first = pending[0]
    kind = first[:2] if first[0] == "metadata" else first[:1]
    batch = []
    for key in pending:
        if key[:len(kind)] != kind:
            continue
        if len(batch) == MAX_ITEMS or canonical_size(args_for(batch + [key])) > MAX_ARGS_BYTES:
            break
        batch.append(key)
    return batch


async def fetch_batch(context, spool, operation, args, abort, seams=PRODUCTION_SEAMS):
    """One host request of `operation` with `args`; the delivered batch
    copied into `spool`: (path, size). Raises BatchFailed."""
    deadline = capture_request_deadline()
    clock = seams.clock
    directory = prepare_upload_dir(context)
    if directory is None:
        raise BatchFailed("request_unavailable")

    async def apply(ready, signal):
        until = min(deadline.until_ns, clock.now() + DELIVERY_TIMEOUT_MS * MS_NS)

        def late():
            return signal.aborted or clock.now() >= until

        name = upload_name(context.session, ready["request"]) or ""
        return await save_upload(os.path.join(directory, name), spool, ready, late, prefix="batch-")

    lane = Lane({"handler": HANDLER, "operation": operation, "args": args},
                lambda ready: upload_name(context.session, ready["request"]) is not None, apply,
                lambda saved: saved.ok)
    run = await run_request(context, lane, deadline.until_ns, seams, abort)
    terminal, outcome = run.terminal, run.outcome
    if (terminal["kind"] == "recorded" and terminal["status"] == "applied" and outcome is not None
            and outcome is not UNKNOWN and outcome.ok and run.ready is not None):
        return outcome.path, run.ready["size"]
    if outcome is not None and outcome is not UNKNOWN and outcome.ok:
        shutil.rmtree(os.path.dirname(outcome.path), ignore_errors=True)
    if terminal["kind"] == "closed":
        raise BatchFailed("request_" + terminal["outcome"], terminal.get("reason"))
    if terminal["kind"] == "rejected":
        raise BatchFailed("request_" + terminal["code"])
    if outcome is not None and outcome is not UNKNOWN and not outcome.ok:
        raise BatchFailed(outcome.code)
    raise BatchFailed("request_" + terminal["kind"])


class Adapter:
    """One outer npm process's registry (module documentation). `fetch`
    (tests replace it) is `fetch_batch` bound to the request context;
    `report(line)` gets one line per failed host request."""

    def __init__(self, fetch, report, spool_parent=None):
        self.fetch = fetch
        self.report = report
        self.spool = tempfile.mkdtemp(prefix=SPOOL_PREFIX, dir=spool_parent)
        self.cache = {}
        self.waiting = {}
        self.pending = []
        self.wake = asyncio.Event()
        self.failed = None
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
        threading.Thread(target=self.server.serve_forever, name="agentbox-npm", daemon=True).start()
        self.batcher = self.loop.create_task(self.batches())

    async def close(self):
        """Stops listening, aborts an active host request and awaits it
        (its one cancel, bounded by `CLOSE_WAIT`), fails every waiting key
        and removes the spool. A connection still open ends at its next
        request or idle timeout."""
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
        shutil.rmtree(self.spool, ignore_errors=True)

    # Keys.

    def lookup(self, key):
        if key[0] == "metadata" and key[1] == "abbreviated":
            full = self.cache.get(("metadata", "full", key[2]))
            if isinstance(full, Delivered):
                return full
        return self.cache.get(key)

    async def answer(self, key):
        """A key's Delivered or MISSING; raises BatchFailed."""
        known = self.lookup(key)
        if known is not None:
            return known
        if self.failed is not None:
            raise self.failed
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
        """One host request at a time, never retried; a failure fails every
        waiting key and every later one."""
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
                    if self.failed is not None:
                        raise self.failed
                    path, size = await self.fetch(keys[0][0], args_for(keys), self.abort)
                    answers = read_batch(path, size, keys[0][0], keys)
                except BatchFailed as failed:
                    if self.failed is None:
                        self.failed = failed
                        reason = "" if failed.reason is None else " reason=%s" % failed.reason
                        if not self.closing:
                            self.report("agentbox-npm: registry request failed (code=%s%s)"
                                        % (failed.code, reason))
                    for key in [*keys, *self.pending]:
                        future = self.waiting.pop(key, None)
                        if future is not None and not future.done():
                            # Closing: its clients are gone already.
                            if self.closing:
                                future.cancel()
                            else:
                                future.set_exception(self.failed)
                    self.pending = []
                    break
                for key, answer in zip(keys, answers):
                    self.cache[key] = answer
                    future = self.waiting.pop(key, None)
                    if future is not None and not future.done():
                        future.set_result(answer)

    # HTTP, on the server's threads.

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
    server_version = "agentbox-npm"
    # Idle keep-alive and stalled reads end the connection.
    timeout = IDLE_TIMEOUT

    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.serve(head=False)

    def do_HEAD(self):
        self.serve(head=True)

    def refuse(self):
        # Its body, if any, is never read: the connection ends with it.
        self.close_connection = True
        self.reply(405, b'{"error":"agentbox: method not supported"}')

    do_PUT = do_POST = do_DELETE = do_PATCH = refuse

    def serve(self, head):
        key = route(self.path, self.headers.get("Accept", ""))
        if key is None:
            return self.reply(404, b'{"error":"Not found"}', head=head)
        try:
            answer = self.server.adapter.resolve(key)
        except BatchFailed as failed:
            body = json.dumps({"error": "agentbox: registry request failed (%s)" % failed.code}).encode()
            return self.reply(503, body, head=head)
        except TimeoutError:
            self.close_connection = True
            return self.reply(504, b'{"error":"agentbox: registry request timed out"}', head=head)
        except Exception:
            # The adapter closed under it.
            self.close_connection = True
            return self.reply(503, b'{"error":"agentbox: registry closed"}', head=head)
        if answer is MISSING:
            return self.reply(404, b'{"error":"Not found"}', head=head)
        kind = "application/json" if key[0] == "metadata" else "application/octet-stream"
        self.reply(200, kind=kind, answer=answer, head=head)

    def reply(self, status, body=b"", kind="application/json", answer=None, head=False):
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(answer.size if answer is not None else len(body)))
        self.end_headers()
        if head:
            return
        if answer is None:
            self.wfile.write(body)
            return
        with open(answer.path, "rb") as stream:
            stream.seek(answer.offset)
            left = answer.size
            while left:
                data = stream.read(min(CHUNK, left))
                if not data:
                    raise ConnectionError("spool truncated")
                self.wfile.write(data)
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
