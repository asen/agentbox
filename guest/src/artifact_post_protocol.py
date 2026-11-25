"""Guest side of the artifact request POST contract v1:
acquisitions/contracts/artifacts/post-v1. Pure codecs and framing only.

The Rust host (artifact_post_protocol.rs, network/request.rs) implements the
same rules and both test the shared fixtures. Bodies reuse the strict JSON
envelope of protocol.py; a body is exactly its message's canonical encoding,
its `args` and `metadata` objects with their keys sorted at every depth. A
submission names a handler, one of its operations and a bounded object of
arguments; its request digest binds the client, the handler, the operation
and the canonical arguments. Artifact bytes never travel here.

Nothing here opens a socket, runs a client or applies anything; the guest
client is artifact_post_client.py. The host alone authorizes; a `result` is
a claim. Errors are fixed codes (`Refused`) and never echo content.
"""

import hashlib
import re

from guest.src.protocol import (
    ERROR_CODES, Refused, decode_envelope, is_id, is_safe_integer, is_sha256, js_json, js_sort_key, js_string,
)

# The contract's version; every body says `"v":1`.
CONTRACT_VERSION = 1
VERSION = 1
METHOD = "POST"
PATH = "/agentbox/v1/request"
# Never resolved: the client dials the fixed numeric proxy endpoint.
HOST = "agentbox"
CONTENT_TYPE = "application/json"
MAX_BODY_BYTES = 65536
MAX_DEPTH = 16
SESSION_HEX_DIGITS = 32
# The fixed response head is far shorter; more is malformed.
MAX_RESPONSE_HEAD_BYTES = 1024
MAX_READY_OVERHEAD_BYTES = 2048
MAX_CODE_BYTES = 64
MAX_KEY_BYTES = 128
# A request's original timeout from its submission (the host's).
REQUEST_TIMEOUT_MS = 1800000

REQUEST_TYPES = ("submit", "cancel", "result")
RESPONSE_TYPES = ("ready", "rejected", "closed", "error")
LANE_CODES = ("session_mismatch", "not_active", "binding_mismatch")
REJECTED_CODES = ("busy", "submission_limit")
CLOSED_OUTCOMES = ("denied", "cancelled", "expired", "recorded")
RESULT_STATUSES = ("applied", "failed")
RESPONSE_STATUSES = {200: "OK", 400: "Bad Request", 403: "Forbidden", 409: "Conflict"}
READER_CODES = (
    "response_malformed", "response_too_large", "response_truncated", "response_trailing",
    "response_status_mismatch",
)

_SESSION = re.compile(r"[0-9a-f]{32}")
_WORD = re.compile(r"[a-z][a-z0-9-]{0,31}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_KEY = re.compile(r"[A-Za-z0-9_.:@/+-]{1,128}")


def is_session(text):
    """Exactly 32 lowercase hex digits."""
    return isinstance(text, str) and _SESSION.fullmatch(text) is not None


def is_word(text):
    """`[a-z][a-z0-9-]{0,31}`: a handler id or an operation."""
    return isinstance(text, str) and _WORD.fullmatch(text) is not None


def is_code(text):
    """`[a-z][a-z0-9_]{0,63}`: a fixed code."""
    return isinstance(text, str) and _CODE.fullmatch(text) is not None


def is_key(text):
    """`[A-Za-z0-9_.:@/+-]{1,128}`: an `args` or `metadata` key."""
    return isinstance(text, str) and _KEY.fullmatch(text) is not None


def keys_valid(value):
    """Every key, at every depth, of the key grammar."""
    if isinstance(value, list):
        return all(keys_valid(item) for item in value)
    if isinstance(value, dict):
        return all(is_key(key) and keys_valid(item) for key, item in value.items())
    return True


def canonical_value(value):
    """The canonical text of a strict JSON value: keys sorted at every depth, compact."""
    if isinstance(value, list):
        return "[" + ",".join(canonical_value(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value, key=js_sort_key)
        return "{" + ",".join(js_string(key) + ":" + canonical_value(value[key]) for key in keys) + "}"
    return js_json(value)


def response_status(response):
    """The HTTP status a response body travels with."""
    if response["type"] != "error":
        return 200
    if response["code"] == "session_mismatch":
        return 403
    if response["code"] in ("not_active", "binding_mismatch"):
        return 409
    return 400


def request_sha256(client, submission):
    """The request digest of a submission by `client`; `Refused` if invalid."""
    if (not is_id(client) or not is_word(submission["handler"]) or not is_word(submission["operation"])
            or not keys_valid(submission["args"])):
        raise Refused("invalid_field")
    text = ('{"client":%s,"handler":%s,"operation":%s,"args":%s}'
            % (js_string(client), js_string(submission["handler"]), js_string(submission["operation"]),
               canonical_value(submission["args"])))
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def encode_request(request):
    """The canonical body, refusing anything the host would refuse."""
    data = _render_request(request).encode("utf-8", "surrogatepass")
    decode_request(data)
    return data


def encode_response(response):
    """The canonical body, refusing anything the guest would refuse."""
    data = _render_response(response).encode("utf-8", "surrogatepass")
    decode_response(data)
    return data


def decode_request(data):
    """The envelope steps, the unknown and missing field checks, fields in canonical order, then canonical form."""
    kind, obj = decode_envelope(data, MAX_BODY_BYTES, MAX_DEPTH, REQUEST_TYPES, RESPONSE_TYPES)
    if kind == "submit":
        _fields(obj, ("session", "client", "handler", "operation", "args"))
        request = {"v": 1, "type": kind, "session": _session(obj["session"]), "client": _id(obj["client"]),
                   "handler": _word(obj["handler"]), "operation": _word(obj["operation"]),
                   "args": _object_of(obj["args"])}
    elif kind == "cancel":
        _fields(obj, ("session", "client"))
        request = {"v": 1, "type": kind, "session": _session(obj["session"]), "client": _id(obj["client"])}
    else:
        _fields(obj, ("session", "client", "request", "request_sha256", "sha256", "status"))
        request = {"v": 1, "type": kind, "session": _session(obj["session"]), "client": _id(obj["client"]),
                   "request": _id(obj["request"]), "request_sha256": _sha256(obj["request_sha256"]),
                   "sha256": _sha256(obj["sha256"]), "status": _member(RESULT_STATUSES, obj["status"])}
    _canonical(data, _render_request(request))
    return request


def decode_response(data):
    """In the order of `decode_request`."""
    kind, obj = decode_envelope(data, MAX_BODY_BYTES, MAX_DEPTH, RESPONSE_TYPES, REQUEST_TYPES)
    if kind == "ready":
        _fields(obj, ("session", "client", "request", "request_sha256", "handler", "operation", "size", "sha256",
                      "metadata"))
        response = {"v": 1, "type": kind, "session": _session(obj["session"]), "client": _id(obj["client"]),
                    "request": _id(obj["request"]), "request_sha256": _sha256(obj["request_sha256"]),
                    "handler": _word(obj["handler"]), "operation": _word(obj["operation"]),
                    "size": _size(obj["size"]), "sha256": _sha256(obj["sha256"]),
                    "metadata": _object_of(obj["metadata"])}
    elif kind == "rejected":
        _fields(obj, ("session", "client", "code"))
        response = {"v": 1, "type": kind, "session": _session(obj["session"]), "client": _id(obj["client"]),
                    "code": _member(REJECTED_CODES, obj["code"])}
    elif kind == "closed":
        _fields(obj, ("session", "client", "request", "request_sha256", "handler", "outcome"), ("reason",))
        response = {"v": 1, "type": kind, "session": _session(obj["session"]), "client": _id(obj["client"]),
                    "request": _id(obj["request"]), "request_sha256": _sha256(obj["request_sha256"]),
                    "handler": _word(obj["handler"])}
        outcome = _member(CLOSED_OUTCOMES, obj["outcome"])
        has_reason = "reason" in obj
        if has_reason != (outcome == "denied"):
            raise Refused("invalid_field")
        response["outcome"] = outcome
        if has_reason:
            response["reason"] = _code(obj["reason"])
    else:
        _fields(obj, ("code",))
        code = obj["code"]
        if not isinstance(code, str) or code not in ERROR_CODES + LANE_CODES:
            raise Refused("invalid_field")
        response = {"v": 1, "type": kind, "code": code}
    _canonical(data, _render_response(response))
    return response


def encode_http_request(body):
    """The exact request head and body; None for a body above MAX_BODY_BYTES."""
    if len(body) > MAX_BODY_BYTES:
        return None
    head = ("%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (METHOD, PATH, HOST, CONTENT_TYPE, len(body)))
    return head.encode("ascii") + bytes(body)


_RESPONSE_HEAD = re.compile(
    r"HTTP/1\.1 ([0-9]{3}) ([A-Za-z ]+)\r\nContent-Type: application/json\r\nContent-Length: (0|[1-9][0-9]*)\r\n"
    r"Connection: close\r\n\r\n")
# The host's transport refusal, exactly as it frames every status-only refusal.
REFUSAL_HEAD = "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
_HEAD_BYTES = frozenset(list(range(0x20, 0x7F)) + [0x0D, 0x0A])

PENDING = {"state": "pending"}


class ResponseReader:
    """One response as the client reads it: exactly the host's fixed head, a
    body of its `Content-Length`, then the server's close. Pure; the caller
    feeds chunks and the end. Apart from that, exactly REFUSAL_HEAD, no byte
    after it, then the server's close is `refused`; any other status-only head
    is `response_malformed`. States are dicts: `pending`, `complete` (status,
    body), `refused` or `failed` (code).

    Memory is bounded before any copy: of a chunk, only what the head can
    still hold is examined and kept (at most MAX_RESPONSE_HEAD_BYTES), and the
    body is allocated once at its declared length (at most MAX_BODY_BYTES); a
    chunk larger than the room left is refused without being copied. Head
    bytes are printable ASCII, CR and LF only."""

    def __init__(self):
        self._head = b""
        self._body = None
        self._filled = 0
        self._status = 0
        self._refused = False
        self._outcome = PENDING

    @property
    def retained(self):
        """The bytes this reader holds."""
        return len(self._head) + (0 if self._body is None else len(self._body))

    def push(self, chunk):
        if self._outcome is not PENDING or len(chunk) == 0:
            return self._outcome
        rest = chunk
        if self._body is None:
            room = MAX_RESPONSE_HEAD_BYTES - len(self._head)
            scanned = self._head + bytes(chunk[:room])
            end = scanned.find(b"\r\n\r\n")
            head = scanned if end < 0 else scanned[:end + 4]
            if any(byte not in _HEAD_BYTES for byte in head):
                return self._fail("response_malformed")
            if end < 0:
                if len(chunk) > room:
                    return self._fail("response_malformed")
                self._head = scanned
                return self._outcome
            text = head.decode("latin-1")
            consumed = end + 4 - len(self._head)
            if text == REFUSAL_HEAD:
                if len(chunk) > consumed:
                    return self._fail("response_trailing")
                self._head = b""
                self._refused = True
                self._body = bytearray()
                return self._outcome
            match = _RESPONSE_HEAD.fullmatch(text)
            if match is None:
                return self._fail("response_malformed")
            status, phrase, length = match.groups()
            if RESPONSE_STATUSES.get(int(status)) != phrase:
                return self._fail("response_malformed")
            if len(length) > len(str(MAX_BODY_BYTES)) or int(length) > MAX_BODY_BYTES:
                return self._fail("response_too_large")
            rest = chunk[consumed:]
            # The head's own chunk is checked against the declared length
            # before the body is allocated.
            if len(rest) > int(length):
                return self._fail("response_trailing")
            self._head = b""
            self._status = int(status)
            self._body = bytearray(int(length))
        if len(rest) > len(self._body) - self._filled:
            return self._fail("response_trailing")
        self._body[self._filled:self._filled + len(rest)] = rest
        self._filled += len(rest)
        return self._outcome

    def end(self):
        """The server closed."""
        if self._outcome is not PENDING:
            return self._outcome
        if self._body is None or self._filled < len(self._body):
            return self._fail("response_truncated")
        if self._refused:
            self._outcome = {"state": "refused"}
        else:
            self._outcome = {"state": "complete", "status": self._status, "body": bytes(self._body)}
        return self._outcome

    def _fail(self, code):
        self._head = b""
        self._body = None
        self._outcome = {"state": "failed", "code": code}
        return self._outcome


def decode_http_response(status, body):
    """A complete response's body under the codec, and its status against it."""
    decoded = decode_response(body)
    if response_status(decoded) != status:
        raise Refused("response_status_mismatch")
    return decoded


def _render_request(request):
    s = js_string
    if request["type"] == "submit":
        return _body("submit", (("session", s(request["session"])), ("client", s(request["client"])),
                                ("handler", s(request["handler"])), ("operation", s(request["operation"])),
                                ("args", canonical_value(request["args"]))))
    if request["type"] == "cancel":
        return _body("cancel", (("session", s(request["session"])), ("client", s(request["client"]))))
    return _body("result", (("session", s(request["session"])), ("client", s(request["client"])),
                            ("request", s(request["request"])), ("request_sha256", s(request["request_sha256"])),
                            ("sha256", s(request["sha256"])), ("status", s(request["status"]))))


def _render_response(response):
    s = js_string
    kind = response["type"]
    if kind == "rejected":
        return _body(kind, (("session", s(response["session"])), ("client", s(response["client"])),
                            ("code", s(response["code"]))))
    if kind == "error":
        return _body(kind, (("code", s(response["code"])),))
    bound = (("session", s(response["session"])), ("client", s(response["client"])),
             ("request", s(response["request"])), ("request_sha256", s(response["request_sha256"])),
             ("handler", s(response["handler"])))
    if kind == "closed":
        reason = () if response.get("reason") is None else (("reason", s(response["reason"])),)
        return _body(kind, bound + (("outcome", s(response["outcome"])),) + reason)
    return _body(kind, bound + (("operation", s(response["operation"])), ("size", str(response["size"])),
                                ("sha256", s(response["sha256"])),
                                ("metadata", canonical_value(response["metadata"]))))


def _body(kind, fields):
    return '{"v":1,"type":%s%s}' % (js_string(kind), "".join(",%s:%s" % (js_string(key), value)
                                                                for key, value in fields))


def _fields(obj, required, optional=()):
    """Unknown fields first, then missing ones."""
    for key in obj:
        if key not in ("v", "type") and key not in required and key not in optional:
            raise Refused("unknown_field")
    if any(key not in obj for key in required):
        raise Refused("missing_field")


def _canonical(data, rendered):
    """The last check: a body is exactly its message's canonical encoding."""
    if rendered.encode("utf-8", "surrogatepass") != bytes(data):
        raise Refused("invalid_field")


def _session(value):
    if not is_session(value):
        raise Refused("invalid_field")
    return value


def _id(value):
    if not is_id(value):
        raise Refused("invalid_field")
    return value


def _word(value):
    if not is_word(value):
        raise Refused("invalid_field")
    return value


def _code(value):
    if not is_code(value):
        raise Refused("invalid_field")
    return value


def _sha256(value):
    if not is_sha256(value):
        raise Refused("invalid_field")
    return value


def _size(value):
    """Any positive safe integer."""
    if not is_safe_integer(value) or value <= 0:
        raise Refused("invalid_field")
    return value


def _object_of(value):
    """An object whose keys, at every depth, are of the key grammar."""
    if not isinstance(value, dict) or not keys_valid(value):
        raise Refused("invalid_field")
    return value


def _member(allowed, value):
    if not isinstance(value, str) or value not in allowed:
        raise Refused("invalid_field")
    return value
