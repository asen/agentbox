"""The artifact request POST body contract v1 (acquisitions/contracts/artifacts/post-v1),
host-side codecs, checked against the shared fixtures.

Requests and responses are dicts in their canonical field order with a
`type`; every body is byte-for-byte its message's canonical encoding.
Errors are the shared fixed codes (`CodecError`) and never echo content.
"""
import hashlib
import json
import re

VERSION = 1
METHOD = "POST"
PATH = "/agentbox/v1/request"
HOST = "agentbox"
CONTENT_TYPE = "application/json"
MAX_BODY_BYTES = 65536
MAX_DEPTH = 16
SESSION_HEX_DIGITS = 32
MAX_CODE_BYTES = 64
MAX_KEY_BYTES = 128
MAX_READY_OVERHEAD_BYTES = 2048
MAX_SAFE_INTEGER = (1 << 53) - 1
REQUEST_TYPES = ("submit", "cancel", "result")
RESPONSE_TYPES = ("ready", "rejected", "closed", "error")
ERROR_CODES = (
    "frame_too_large", "truncated_frame", "invalid_framing", "invalid_encoding", "invalid_json",
    "invalid_number", "duplicate_key", "not_object", "invalid_version", "unsupported_version",
    "unknown_type", "wrong_direction", "unknown_field", "missing_field", "invalid_field",
    "limit_exceeded",
)
LANE_FAULTS = ("session_mismatch", "not_active", "binding_mismatch")
_SURROGATE = re.compile("[\ud800-\udfff]")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_SESSION = re.compile(r"[0-9a-f]{32}")
_WORD = re.compile(r"[a-z][a-z0-9-]{0,31}")
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_KEY = re.compile(r"[A-Za-z0-9_.:@/+-]{1,128}")
_SAFE = re.compile(r"0|[1-9][0-9]{0,15}")


class CodecError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def is_id(text):
    return isinstance(text, str) and _ID.fullmatch(text) is not None


def is_sha256(text):
    return isinstance(text, str) and _SHA256.fullmatch(text) is not None


def is_session(text):
    return isinstance(text, str) and _SESSION.fullmatch(text) is not None


def is_word(text):
    """A handler id or operation: `[a-z][a-z0-9-]{0,31}`."""
    return isinstance(text, str) and _WORD.fullmatch(text) is not None


def is_code(text):
    return isinstance(text, str) and _CODE.fullmatch(text) is not None


def is_key(text):
    return isinstance(text, str) and _KEY.fullmatch(text) is not None


def keys_valid(value):
    if isinstance(value, dict):
        return all(is_key(key) and keys_valid(item) for key, item in value.items())
    if isinstance(value, list):
        return all(keys_valid(item) for item in value)
    return True


def json_str(text):
    return json.dumps(text, ensure_ascii=False)


def canonical_value(value):
    """Compact, object keys sorted, minimal escapes (serde_json's)."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def nesting_depth(text):
    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "}]":
            depth = max(0, depth - 1)
    return deepest


def _reject(_name):
    raise ValueError("not JSON")


def _grammar(text):
    """JSON grammar only: no number range or surrogate check."""
    return json.loads(text, parse_constant=_reject, parse_int=lambda token: 0,
                      parse_float=lambda token: 0.5, object_pairs_hook=lambda pairs: None)


def check_tokens(text):
    """String tokens, number tokens and duplicate keys of grammatical text,
    in the contract's precedence."""
    scopes = []
    bad_string = bad_number = duplicate = False
    index, length = 0, len(text)
    while index < length:
        char = text[index]
        if char == "{":
            scopes.append([set(), True])
        elif char == "[":
            scopes.append(None)
        elif char in "}]":
            scopes.pop()
        elif char in ",:":
            if scopes and scopes[-1] is not None:
                scopes[-1][1] = char == ","
        elif char == '"':
            end = index + 1
            while text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end += 1
            token = json.loads(text[index:end])
            if _SURROGATE.search(token):
                bad_string = True
            elif scopes and scopes[-1] is not None and scopes[-1][1]:
                if token in scopes[-1][0]:
                    duplicate = True
                scopes[-1][0].add(token)
            if scopes and scopes[-1] is not None:
                scopes[-1][1] = False
            index = end
            continue
        elif char == "-" or "0" <= char <= "9":
            start = index
            while index < length and text[index] in "-+.eE0123456789":
                index += 1
            token = text[start:index]
            bad_number |= not (_SAFE.fullmatch(token) and int(token) <= MAX_SAFE_INTEGER)
            continue
        index += 1
    if bad_string:
        raise CodecError("invalid_json")
    if bad_number:
        raise CodecError("invalid_number")
    if duplicate:
        raise CodecError("duplicate_key")


def envelope(data, own, other):
    """Steps 1-10: (type, object)."""
    data = bytes(data)
    if len(data) > MAX_BODY_BYTES:
        raise CodecError("frame_too_large")
    if b"\n" in data or b"\r" in data:
        raise CodecError("invalid_framing")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise CodecError("invalid_encoding") from None
    if nesting_depth(text) > MAX_DEPTH:
        raise CodecError("invalid_json")
    try:
        _grammar(text)
    except (ValueError, RecursionError):
        raise CodecError("invalid_json") from None
    check_tokens(text)
    value = json.loads(text)
    if not isinstance(value, dict):
        raise CodecError("not_object")
    version = value.get("v")
    if type(version) is not int:
        raise CodecError("invalid_version")
    if version != VERSION:
        raise CodecError("unsupported_version")
    if "type" not in value:
        raise CodecError("missing_field")
    kind = value["type"]
    if not isinstance(kind, str):
        raise CodecError("invalid_field")
    if kind not in own:
        raise CodecError("wrong_direction" if kind in other else "unknown_type")
    return kind, value


def _fields(value, required, optional=()):
    for key in value:
        if key not in ("v", "type") and key not in required and key not in optional:
            raise CodecError("unknown_field")
    if any(key not in value for key in required):
        raise CodecError("missing_field")


def _check(valid, value):
    if not valid(value):
        raise CodecError("invalid_field")
    return value


def _object(value):
    if not isinstance(value, dict) or not keys_valid(value):
        raise CodecError("invalid_field")
    return value


def _size(value):
    if type(value) is not int or not 0 < value <= MAX_SAFE_INTEGER:
        raise CodecError("invalid_field")
    return value


def _body(kind, fields):
    return '{"v":1,"type":"%s",%s}' % (kind, fields)


def request_sha256(client, handler, operation, args):
    """The SHA-256 of `{"client":C,"handler":H,"operation":O,"args":A}`."""
    if not is_id(client) or not is_word(handler) or not is_word(operation):
        raise CodecError("invalid_field")
    text = '{"client":%s,"handler":%s,"operation":%s,"args":%s}' % (
        json_str(client), json_str(handler), json_str(operation), canonical_value(args))
    return hashlib.sha256(text.encode()).hexdigest()


def render_request(request):
    kind = request["type"]
    if kind == "submit":
        return _body("submit", '"session":%s,"client":%s,"handler":%s,"operation":%s,"args":%s' % (
            json_str(request["session"]), json_str(request["client"]), json_str(request["handler"]),
            json_str(request["operation"]), canonical_value(request["args"])))
    if kind == "cancel":
        return _body("cancel", '"session":%s,"client":%s' % (
            json_str(request["session"]), json_str(request["client"])))
    return _body("result", '"session":%s,"client":%s,"request":%s,"request_sha256":%s,"sha256":%s,"status":"%s"' % (
        json_str(request["session"]), json_str(request["client"]), json_str(request["request"]),
        json_str(request["request_sha256"]), json_str(request["sha256"]), request["status"]))


def render_response(response):
    kind = response["type"]
    if kind == "ready":
        return _body("ready", '"session":%s,"client":%s,"request":%s,"request_sha256":%s,"handler":%s,'
                     '"operation":%s,"size":%d,"sha256":%s,"metadata":%s' % (
                         json_str(response["session"]), json_str(response["client"]),
                         json_str(response["request"]), json_str(response["request_sha256"]),
                         json_str(response["handler"]), json_str(response["operation"]), response["size"],
                         json_str(response["sha256"]), canonical_value(response["metadata"])))
    if kind == "rejected":
        return _body("rejected", '"session":%s,"client":%s,"code":"%s"' % (
            json_str(response["session"]), json_str(response["client"]), response["code"]))
    if kind == "closed":
        reason = response.get("reason")
        reason = "" if reason is None else ',"reason":%s' % json_str(reason)
        return _body("closed", '"session":%s,"client":%s,"request":%s,"request_sha256":%s,"handler":%s,'
                     '"outcome":"%s"%s' % (
                         json_str(response["session"]), json_str(response["client"]),
                         json_str(response["request"]), json_str(response["request_sha256"]),
                         json_str(response["handler"]), response["outcome"], reason))
    return _body("error", '"code":"%s"' % response["code"])


def _canonical(data, rendered):
    if bytes(data) != rendered.encode():
        raise CodecError("invalid_field")


def decode_request(data):
    kind, value = envelope(data, REQUEST_TYPES, RESPONSE_TYPES)
    if kind == "submit":
        _fields(value, ("session", "client", "handler", "operation", "args"))
        request = {"type": "submit", "session": _check(is_session, value["session"]),
                   "client": _check(is_id, value["client"]), "handler": _check(is_word, value["handler"]),
                   "operation": _check(is_word, value["operation"]), "args": _object(value["args"])}
    elif kind == "cancel":
        _fields(value, ("session", "client"))
        request = {"type": "cancel", "session": _check(is_session, value["session"]),
                   "client": _check(is_id, value["client"])}
    else:
        _fields(value, ("session", "client", "request", "request_sha256", "sha256", "status"))
        request = {"type": "result", "session": _check(is_session, value["session"]),
                   "client": _check(is_id, value["client"]), "request": _check(is_id, value["request"]),
                   "request_sha256": _check(is_sha256, value["request_sha256"]),
                   "sha256": _check(is_sha256, value["sha256"]),
                   "status": _check(lambda status: status in ("applied", "failed"), value["status"])}
    _canonical(data, render_request(request))
    return request


def decode_response(data):
    kind, value = envelope(data, RESPONSE_TYPES, REQUEST_TYPES)
    if kind == "ready":
        _fields(value, ("session", "client", "request", "request_sha256", "handler", "operation", "size",
                        "sha256", "metadata"))
        response = {"type": "ready", "session": _check(is_session, value["session"]),
                    "client": _check(is_id, value["client"]), "request": _check(is_id, value["request"]),
                    "request_sha256": _check(is_sha256, value["request_sha256"]),
                    "handler": _check(is_word, value["handler"]),
                    "operation": _check(is_word, value["operation"]), "size": _size(value["size"]),
                    "sha256": _check(is_sha256, value["sha256"]), "metadata": _object(value["metadata"])}
    elif kind == "rejected":
        _fields(value, ("session", "client", "code"))
        response = {"type": "rejected", "session": _check(is_session, value["session"]),
                    "client": _check(is_id, value["client"]),
                    "code": _check(lambda code: code in ("busy", "submission_limit"), value["code"])}
    elif kind == "closed":
        _fields(value, ("session", "client", "request", "request_sha256", "handler", "outcome"), ("reason",))
        response = {"type": "closed", "session": _check(is_session, value["session"]),
                    "client": _check(is_id, value["client"]), "request": _check(is_id, value["request"]),
                    "request_sha256": _check(is_sha256, value["request_sha256"]),
                    "handler": _check(is_word, value["handler"]),
                    "outcome": _check(lambda outcome: outcome in ("denied", "cancelled", "expired", "recorded"),
                                      value["outcome"])}
        response["reason"] = _check(is_code, value["reason"]) if "reason" in value else None
        if (response["reason"] is not None) != (response["outcome"] == "denied"):
            raise CodecError("invalid_field")
    else:
        _fields(value, ("code",))
        code = value["code"]
        if not isinstance(code, str) or (code not in ERROR_CODES and code not in LANE_FAULTS):
            raise CodecError("invalid_field")
        response = {"type": "error", "code": code}
    _canonical(data, render_response(response))
    return response


def encode_response(response):
    """The canonical body, refusing anything the guest would refuse."""
    text = render_response(response)
    decode_response(text.encode())
    return text.encode()


def encode_request(request):
    text = render_request(request)
    decode_request(text.encode())
    return text.encode()


def fault_status(code):
    """The HTTP status of an `error` body."""
    if code == "session_mismatch":
        return 403
    if code in ("not_active", "binding_mismatch"):
        return 409
    return 400


def response_status(response):
    return fault_status(response["code"]) if response["type"] == "error" else 200
