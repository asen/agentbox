"""Guest side of the `agentbox.guest` v1 frame protocol over SSH stdio.

The contract, limits and validation order are in contracts/v1/README.md; the
Rust host implements the same rules and both test the shared fixtures.
Errors are fixed codes only and never echo frame content.

Frames are plain dicts in their canonical key order; `env` is a tuple of
(name, value) pairs sorted by name. Decoders and encoders raise `Refused`.
"""

import base64
import json
import re

PROTOCOL = "agentbox.guest"
VERSION = 1

MAX_FRAME_BYTES = 65536
MAX_DEPTH = 8
MAX_ID_BYTES = 64
MAX_GUEST_VERSION_BYTES = 32
MAX_OUTPUT_BYTES = 16384
# Base64 text length of MAX_OUTPUT_BYTES.
MAX_OUTPUT_TEXT_BYTES = 4 * -(-MAX_OUTPUT_BYTES // 3)
MAX_ARGV_ITEMS = 64
MAX_ARG_BYTES = 4096
MAX_ARGV_BYTES = 32768
MAX_EXIT_CODE = 255
MAX_SAFE_INTEGER = 2**53 - 1
# An `exec` frame's optional `env`: the host's explicit selection.
MAX_ENV_VARS = 32
MAX_ENV_NAME_BYTES = 128
MAX_ENV_VALUE_BYTES = 8192
# Names and values together.
MAX_ENV_BYTES = 16384
# One `stdin` frame's task input bytes: at most this, never empty.
MAX_STDIN_BYTES = 2048
MAX_STDIN_TEXT_BYTES = 4 * -(-MAX_STDIN_BYTES // 3)
# The helper's fixed command environment (execution.py), the request context
# (artifact_post_context.py) included; never selectable.
RESERVED_ENV = (
    "PATH", "HOME", "LANG", "TERM", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
    "AGENTBOX_REQUEST_SESSION", "AGENTBOX_WORK_ROOT", "AGENTBOX_WORK_MOUNT",
)

ERROR_CODES = (
    "frame_too_large", "truncated_frame", "invalid_framing", "invalid_encoding", "invalid_json",
    "invalid_number", "duplicate_key", "not_object", "invalid_version", "unsupported_version",
    "unknown_type", "wrong_direction", "unknown_field", "missing_field", "invalid_field",
    "limit_exceeded",
)

HOST_TYPES = ("hello", "exec", "cancel", "inputs_setup", "stdin", "stdin_eof")
GUEST_TYPES = ("hello", "output", "exit", "error", "inputs_ready", "stdin_ready", "stdin_closed")


class Refused(Exception):
    """A fixed protocol code; never frame content."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GUEST_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,31}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_SAFE_TOKEN = re.compile(r"0|[1-9][0-9]{0,15}")
_NUMBER_CHARS = frozenset("-+.eE0123456789")
_SURROGATE = re.compile("[\ud800-\udfff]")


def is_id(text):
    """`[A-Za-z0-9][A-Za-z0-9._-]{0,63}`."""
    return isinstance(text, str) and _ID.fullmatch(text) is not None


def is_sha256(text):
    """Exactly 64 lowercase hex digits."""
    return isinstance(text, str) and _SHA256.fullmatch(text) is not None


def is_env_name(text):
    """`[A-Za-z_][A-Za-z0-9_]*`; the length is checked separately."""
    return _ENV_NAME.fullmatch(text) is not None


def is_safe_integer(value):
    """A JSON integer of the contracts: an int, never a bool, 0 to 2^53 - 1."""
    return type(value) is int and 0 <= value <= MAX_SAFE_INTEGER


def byte_length(text):
    return len(text.encode("utf-8", "surrogatepass"))


def well_formed(text):
    return _SURROGATE.search(text) is None


def js_sort_key(text):
    """JavaScript's default string order: UTF-16 code units."""
    return text.encode("utf-16-be", "surrogatepass")


def js_string(text):
    """`JSON.stringify` of a string: minimal escapes, lone surrogates escaped."""
    encoded = json.dumps(text, ensure_ascii=False)
    return _SURROGATE.sub(lambda match: "\\u%04x" % ord(match.group()), encoded)


def js_json(value):
    """`JSON.stringify` of a JSON value without floats: compact, in key order."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        # As JavaScript prints a number; never a canonical one here.
        return str(int(value)) if value.is_integer() and abs(value) < 1e21 else repr(value)
    if isinstance(value, str):
        return js_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(js_json(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(js_string(key) + ":" + js_json(item) for key, item in value.items()) + "}"
    raise TypeError("not a JSON value")


def utf8(text):
    """The UTF-8 bytes of well-formed text; `Refused` otherwise."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError:
        raise Refused("invalid_encoding") from None


def decode_host_frame(data):
    obj_type, obj = _envelope(data, MAX_FRAME_BYTES, MAX_DEPTH, HOST_TYPES, GUEST_TYPES)
    if obj_type == "hello":
        _fields(obj, ("session",), ())
        return {"v": 1, "type": "hello", "session": _id(obj["session"])}
    if obj_type == "exec":
        _fields(obj, ("id", "argv"), ("env", "stdin"))
        frame_id = _id(obj["id"])
        if not isinstance(obj["argv"], list):
            raise Refused("invalid_field")
        argv = _argv_items(obj["argv"])
        env = _env_vars(obj["env"]) if "env" in obj else None
        # Only `true`: the default is the field's absence.
        if "stdin" in obj and obj["stdin"] is not True:
            raise Refused("invalid_field")
        frame = {"v": 1, "type": "exec", "id": frame_id, "argv": argv}
        if env is not None:
            frame["env"] = env
        if obj.get("stdin") is True:
            frame["stdin"] = True
        return frame
    if obj_type == "stdin":
        _fields(obj, ("id", "seq", "data"), ())
        frame_id = _id(obj["id"])
        sequence = _seq(obj["seq"])
        return {"v": 1, "type": "stdin", "id": frame_id, "seq": sequence, "data": _stdin_data(obj["data"])}
    if obj_type == "stdin_eof":
        _fields(obj, ("id", "seq"), ())
        frame_id = _id(obj["id"])
        return {"v": 1, "type": "stdin_eof", "id": frame_id, "seq": _seq(obj["seq"])}
    if obj_type == "inputs_setup":
        _fields(obj, ("execution_id",), ())
        return {"v": 1, "type": "inputs_setup", "execution_id": _id(obj["execution_id"])}
    _fields(obj, ("id",), ())
    return {"v": 1, "type": "cancel", "id": _id(obj["id"])}


def decode_guest_frame(data):
    obj_type, obj = _envelope(data, MAX_FRAME_BYTES, MAX_DEPTH, GUEST_TYPES, HOST_TYPES)
    if obj_type == "hello":
        _fields(obj, ("session", "guest_version"), ())
        session = _id(obj["session"])
        version = obj["guest_version"]
        if not isinstance(version, str) or _GUEST_VERSION.fullmatch(version) is None:
            raise Refused("invalid_field")
        return {"v": 1, "type": "hello", "session": session, "guest_version": version}
    if obj_type == "output":
        _fields(obj, ("id", "stream", "data"), ())
        frame_id = _id(obj["id"])
        stream = obj["stream"]
        if stream not in ("stdout", "stderr"):
            raise Refused("invalid_field")
        return {"v": 1, "type": "output", "id": frame_id, "stream": stream, "data": _output_data(obj["data"])}
    if obj_type == "exit":
        _fields(obj, ("id", "outcome"), ("code",))
        frame_id = _id(obj["id"])
        outcome = obj["outcome"]
        if outcome == "exited":
            if "code" not in obj:
                raise Refused("missing_field")
            code = obj["code"]
            if type(code) is not int or code > MAX_EXIT_CODE:
                raise Refused("invalid_field")
            return {"v": 1, "type": "exit", "id": frame_id, "outcome": outcome, "code": code}
        if outcome not in ("signaled", "cancelled", "failed"):
            raise Refused("invalid_field")
        if "code" in obj:
            raise Refused("invalid_field")
        return {"v": 1, "type": "exit", "id": frame_id, "outcome": outcome}
    if obj_type == "inputs_ready":
        _fields(obj, (), ())
        return {"v": 1, "type": "inputs_ready"}
    if obj_type == "stdin_ready":
        _fields(obj, ("id", "seq"), ())
        frame_id = _id(obj["id"])
        return {"v": 1, "type": "stdin_ready", "id": frame_id, "seq": _seq(obj["seq"])}
    if obj_type == "stdin_closed":
        _fields(obj, ("id",), ())
        return {"v": 1, "type": "stdin_closed", "id": _id(obj["id"])}
    _fields(obj, ("code",), ())
    code = obj["code"]
    if not isinstance(code, str) or code not in ERROR_CODES:
        raise Refused("invalid_field")
    return {"v": 1, "type": "error", "code": code}


def encode_host_frame(frame):
    """A frame without its LF, refusing anything the peer would refuse."""
    kind = frame["type"]
    if kind == "hello":
        value = {"v": 1, "type": "hello", "session": frame["session"]}
    elif kind == "exec":
        value = {"v": 1, "type": "exec", "id": frame["id"], "argv": list(frame["argv"])}
        env = frame.get("env") or ()
        if isinstance(env, dict):
            env = tuple(env.items())
        if len(env) > 0:
            value["env"] = dict(_sorted_env(env))
        if frame.get("stdin") is True:
            value["stdin"] = True
    elif kind in ("stdin", "stdin_eof"):
        value = {"v": 1, "type": kind, "id": frame["id"], "seq": frame["seq"]}
        if kind == "stdin":
            value["data"] = frame["data"]
    elif kind == "inputs_setup":
        value = {"v": 1, "type": "inputs_setup", "execution_id": frame["execution_id"]}
    else:
        value = {"v": 1, "type": "cancel", "id": frame["id"]}
    return _checked(value, decode_host_frame)


def encode_guest_frame(frame):
    """A frame without its LF, refusing anything the peer would refuse."""
    kind = frame["type"]
    if kind == "hello":
        value = {"v": 1, "type": "hello", "session": frame["session"], "guest_version": frame["guest_version"]}
    elif kind == "output":
        value = {"v": 1, "type": "output", "id": frame["id"], "stream": frame["stream"], "data": frame["data"]}
    elif kind == "exit":
        value = {"v": 1, "type": "exit", "id": frame["id"], "outcome": frame["outcome"]}
        if frame["outcome"] == "exited":
            value["code"] = frame["code"]
    elif kind == "inputs_ready":
        value = {"v": 1, "type": "inputs_ready"}
    elif kind == "stdin_ready":
        value = {"v": 1, "type": "stdin_ready", "id": frame["id"], "seq": frame["seq"]}
    elif kind == "stdin_closed":
        value = {"v": 1, "type": "stdin_closed", "id": frame["id"]}
    else:
        value = {"v": 1, "type": "error", "code": frame["code"]}
    return _checked(value, decode_guest_frame)


def _checked(value, decode):
    data = js_json(value).encode("utf-8", "surrogatepass")
    decode(data)
    return data


class FrameSplitter:
    """Splits a byte stream into frames without their LF. Never buffers more
    than MAX_FRAME_BYTES of an unfinished frame; after an error the stream is
    unusable and every later call raises the same code."""

    def __init__(self):
        self._pending = bytearray()
        self._failed = None

    def push(self, chunk):
        if self._failed is not None:
            raise Refused(self._failed)
        frames = []
        start = 0
        while True:
            newline = chunk.find(b"\n", start)
            end = len(chunk) if newline < 0 else newline
            if len(self._pending) + end - start > MAX_FRAME_BYTES:
                self._fail("frame_too_large")
            if newline < 0:
                self._pending += chunk[start:end]
                return frames
            self._pending += chunk[start:end]
            frames.append(bytes(self._pending))
            self._pending = bytearray()
            start = newline + 1

    def end(self):
        """Reports a partial frame left at the end of the stream."""
        if self._failed is not None:
            raise Refused(self._failed)
        if self._pending:
            self._fail("truncated_frame")

    def _fail(self, code):
        self._failed = code
        self._pending = bytearray()
        raise Refused(code)


def validate_argv(argv):
    """A guest-only argument vector against the `exec` limits: its code or None."""
    try:
        _argv_items(argv)
        return None
    except Refused as error:
        return error.code


def decode_envelope(data, max_frame_bytes, max_depth, own, other):
    """Steps 1-10 of the validation order: (type, object)."""
    return _envelope(data, max_frame_bytes, max_depth, own, other)


def decode_object(data, max_bytes, max_depth):
    """Steps 1-7 of the validation order: a strict JSON object."""
    return _strict_object(data, max_bytes, max_depth)


def _envelope(data, max_frame_bytes, max_depth, own, other):
    obj = _strict_object(data, max_frame_bytes, max_depth)
    version = obj.get("v")
    if type(version) is not int:
        raise Refused("invalid_version")
    if version != VERSION:
        raise Refused("unsupported_version")
    if "type" not in obj:
        raise Refused("missing_field")
    kind = obj["type"]
    if not isinstance(kind, str):
        raise Refused("invalid_field")
    if kind not in own:
        raise Refused("wrong_direction" if kind in other else "unknown_type")
    return kind, obj


def _reject_constant(_name):
    raise ValueError("not JSON")


def _parse_int(token):
    # Every number token is checked again (`_check_tokens`); a long one is
    # never converted.
    return int(token) if len(token) <= 32 else 0


def _parse_float(_token):
    return 0.5


def strict_loads(text):
    """JSON.parse of text: the value, or ValueError. No NaN or Infinity."""
    return json.loads(text, parse_constant=_reject_constant, parse_int=_parse_int, parse_float=_parse_float)


def _strict_object(data, max_frame_bytes, max_depth):
    data = bytes(data)
    if len(data) > max_frame_bytes:
        raise Refused("frame_too_large")
    if b"\n" in data or b"\r" in data:
        raise Refused("invalid_framing")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("invalid_encoding") from None
    if _nesting_depth(text) > max_depth:
        raise Refused("invalid_json")
    try:
        value = strict_loads(text)
    except (ValueError, RecursionError):
        raise Refused("invalid_json") from None
    _check_tokens(text)
    if not isinstance(value, dict):
        raise Refused("not_object")
    return value


def _fields(obj, required, optional):
    """The unknown and missing field checks of one frame type."""
    for key in obj:
        if key not in ("v", "type") and key not in required and key not in optional:
            raise Refused("unknown_field")
    if any(key not in obj for key in required):
        raise Refused("missing_field")


def _id(value):
    if not is_id(value):
        raise Refused("invalid_field")
    return value


def canonical_base64(value, max_text, max_bytes):
    """Canonical padded standard base64 of 1 to `max_bytes` bytes: the bytes."""
    if not isinstance(value, str):
        raise Refused("invalid_field")
    if byte_length(value) > max_text:
        raise Refused("limit_exceeded")
    if _BASE64.fullmatch(value) is None:
        raise Refused("invalid_field")
    data = base64.b64decode(value, validate=True)
    if base64.b64encode(data).decode("ascii") != value or len(data) == 0:
        raise Refused("invalid_field")
    if len(data) > max_bytes:
        raise Refused("limit_exceeded")
    return data


def _output_data(value):
    canonical_base64(value, MAX_OUTPUT_TEXT_BYTES, MAX_OUTPUT_BYTES)
    return value


def _stdin_data(value):
    canonical_base64(value, MAX_STDIN_TEXT_BYTES, MAX_STDIN_BYTES)
    return value


def _seq(value):
    """A task input sequence number: a safe integer."""
    if not is_safe_integer(value):
        raise Refused("invalid_field")
    return value


def _argv_items(items):
    if len(items) > MAX_ARGV_ITEMS:
        raise Refused("limit_exceeded")
    if len(items) == 0:
        raise Refused("invalid_field")
    argv = []
    total = 0
    for index, item in enumerate(items):
        if not isinstance(item, str):
            raise Refused("invalid_field")
        length = byte_length(item)
        if length > MAX_ARG_BYTES:
            raise Refused("limit_exceeded")
        if (index == 0 and item == "") or "\0" in item:
            raise Refused("invalid_field")
        total += length
        argv.append(item)
    if total > MAX_ARGV_BYTES:
        raise Refused("limit_exceeded")
    return argv


def _sorted_env(pairs):
    return sorted(((name, value) for name, value in pairs), key=lambda pair: js_sort_key(pair[0]))


def _env_vars(value):
    """An `exec` frame's `env`: 1 to MAX_ENV_VARS entries, checked in name order
    (pattern, length, reserved, value type, value length, NUL), then the total."""
    if not isinstance(value, dict):
        raise Refused("invalid_field")
    entries = _sorted_env(value.items())
    if len(entries) > MAX_ENV_VARS:
        raise Refused("limit_exceeded")
    if len(entries) == 0:
        raise Refused("invalid_field")
    total = 0
    for name, item in entries:
        if not is_env_name(name):
            raise Refused("invalid_field")
        if byte_length(name) > MAX_ENV_NAME_BYTES:
            raise Refused("limit_exceeded")
        if name in RESERVED_ENV:
            raise Refused("invalid_field")
        if not isinstance(item, str):
            raise Refused("invalid_field")
        if byte_length(item) > MAX_ENV_VALUE_BYTES:
            raise Refused("limit_exceeded")
        if "\0" in item:
            raise Refused("invalid_field")
        total += byte_length(name) + byte_length(item)
    if total > MAX_ENV_BYTES:
        raise Refused("limit_exceeded")
    return tuple(entries)


def encode_env_config(pairs):
    """The helper's private config for one command's anchor (anchor.py): the
    frame's `env` object again, never larger than the frame it came from."""
    return js_json(dict(_sorted_env(pairs))).encode("utf-8", "surrogatepass")


def decode_env_config(data):
    """Strictly as an `exec` frame's `env`, through the same bounded strict JSON
    object rules as a frame; None for anything else."""
    try:
        return _env_vars(_strict_object(data, MAX_FRAME_BYTES, 1))
    except Refused:
        return None


def _nesting_depth(text):
    """Maximum object/array nesting, counting brackets outside strings."""
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


def _check_tokens(text):
    """String tokens, number tokens and duplicate keys of text that already
    parsed as JSON. Every string, including one a duplicate key would replace,
    must be free of lone surrogates; then a bad number takes precedence over a
    duplicate key."""
    scopes = []
    bad_string = bad_number = duplicate = False
    index = 0
    length = len(text)
    while index < length:
        char = text[index]
        scope = scopes[-1] if scopes else None
        if char == "{":
            scopes.append({"keys": set(), "expect_key": True})
        elif char == "[":
            scopes.append(None)
        elif char in "}]":
            scopes.pop()
        elif char in ",:" and scope is not None:
            scope["expect_key"] = char == ","
        elif char == '"':
            end = index + 1
            while text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            end += 1
            token = json.loads(text[index:end])
            if not well_formed(token):
                bad_string = True
            elif scope is not None and scope["expect_key"]:
                if token in scope["keys"]:
                    duplicate = True
                scope["keys"].add(token)
            if scope is not None:
                scope["expect_key"] = False
            index = end
            continue
        elif char == "-" or "0" <= char <= "9":
            start = index
            while index < length and text[index] in _NUMBER_CHARS:
                index += 1
            token = text[start:index]
            bad_number = bad_number or not (_SAFE_TOKEN.fullmatch(token) is not None and int(token) <= MAX_SAFE_INTEGER)
            continue
        index += 1
    if bad_string:
        raise Refused("invalid_json")
    if bad_number:
        raise Refused("invalid_number")
    if duplicate:
        raise Refused("duplicate_key")
