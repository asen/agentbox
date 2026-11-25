"""The control protocol `agentbox.server.v1` (docs/server-protocol.md):
framing and the controller's strict commands. Anything else is a fatal violation; its fixed code is
the stop reason."""
import json
import os
import re

from . import codec, strictjson, transport
from .policy import Policy, PolicyError, parse_grant

VERSION = 1
MAX_FRAME_BYTES = 1 << 20
MAX_LIFETIME_MS = 366 * 24 * 3600 * 1000
REQUEST_TIMEOUT_MS = 1800 * 1000
MAX_ACQUIRED_BYTES = 2 << 30
_PREFIXED = re.compile(r"[0-9a-f]{32}")
MALFORMED = "control_malformed"
INVALID = "configure_invalid"


class Violation(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def frame(message):
    """One message as its frame; None above MAX_FRAME_BYTES."""
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode()
    if len(body) > MAX_FRAME_BYTES:
        return None
    return len(body).to_bytes(4, "big") + body


class Reader:
    """Frames from the control input as they come: `feed(data)` returns
    the complete commands; `end()` the end of input's code."""

    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer += data
        commands = []
        while len(self.buffer) >= 4:
            length = int.from_bytes(self.buffer[:4], "big")
            if length == 0 or length > MAX_FRAME_BYTES:
                raise Violation("control_oversize")
            if len(self.buffer) < 4 + length:
                break
            body = bytes(self.buffer[4:4 + length])
            del self.buffer[:4 + length]
            try:
                value = strictjson.loads(body)
            except strictjson.Invalid:
                raise Violation(MALFORMED) from None
            if not isinstance(value, dict):
                raise Violation(MALFORMED)
            commands.append(value)
        return commands

    def end(self):
        return "control_truncated" if self.buffer else "control_eof"


def _exact(value, keys):
    if len(value) != len(keys) or any(key not in value for key in keys):
        raise Violation(MALFORMED)


def _text(value, key):
    item = value.get(key)
    if not isinstance(item, str):
        raise Violation(MALFORMED)
    return item


def _number(value, key):
    item = value.get(key)
    if not strictjson.is_u64(item):
        raise Violation(MALFORMED)
    return item


def _object(value):
    if not isinstance(value, dict):
        raise Violation(MALFORMED)
    return value


def _millis(value, key, maximum):
    item = _number(value, key)
    if item == 0 or item > maximum:
        raise Violation(MALFORMED)
    return item


def _id(value, key):
    item = _text(value, key)
    if not codec.is_id(item):
        raise Violation(MALFORMED)
    return item


def command(value, configured, last):
    """One command: (id, kind, fields)."""
    kind = _text(value, "type")
    ident = _number(value, "id")
    if ident <= last:
        raise Violation("control_order")
    if (kind == "configure") == configured:
        raise Violation("control_order" if kind in ("configure", "deliver", "respond", "revoke")
                        else "control_unknown")

    def fields(*keys):
        _exact(value, ("type", "id") + keys)

    if kind == "configure":
        fields("v", "session", "run_id", "execution_id", "lifetime_ms", "policy", "post",
               *(key for key in ("grants", "connect_proxy") if key in value))
        if _number(value, "v") != VERSION:
            raise Violation("control_version")
        return ident, kind, _configure(value)
    if kind == "deliver":
        fields("exchange", "request", "deadline_ms", "name", "size", "sha256")
        size = _number(value, "size")
        sha256 = _text(value, "sha256")
        if size == 0 or size > MAX_ACQUIRED_BYTES or not codec.is_sha256(sha256):
            raise Violation(MALFORMED)
        return ident, kind, {
            "exchange": _number(value, "exchange"), "request": _id(value, "request"),
            "deadline": _millis(value, "deadline_ms", REQUEST_TIMEOUT_MS) / 1000,
            "name": _id(value, "name"), "size": size, "sha256": sha256}
    if kind == "respond":
        fields("exchange", "body")
        body = _text(value, "body")
        size = len(body.encode("utf-8", "surrogatepass"))
        if size == 0 or size > codec.MAX_BODY_BYTES:
            raise Violation(MALFORMED)
        return ident, kind, {"exchange": _number(value, "exchange"), "body": body}
    if kind == "revoke":
        fields("request")
        return ident, kind, {"request": _id(value, "request")}
    raise Violation("control_unknown")


def _is_prefixed(text, prefix):
    return text.startswith(prefix) and _PREFIXED.fullmatch(text[len(prefix):]) is not None


def _configure(value):
    run_id = _text(value, "run_id")
    execution_id = _text(value, "execution_id")
    if not _is_prefixed(run_id, "r-") or not _is_prefixed(execution_id, "e-"):
        raise Violation(INVALID)
    if "policy" not in value:
        raise Violation(MALFORMED)
    document = _object(value["policy"])
    grants = value.get("grants", [])
    if not isinstance(grants, list):
        raise Violation(MALFORMED)
    try:
        policy = Policy.parse(strictjson.dumps(document).encode()).with_grants(grants)
    except PolicyError:
        raise Violation(INVALID) from None
    proxy = None
    if "connect_proxy" in value:
        try:
            proxy = parse_grant(_text(value, "connect_proxy"))
        except PolicyError:
            raise Violation(INVALID) from None
    if "post" not in value:
        raise Violation(MALFORMED)
    post = None if value["post"] is None else _post(_object(value["post"]))
    if "lifetime_ms" not in value:
        raise Violation(MALFORMED)
    lifetime = None if value["lifetime_ms"] is None else _millis(value, "lifetime_ms", MAX_LIFETIME_MS) / 1000
    return {"session": _id(value, "session"), "run_id": run_id, "execution_id": execution_id,
            "lifetime": lifetime, "policy": policy, "post": post, "connect_proxy": proxy}


def _post(post):
    _exact(post, ("nonce", "delivery"))
    nonce = _text(post, "nonce")
    if not codec.is_session(nonce):
        raise Violation(INVALID)
    delivery = None if post["delivery"] is None else _delivery(_object(post["delivery"]))
    return {"nonce": nonce, "delivery": delivery}


def _path(value, key):
    text = _text(value, key)
    try:
        return transport.plain_path(text)
    except transport.Invalid:
        raise Violation(INVALID) from None


def _delivery(delivery):
    _exact(delivery, ("route", "user", "identity", "known_hosts", "host_key_alias", "work_dir", "spool_root"))
    route = _object(delivery["route"])
    try:
        if "endpoint" in route:
            _exact(route, ("endpoint",))
            endpoint = _object(route["endpoint"])
            _exact(endpoint, ("host", "port"))
            host = _text(endpoint, "host")
            port = _number(endpoint, "port")
            if port > 65535:
                raise Violation(INVALID)
            route = transport.Connection.endpoint(host, port)
        else:
            _exact(route, ("proxy",))
            proxy = _object(route["proxy"])
            _exact(proxy, ("words", "env"))
            words, env = proxy["words"], proxy["env"]
            if not strictjson.is_array(words) or not all(isinstance(word, str) for word in words):
                raise Violation(MALFORMED)
            if not strictjson.is_array(env) or not all(
                    strictjson.is_array(pair) and len(pair) == 2 and all(isinstance(item, str) for item in pair)
                    for pair in env):
                raise Violation(MALFORMED)
            route = transport.Connection.proxy(words, [tuple(pair) for pair in env])
        user = _text(delivery, "user")
        identity = _path(delivery, "identity")
        known_hosts = _path(delivery, "known_hosts")
        alias = _text(delivery, "host_key_alias")
        connection = transport.Connection(route, user, identity, known_hosts, alias)
    except transport.Invalid:
        raise Violation(INVALID) from None
    return {"connection": connection, "work_dir": _path(delivery, "work_dir"),
            "spool_root": _path(delivery, "spool_root")}


def message(kind, **fields):
    return dict(fields, type=kind)


def note(code):
    """A best-effort fixed code on stderr, written only if it fits now."""
    try:
        os.write(2, f"agentbox-server: {code}\n".encode())
    except OSError:
        pass
