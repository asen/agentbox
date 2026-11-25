"""The request head: strict parsing of CONNECT and the framing of the one
fixed artifact POST. Reading is the broker's (bounded, nonblocking); errors
are fixed codes and never echo the input.
"""
import re

from . import codec
from .address import AddressError, parse_authority

# code -> HTTP status of its refusal; None: nothing is sent.
STATUS = {
    "request_malformed": 400, "request_framing_invalid": 400, "request_target_invalid": 400,
    "request_header_invalid": 400, "request_body_overrun": 400,
    "method_not_allowed": 405, "post_unconfigured": 405,
    "request_timeout": 408, "request_body_too_large": 413, "request_line_too_long": 414,
    "request_head_too_large": 431, "request_headers_too_many": 431,
    "post_capacity": 503, "post_closed": 503,
    "request_incomplete": None, "broker_stopping": None,
}
AUTHORITY_CODES = ("authority_too_long", "authority_invalid", "port_invalid", "host_invalid",
                   "ip_literal_ambiguous", "network_invalid")
# RFC 9112 status-line: HTTP-version SP 3DIGIT SP [reason-phrase].
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\t\x20-\x7e\x80-\xff]*")
_TCHAR = frozenset(b"!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")


class RequestError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code

    def status(self):
        if self.code in AUTHORITY_CODES:
            return 400
        return STATUS[self.code]


def status_of(code):
    return 400 if code in AUTHORITY_CODES else STATUS[code]


class Limits:
    def __init__(self, max_head_bytes, max_line_bytes, max_headers):
        self.max_head_bytes, self.max_line_bytes, self.max_headers = \
            max_head_bytes, max_line_bytes, max_headers


def check_line(buf, limits):
    """Refuses a request line longer than `max_line_bytes` once certain."""
    at = buf.find(b"\r\n")
    too_long = at > limits.max_line_bytes if at >= 0 else len(buf) > limits.max_line_bytes + 1
    if too_long:
        raise RequestError("request_line_too_long")


def head_end(buf, before):
    """The end of the head (after its blank line) in `buf`, whose first
    `before` bytes were already searched; None while incomplete."""
    at = buf.find(b"\r\n\r\n", max(0, before - 3))
    return None if at < 0 else at + 4


def _lines(body):
    return body.split(b"\r\n")


def _field(line):
    colon = line.find(b":")
    if colon < 0:
        raise RequestError("request_malformed")
    name, value = line[:colon], line[colon + 1:]
    if not name or not all(byte in _TCHAR for byte in name):
        raise RequestError("request_malformed")
    if not all(byte == 9 or byte == 32 or 0x21 <= byte <= 0x7e or byte >= 0x80 for byte in value):
        raise RequestError("request_malformed")
    return name, value


def parse_head(head, limits):
    """A complete CONNECT head: its authority."""
    if len(head) > limits.max_head_bytes:
        raise RequestError("request_head_too_large")
    if not head.endswith(b"\r\n\r\n"):
        raise RequestError("request_malformed")
    lines = _lines(head[:-4])
    request_line = lines[0]
    if len(request_line) > limits.max_line_bytes:
        raise RequestError("request_line_too_long")
    for count, line in enumerate(lines[1:], 1):
        if count > limits.max_headers:
            raise RequestError("request_headers_too_many")
        name, _ = _field(line)
        if name.lower() in (b"content-length", b"transfer-encoding"):
            raise RequestError("request_framing_invalid")
    if b"\r" in request_line or b"\n" in request_line:
        raise RequestError("request_malformed")
    parts = request_line.split(b" ")
    if len(parts) != 3:
        raise RequestError("request_malformed")
    method, target, version = parts
    if not method or not all(byte in _TCHAR for byte in method):
        raise RequestError("request_malformed")
    if version not in (b"HTTP/1.1", b"HTTP/1.0"):
        raise RequestError("request_malformed")
    if method != b"CONNECT":
        raise RequestError("method_not_allowed")
    try:
        target = target.decode("utf-8")
    except UnicodeDecodeError:
        raise RequestError("request_malformed") from None
    try:
        return parse_authority(target)
    except AddressError as error:
        raise RequestError(error.code) from None


def parse_proxy_head(head, limits):
    """A CONNECT proxy's complete response head: its status code. Its
    status line and every field checked as a request's (no folding, no
    control bytes); `request_malformed` otherwise."""
    if len(head) > limits.max_head_bytes or not head.endswith(b"\r\n\r\n"):
        raise RequestError("request_malformed")
    lines = _lines(head[:-4])
    if len(lines) - 1 > limits.max_headers or len(lines[0]) > limits.max_line_bytes:
        raise RequestError("request_malformed")
    status = _STATUS_LINE.fullmatch(lines[0])
    if status is None:
        raise RequestError("request_malformed")
    for line in lines[1:]:
        _field(line)
    return int(status.group(1))


def parse_request_head(head, limits):
    """("connect", authority) or ("post", content_length)."""
    if head.startswith(b"POST "):
        return "post", parse_post_head(head, limits)
    return "connect", parse_head(head, limits)


def _trim(value):
    return value.strip(b" \t")


def parse_post_head(head, limits):
    """The fixed POST's head rules: its Content-Length."""
    if len(head) > limits.max_head_bytes:
        raise RequestError("request_head_too_large")
    if not head.endswith(b"\r\n\r\n"):
        raise RequestError("request_malformed")
    lines = _lines(head[:-4])
    request_line = lines[0]
    if len(request_line) > limits.max_line_bytes:
        raise RequestError("request_line_too_long")
    fields = []
    for line in lines[1:]:
        if len(fields) == limits.max_headers:
            raise RequestError("request_headers_too_many")
        fields.append(_field(line))
    if b"\r" in request_line or b"\n" in request_line:
        raise RequestError("request_malformed")
    parts = request_line.split(b" ")
    if len(parts) != 3 or parts[0] != b"POST":
        raise RequestError("request_malformed")
    _, target, version = parts
    if version != b"HTTP/1.1":
        raise RequestError("request_malformed")
    if target != codec.PATH.encode():
        raise RequestError("request_target_invalid")
    seen = {"host": False, "content-type": False, "connection": False}
    length = None

    def once(key, exact, code):
        if seen[key] or not exact:
            raise RequestError(code)
        seen[key] = True

    for name, value in fields:
        value = _trim(value)
        lower = name.lower()
        if lower == b"host":
            once("host", value == codec.HOST.encode(), "request_header_invalid")
        elif lower == b"content-type":
            once("content-type", value == codec.CONTENT_TYPE.encode(), "request_header_invalid")
        elif lower == b"connection":
            once("connection", value == b"close", "request_framing_invalid")
        elif lower == b"content-length":
            if length is not None:
                raise RequestError("request_framing_invalid")
            length = _length(value)
        elif lower in (b"transfer-encoding", b"content-encoding", b"expect", b"upgrade", b"te",
                       b"trailer", b"keep-alive", b"proxy-connection"):
            raise RequestError("request_framing_invalid")
        else:
            raise RequestError("request_header_invalid")
    if not seen["host"] or not seen["content-type"]:
        raise RequestError("request_header_invalid")
    if length is None or not seen["connection"]:
        raise RequestError("request_framing_invalid")
    return length


def _length(value):
    canonical = value == b"0" or (value and value[:1] != b"0" and value.isdigit() and value.isascii())
    if not canonical:
        raise RequestError("request_framing_invalid")
    if len(value) > len(str(codec.MAX_BODY_BYTES)):
        raise RequestError("request_body_too_large")
    length = int(value)
    if length > codec.MAX_BODY_BYTES:
        raise RequestError("request_body_too_large")
    return length


class PostExchange:
    """One POST connection after its head: pure and clock-free. Steps: ("pending",), ("body", bytes), ("refused",
    code), ("abandoned", "eof"|"reset"|"extra_input"), ("ignored",)."""

    def __init__(self, length, leftover):
        self.phase = "body"
        self.length = length
        self.body = b""
        self.response = None
        self.written = 0
        self.first = self.input(leftover)

    def input(self, data):
        if self.phase == "body":
            if len(data) > self.length - len(self.body):
                self.phase = "ended"
                return ("refused", "request_body_overrun")
            self.body += data
            if len(self.body) < self.length:
                return ("pending",)
            body, self.body = self.body, b""
            self.phase = "awaiting"
            return ("body", body)
        if self.phase in ("awaiting", "responding"):
            if not data:
                return ("pending",)
            self.phase = "ended"
            return ("abandoned", "extra_input")
        if self.phase == "complete":
            return ("ignored",)
        return ("pending",)

    def end(self, reset):
        if self.phase == "body":
            step = ("refused", "request_incomplete")
        elif self.phase in ("awaiting", "responding"):
            step = ("abandoned", "reset" if reset else "eof")
        elif self.phase == "complete":
            return ("ignored",)
        else:
            return ("pending",)
        self.phase = "ended"
        return step

    def respond(self, response):
        if self.phase != "awaiting":
            return False
        self.phase = "responding"
        self.response = response
        self.written = 0
        return True

    def output(self):
        return self.response[self.written:] if self.phase == "responding" else b""

    def wrote(self, count):
        if self.phase == "responding":
            self.written += min(count, len(self.response) - self.written)
            if self.written == len(self.response):
                self.phase = "complete"
        return self.phase == "complete"


_PHRASES = {200: "OK", 400: "Bad Request", 403: "Forbidden", 409: "Conflict"}


def post_response(status, body):
    """One fixed-length JSON response, then close; None for a body above
    MAX_BODY_BYTES or a status the contract does not use."""
    phrase = _PHRASES.get(status)
    if phrase is None or len(body) > codec.MAX_BODY_BYTES:
        return None
    head = (f"HTTP/1.1 {status} {phrase}\r\nContent-Type: {codec.CONTENT_TYPE}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return head.encode() + body


_REFUSAL_PHRASES = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed",
                    408: "Request Timeout", 413: "Content Too Large", 414: "URI Too Long",
                    431: "Request Header Fields Too Large", 502: "Bad Gateway", 504: "Gateway Timeout"}


def refusal(status):
    """A status-only refusal."""
    phrase = _REFUSAL_PHRASES.get(status, "Service Unavailable")
    return f"HTTP/1.1 {status} {phrase}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode()
