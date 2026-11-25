"""agentbox.provider v1 control codec and exchange checks (stdlib only).

The contract is contracts/provider/v1/README.md; the host's Rust codec
(crates/agentbox/src/provider.rs) implements the same rules and both test the
shared fixtures. Providers use this module for their control channel: frames
on stdin/stdout, diagnostics on stderr. Errors are fixed codes only and never
echo frame content.
"""
import base64
import json
import re

PROTOCOL = "agentbox.provider"
VERSION = 1

MAX_FRAME_BYTES = 16384
MAX_DEPTH = 3
MAX_ID_BYTES = 64
MAX_PATH_BYTES = 4096
MAX_PROVIDER_BYTES = 32
MAX_USER_BYTES = 32
MAX_TIMEOUT_MS = 86400000
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_DIAGNOSTIC_BYTES = 65536
CANCEL_GRACE_MS = 30000

REQUIRED_OPERATIONS = ("capabilities", "prepare", "create", "start", "status", "stop", "discard")
OPTIONAL_OPERATIONS = ("checkpoint", "restore")
OPERATIONS = REQUIRED_OPERATIONS + OPTIONAL_OPERATIONS
HOST_TYPES = OPERATIONS + ("cancel",)
PROVIDER_TYPES = (
    "described", "prepared", "created", "started", "reported",
    "stopped", "discarded", "checkpointed", "restored", "failed",
)
RESULTS = {
    "capabilities": "described",
    "prepare": "prepared",
    "create": "created",
    "start": "started",
    "status": "reported",
    "stop": "stopped",
    "discard": "discarded",
    "checkpoint": "checkpointed",
    "restore": "restored",
}
TRANSPORTS = ("tcp", "stdio")
TCP_HOSTS = ("127.0.0.1", "::1")
RETENTION = ("none", "home", "home_tmp", "disk")
# Optional provider features `described` declares. `select_user`: `create`
# may name an account other than DEFAULT_USER; `project_layout`: the host
# may place an explicit workspace at its own HOME-relative project location;
# `host_mounts`: `create` may bind host directories into a retained HOME;
# `explicit_retention`: retained storage lives outside the provider's own
# state (Podman's shared store), so a host allocates it only when the
# operator asks for it by name, never as a default.
FEATURES = ("select_user", "project_layout", "host_mounts", "explicit_retention")
# `create.mounts`: at most MAX_MOUNTS, each path at most MAX_MOUNT_PATH_BYTES.
MAX_MOUNTS = 8
MAX_MOUNT_PATH_BYTES = 768
ACCESS = ("ro", "rw")
# A project location's first component when outside the host HOME
# (crates/agentbox/src/inputs.rs OUTSIDE_ROOT).
OUTSIDE_ROOT = ".agentbox-root"
# The guest account every provider supports.
DEFAULT_USER = "agentbox"
# `prepared.agents`: an image's baked coding agents, each its npm version.
AGENTS = ("pi", "codex", "claude")
LIMIT_RANGES = {
    "cpus": (1, 256),
    "memory_mib": (64, 1048576),
    "pids": (1, 1048576),
    "disk_mib": (1, 16777216),
}
SETTLEMENT = ("settled", "unsettled", "unknown")
DURABILITY = ("unchanged", "retained", "uncertain")
STORAGE = ("clean", "unclean")
RESOURCE_STATES = ("absent", "ready", "unclean", "busy", "partial")
INSTANCE_STATES = ("absent", "live", "settled", "unsettled")
FAILURE_CODES = (
    "unsupported", "not_found", "binding_mismatch", "exists", "busy",
    "generation_mismatch", "unclean", "partial", "prerequisite",
    "cancelled", "timeout", "failed", "user_conflict",
    # Mount refusals (`host_mounts`): which cause, never its path or value.
    "mount_source_unavailable", "mount_source_unsupported", "mount_source_protected",
    "mount_source_overlap", "mount_destination_unsafe", "mounts_need_memory",
    # A shared engine store's refusals (Podman `store` shared): its helper
    # not demonstrably running (or not recognized), the prepared image
    # absent from it.
    "shared_store_uninitialized", "shared_image_missing",
    # A retained HOME that is gone (removed outside Agentbox): never made
    # again by a start.
    "retained_home_missing",
)
# A lost invocation of these may have written retained storage.
LOST_UNCERTAIN = ("create", "start", "stop", "discard", "restore")
FRAME_ERROR_CODES = (
    "frame_too_large", "truncated_frame", "invalid_framing", "invalid_encoding",
    "invalid_json", "invalid_number", "duplicate_key", "not_object",
    "invalid_version", "unsupported_version", "unknown_type", "wrong_direction",
    "unknown_field", "missing_field", "invalid_field", "limit_exceeded",
)
EXCHANGE_ERROR_CODES = (
    "unsupported_operation", "unsupported_capability", "operation_mismatch",
    "binding_mismatch", "generation_mismatch", "worker_mismatch",
    "capability_mismatch", "unexpected_frame",
)
ARGV_ERROR = "invalid_argv"


class ProtocolError(Exception):
    """A frame, exchange or argv refusal; `code` is the fixed code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _fail(code):
    raise ProtocolError(code)


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_COMPONENT = re.compile(r"[A-Za-z0-9._+-]+\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
# A retained HOME's engine volume name (`created.volume`, display only).
_VOLUME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_AGENT_VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z.-]{1,64})?\Z")
_ED25519_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"


def is_id(value):
    return isinstance(value, str) and _ID.match(value) is not None


def is_volume(value):
    """A retained HOME's engine volume name (`created.volume`)."""
    return isinstance(value, str) and _VOLUME.match(value) is not None


def is_user(value):
    """A guest login: `[a-z_][a-z0-9_-]{0,31}`."""
    return isinstance(value, str) and _USER.match(value) is not None


def is_path(value):
    """An absolute, normalized, shell-inert path of at most MAX_PATH_BYTES."""
    if not isinstance(value, str) or len(value.encode()) > MAX_PATH_BYTES:
        return False
    if not value.startswith("/"):
        return False
    parts = value[1:].split("/")
    return all(_COMPONENT.match(p) and p not in (".", "..") for p in parts)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


# Field checks. Each raises ProtocolError or returns.

def _id(value):
    if not is_id(value):
        _fail("invalid_field")


def _path(value):
    if not isinstance(value, str):
        _fail("invalid_field")
    if len(value.encode()) > MAX_PATH_BYTES:
        _fail("limit_exceeded")
    if not is_path(value):
        _fail("invalid_field")


def _sha256(value):
    if not (isinstance(value, str) and _SHA256.match(value)):
        _fail("invalid_field")


def _timeout(value):
    if not _is_int(value) or value < 1:
        _fail("invalid_field")
    if value > MAX_TIMEOUT_MS:
        _fail("limit_exceeded")


def _generation(value):
    if not _is_int(value):
        _fail("invalid_field")


def _bool(value):
    if not isinstance(value, bool):
        _fail("invalid_field")


def _ssh_key(value):
    if not isinstance(value, str) or not value.startswith("ssh-ed25519 "):
        _fail("invalid_field")
    text = value[len("ssh-ed25519 "):]
    try:
        blob = base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        _fail("invalid_field")
    if (len(blob) != 51 or not blob.startswith(_ED25519_PREFIX)
            or base64.b64encode(blob).decode() != text):
        _fail("invalid_field")


def _matches(pattern):
    def check(value):
        if not (isinstance(value, str) and pattern.match(value)):
            _fail("invalid_field")
    return check


def _one_of(values):
    def check(value):
        if not (isinstance(value, str) and value in values):
            _fail("invalid_field")
    return check


def _distinct(values):
    """A list of distinct strings of `values`; returns it."""
    def check(value):
        if not isinstance(value, list):
            _fail("invalid_field")
        if any(not isinstance(v, str) or v not in values for v in value):
            _fail("invalid_field")
        if len(set(value)) != len(value):
            _fail("invalid_field")
    return check


def _operations(value):
    _distinct(OPERATIONS)(value)
    if any(op not in value for op in REQUIRED_OPERATIONS):
        _fail("invalid_field")
    if sum(op in value for op in OPTIONAL_OPERATIONS) == 1:
        _fail("invalid_field")


def _retention_list(value):
    _distinct(RETENTION)(value)
    if not value:
        _fail("invalid_field")


_PLAIN = re.compile(r"[A-Za-z0-9._-]{1,255}\Z")


def _plain_parts(text):
    """`text`'s components when all plain and at most 1024 bytes, else None."""
    if not isinstance(text, str) or len(text.encode()) > 1024:
        return None
    parts = text.split("/")
    return parts if all(_PLAIN.match(p) and p not in (".", "..") for p in parts) else None


def is_project(text):
    """A guest-HOME-relative location (crates/agentbox/src/inputs.rs
    `is_project`): plain components, at most 1024 bytes, a hidden first
    component only as OUTSIDE_ROOT with something beneath it."""
    parts = _plain_parts(text)
    return parts is not None and (not parts[0].startswith(".") or (parts[0] == OUTSIDE_ROOT and len(parts) > 1))


def is_mount_destination(text):
    """A mount's HOME-relative destination: `is_project`'s, a hidden first
    component allowed too (`.pi`, `.ssh`) save Agentbox's own: one starting
    `.agentbox` only as OUTSIDE_ROOT with something beneath it."""
    parts = _plain_parts(text)
    return parts is not None and (not parts[0].startswith(".agentbox")
                                  or (parts[0] == OUTSIDE_ROOT and len(parts) > 1))


def overlap(a, b):
    """Whether `/`-separated paths `a` and `b` are equal or one contains the other."""
    def within(inner, outer):
        return inner == outer or inner.startswith(outer + "/")
    return within(a, b) or within(b, a)


def mounts_valid(mounts):
    """A list of 1 to MAX_MOUNTS {source, destination, access} dicts: sources
    `is_path`, destinations `is_mount_destination`, each at most
    MAX_MOUNT_PATH_BYTES, sources and destinations pairwise disjoint."""
    if not isinstance(mounts, list) or not 1 <= len(mounts) <= MAX_MOUNTS:
        return False
    for index, mount in enumerate(mounts):
        if not isinstance(mount, dict) or set(mount) != {"source", "destination", "access"}:
            return False
        source, destination = mount["source"], mount["destination"]
        if not (is_path(source) and len(source.encode()) <= MAX_MOUNT_PATH_BYTES
                and is_mount_destination(destination)
                and len(destination.encode()) <= MAX_MOUNT_PATH_BYTES and mount["access"] in ACCESS):
            return False
        if any(overlap(source, o["source"]) or overlap(destination, o["destination"]) for o in mounts[:index]):
            return False
    return True


def _mounts(value):
    if not isinstance(value, list):
        _fail("invalid_field")
    if len(value) > MAX_MOUNTS:
        _fail("limit_exceeded")
    for item in value:
        if not isinstance(item, dict):
            _fail("invalid_field")
        if any(key not in ("source", "destination", "access") for key in item):
            _fail("unknown_field")
        if any(key not in item for key in ("source", "destination", "access")):
            _fail("missing_field")
        if not all(isinstance(item[key], str) for key in item):
            _fail("invalid_field")
    if not mounts_valid(value):
        _fail("invalid_field")


def _agents(value):
    """Every agent of AGENTS, each a plain npm version."""
    if not isinstance(value, dict):
        _fail("invalid_field")
    if any(key not in AGENTS for key in value):
        _fail("unknown_field")
    if any(key not in value for key in AGENTS):
        _fail("missing_field")
    if not all(isinstance(v, str) and _AGENT_VERSION.match(v) for v in value.values()):
        _fail("invalid_field")


def _limits(value):
    if not isinstance(value, dict):
        _fail("invalid_field")
    if any(key not in LIMIT_RANGES for key in value):
        _fail("unknown_field")
    for key, (low, high) in LIMIT_RANGES.items():
        if key in value:
            item = value[key]
            if not _is_int(item) or item < low:
                _fail("invalid_field")
            if item > high:
                _fail("limit_exceeded")


def _transport(value):
    if not isinstance(value, dict):
        _fail("invalid_field")
    if any(key not in ("kind", "host", "port") for key in value):
        _fail("unknown_field")
    if "kind" not in value:
        _fail("missing_field")
    _one_of(TRANSPORTS)(value["kind"])
    if value["kind"] == "stdio":
        if len(value) != 1:
            _fail("unknown_field")
        return
    for key in ("host", "port"):
        if key not in value:
            _fail("missing_field")
    _one_of(TCP_HOSTS)(value["host"])
    port = value["port"]
    if not _is_int(port) or not 1 <= port <= 65535:
        _fail("invalid_field")


def _only(*allowed):
    return _one_of(allowed)


_COMMON = {
    "operation": _id, "timeout_ms": _timeout, "run": _id, "resource": _id,
    "execution": _id, "instance": _id, "checkpoint": _id,
    "generation": _generation, "recipe": _path, "worker": _path,
    "image": _sha256, "worker_sha256": _sha256, "accept_unclean": _bool,
    "authorized_key": _ssh_key, "host_key": _ssh_key,
    "provider": _matches(_PROVIDER), "user": _matches(_USER),
    "resource_state": _one_of(RESOURCE_STATES),
    "instance_state": _one_of(INSTANCE_STATES),
    "durability": _one_of(DURABILITY), "storage": _one_of(STORAGE),
    "settlement": _one_of(SETTLEMENT), "op": _one_of(OPERATIONS),
    "code": _one_of(FAILURE_CODES),
}

# type -> (required, optional, per-type overrides of _COMMON)
FIELDS = {
    "capabilities": (("operation", "timeout_ms"), (), {}),
    "prepare": (("operation", "timeout_ms", "recipe", "worker"), (), {}),
    "create": (("operation", "timeout_ms", "run", "resource", "image", "retention", "user"), ("mounts",),
               {"retention": _one_of(RETENTION), "mounts": _mounts}),
    "start": (("operation", "timeout_ms", "run", "resource", "execution", "instance",
               "generation", "accept_unclean", "authorized_key", "limits"), (),
              {"limits": _limits}),
    "status": (("operation", "timeout_ms", "run", "resource"), ("execution", "instance"), {}),
    "stop": (("operation", "timeout_ms", "run", "resource", "execution", "instance",
              "generation"), (), {}),
    "discard": (("operation", "timeout_ms", "run", "resource"), ("checkpoint",), {}),
    "checkpoint": (("operation", "timeout_ms", "run", "resource", "checkpoint", "generation",
                    "accept_unclean"), (), {}),
    "restore": (("operation", "timeout_ms", "run", "resource", "checkpoint", "generation"), (), {}),
    "cancel": (("operation",), (), {}),
    "described": (("operation", "provider", "operations", "transport", "retention", "limits", "features"), (),
                  {"operations": _operations, "transport": _one_of(TRANSPORTS),
                   "retention": _retention_list, "limits": _distinct(tuple(LIMIT_RANGES)),
                   "features": _distinct(FEATURES)}),
    "prepared": (("operation", "image", "worker_sha256"), ("agents",), {"agents": _agents}),
    "created": (("operation", "run", "resource", "retention", "generation", "user", "home"), ("volume",),
                {"retention": _one_of(RETENTION), "home": _path, "volume": _matches(_VOLUME)}),
    "started": (("operation", "run", "resource", "execution", "instance", "generation",
                 "transport", "user", "host_key", "worker_sha256", "home", "control"), (),
                {"transport": _transport, "home": _path, "control": _path}),
    "reported": (("operation", "run", "resource", "resource_state", "generation"),
                 ("execution", "instance", "instance_state"), {}),
    "stopped": (("operation", "run", "resource", "execution", "instance", "settlement",
                 "durability", "generation", "storage"), (),
                {"settlement": _only("settled")}),
    "discarded": (("operation", "run", "resource", "settlement"), ("checkpoint",),
                  {"settlement": _only("settled")}),
    "checkpointed": (("operation", "run", "resource", "checkpoint", "generation", "storage"), (), {}),
    "restored": (("operation", "run", "resource", "checkpoint", "generation", "storage"), (), {}),
    "failed": (("operation", "op", "code", "settlement", "durability"), (), {}),
}

# Optional fields that appear all together or not at all.
_GROUPS = {
    "status": ("execution", "instance"),
    "reported": ("execution", "instance", "instance_state"),
}

# Table order of each type, for canonical encoding and field checks.
_ORDER = {
    "status": ("operation", "timeout_ms", "run", "resource", "execution", "instance"),
    "reported": ("operation", "run", "resource", "execution", "instance", "instance_state",
                 "resource_state", "generation"),
}


def _order(kind):
    required, optional, _ = FIELDS[kind]
    return _ORDER.get(kind, required + optional)


# Envelope: steps 1-9 of contracts/v1's validation order.

def nesting_depth(text):
    depth = deepest = 0
    in_string = escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            deepest = max(deepest, depth)
        elif ch in "}]":
            depth = max(depth - 1, 0)
    return deepest


def _safe_integer(token):
    plain = token == "0" or (token[:1] not in ("", "0") and token.isdigit() and token.isascii())
    return plain and len(token) <= 16 and int(token) <= MAX_SAFE_INTEGER


class _Pairs(list):
    pass


def _parse(text):
    """JSON grammar, then lone surrogates, numbers and duplicate keys, in
    that order over the whole text."""
    flags = {"number": False}

    def number(token):
        if not _safe_integer(token):
            flags["number"] = True
            return 0
        return int(token)

    def constant(_):
        raise ValueError

    try:
        tree = json.loads(text, object_pairs_hook=_Pairs, parse_int=number,
                          parse_float=number, parse_constant=constant)
    except (ValueError, RecursionError):
        _fail("invalid_json")
    state = {"string": False, "duplicate": False}

    def string(value):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            state["string"] = True

    def build(node):
        if isinstance(node, _Pairs):
            out = {}
            for key, value in node:
                string(key)
                if key in out:
                    state["duplicate"] = True
                out[key] = build(value)
            return out
        if isinstance(node, list):
            return [build(item) for item in node]
        if isinstance(node, str):
            string(node)
        return node

    value = build(tree)
    if state["string"]:
        _fail("invalid_json")
    if flags["number"]:
        _fail("invalid_number")
    if state["duplicate"]:
        _fail("duplicate_key")
    return value


def _envelope(data, own, other):
    if len(data) > MAX_FRAME_BYTES:
        _fail("frame_too_large")
    if b"\n" in data or b"\r" in data:
        _fail("invalid_framing")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid_encoding")
    if nesting_depth(text) > MAX_DEPTH:
        _fail("invalid_json")
    frame = _parse(text)
    if not isinstance(frame, dict):
        _fail("not_object")
    version = frame.get("v")
    if not _is_int(version):
        _fail("invalid_version")
    if version != VERSION:
        _fail("unsupported_version")
    if "type" not in frame:
        _fail("missing_field")
    kind = frame["type"]
    if not isinstance(kind, str):
        _fail("invalid_field")
    if kind not in own:
        _fail("wrong_direction" if kind in other else "unknown_type")
    return kind, frame


def _decode(data, own, other):
    kind, frame = _envelope(data, own, other)
    _fields(kind, frame)
    return frame


def _fields(kind, frame):
    """Steps 10-12 on a parsed frame of a known type."""
    required, optional, overrides = FIELDS[kind]
    for key in frame:
        if key not in ("v", "type") and key not in required and key not in optional:
            _fail("unknown_field")
    if any(key not in frame for key in required):
        _fail("missing_field")
    group = _GROUPS.get(kind, ())
    if any(key in frame for key in group) and not all(key in frame for key in group):
        _fail("missing_field")
    for key in _order(kind):
        if key in frame:
            overrides.get(key, _COMMON.get(key))(frame[key])
    if kind == "stopped":
        clean = {"retained": "clean", "uncertain": "unclean"}.get(frame["durability"])
        if clean is not None and frame["storage"] != clean:
            _fail("invalid_field")


def decode_request(data):
    """A host -> provider frame (bytes without LF) as a dict."""
    return _decode(data, HOST_TYPES, PROVIDER_TYPES)


def decode_response(data):
    """A provider -> host frame (bytes without LF) as a dict."""
    return _decode(data, PROVIDER_TYPES, HOST_TYPES)


def encode(frame):
    """Canonical bytes (no LF) of a valid frame dict; checks it first."""
    kind = frame.get("type")
    if kind not in FIELDS:
        _fail("unknown_type")
    if "v" in frame:
        if not _is_int(frame["v"]):
            _fail("invalid_version")
        if frame["v"] != VERSION:
            _fail("unsupported_version")
    # The original shape, nested objects included: nothing unknown is
    # dropped by canonicalizing below.
    _fields(kind, frame)
    ordered = {"v": VERSION, "type": kind}
    for key in _order(kind):
        if key in frame:
            value = frame[key]
            if key == "transport" and isinstance(value, dict):
                value = {k: value[k] for k in ("kind", "host", "port") if k in value}
            elif key == "limits" and isinstance(value, dict):
                value = {k: value[k] for k in LIMIT_RANGES if k in value}
            elif key == "agents" and isinstance(value, dict):
                value = {k: value[k] for k in AGENTS if k in value}
            elif key == "mounts" and isinstance(value, list):
                value = [{k: m[k] for k in ("source", "destination", "access") if k in m}
                         if isinstance(m, dict) else m for m in value]
            ordered[key] = value
    data = json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()
    if kind in PROVIDER_TYPES:
        decode_response(data)
    else:
        decode_request(data)
    return data


def read_frame(stream):
    """One frame without its LF from a binary stream; None at a clean end.
    Never buffers more than MAX_FRAME_BYTES + 1 bytes."""
    line = stream.readline(MAX_FRAME_BYTES + 1)
    if not line:
        return None
    if line.endswith(b"\n"):
        return line[:-1]
    if len(line) > MAX_FRAME_BYTES:
        _fail("frame_too_large")
    _fail("truncated_frame")


def write_frame(stream, frame):
    stream.write(encode(frame) + b"\n")
    stream.flush()


# Invocation argv after the entry.

def parse_argv(args):
    """`control STATE` or `connect STATE RUN EXECUTION INSTANCE` as a tuple."""
    args = list(args)
    if len(args) == 2 and args[0] == "control" and is_path(args[1]):
        return tuple(args)
    if (len(args) == 5 and args[0] == "connect" and is_path(args[1])
            and all(is_id(a) for a in args[2:])):
        return tuple(args)
    _fail(ARGV_ERROR)


def control_argv(state):
    return list(parse_argv(["control", state]))


def connect_argv(state, run, execution, instance):
    return list(parse_argv(["connect", state, run, execution, instance]))


# Exchange checks: the host's view of one control invocation.

_ECHOED = ("run", "resource", "execution", "instance", "checkpoint", "retention", "user")


class Exchange:
    """One invocation from its request to its terminal frame or loss.

    `described` is the provider's decoded `described` frame (required for
    every request but `capabilities`); `worker_sha256` the prepared image's
    worker, required for `start`. Any error is final and leaves settlement
    unknown."""

    def __init__(self, request, described=None, worker_sha256=None):
        self.request = request
        self.described = described
        self.worker_sha256 = worker_sha256
        self.inflight = None
        self.cancelled = False
        self.waiting = False
        self.result = None
        kind = request["type"]
        if kind == "cancel":
            self._break("unexpected_frame")
        if kind != "capabilities":
            if described is None or kind not in described["operations"]:
                self._break("unsupported_operation")
            if kind == "create" and request["retention"] not in described["retention"]:
                self._break("unsupported_capability")
            if kind == "create" and request["user"] != DEFAULT_USER and "select_user" not in described["features"]:
                self._break("unsupported_capability")
            # Mounts need the feature and retained storage.
            if kind == "create" and "mounts" in request and (
                    "host_mounts" not in described["features"] or request["retention"] == "none"):
                self._break("unsupported_capability")
            if kind == "start" and any(k not in described["limits"] for k in request["limits"]):
                self._break("unsupported_capability")
            # Removing one checkpoint is part of the optional operations.
            if kind == "discard" and "checkpoint" in request and "checkpoint" not in described["operations"]:
                self._break("unsupported_operation")
        self.inflight = request

    def _break(self, code):
        # Final; replaces any earlier terminal frame.
        self.result = "error"
        raise ProtocolError(code)

    def _check(self):
        """Any frame after the terminal one, or after an error, is refused
        and poisons the exchange."""
        if self.result is not None:
            self._break("unexpected_frame")

    def frame_error(self):
        """The host refused a frame of this invocation before the exchange
        saw it (a frame error): final, as an exchange error."""
        self.result = "error"

    def host(self, frame):
        """A later host frame: `cancel`, or the owner session's `stop`."""
        self._check()
        start = self.request
        if frame["type"] == "cancel":
            if self.inflight is None or self.cancelled:
                self._break("unexpected_frame")
            if frame["operation"] != self.inflight["operation"]:
                self._break("operation_mismatch")
            self.cancelled = True
            return
        if frame["type"] != "stop" or not self.waiting:
            self._break("unexpected_frame")
        if frame["operation"] == start["operation"]:
            self._break("operation_mismatch")
        if any(frame[k] != start[k] for k in ("run", "resource", "execution", "instance")):
            self._break("binding_mismatch")
        if frame["generation"] != start["generation"]:
            self._break("generation_mismatch")
        self.waiting = False
        self.cancelled = False
        self.inflight = frame

    def provider(self, frame):
        """A provider frame on control stdout."""
        self._check()
        if self.waiting:
            self._break("unexpected_frame")
        request = self.inflight
        if frame["operation"] != request["operation"]:
            self._break("operation_mismatch")
        if frame["type"] == "failed":
            if frame["op"] != request["type"]:
                self._break("operation_mismatch")
            self.result = frame
            return
        if frame["type"] != RESULTS[request["type"]]:
            self._break("unexpected_frame")
        for key in _ECHOED:
            if key in frame and key in request and frame[key] != request[key]:
                self._break("binding_mismatch")
        if frame["type"] == "reported" and ("instance" in frame) != ("instance" in request):
            self._break("binding_mismatch")
        if frame["type"] == "discarded" and ("checkpoint" in frame) != ("checkpoint" in request):
            self._break("binding_mismatch")
        if (frame["type"] == "checkpointed" and frame["storage"] == "unclean"
                and not request["accept_unclean"]):
            self._break("binding_mismatch")
        self._generation(request, frame)
        if frame["type"] == "started":
            if frame["worker_sha256"] != self.worker_sha256:
                self._break("worker_mismatch")
            if frame["transport"]["kind"] != self.described["transport"]:
                self._break("capability_mismatch")
            self.waiting = True
            self.cancelled = False
            self.inflight = None
            return
        self.result = frame

    def _generation(self, request, frame):
        kind = frame["type"]
        if kind == "created":
            expected = 0
        elif kind in ("started", "checkpointed"):
            expected = request["generation"]
        elif kind == "restored":
            expected = request["generation"] + 1
        elif kind == "stopped":
            expected = request["generation"] + (0 if frame["durability"] == "unchanged" else 1)
        else:
            return
        if frame["generation"] != expected:
            self._break("generation_mismatch")

    def exit(self):
        """The invocation ended (any exit status, or killed)."""
        if self.result is None:
            self.result = "lost"

    def disconnect(self):
        """An SSH connection ended; it settles nothing."""

    def outcome(self):
        """None while pending; else {end, code, settlement, durability}.
        Lost and refused ("error") exchanges settle nothing."""
        result = self.result
        if result is None:
            return None
        if result in ("lost", "error"):
            op = self.inflight["type"] if self.inflight is not None else "start"
            durability = "uncertain" if op in LOST_UNCERTAIN else "unchanged"
            return {"end": result, "code": None, "settlement": "unknown",
                    "durability": durability}
        if result["type"] == "failed":
            return {"end": "failed", "code": result["code"],
                    "settlement": result["settlement"], "durability": result["durability"]}
        return {"end": result["type"], "code": None,
                "settlement": result.get("settlement"),
                "durability": result.get("durability")}
