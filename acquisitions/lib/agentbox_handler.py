"""Shared runtime of trusted handler workers (acquisitions/contracts/handlers/v1).

Host control code, not an untrusted plugin. Agentbox runs one handler's
worker per admitted request through its lifecycle-owned tool slot, in a
process group of its own that the slot kills and reaps on a stop,
cancellation or deadline:

    INTERPRETER -I -B ASSETS/acquisitions/handlers/ID/worker.py acquire STAGE/request.json

The host made STAGE fresh (0700, this user's) and wrote request.json into
it (O_EXCL, 0600) before the start:

    {"schema":"agentbox.handler-request.v1", "handler":ID, "version":V,
     "operation":OP, "args":{...guest...}, "policy":{...operator...},
     "ids":{"run","execution","session","request","request_sha256"},
     "stage":ABS, "artifact":ABS (STAGE/artifact), "remaining_ms":N,
     "tools":{NAME:ABS}, "limits":{"metadata_bytes":N[, "acquire_bytes":N]}
     [, "test":{...}]}

`args` are the guest's, admitted by grammar and size only: every meaning is
the worker's to check against `policy`, the operator's snapshotted file.
`test` exists only in the host's test build (a synthetic loopback endpoint).
`acquire_bytes` is given exactly to an `http`-metered handler (its
manifest's `metering`): the upstream HTTP body bytes it may read, its share
of the execution's acquired-byte allowance (`Meter`).

The worker writes exactly one file, STAGE/artifact (O_EXCL, 0600), and
prints exactly one line:

    {"schema":"agentbox.handler-result.v1","outcome":"ok","size":N,
     "sha256":HEX,"metadata":{...}[,"provenance":[{name,version,integrity}]]
     [,"acquired":N]}
    {"schema":"agentbox.handler-result.v1","outcome":"error","code":C
     [,"acquired":N]}

C matches `[a-z][a-z0-9_]{0,63}`; it reaches the guest as the request's
denial reason, attributed to this handler. The metadata reaches the guest
in its `ready`; the provenance (at most 256 packages it fetched) stays the
host's record. None carries a path, URL, address or tool text. A metered
worker's every line carries `acquired`, what its `Meter` counted, failures
included. A malformed request or an unexpected failure exits nonzero with
no line; the host reports a fixed failure and keeps the whole allowance
charged. The host removes STAGE once the slot settled.

Workers import this module from the trusted import directory
ASSETS/acquisitions/lib, which they put on `sys.path` themselves (`-I`
adds no script directory).
"""

import hashlib
import json
import os
import re
import stat
import sys
import time

REQUEST_SCHEMA = "agentbox.handler-request.v1"
RESULT_SCHEMA = "agentbox.handler-result.v1"
COMMAND = "acquire"
REQUEST_FILE = "request.json"
ARTIFACT_FILE = "artifact"
MAX_REQUEST_BYTES = 256 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 16

CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
HANDLER = re.compile(r"[a-z][a-z0-9-]{0,31}")
ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
SESSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SHA256 = re.compile(r"[0-9a-f]{64}")
KEY = re.compile(r"[A-Za-z0-9_.:@/+-]{1,128}")
TOOL = re.compile(r"[a-z][a-z0-9.-]{0,31}")

FIELDS = {"schema", "handler", "version", "operation", "args", "policy", "ids", "stage",
          "artifact", "remaining_ms", "tools", "limits"}
IDS = {"run", "execution", "session", "request", "request_sha256"}


class Refused(Exception):
    """A handler's fixed outcome code; never carries a path, URL or tool text."""

    def __init__(self, code):
        super().__init__(code)
        assert CODE.fullmatch(code), code
        self.code = code


class Malformed(Exception):
    """Not a request of this host: no result line."""


def strict_loads(data, max_bytes=MAX_REQUEST_BYTES):
    """Strict JSON: UTF-8, no duplicate key, no NaN or infinity, at most
    `MAX_DEPTH` levels; raises ValueError."""
    if len(data) > max_bytes:
        raise ValueError("too large")
    text = data.decode("utf-8") if isinstance(data, bytes) else data

    def unique(pairs):
        keys = [key for key, _ in pairs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate key")
        return dict(pairs)

    def constant(_):
        raise ValueError("constant")

    value = json.loads(text, object_pairs_hook=unique, parse_constant=constant)
    if depth(value) > MAX_DEPTH:
        raise ValueError("too deep")
    return value


def depth(value):
    if isinstance(value, dict):
        return 1 + max((depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((depth(item) for item in value), default=0)
    return 0


def canonical(value):
    """The host's canonical bytes: sorted keys, compact, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def plain_path(text):
    return (isinstance(text, str) and text.startswith("/") and "\0" not in text
            and all(part not in ("", ".", "..") for part in text[1:].split("/")))


def safe_integer(value, low=0, high=MAX_SAFE_INTEGER):
    return type(value) is int and low <= value <= high


def keys_valid(value):
    if isinstance(value, dict):
        return all(isinstance(key, str) and KEY.fullmatch(key) and keys_valid(item)
                   for key, item in value.items())
    if isinstance(value, list):
        return all(keys_valid(item) for item in value)
    return True


def exact(obj, required, optional=()):
    """`obj` is an object of exactly `required` plus some of `optional`."""
    return isinstance(obj, dict) and set(required) <= set(obj) <= set(required) | set(optional)


class Clock:
    """The request's one clock, from `remaining_ms` at start."""

    def __init__(self, remaining_ms, code="acquisition_expired"):
        self.deadline = time.monotonic() + remaining_ms / 1000.0
        self.code = code

    def left(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Refused(self.code)
        return left


class Meter:
    """Upstream body bytes read against the request's allowance (`None`:
    unmetered, nothing counted or bounded). `room()` is what may still be
    read; `take(n)` counts bytes already read and never passes the
    allowance, because callers read at most `room()`."""

    def __init__(self, allowance):
        self.allowance = allowance
        self.used = 0

    def room(self, wanted):
        """At most `wanted`, within the allowance."""
        if self.allowance is None:
            return wanted
        return max(0, min(wanted, self.allowance - self.used))

    def take(self, count):
        self.used += count
        if self.allowance is not None and self.used > self.allowance:
            raise AssertionError("read past the allowance")

    def check(self, total):
        """Refuses (`acquire_limit`) a body of known length `total` that
        cannot fit, before any of it is read."""
        if self.allowance is not None and self.used + total > self.allowance:
            raise Refused("acquire_limit")


class Request:
    """One validated request file."""

    def __init__(self, value):
        self.value = value
        self.handler = value["handler"]
        self.version = value["version"]
        self.operation = value["operation"]
        self.args = value["args"]
        self.policy = value["policy"]
        self.ids = value["ids"]
        self.stage = value["stage"]
        self.artifact = value["artifact"]
        self.tools = value["tools"]
        self.metadata_bytes = value["limits"]["metadata_bytes"]
        self.meter = Meter(value["limits"].get("acquire_bytes"))
        self.test = value.get("test")
        self.clock = Clock(value["remaining_ms"])


def read_request(argv):
    """`acquire STAGE/request.json`: this user's private regular file, never
    through a link, of the request grammar."""
    if len(argv) != 2 or argv[0] != COMMAND or not plain_path(argv[1]) \
            or not argv[1].endswith("/" + REQUEST_FILE):
        raise Malformed()
    path = argv[1]
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Malformed() from None
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or stat.S_IMODE(st.st_mode) & 0o077 or st.st_size > MAX_REQUEST_BYTES):
            raise Malformed()
        data = b""
        while len(data) <= MAX_REQUEST_BYTES:
            chunk = os.read(fd, MAX_REQUEST_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    try:
        value = strict_loads(data)
    except (ValueError, UnicodeDecodeError):
        raise Malformed() from None
    if not exact(value, FIELDS, ("test",)):
        raise Malformed()
    ids, tools, limits = value["ids"], value["tools"], value["limits"]
    stage = value["stage"]
    ok = (value["schema"] == REQUEST_SCHEMA
          and isinstance(value["handler"], str) and HANDLER.fullmatch(value["handler"])
          and isinstance(value["version"], str) and 0 < len(value["version"]) <= 32
          and isinstance(value["operation"], str) and HANDLER.fullmatch(value["operation"])
          and isinstance(value["args"], dict) and isinstance(value["policy"], dict)
          and exact(ids, IDS)
          and all(isinstance(ids[key], str) for key in IDS)
          and ID.fullmatch(ids["request"]) and SESSION.fullmatch(ids["session"])
          and SHA256.fullmatch(ids["request_sha256"])
          and plain_path(stage) and path == stage + "/" + REQUEST_FILE
          and value["artifact"] == stage + "/" + ARTIFACT_FILE
          and safe_integer(value["remaining_ms"])
          and isinstance(tools, dict)
          and all(isinstance(name, str) and TOOL.fullmatch(name) and plain_path(tool)
                  for name, tool in tools.items())
          and exact(limits, {"metadata_bytes"}, ("acquire_bytes",))
          and safe_integer(limits["metadata_bytes"])
          and ("acquire_bytes" not in limits or safe_integer(limits["acquire_bytes"]))
          and ("test" not in value or isinstance(value["test"], dict)))
    if not ok:
        raise Malformed()
    return Request(value)


def open_stage(request, unsafe="staging_unsafe"):
    """The host's fresh request directory: this user's, private, not a link,
    holding exactly the request file. Its descriptor."""
    try:
        fd = os.open(request.stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused(unsafe) from None
    try:
        st = os.fstat(fd)
        if (st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077
                or sorted(os.listdir(fd)) != [REQUEST_FILE]):
            raise Refused(unsafe)
    except BaseException:
        os.close(fd)
        raise
    return fd


def create(stage_fd, name, failed="staging_failed"):
    """A fresh private file `name` under the stage (O_EXCL, never a link)."""
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=stage_fd)
    except OSError:
        raise Refused(failed) from None
    try:
        os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise Refused(failed) from None
    return fd


def write_all(fd, data, failed="staging_failed"):
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except OSError:
            raise Refused(failed) from None
        view = view[written:]


class Sink:
    """The artifact as it streams: written, counted and hashed."""

    def __init__(self, fd, failed="staging_failed"):
        self.fd = fd
        self.failed = failed
        self.digest = hashlib.sha256()
        self.size = 0

    def write(self, data):
        write_all(self.fd, data, self.failed)
        self.digest.update(data)
        self.size += len(data)

    def finish(self):
        try:
            os.fsync(self.fd)
        except OSError:
            raise Refused(self.failed) from None
        return self.size, self.digest.hexdigest()


def emit(fields):
    line = json.dumps(dict([("schema", RESULT_SCHEMA)] + fields), separators=(",", ":"),
                      ensure_ascii=False)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


MAX_PROVENANCE = 256


def main(operations, argv=None):
    """Runs one request: `operations` maps each operation the worker serves
    to a function of the request returning (size, sha256, metadata) of the
    artifact it wrote, or (size, sha256, metadata, provenance) with the
    packages it fetched, or raising `Refused`. Exit status."""
    sys.dont_write_bytecode = True
    argv = sys.argv[1:] if argv is None else argv
    try:
        request = read_request(argv)
    except Malformed:
        return 2
    acquire = operations.get(request.operation)
    metered = [] if request.meter.allowance is None else [("acquired", request.meter.used)]
    try:
        if acquire is None:
            raise Refused("operation_unsupported")
        result = acquire(request)
        size, sha256, metadata = result[:3]
        provenance = result[3] if len(result) == 4 else []
        if not (safe_integer(size, 1) and SHA256.fullmatch(sha256)
                and isinstance(metadata, dict) and keys_valid(metadata)
                and isinstance(provenance, list) and len(provenance) <= MAX_PROVENANCE):
            return 3
        if len(canonical(metadata)) > request.metadata_bytes:
            raise Refused("metadata_too_large")
    except Refused as refused:
        if metered:
            metered = [("acquired", request.meter.used)]
        emit([("outcome", "error"), ("code", refused.code)] + metered)
        return 0
    if metered:
        metered = [("acquired", request.meter.used)]
    fields = [("outcome", "ok"), ("size", size), ("sha256", sha256), ("metadata", metadata)]
    if provenance:
        fields.append(("provenance", provenance))
    emit(fields + metered)
    return 0
