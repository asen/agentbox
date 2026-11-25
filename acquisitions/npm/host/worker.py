"""Trusted host worker of the `npm` handler (acquisitions/npm/contract/v1): read access
to one operator-approved npm registry for native npm in the jail.

    policy  {"schema":"agentbox.npm.registry-policy.v1",
             "registry":"https://registry.npmjs.org/"}

Two operations, each one batch of at most 256 items the jail's registry
adapter asks for on behalf of npm (acquisitions/npm/jail/npm.py):

    metadata  {"names":[NAME,...],"format":"abbreviated"|"full"}
              per name: GET REGISTRY/NAME (scoped: @SCOPE%2fNAME), the
              abbreviated (`application/vnd.npm.install-v1+json`) or full
              document; 404 is `missing`. Bodies stay opaque here: npm in
              the jail parses and resolves them.
    tarballs  {"packages":[{"name":NAME,"version":VERSION},...]}
              per package: GET REGISTRY/NAME/VERSION, its version document,
              parsed (bounded): exactly that name and version, and
              `dist.tarball` exactly REGISTRY/NAME/-/BASENAME-VERSION.tgz,
              the URL this worker derives itself; then that tarball, its
              `dist.integrity` (sha512, else `dist.shasum`) checked. A
              missing version is `missing`. The tarball stays opaque.

The host never resolves, extracts or runs anything: names and versions are
the guest's (npm's) choice, the URLs this worker's, every one on the
policy's registry. HTTPS only, the host's resolver and system trust, no
redirect, proxy, credential, cookie, retry or compression, one connection
per GET. Every body byte read counts against the request's acquired-byte
allowance (`agentbox_handler.Meter`); a metadata batch's bodies are at most
64 MiB, a tarball batch's 500 MiB.

    artifact  BODY... INDEX TRAILER
              INDEX    canonical JSON {"schema":"agentbox.npm.batch.v1",
                       "operation":OP,"items":[{"name","status","bytes"
                       [,"version","integrity"]}...]} (ok items' bodies in
                       order before it)
              TRAILER  "\\nagentbox.npm.batch.v1 " + 20 decimal digits (the
                       INDEX's length) + "\\n"
    metadata  {"format":"agentbox.npm.batch.v1","items":N}
    result    `provenance`: each tarball fetched, {name, version, integrity}

The guest checks the artifact's size and SHA-256 against its `ready`, then
the index against the bytes; the registry's documents are untrusted input
to npm there, not to this host.
"""

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
import agentbox_packages as packages  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, Refused  # noqa: E402

POLICY_SCHEMA = "agentbox.npm.registry-policy.v1"
BATCH_SCHEMA = "agentbox.npm.batch.v1"
TRAILER_PREFIX = b"\nagentbox.npm.batch.v1 "
TRAILER_DIGITS = 20
MAX_ITEMS = 256
MAX_NAME_BYTES = 214
MAX_VERSION_BYTES = 256
MAX_METADATA_BATCH = 64 * 1024 * 1024
MAX_TARBALL_BATCH = 500 * 1024 * 1024
# One version document, read and parsed whole.
MAX_VERSION_DOC = 4 * 1024 * 1024
MAX_REGISTRY_URL = 256
CHUNK = 1 << 16

ABBREVIATED = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8, */*"
FULL = "application/json"
FORMATS = {"abbreviated": ABBREVIATED, "full": FULL}

NAME_PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~-]*")
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?")
SEGMENT = re.compile(r"[A-Za-z0-9_~@+-][A-Za-z0-9._~@+-]*")
SHA512 = re.compile(r"sha512-([A-Za-z0-9+/]{86}==)")
SHA1_HEX = re.compile(r"[0-9a-f]{40}")


# Grammar.

def package_name(text):
    """An npm name: `NAME` or `@SCOPE/NAME`, each part
    `[A-Za-z0-9][A-Za-z0-9._~-]*` (legacy names keep their capitals), at
    most 214 bytes."""
    if not isinstance(text, str) or not 0 < len(text) <= MAX_NAME_BYTES:
        return False
    if text.startswith("@"):
        scope, slash, name = text[1:].partition("/")
        return bool(slash) and NAME_PART.fullmatch(scope) is not None \
            and NAME_PART.fullmatch(name) is not None
    return NAME_PART.fullmatch(text) is not None


def package_version(text):
    """An exact SemVer 2.0 version, at most 256 bytes."""
    return isinstance(text, str) and 0 < len(text) <= MAX_VERSION_BYTES \
        and SEMVER.fullmatch(text) is not None


def registry_of(policy):
    """The policy's (host, path prefix): `https://HOST/[SEGMENT/...]`, a
    lowercase multi-label name, no port, userinfo, query, fragment or
    escape, the path ending in `/`."""
    invalid = Refused("npm_policy_invalid")
    if not handler.exact(policy, {"schema", "registry"}) or policy["schema"] != POLICY_SCHEMA:
        raise invalid
    url = policy["registry"]
    if not isinstance(url, str) or len(url) > MAX_REGISTRY_URL or not url.startswith("https://"):
        raise invalid
    host, slash, path = url[len("https://"):].partition("/")
    path = slash + path
    if (packages.HOST.fullmatch(host) is None or host.rsplit(".", 1)[-1].isdigit()
            or len(host) > 253 or not path.endswith("/")):
        raise invalid
    if path != "/" and not all(SEGMENT.fullmatch(part) for part in path[1:-1].split("/")):
        raise invalid
    return host, path


def escaped(name):
    """The registry path of a name: a scope's slash as `%2f`."""
    return name.replace("/", "%2f")


def basename(name):
    return name.rsplit("/", 1)[-1]


def names_of(args):
    if not handler.exact(args, {"names", "format"}) or args["format"] not in FORMATS:
        raise Refused("npm_args_invalid")
    names = args["names"]
    if (not isinstance(names, list) or not 0 < len(names) <= MAX_ITEMS
            or not all(package_name(name) for name in names) or len(set(names)) != len(names)):
        raise Refused("npm_args_invalid")
    return names, FORMATS[args["format"]]


def packages_of(args):
    if not handler.exact(args, {"packages"}):
        raise Refused("npm_args_invalid")
    items = args["packages"]
    if not isinstance(items, list) or not 0 < len(items) <= MAX_ITEMS:
        raise Refused("npm_args_invalid")
    seen = set()
    for item in items:
        if (not handler.exact(item, {"name", "version"}) or not package_name(item["name"])
                or not package_version(item["version"])):
            raise Refused("npm_args_invalid")
        seen.add((item["name"], item["version"]))
    if len(seen) != len(items):
        raise Refused("npm_args_invalid")
    return [(item["name"], item["version"]) for item in items]


# One GET.

def check_headers(response):
    """A header block parsed whole; no content coding but identity, no
    transfer coding but chunked, each at most once; at most one plain
    length. The length, or None."""
    fields = response.msg
    if fields.defects or fields.get_unixfrom() is not None or fields.get_payload():
        raise Refused("npm_response_malformed")
    encodings = fields.get_all("Content-Encoding") or []
    if len(encodings) > 1 or any(value.strip().lower() != "identity" for value in encodings):
        raise Refused("npm_response_encoding")
    transfers = fields.get_all("Transfer-Encoding") or []
    if len(transfers) > 1 or any(value.strip().lower() != "chunked" for value in transfers):
        raise Refused("npm_response_encoding")
    lengths = fields.get_all("Content-Length") or []
    if len(lengths) > 1:
        raise Refused("npm_response_length")
    if not lengths:
        return None
    length = lengths[0].strip()
    if not (length.isdigit() and length.isascii()):
        raise Refused("npm_response_length")
    return int(length)


class Upstream:
    """The registry as this request reaches it: its host (or the test
    seam's loopback endpoint), TLS context, clock and meter."""

    def __init__(self, request, host):
        endpoint, ca_file = packages.seam(request)
        self.host, self.port = (host, 443) if endpoint is None else endpoint
        self.tls = packages.context(ca_file)
        self.clock = request.clock
        self.meter = request.meter

    def get(self, path, accept, limit, sink):
        """One GET of `path`: 200 streams its body into `sink(data)`, at
        most `limit` bytes (`npm_batch_too_large` past it) and the
        allowance (`acquire_limit`); 404 reads nothing. The status."""
        clock = self.clock
        connection = http.client.HTTPSConnection(self.host, self.port, timeout=clock.left(),
                                                 context=self.tls)
        sock = None
        try:
            try:
                connection.connect()
                sock = connection.sock
                sock.settimeout(clock.left())
                connection.putrequest("GET", path, skip_accept_encoding=True)
                connection.putheader("Accept", accept)
                connection.putheader("Accept-Encoding", "identity")
                connection.putheader("User-Agent", packages.USER_AGENT)
                connection.putheader("Connection", "close")
                connection.endheaders()
                sock.settimeout(clock.left())
                response = connection.getresponse()
            except Refused:
                raise
            except (socket.timeout, TimeoutError, http.client.RemoteDisconnected):
                clock.left()
                raise Refused("npm_fetch_failed") from None
            except http.client.HTTPException:
                clock.left()
                raise Refused("npm_response_malformed") from None
            except (OSError, ValueError):
                clock.left()
                raise Refused("npm_fetch_failed") from None
            clock.left()
            try:
                if response.status == 404:
                    return 404
                if response.status != 200:
                    raise Refused("npm_response_status")
                length = check_headers(response)
                if length is not None:
                    if length > limit:
                        raise Refused("npm_batch_too_large")
                    self.meter.check(length)
                received = 0
                while not response.isclosed():
                    sock.settimeout(clock.left())
                    wanted = min(CHUNK, limit + 1 - received)
                    room = self.meter.room(wanted)
                    if room == 0:
                        raise Refused("acquire_limit")
                    # One underlying read at most: the clock is read after each.
                    data = response.read1(room)
                    self.meter.take(len(data))
                    clock.left()
                    if not data:
                        break
                    received += len(data)
                    if received > limit:
                        raise Refused("npm_batch_too_large")
                    sink(data)
                if length is not None and received != length:
                    raise Refused("npm_body_incomplete")
                return 200
            except Refused:
                raise
            except (socket.timeout, TimeoutError):
                clock.left()
                raise Refused("npm_body_incomplete") from None
            except (http.client.HTTPException, OSError, ValueError):
                clock.left()
                raise Refused("npm_body_incomplete") from None
            finally:
                response.close()
        finally:
            connection.close()
            if sock is not None:
                sock.close()


# The batch artifact.

class Batch:
    """The artifact as it streams: bodies, then the index and trailer."""

    def __init__(self, request, operation, limit):
        self.request = request
        self.operation = operation
        self.limit = limit
        self.items = []
        self.bodies = 0

    def room(self):
        return self.limit - self.bodies

    def run(self, fill):
        stage_fd = handler.open_stage(self.request, "npm_staging_unsafe")
        try:
            fd = handler.create(stage_fd, ARTIFACT_FILE, "npm_staging_failed")
            try:
                self.sink = handler.Sink(fd, "npm_staging_failed")
                fill(self)
                index = handler.canonical({"schema": BATCH_SCHEMA, "operation": self.operation,
                                           "items": self.items})
                self.sink.write(index)
                self.sink.write(TRAILER_PREFIX + b"%0*d\n" % (TRAILER_DIGITS, len(index)))
                return self.sink.finish()
            finally:
                os.close(fd)
        finally:
            os.close(stage_fd)

    def body(self, data):
        self.bodies += len(data)
        self.sink.write(data)


def metadata(request):
    host, prefix = registry_of(request.policy)
    names, accept = names_of(request.args)
    upstream = Upstream(request, host)
    batch = Batch(request, "metadata", MAX_METADATA_BATCH)

    def fill(batch):
        for name in names:
            before = batch.bodies
            status = upstream.get(prefix + escaped(name), accept, batch.room(), batch.body)
            item = {"name": name, "status": "ok" if status == 200 else "missing",
                    "bytes": batch.bodies - before}
            batch.items.append(item)

    size, sha256 = batch.run(fill)
    return size, sha256, {"format": BATCH_SCHEMA, "items": len(names)}


def integrity_of(dist):
    """The strongest published integrity: `sha512-...` from `integrity`,
    else `sha1-...` from the hex `shasum`; (algorithm, digest bytes,
    text)."""
    published = dist.get("integrity")
    if isinstance(published, str):
        for part in published.split():
            match = SHA512.fullmatch(part)
            if match is not None:
                return "sha512", base64.b64decode(match.group(1)), part
    shasum = dist.get("shasum")
    if isinstance(shasum, str) and SHA1_HEX.fullmatch(shasum):
        digest = bytes.fromhex(shasum)
        return "sha1", digest, "sha1-" + base64.b64encode(digest).decode()
    raise Refused("npm_integrity_missing")


def version_document(upstream, prefix, name, version):
    """The version's document, parsed and bound to exactly that name and
    version; None when the registry has no such version."""
    collected = bytearray()
    status = upstream.get(prefix + escaped(name) + "/" + version, FULL, MAX_VERSION_DOC,
                          collected.extend)
    if status == 404:
        return None
    try:
        document = json.loads(bytes(collected).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise Refused("npm_document_invalid") from None
    if (not isinstance(document, dict) or document.get("name") != name
            or document.get("version") != version or not isinstance(document.get("dist"), dict)):
        raise Refused("npm_document_invalid")
    return document


def tarballs(request):
    host, prefix = registry_of(request.policy)
    wanted = packages_of(request.args)
    upstream = Upstream(request, host)
    batch = Batch(request, "tarballs", MAX_TARBALL_BATCH)
    provenance = []

    def fill(batch):
        for name, version in wanted:
            document = version_document(upstream, prefix, name, version)
            if document is None:
                batch.items.append({"name": name, "version": version, "status": "missing", "bytes": 0})
                continue
            dist = document["dist"]
            path = "%s%s/-/%s-%s.tgz" % (prefix, name, basename(name), version)
            if dist.get("tarball") != "https://%s%s" % (host, path):
                raise Refused("npm_tarball_unexpected")
            algorithm, expected, integrity = integrity_of(dist)
            digest = hashlib.new(algorithm)
            before = batch.bodies

            def body(data):
                digest.update(data)
                batch.body(data)

            if upstream.get(path, "application/octet-stream", batch.room(), body) != 200:
                raise Refused("npm_tarball_missing")
            if digest.digest() != expected:
                raise Refused("npm_tarball_mismatch")
            batch.items.append({"name": name, "version": version, "status": "ok",
                                "bytes": batch.bodies - before, "integrity": integrity})
            provenance.append({"name": name, "version": version, "integrity": integrity})

    size, sha256 = batch.run(fill)
    return size, sha256, {"format": BATCH_SCHEMA, "items": len(wanted)}, provenance


if __name__ == "__main__":
    sys.exit(handler.main({"metadata": metadata, "tarballs": tarballs}))
