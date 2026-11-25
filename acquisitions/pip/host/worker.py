"""Trusted host worker of the `pip` handler (acquisitions/pip/contract/v1):
read access to one operator-approved Python package index (a PEP 691 JSON
Simple API) for native pip in the jail.

    policy  {"schema":"agentbox.pip.index-policy.v1",
             "index":"https://pypi.org/simple/",
             "files":["https://files.pythonhosted.org/packages/"]}

Two operations, each one batch of at most 64 items the jail's loopback
index (acquisitions/pip/jail/index.py) asks for on behalf of pip:

    files  {"projects":[NAME,...]}
           per project (PEP 503 normalized): GET INDEX/NAME/ as
           `application/vnd.pypi.simple.v1+json`; 404 is `missing`. The page
           is parsed (bounded) and rebuilt: only files whose URL, resolved
           against the page, lies under an approved file origin, whose name
           is a wheel, `.tar.gz` or `.zip` of this project, with a SHA-256.
           Each keeps its filename, digest, `requires-python`, `yanked` and
           hashed core metadata (PEP 658/714); its URL becomes the jail's
           own `/files/NAME/SHA256/FILENAME`. No upstream URL leaves the
           host.
    fetch  {"files":[{"project":NAME,"filename":F,"sha256":HEX},...]}
           per file: the project's page again (once per batch), the file
           listed there under exactly that name and digest, else `missing`;
           GET its URL, as built from the page, never the guest's; size (if
           listed) and SHA-256 checked. `F.metadata` with the file's digest
           is its core metadata sidecar: GET URL.metadata, checked against
           the page's metadata digest.

The host never resolves, unpacks, builds or runs anything: names, files and
versions are pip's choice in the jail; wheels and source archives alike are
opaque here. HTTPS only, the host's resolver and system trust, no redirect,
proxy, credential, cookie, retry or compression, one connection per GET.
Every body byte read counts against the request's acquired-byte allowance;
a page is at most 16 MiB, a file 1 GiB, a batch's bodies 64 MiB (files) or
1.5 GiB (fetch).

    artifact  BODY... INDEX TRAILER
              INDEX    canonical JSON {"schema":"agentbox.pip.batch.v1",
                       "operation":OP,"items":[{"name","status","bytes"
                       [,"filename","sha256"]}...]}
              TRAILER  "\\nagentbox.pip.batch.v1 " + 20 digits + "\\n"
    metadata  {"format":"agentbox.pip.batch.v1","items":N}
    result    `provenance`: each file fetched, {name: project, version:
              filename, integrity: sha256-BASE64}
"""

import base64
import hashlib
import http.client
import os
import re
import socket
import sys
from urllib.parse import unquote, urljoin

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "lib"))

import agentbox_handler as handler  # noqa: E402
import agentbox_packages as packages  # noqa: E402
from agentbox_handler import ARTIFACT_FILE, Refused  # noqa: E402

POLICY_SCHEMA = "agentbox.pip.index-policy.v1"
BATCH_SCHEMA = "agentbox.pip.batch.v1"
TRAILER_PREFIX = b"\nagentbox.pip.batch.v1 "
TRAILER_DIGITS = 20
ACCEPT = "application/vnd.pypi.simple.v1+json"
MAX_ITEMS = 64
MAX_ORIGINS = 8
MAX_POLICY_URL = 256
MAX_PROJECT_BYTES = 128
MAX_FILENAME_BYTES = 255
MAX_PAGE = 16 * 1024 * 1024
MAX_FILE = 1 << 30
MAX_FILES_BATCH = 64 * 1024 * 1024
MAX_FETCH_BATCH = 3 << 29
MAX_URL_BYTES = 2048
MAX_TEXT = 1024
SIDECAR = ".metadata"
CHUNK = 1 << 16

PROJECT = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]*")
SEGMENT = re.compile(r"[A-Za-z0-9_~@+-][A-Za-z0-9._~@+-]*")
URL_SEGMENT = re.compile(r"(?:[A-Za-z0-9._~@+!-]|%[0-9A-Fa-f]{2})+")
ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
SHA256 = re.compile(r"[0-9a-f]{64}")
PRINTABLE = re.compile(r"[\x20-\x7e]*")
SDISTS = (".tar.gz", ".zip")


# Grammar.

def normalized(name):
    """PEP 503: runs of `-_.` as one `-`, lowercase."""
    return re.sub(r"[-_.]+", "-", name).lower()


def project_name(text):
    return isinstance(text, str) and len(text) <= MAX_PROJECT_BYTES and PROJECT.fullmatch(text) is not None


def filename_of(text):
    return isinstance(text, str) and len(text) <= MAX_FILENAME_BYTES and FILENAME.fullmatch(text) is not None


def belongs(filename, project):
    """A wheel (`NAME-VERSION[-BUILD]-PY-ABI-PLATFORM.whl`) or source archive
    (`NAME-VERSION.tar.gz|.zip`) whose name part normalizes to `project`."""
    if filename.endswith(".whl"):
        parts = filename[:-len(".whl")].split("-")
        return len(parts) in (5, 6) and all(parts) and normalized(parts[0]) == project
    for suffix in SDISTS:
        if filename.endswith(suffix):
            stem = filename[:-len(suffix)]
            return any(stem[at] == "-" and at + 1 < len(stem) and normalized(stem[:at]) == project
                       for at in range(1, len(stem)))
    return False


def base_url(text, invalid):
    """`https://HOST/[SEGMENT/...]` of the policy: a lowercase multi-label
    name, no port, userinfo, query, fragment or escape, ending in `/`."""
    if not isinstance(text, str) or len(text) > MAX_POLICY_URL or not text.startswith("https://"):
        raise invalid
    host, slash, path = text[len("https://"):].partition("/")
    path = slash + path
    if (packages.HOST.fullmatch(host) is None or host.rsplit(".", 1)[-1].isdigit()
            or len(host) > 253 or not path.endswith("/")):
        raise invalid
    if path != "/" and not all(SEGMENT.fullmatch(part) for part in path[1:-1].split("/")):
        raise invalid
    return host, path


def approved(policy):
    """The policy's index (host, path) and file origin URLs."""
    invalid = Refused("pip_policy_invalid")
    if not handler.exact(policy, {"schema", "index", "files"}) or policy["schema"] != POLICY_SCHEMA:
        raise invalid
    index = base_url(policy["index"], invalid)
    origins = policy["files"]
    if not isinstance(origins, list) or not 0 < len(origins) <= MAX_ORIGINS or len(set(origins)) != len(origins):
        raise invalid
    for origin in origins:
        base_url(origin, invalid)
    return index, origins


def file_url(page, raw, filename, origins):
    """A listed file's URL resolved against the page: HTTPS, a policy host
    grammar, no port, userinfo or query, plain or escaped segments (no
    escaped `.`, `/`, `\\` or `%`), its last segment exactly the filename,
    under an approved origin. (host, path) or None."""
    if not isinstance(raw, str) or len(raw) > MAX_URL_BYTES or PRINTABLE.fullmatch(raw) is None or " " in raw \
            or "\\" in raw:
        return None
    url = urljoin(page, raw).partition("#")[0]
    if not url.startswith("https://") or len(url) > MAX_URL_BYTES:
        return None
    host, slash, path = url[len("https://"):].partition("/")
    path = slash + path
    if packages.HOST.fullmatch(host) is None or host.rsplit(".", 1)[-1].isdigit() or len(host) > 253:
        return None
    segments = path[1:].split("/")
    for segment in segments:
        if URL_SEGMENT.fullmatch(segment) is None or segment in (".", ".."):
            return None
        if any(chr(int(code, 16)) in "./\\%" or not 0x20 < int(code, 16) < 0x7f
               for code in ESCAPE.findall(segment)):
            return None
    if unquote(segments[-1]) != filename or not any(url.startswith(origin) for origin in origins):
        return None
    return host, path


# One GET.

def check_headers(response):
    """A header block parsed whole; no content coding but identity, no
    transfer coding but chunked, each at most once; at most one plain
    length. The length, or None."""
    fields = response.msg
    if fields.defects or fields.get_unixfrom() is not None or fields.get_payload():
        raise Refused("pip_response_malformed")
    encodings = fields.get_all("Content-Encoding") or []
    if len(encodings) > 1 or any(value.strip().lower() != "identity" for value in encodings):
        raise Refused("pip_response_encoding")
    transfers = fields.get_all("Transfer-Encoding") or []
    if len(transfers) > 1 or any(value.strip().lower() != "chunked" for value in transfers):
        raise Refused("pip_response_encoding")
    lengths = fields.get_all("Content-Length") or []
    if len(lengths) > 1:
        raise Refused("pip_response_length")
    if not lengths:
        return None
    length = lengths[0].strip()
    if not (length.isdigit() and length.isascii()):
        raise Refused("pip_response_length")
    return int(length)


class Upstream:
    """The index and file hosts as this request reaches them (or the test
    seam's loopback endpoint for every host), its TLS context, clock and
    meter."""

    def __init__(self, request):
        self.endpoint, ca_file = packages.seam(request)
        self.tls = packages.context(ca_file)
        self.clock = request.clock
        self.meter = request.meter

    def get(self, host, path, accept, limit, sink, too_large):
        """One GET of `path` on `host`: 200 streams its body into
        `sink(data)`, at most `limit` bytes (`too_large` past it) and the
        allowance (`acquire_limit`); 404 reads nothing. The status."""
        clock = self.clock
        host, port = (host, 443) if self.endpoint is None else self.endpoint
        connection = http.client.HTTPSConnection(host, port, timeout=clock.left(), context=self.tls)
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
            except http.client.RemoteDisconnected:
                clock.left()
                raise Refused("pip_fetch_failed") from None
            except http.client.HTTPException:
                clock.left()
                raise Refused("pip_response_malformed") from None
            except (socket.timeout, TimeoutError, OSError, ValueError):
                clock.left()
                raise Refused("pip_fetch_failed") from None
            clock.left()
            try:
                if response.status == 404:
                    return 404
                if response.status != 200:
                    raise Refused("pip_response_status")
                length = check_headers(response)
                if length is not None:
                    if length > limit:
                        raise Refused(too_large)
                    self.meter.check(length)
                received = 0
                while not response.isclosed():
                    sock.settimeout(clock.left())
                    room = self.meter.room(min(CHUNK, limit + 1 - received))
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
                        raise Refused(too_large)
                    sink(data)
                if length is not None and received != length:
                    raise Refused("pip_body_incomplete")
                return 200
            except Refused:
                raise
            except (socket.timeout, TimeoutError, http.client.HTTPException, OSError, ValueError):
                clock.left()
                raise Refused("pip_body_incomplete") from None
            finally:
                response.close()
        finally:
            connection.close()
            if sock is not None:
                sock.close()


# A project's page.

def text_field(value):
    return isinstance(value, str) and len(value) <= MAX_TEXT and PRINTABLE.fullmatch(value) is not None


def listing(upstream, index, origins, project, room):
    """The project's approved files, in page order, {filename: {url (host,
    path), sha256, size, metadata}} and the jail's page; None when the
    index has no such project."""
    host, prefix = index
    page_url = "https://%s%s%s/" % (host, prefix, project)
    collected = bytearray()
    status = upstream.get(host, prefix + project + "/", ACCEPT, min(MAX_PAGE, room), collected.extend,
                          "pip_page_too_large")
    if status == 404:
        return None
    invalid = Refused("pip_page_invalid")
    try:
        page = handler.strict_loads(bytes(collected), MAX_PAGE)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise invalid from None
    meta = page.get("meta") if isinstance(page, dict) else None
    version = meta.get("api-version") if isinstance(meta, dict) else None
    if (not isinstance(version, str) or not version.startswith("1.") or not isinstance(page.get("name"), str)
            or normalized(page["name"]) != project or not isinstance(page.get("files"), list)):
        raise invalid
    files, served = {}, []
    for entry in page["files"]:
        if not isinstance(entry, dict):
            continue
        filename, hashes = entry.get("filename"), entry.get("hashes")
        if not filename_of(filename) or filename in files or not belongs(filename, project) \
                or not isinstance(hashes, dict):
            continue
        digest = hashes.get("sha256")
        digest = digest.lower() if isinstance(digest, str) else None
        url = file_url(page_url, entry.get("url"), filename, origins)
        if digest is None or SHA256.fullmatch(digest) is None or url is None:
            continue
        item = {"filename": filename, "url": "/files/%s/%s/%s" % (project, digest, filename),
                "hashes": {"sha256": digest}}
        requires = entry.get("requires-python")
        if requires is not None:
            if not text_field(requires):
                continue
            item["requires-python"] = requires
        yanked = entry.get("yanked", False)
        if yanked is True or (isinstance(yanked, str) and len(yanked) <= MAX_TEXT):
            item["yanked"] = yanked
        elif yanked is not False:
            continue
        metadata = None
        for key in ("core-metadata", "dist-info-metadata"):
            if key in entry:
                declared = entry[key]
                value = declared.get("sha256") if isinstance(declared, dict) else None
                value = value.lower() if isinstance(value, str) else None
                if value is not None and SHA256.fullmatch(value):
                    metadata = value
                break
        if metadata is not None:
            item["core-metadata"] = item["dist-info-metadata"] = {"sha256": metadata}
        size = entry.get("size")
        files[filename] = {"url": url, "sha256": digest, "metadata": metadata,
                           "size": size if handler.safe_integer(size, 0, MAX_FILE) else None}
        served.append(item)
    return files, {"meta": {"api-version": "1.0"}, "name": project, "files": served}


# Arguments.

def projects_of(args):
    if not handler.exact(args, {"projects"}):
        raise Refused("pip_args_invalid")
    names = args["projects"]
    if (not isinstance(names, list) or not 0 < len(names) <= MAX_ITEMS
            or not all(project_name(name) for name in names) or len(set(names)) != len(names)):
        raise Refused("pip_args_invalid")
    return names


def files_of(args):
    if not handler.exact(args, {"files"}):
        raise Refused("pip_args_invalid")
    items = args["files"]
    if not isinstance(items, list) or not 0 < len(items) <= MAX_ITEMS:
        raise Refused("pip_args_invalid")
    seen = set()
    for item in items:
        if (not handler.exact(item, {"project", "filename", "sha256"}) or not project_name(item["project"])
                or not filename_of(item["filename"]) or not isinstance(item["sha256"], str)
                or SHA256.fullmatch(item["sha256"]) is None):
            raise Refused("pip_args_invalid")
        seen.add((item["project"], item["filename"]))
    if len(seen) != len(items):
        raise Refused("pip_args_invalid")
    return [(item["project"], item["filename"], item["sha256"]) for item in items]


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
        stage_fd = handler.open_stage(self.request, "pip_staging_unsafe")
        try:
            fd = handler.create(stage_fd, ARTIFACT_FILE, "pip_staging_failed")
            try:
                self.sink = handler.Sink(fd, "pip_staging_failed")
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


def files(request):
    index, origins = approved(request.policy)
    names = projects_of(request.args)
    upstream = Upstream(request)
    batch = Batch(request, "files", MAX_FILES_BATCH)

    def fill(batch):
        for name in names:
            found = listing(upstream, index, origins, name, batch.room())
            if found is None:
                batch.items.append({"name": name, "status": "missing", "bytes": 0})
                continue
            data = handler.canonical(found[1])
            if len(data) > batch.room():
                raise Refused("pip_batch_too_large")
            batch.body(data)
            batch.items.append({"name": name, "status": "ok", "bytes": len(data)})

    size, sha256 = batch.run(fill)
    return size, sha256, {"format": BATCH_SCHEMA, "items": len(names)}


def fetch(request):
    index, origins = approved(request.policy)
    wanted = files_of(request.args)
    upstream = Upstream(request)
    batch = Batch(request, "fetch", MAX_FETCH_BATCH)
    pages = {}
    provenance = []

    def fill(batch):
        for project, filename, sha256 in wanted:
            if project not in pages:
                found = listing(upstream, index, origins, project, MAX_PAGE)
                pages[project] = None if found is None else found[0]
            listed = pages[project]
            sidecar = filename.endswith(SIDECAR)
            entry = None if listed is None else listed.get(filename[:-len(SIDECAR)] if sidecar else filename)
            if entry is None or entry["sha256"] != sha256 or (sidecar and entry["metadata"] is None):
                batch.items.append({"name": project, "filename": filename, "sha256": sha256,
                                    "status": "missing", "bytes": 0})
                continue
            host, path = entry["url"]
            expected = entry["metadata"] if sidecar else sha256
            limit = MAX_FILE if sidecar or entry["size"] is None else entry["size"]
            digest = hashlib.sha256()
            before = batch.bodies

            def body(data):
                digest.update(data)
                batch.body(data)

            too_large = "pip_batch_too_large" if batch.room() < limit else "pip_file_mismatch"
            status = upstream.get(host, path + SIDECAR if sidecar else path, "application/octet-stream",
                                  min(limit, batch.room()), body, too_large)
            if status != 200:
                raise Refused("pip_file_missing")
            if digest.hexdigest() != expected or (not sidecar and entry["size"] is not None
                                                  and batch.bodies - before != entry["size"]):
                raise Refused("pip_file_mismatch")
            batch.items.append({"name": project, "filename": filename, "sha256": sha256, "status": "ok",
                                "bytes": batch.bodies - before})
            provenance.append({"name": project, "version": filename,
                               "integrity": "sha256-" + base64.b64encode(digest.digest()).decode()})

    size, sha256 = batch.run(fill)
    return size, sha256, {"format": BATCH_SCHEMA, "items": len(wanted)}, provenance


if __name__ == "__main__":
    sys.exit(handler.main({"files": files, "fetch": fetch}))
