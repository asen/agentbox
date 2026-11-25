"""Test-only synthetic HTTPS Git server and process owner for the Git
acquisition fixtures.

Not product code, never packaged and never a production listener: the
worker's tests (test_git.py) and the Rust tests (git_tests.rs,
git_acquisition_tests.rs, execution_session.rs) start it for one case,
over synthetic repositories they created. Python standard library only, single-threaded, loopback ephemeral
ports only. Two roles:

    python3 -I -S -B git_fixture_server.py own --report FILE [--stdin FILE] [--graceful S] -- ARGV...
    python3 -I -S -B git_fixture_server.py serve MODE ROOT CERT KEY GIT
    python3 -I -S -B git_fixture_server.py relay-check < CASES

`own` is the outer owner the Rust test holds (its own session, an unreaped
child of the test, never signalled by it). It is a child subreaper, spawns
ARGV in a new process group of its own (that child the group leader) and
relays the child's stdout lines, each prefixed `c `, non-blocking and
bounded (`Relay`). EOF on its stdin (also when the test process itself is gone)
closes the child's stdin and allows `--graceful` seconds; a `force` line
kills at once. Then, the leader still unreaped (alive or a zombie, so its
group id is anchored), it SIGKILLs that group and reaps every child and
orphan until ECHILD (orphans of a dead server come to it as subreaper), with
blocking waits and no deadline. Only then does it write its accounting to
`--report` (exclusive create) and exit 0 (4 if it could not). Every path
after the spawn, exceptions included, goes through that settlement.
`AGENTBOX_G1_OWNER_FAULT=raise-after-line` injects a fault for the
fixture's own tests only.

`relay-check` (run under `own` by the tests) compares `Relay` alone with
literal expected results from JSON cases on stdin and prints one compact
verdict line per run: pure, no process, file or socket of its own, and
bounded by guards of its own (`CHECK_*`), independent of `Relay`'s.

`serve` MODE: backend (smart HTTP through `git http-backend`), dumb (static
dumb-HTTP files), redirect (302 to the tripwire), auth (401), stall (accept,
then never answer), crash (on its first request start a `sleep` helper in
its group, then SIGKILL itself: a forced server death leaving a live
descendant for the owner). ROOT holds `<owner>/<name>.git` repositories; only exact
smart/dumb Git paths of an existing repository there are served, never
another file. A second plain TCP listener, the tripwire, only counts
connections.

stdout: `ready <port> <tripwire-port>`, `stalled` when a stall begins, and
at exit one JSON accounting line. EOF on stdin ends it. Every request is
bounded before buffering. CGI children stay in this process's group; the
server is a child subreaper too and reaps until ECHILD before it reports.
If it dies first, its descendants go to the owner, which kills its group.
"""

import ctypes
import json
import os
import re
import select
import signal
import socket
import ssl
import subprocess
import sys
import time
import zlib

MAX_LINE = 8192
MAX_HEADERS = 64
MAX_BODY = 1 << 20
MAX_CGI_OUTPUT = 64 << 20
MAX_LOGGED = 64
IO_TIMEOUT = 30.0
REPO = re.compile(r"^/([a-z0-9][a-z0-9-]{0,38})/([a-z0-9._-]{1,100})\.git(/.*)$")
DUMB = re.compile(r"^/(HEAD|info/refs|objects/info/(packs|alternates|http-alternates)|objects/[0-9a-f]{2}/[0-9a-f]{38}|objects/pack/pack-[0-9a-f]{40}\.(pack|idx))$")


class Refused(Exception):
    pass


def readline(conn, buffer):
    while b"\r\n" not in buffer[0]:
        if len(buffer[0]) > MAX_LINE:
            raise Refused("line")
        chunk = conn.recv(4096)
        if not chunk:
            raise Refused("eof")
        buffer[0] += chunk
    line, _, rest = buffer[0].partition(b"\r\n")
    buffer[0] = rest
    if len(line) > MAX_LINE:
        raise Refused("line")
    return line.decode("latin-1")


def read_request(conn):
    buffer = [b""]
    request = readline(conn, buffer)
    method, target, _version = request.split(" ", 2)
    headers = {}
    for _ in range(MAX_HEADERS + 1):
        line = readline(conn, buffer)
        if line == "":
            break
        key, _, value = line.partition(":")
        headers[key.strip().lower()] = value.strip()
    else:
        raise Refused("headers")
    length = int(headers.get("content-length", "0") or "0")
    if length < 0 or length > MAX_BODY or "transfer-encoding" in headers:
        raise Refused("body")
    body = buffer[0]
    while len(body) < length:
        chunk = conn.recv(min(65536, length - len(body)))
        if not chunk:
            raise Refused("eof")
        body += chunk
    return method, target, headers, body[:length]


def decoded(headers, body):
    if headers.get("content-encoding") == "gzip":
        inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = inflater.decompress(body, MAX_BODY)
        return out
    return body


def commands(body):
    """The protocol v2 `command=` lines of a request body's pkt-lines."""
    found, offset = set(), 0
    while offset + 4 <= len(body):
        try:
            length = int(body[offset:offset + 4], 16)
        except ValueError:
            break
        if length < 4:
            offset += 4
            continue
        line = body[offset + 4:offset + length].rstrip(b"\n")
        if line.startswith(b"command="):
            found.add(line.decode("ascii", "replace"))
        offset += length
    return sorted(found)


def respond(conn, status, reason, headers, payload):
    head = "HTTP/1.1 %d %s\r\n" % (status, reason)
    for key, value in headers:
        head += "%s: %s\r\n" % (key, value)
    head += "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(payload)
    conn.sendall(head.encode("latin-1") + payload)
    return len(payload)


class Server:
    def __init__(self, mode, root, cert, key, git):
        self.mode, self.root, self.git = mode, os.path.realpath(root), git
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.tripwire = socket.socket()
        self.tripwire.bind(("127.0.0.1", 0))
        self.tripwire.listen(8)
        self.stats = {"accepted": 0, "tls_failures": 0, "refused": 0, "requests": [], "requests_total": 0,
                      "cgi_spawned": 0, "cgi_reaped": 0, "cgi_killed": 0, "tripwire": 0, "peer_closed": 0,
                      "aborted_before_request": 0,
                      "orphans_reaped": 0, "echild": False}
        self.env = {
            "PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": os.path.join(self.root, ".server-home"),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CEILING_DIRECTORIES": self.root,
            "GIT_PROJECT_ROOT": self.root, "GIT_HTTP_EXPORT_ALL": "1",
        }

    def log(self, item):
        self.stats["requests_total"] += 1
        if len(self.stats["requests"]) < MAX_LOGGED:
            self.stats["requests"].append(item)

    def repository(self, path):
        match = REPO.match(path)
        if not match:
            raise Refused("path")
        repo = os.path.join(self.root, match.group(1), match.group(2) + ".git")
        if os.path.realpath(repo) != repo or not os.path.isdir(repo):
            raise Refused("repository")
        return repo, match.group(3)

    def cgi(self, method, path, query, headers, body):
        env = dict(self.env)
        env.update({"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": query,
                    "CONTENT_TYPE": headers.get("content-type", ""), "CONTENT_LENGTH": str(len(body)),
                    "REMOTE_ADDR": "127.0.0.1"})
        if "git-protocol" in headers:
            env["HTTP_GIT_PROTOCOL"] = headers["git-protocol"]
        if "content-encoding" in headers:
            env["HTTP_CONTENT_ENCODING"] = headers["content-encoding"]
        # Same process group as this server: the owner's group kill covers it.
        child = subprocess.Popen([self.git, "http-backend"], env=env, cwd=self.root, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        self.stats["cgi_spawned"] += 1
        output = b""
        try:
            child.stdin.write(body)
            child.stdin.close()
            deadline = time.monotonic() + IO_TIMEOUT
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Refused("cgi timeout")
                ready, _, _ = select.select([child.stdout], [], [], left)
                if not ready:
                    continue
                chunk = os.read(child.stdout.fileno(), 65536)
                if not chunk:
                    break
                output += chunk
                if len(output) > MAX_CGI_OUTPUT:
                    raise Refused("cgi output")
        except BaseException:
            if child.poll() is None:
                child.kill()  # still an unreaped child: its pid is its own
                self.stats["cgi_killed"] += 1
            raise
        finally:
            child.stdout.close()
            child.wait()
            self.stats["cgi_reaped"] += 1
        head, _, payload = output.partition(b"\r\n\r\n")
        status, out = 200, []
        for line in head.split(b"\r\n"):
            key, _, value = line.decode("latin-1").partition(":")
            if key.lower() == "status":
                status = int(value.strip().split()[0])
            elif key:
                out.append((key, value.strip()))
        return status, out, payload

    def dumb(self, repo, rest):
        if not DUMB.match(rest):
            raise Refused("dumb path")
        target = os.path.join(repo, rest[1:])
        if os.path.realpath(target) != target or not os.path.isfile(target):
            return 404, [], b""
        with open(target, "rb") as handle:
            payload = handle.read(MAX_CGI_OUTPUT + 1)
        if len(payload) > MAX_CGI_OUTPUT:
            raise Refused("dumb size")
        return 200, [("Content-Type", "text/plain")], payload

    def stall(self, conn):
        print("stalled", flush=True)
        while True:
            ready, _, _ = select.select([conn, sys.stdin], [], [], 1.0)
            if sys.stdin in ready:
                return "stdin"
            if conn in ready:
                try:
                    if not conn.recv(4096):
                        self.stats["peer_closed"] += 1
                        return "peer"
                except (OSError, ssl.SSLError):
                    self.stats["peer_closed"] += 1
                    return "peer"

    def connection(self, raw):
        raw.settimeout(IO_TIMEOUT)
        try:
            conn = self.context.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            self.stats["tls_failures"] += 1
            raw.close()
            return
        try:
            try:
                method, target, headers, body = read_request(conn)
            except (OSError, ssl.SSLError):
                # The client gave up before any request: a refused
                # certificate ends here, after the server-side handshake.
                self.stats["aborted_before_request"] += 1
                return
            path, _, query = target.partition("?")
            text = decoded(headers, body)
            item = {"method": method, "path": path, "query": query, "host": headers.get("host"),
                    "git_protocol": headers.get("git-protocol"), "authorization": "authorization" in headers,
                    "proxy_headers": sorted(k for k in headers if k.startswith("proxy")),
                    "commands": commands(text),
                    "packfile_uris": b"packfile-uris" in text, "bundle_uri": b"bundle-uri" in text}
            if self.mode == "crash":
                # A descendant in this group that outlives this process.
                subprocess.Popen(["/usr/bin/sleep", "30"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, close_fds=True)
                print("crashing", flush=True)
                os.kill(os.getpid(), signal.SIGKILL)
            if self.mode == "stall":
                item["status"] = None
                self.log(item)
                item["ended_by"] = self.stall(conn)
                return
            if self.mode == "redirect":
                item["status"] = 302
                item["bytes"] = respond(conn, 302, "Found", [("Location", "https://127.0.0.1:%d%s" % (self.tripwire.getsockname()[1], target))], b"")
            elif self.mode == "auth":
                item["status"] = 401
                item["bytes"] = respond(conn, 401, "Unauthorized", [("WWW-Authenticate", 'Basic realm="fixture"')], b"")
            else:
                repo, rest = self.repository(path)
                if self.mode == "dumb":
                    status, out, payload = self.dumb(repo, rest)
                elif (method, rest) in (("GET", "/info/refs"), ("POST", "/git-upload-pack")):
                    status, out, payload = self.cgi(method, path, query, headers, body)
                else:
                    raise Refused("route")
                item["status"] = status
                # Which other-source features this answer offered the client.
                item["offered"] = sorted(token.decode() for token in
                                         (b"bundle-uri", b"promisor-remote", b"packfile-uris", b"shallow-info", b"http-alternates")
                                         if token in payload or token in rest.encode())
                item["bytes"] = respond(conn, status, "OK" if status == 200 else "Status", out, payload)
            self.log(item)
        except (Refused, ValueError, OSError, ssl.SSLError) as error:
            self.stats["refused"] += 1
            self.log({"refused": type(error).__name__ + ":" + str(error)[:64]})
            try:
                respond(conn, 404, "Not Found", [], b"")
            except (OSError, ssl.SSLError):
                pass
        finally:
            try:
                conn.close()
            except (OSError, ssl.SSLError):
                pass

    def run(self):
        print("ready %d %d" % (self.listener.getsockname()[1], self.tripwire.getsockname()[1]), flush=True)
        while True:
            ready, _, _ = select.select([self.listener, self.tripwire, sys.stdin], [], [], 1.0)
            if sys.stdin in ready and not os.read(sys.stdin.fileno(), 1):
                break
            if self.tripwire in ready:
                conn, _ = self.tripwire.accept()
                self.stats["tripwire"] += 1
                conn.close()
            if self.listener in ready:
                conn, _ = self.listener.accept()
                self.stats["accepted"] += 1
                self.connection(conn)
        self.listener.close()
        self.tripwire.close()
        self.stats["listeners_closed"] = True

    def reap(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                self.stats["echild"] = True
                return
            if pid:
                self.stats["orphans_reaped"] += 1
            else:
                time.sleep(0.01)


MAX_RELAY_LINE = 64 * 1024
MAX_RELAY = 1 << 20
MAX_REPORT = 64 * 1024
# relay-check's own guards: fixed here, never derived from Relay's bounds.
CHECK_INPUT = 1 << 20      # encoded stdin
CHECK_CASES = 64
CHECK_PIECES = 8           # piece sizes per case
CHECK_CHUNK = 1 << 20      # one expanded chunk
CHECK_EXPANDED = 16 << 20  # all expanded chunks and expected outputs
CHECK_TAKES = 1 << 22      # Relay.take calls in all runs
CHECK_OUT = 4 << 20        # what one run may queue
CHECK_PENDING = 4 << 20    # one run's pending line
CHECK_ID = re.compile(r"^[a-z0-9-]{1,32}$")
CHECK_HEX = re.compile(r"^(?:[0-9a-f]{2})*$")


class Relay:
    """The owner's relay of its command's stdout, pure (no I/O): each line
    queued into `out` as `c LINE` and LF. A line is kept to MAX_RELAY_LINE
    bytes however its bytes arrive in chunks: of a longer one, its first
    MAX_RELAY_LINE bytes are queued, `line_truncated` set and the rest
    skipped to its LF. Bytes, never decoded. `pending` stays within
    MAX_RELAY_LINE, all that was ever queued within MAX_RELAY
    (`output_over_bound`), and nothing is queued after `relay_failed`."""

    def __init__(self, report, on_line=lambda: None):
        self.report, self.on_line = report, on_line
        self.out, self.pending = bytearray(), bytearray()
        self.discarding, self.relayed = False, 0

    def queue(self, line):
        if self.report["relay_failed"]:
            return
        if self.relayed + len(line) + 3 > MAX_RELAY:
            self.report["output_over_bound"] = True
            return
        self.relayed += len(line) + 3
        self.out.extend(b"c " + line + b"\n")

    def take(self, chunk):
        start = 0
        while start < len(chunk):
            cut = chunk.find(b"\n", start)
            end = len(chunk) if cut < 0 else cut
            if not self.discarding:
                room = MAX_RELAY_LINE - len(self.pending)
                self.pending += chunk[start:min(end, start + room)]
                if end - start > room:
                    self.queue(bytes(self.pending))
                    self.report["line_truncated"] = True
                    self.discarding = True
                    self.pending.clear()
            if cut < 0:
                return
            start = cut + 1
            if self.discarding:
                self.discarding = False
            else:
                line = bytes(self.pending)
                self.pending.clear()
                self.queue(line)
                self.on_line()

    def finish(self):
        if self.pending:
            self.report["partial_line"] = True
            self.queue(bytes(self.pending))
            self.pending.clear()


class CheckOverflow(Exception):
    pass


class Capped(bytearray):
    """A Relay buffer for relay-check: refuses growth past `cap` before it
    happens, whatever Relay tries to queue."""

    def __init__(self, cap, what):
        super().__init__()
        self.cap, self.what = cap, what

    def room(self, data):
        if len(self) + len(data) > self.cap:
            raise CheckOverflow(self.what)

    def extend(self, data):
        self.room(data)
        super().extend(data)

    def __iadd__(self, data):
        self.room(data)
        return super().__iadd__(data)


def check_cases(data):
    """Validates the cases and their whole cost before expanding anything:
    a list of (id, chunks, pieces, finish, expect), or a refusal reason."""
    if len(data) > CHECK_INPUT:
        return "input"
    try:
        cases = json.loads(data)
    except ValueError:
        return "spec"
    if not isinstance(cases, list):
        return "spec"
    if len(cases) > CHECK_CASES:
        return "cases"

    def size(spec):
        if not isinstance(spec, list):
            raise ValueError
        total = 0
        for item in spec:
            text, times = item
            if not isinstance(text, str) or not CHECK_HEX.match(text) or type(times) is not int or times < 0:
                raise ValueError
            total += len(text) // 2 * times
        return total

    expanded, takes, checked = 0, 0, []
    try:
        for case in cases:
            ident, pieces, expect = case["id"], case["pieces"], case["expect"]
            if not isinstance(ident, str) or not CHECK_ID.match(ident) or type(case["finish"]) is not bool:
                return "spec"
            if not isinstance(pieces, list) or not 1 <= len(pieces) <= CHECK_PIECES:
                return "pieces"
            if any(type(piece) is not int or not 0 <= piece <= CHECK_CHUNK for piece in pieces):
                return "spec"
            cap = expect.get("out_cap", CHECK_OUT)
            if type(cap) is not int or not 0 <= cap <= CHECK_OUT or type(expect["pending_bound"]) is not int:
                return "spec"
            if any(type(expect[flag]) is not bool for flag in ("line_truncated", "partial_line", "output_over_bound")):
                return "spec"
            lengths = [size(chunk) for chunk in case["chunks"]]
            if any(length > CHECK_CHUNK for length in lengths):
                return "chunk"
            expanded += sum(lengths) + size(expect["out"])
            if expanded > CHECK_EXPANDED:
                return "expanded"
            for piece in pieces:
                takes += sum(-(-length // (piece or max(length, 1))) for length in lengths)
            if takes > CHECK_TAKES:
                return "takes"
            checked.append((ident, case["chunks"], pieces, case["finish"], expect, cap))
    except (KeyError, TypeError, ValueError, AttributeError):
        return "spec"
    return checked


def expand(spec):
    return b"".join(bytes.fromhex(text) * times for text, times in spec)


def relay_check():
    """Each case `{"id", "chunks": [[[HEX, TIMES], ...], ...], "pieces": [N, ...],
    "finish", "expect": {"out": [[HEX, TIMES], ...], "line_truncated",
    "partial_line", "output_over_bound", "pending_bound", ["out_cap"]}}`: for
    each piece size N (0: whole chunks) one fresh Relay takes every chunk in
    pieces of N bytes, then `finish` if asked, and is compared with `expect`.
    Prints `run ID N ok|mismatch FIELD|overflow out|pending` per run, then
    `summary runs=R ok=K`; or only `refused REASON` (exit 2) when the cases
    are malformed or over a CHECK_* guard, checked before any expansion."""
    checked = check_cases(sys.stdin.buffer.read(CHECK_INPUT + 1))
    if isinstance(checked, str):
        sys.stdout.write("refused %s\n" % checked)
        sys.stdout.flush()
        raise SystemExit(2)
    lines, passed = [], 0
    for ident, chunks, pieces, finish, expect, cap in checked:
        chunks, out = [expand(chunk) for chunk in chunks], expand(expect["out"])
        for piece in pieces:
            report = {"output_over_bound": False, "line_truncated": False, "partial_line": False,
                      "relay_failed": False}
            relay, most, verdict = Relay(report), 0, "ok"
            relay.out, relay.pending = Capped(cap, "out"), Capped(CHECK_PENDING, "pending")
            try:
                for chunk in chunks:
                    step = piece or max(len(chunk), 1)
                    for at in range(0, len(chunk), step):
                        relay.take(chunk[at:at + step])
                        most = max(most, len(relay.pending))
                if finish:
                    relay.finish()
            except CheckOverflow as error:
                verdict = "overflow %s" % error
            if verdict == "ok":
                for field, good in (("out", bytes(relay.out) == out),
                                    ("line_truncated", report["line_truncated"] == expect["line_truncated"]),
                                    ("partial_line", report["partial_line"] == expect["partial_line"]),
                                    ("output_over_bound", report["output_over_bound"] == expect["output_over_bound"]),
                                    ("pending", most <= expect["pending_bound"])):
                    if not good:
                        verdict = "mismatch " + field
                        break
            passed += verdict == "ok"
            lines.append("run %s %d %s" % (ident, piece, verdict))
    lines.append("summary runs=%d ok=%d" % (len(lines), passed))
    sys.stdout.write("\n".join(lines) + "\n")
    sys.stdout.flush()


def own(args):
    """The outer owner: see the module documentation.

    After the spawn every path goes through `settle`: the command's group is
    SIGKILLed while its leader is still unreaped (never waited for before),
    then children and orphans are reaped with blocking waits until ECHILD,
    with no deadline that could end this owner while one remains. Relayed
    output is non-blocking and bounded: a slow, closed or failing reader, a
    flood, overlong or partial lines only set flags and never stop this
    owner from reading its control input. The accounting goes to `--report`
    (created exclusively, after the group is reaped), not to the relay, so a
    lost or forged relay line cannot stand for it.
    """
    stdin_file, graceful, report_path = None, 10.0, None
    while args and args[0] != "--":
        flag, value, args = args[0], args[1], args[2:]
        if flag == "--stdin":
            stdin_file = value
        elif flag == "--graceful":
            graceful = float(value)
        elif flag == "--report":
            report_path = value
        else:
            raise SystemExit(2)
    argv = args[1:]
    if not argv or not argv[0].startswith("/") or report_path is None:
        raise SystemExit(2)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise SystemExit(3)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    report = {"child_exit": None, "forced": False, "graceful_timeout": False, "held_output": False,
              "output_over_bound": False, "line_truncated": False, "partial_line": False, "relay_failed": False,
              "owner_error": None, "group_killed": False, "reaped": 0, "echild": False}
    if stdin_file is not None:
        child_in, control = os.open(stdin_file, os.O_RDONLY | os.O_CLOEXEC), None
    else:
        child_in, control = os.pipe()
    # Test-only fault injection for the fixture's own tests.
    fault = os.environ.get("AGENTBOX_G1_OWNER_FAULT", "")

    def after_line():
        if fault == "raise-after-line":
            raise RuntimeError("injected owner fault")

    relay = Relay(report, after_line)
    outbuf = relay.out
    out_r, out_w = os.pipe()
    pid = os.posix_spawn(argv[0], argv, os.environ, setpgroup=0,
                         file_actions=[(os.POSIX_SPAWN_DUP2, child_in, 0), (os.POSIX_SPAWN_DUP2, out_w, 1)])
    # From here on the command may have descendants: every exit is guarded.
    def flush():
        while outbuf and not report["relay_failed"]:
            try:
                written = os.write(1, outbuf)
            except BlockingIOError:
                return
            except OSError:
                report["relay_failed"] = True
                outbuf.clear()
                return
            del outbuf[:written]

    def exited():
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    try:
        os.close(child_in)
        os.close(out_w)
        os.set_blocking(out_r, False)
        os.set_blocking(1, False)
        stdin_open, out_open, deadline, exit_seen = True, True, None, None
        while True:
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                report["graceful_timeout"] = True
                break
            if exit_seen is None and exited():
                exit_seen = now
            if exit_seen is not None and (not out_open or now >= exit_seen + 1.0):
                report["held_output"] = out_open
                break
            readable = ([0] if stdin_open else []) + ([out_r] if out_open else [])
            writable = [1] if outbuf and not report["relay_failed"] else []
            ready, can_write, _ = select.select(readable, writable, [], 0.1)
            if 1 in can_write:
                flush()
            if 0 in ready:
                data = os.read(0, 4096)
                if b"force" in data:
                    report["forced"] = True
                    break
                if not data:
                    stdin_open = False
                    if control is not None:
                        os.close(control)
                        control = None
                    deadline = time.monotonic() + graceful
            if out_r in ready:
                try:
                    chunk = os.read(out_r, 65536)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    out_open = False
                elif chunk:
                    relay.take(chunk)
    except BaseException as error:
        report["owner_error"] = type(error).__name__
    settle(pid, report)
    wrote = False
    try:
        if control is not None:
            os.close(control)
        # Every writer of the relay pipe is gone: drain what it still holds.
        while True:
            try:
                chunk = os.read(out_r, 65536)
            except BlockingIOError:
                break
            if not chunk:
                break
            relay.take(chunk)
        relay.finish()
        os.set_blocking(1, True)
        flush()
    except BaseException as error:
        report["owner_error"] = report["owner_error"] or type(error).__name__
    text = json.dumps(report, sort_keys=True).encode()[:MAX_REPORT]
    try:
        # Untrusted diagnostic copy (stderr is the test's log file).
        os.write(2, b"owner-diagnostic " + text + b"\n")
    except BaseException:
        pass
    try:
        fd = os.open(report_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, text)
            os.fsync(fd)
        finally:
            os.close(fd)
        wrote = True
    except BaseException:
        wrote = False
    os._exit(0 if wrote else 4)


def settle(pid, report):
    """Kills the command's group, then reaps until ECHILD, blocking, with no
    deadline: this owner never ends while a child of it remains. The leader
    was never waited for before this, so its group id is still its own."""
    try:
        os.killpg(pid, signal.SIGKILL)
        report["group_killed"] = True
    except BaseException as error:
        report["owner_error"] = report["owner_error"] or "killpg:" + type(error).__name__
    while True:
        try:
            reaped, status = os.waitpid(-1, 0)
        except ChildProcessError:
            report["echild"] = True
            return
        except InterruptedError:
            continue
        except BaseException as error:
            report["owner_error"] = report["owner_error"] or "waitpid:" + type(error).__name__
            continue
        report["reaped"] += 1
        if reaped == pid:
            code = os.waitstatus_to_exitcode(status)
            report["child_exit"] = {"code": code} if code >= 0 else {"signal": -code}


def main():
    if sys.argv[1:2] == ["own"]:
        own(sys.argv[2:])
        return
    if sys.argv[1:] == ["relay-check"]:
        relay_check()
        return
    if sys.argv[1:2] != ["serve"]:
        raise SystemExit(2)
    mode, root, cert, key, git = sys.argv[2:7]
    if mode not in ("backend", "dumb", "redirect", "auth", "stall", "crash"):
        raise SystemExit(2)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    # PR_SET_CHILD_SUBREAPER: anything orphaned below this server is its own
    # to reap, never the init process's.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise SystemExit(3)
    server = Server(mode, root, cert, key, git)
    try:
        server.run()
    finally:
        server.reap()
        print(json.dumps(server.stats, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
