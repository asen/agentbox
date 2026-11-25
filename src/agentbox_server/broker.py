"""The per-execution CONNECT broker on a single event loop, with bounded resolver threads.

One loopback listener serves one execution. For each client it reads a
bounded head (`request`). A valid artifact POST head is classified before
any lookup or dial: without a POST ingress it is refused
`post_unconfigured`; with one, the connection leaves the CONNECT
allowances for one of the ingress's two permits and serves one exchange.
For a CONNECT, in this order:

1. admits the host and port by the policy, before any lookup;
2. reserves a tunnel slot;
3. resolves a name with its own bounded resolver, never an IP literal;
4. validates every candidate: one unspecified address refuses the
   request (policy.py);
5. dials the validated numeric addresses in order, with no second lookup;
6. registers the tunnel, records the decision and commits: the broker
   running and the tunnel not revoked, it hands both sockets and the bytes
   read past the head to one `agentbox-relay` child (`relay`), which alone
   sends the `200` and relays. Before the child's START the broker may
   refuse; after it, or when it cannot tell, it never writes to that
   client.

A stop is seen the moment it is known, not when the server gets to it:
the server's `stopped()` (its end of input, a signal, lost output,
recognized in the middle of a selector batch or of a required write) is
read with the broker's own at every admission, lookup grant and result,
dial and the commit, the last boundary before the handoff. Each step's
deadline is absolute: read where its result is taken (a lookup's answers,
a dial's next candidate, an immediate or a ready connect), not only by
the sweep.

```text
accept -> head -> policy -> slot -> lookup -> validate -> dial -> register
       -> record -> commit -> relay child (200, payload) -> closed line
```

With a configured CONNECT proxy (`proxy`, the controller's
`connect_proxy`) steps 3-5 change: the admitted authority is never
resolved here, only an unspecified literal refused (`Admission.proxied`);
the proxy's own name is looked up, validated and dialed as above, then
asked `CONNECT authority`. Its response head is bounded (`max_head_bytes`,
`max_line_bytes`, `max_headers`), parsed whole (`request.parse_proxy_head`:
status line and every field) and read within the dial's deadline, peeked and taken
exactly to its blank line: any tunnel bytes after it stay in the socket
for the relay. Only a `2xx` goes on to step 6; anything else, an end, a
timeout or a stop closes both sockets. Never a direct fallback; nothing
of the proxy's response reaches the client.

```text
policy -> proxied? -> slot -> lookup proxy -> validate -> dial -> CONNECT authority
       -> head (peek, take to CRLFCRLF) -> 2xx? -> register ... (as above)
```

A stop revokes every tunnel (one byte to its child), closes the listener
and every pending client, waits for the children within its deadline,
then kills those left. Every record is required: one not written within
`RECORD_WAIT` fails the broker closed. Events carry fixed codes, counters,
timing and digests: never request bytes, names, addresses or payload.
"""
import errno
import hashlib
import ipaddress
import os
import queue
import selectors
import socket
import threading

from . import address, ingress as ingress_mod, policy as policy_mod, request
from .relay import Relay, RelayError, RelayStopped

RECORD_WAIT = 0.25
STOP_WAIT = 1.0
LINGER = 0.25
LINGER_BYTES = 64 * 1024
BUFFER_BYTES = 16 * 1024
# A child that said `closed` exits at once; one that did not is killed.
REAP_WAIT = 1.0


class Limits:
    """Per-execution broker budgets."""

    def __init__(self, **overrides):
        self.max_head_bytes = 8 * 1024
        self.max_line_bytes = 1024
        self.max_headers = 32
        self.head_timeout = 5.0
        self.max_pending = 8
        self.max_resolutions = 4
        self.max_tunnels = 16
        self.dns_timeout = 5.0
        self.connect_timeout = 5.0
        self.idle_timeout = 120.0
        self.max_lifetime = 3600.0
        for key, value in overrides.items():
            if not hasattr(self, key):
                raise TypeError(key)
            setattr(self, key, value)

    def head(self):
        return request.Limits(self.max_head_bytes, self.max_line_bytes, self.max_headers)


# Refusal code -> HTTP status, beside the request and denial codes.
REFUSALS = {
    "pending_limit": 503, "tunnel_limit": 503, "resolver_busy": 503, "dns_failed": 502,
    "dns_timeout": 504, "connect_refused": 502, "connect_failed": 502, "connect_timeout": 504,
    "broker_stopping": 503, "broker_internal": 503,
    "proxy_refused": 502, "proxy_malformed": 502, "proxy_failed": 502, "proxy_timeout": 504,
}


def status_of(code):
    if code in REFUSALS:
        return REFUSALS[code]
    if code in request.STATUS or code in request.AUTHORITY_CODES:
        return request.status_of(code)
    # Every policy denial.
    return 403


def event(kind, severity, **attributes):
    return {"event": kind, "severity": severity, "attributes": attributes}


def destination_digest(authority):
    return hashlib.sha256(address.authority_text(authority).encode()).hexdigest()


def millis(seconds):
    return max(0, int(seconds * 1000))


class Facts:
    """What an event may say about one request."""

    def __init__(self):
        self.port = self.destination = self.answers = None
        self.attempts = 0

    def event(self, ident, decision, reason, duration):
        severity = "info" if decision == "tunnel" else "warn"
        attributes = {"connection": ident, "decision": decision, "reason": reason,
                      "attempts": self.attempts, "duration_ms": millis(duration)}
        if self.port is not None:
            attributes["port"] = self.port
        if self.destination is not None:
            attributes["destination_sha256"] = self.destination
        if self.answers is not None:
            attributes["answers"] = self.answers
        return {"event": "broker.request", "severity": severity, "attributes": attributes}


class Conn:
    """One accepted client, from accept to its last record."""

    def __init__(self, ident, sock, started):
        self.id, self.sock, self.started = ident, sock, started
        self.facts = Facts()
        self.state = "head"
        self.buf = b""
        self.searched = 0
        self.pending = True
        self.thread = True
        self.slot = False
        self.post = False
        self.deadline = None
        self.events = 0
        # A refusal's linger, a lookup, a dial, a POST exchange.
        self.linger = None
        self.lookup = None
        self.dial = None
        self.exchange = None
        self.target = None
        # Through a proxy: its CONNECT still to send, its head so far.
        self.request = b""
        self.reply = b""


class Tunnel:
    def __init__(self, conn):
        self.conn = conn
        self.signal = None
        self.relay = None
        self.opened = False
        self.result = None
        self.reap_until = None


class Resolver:
    """At most `max` lookup threads, stalled ones included; a full pool
    refuses rather than queues past a caller's deadline. Answers arrive on
    `results` with a wake byte."""

    def __init__(self, maximum, lookup, wake):
        self.max, self.lookup, self.wake = maximum, lookup, wake
        self.busy = 0
        self.results = queue.SimpleQueue()

    def start(self, job):
        if self.busy >= self.max:
            return False
        self.busy += 1
        thread = threading.Thread(target=self._run, args=(job,), name="agentbox-resolver", daemon=True)
        thread.start()
        return True

    def _run(self, job):
        try:
            answers = self.lookup(job.query)
        except Exception:  # noqa: BLE001 - any failure is `dns_failed`
            answers = None
        self.results.put((job, answers))
        try:
            os.write(self.wake, b"r")
        except OSError:
            pass

    def drain(self):
        """Finished lookups, each freeing its slot: [(job, answers)]."""
        done = []
        while True:
            try:
                job, answers = self.results.get_nowait()
            except queue.Empty:
                return done
            self.busy -= 1
            done.append((job, answers))


def system_lookup(query):
    """The system resolver, for TCP; at most MAX_ANSWERS + 1 answers kept."""
    answers = []
    for _family, _type, _proto, _name, sockaddr in socket.getaddrinfo(query, 0, type=socket.SOCK_STREAM):
        answers.append(ipaddress.ip_address(sockaddr[0].split("%")[0]))
        if len(answers) > policy_mod.MAX_ANSWERS:
            break
    return answers


class Lookup:
    def __init__(self, conn, query, deadline):
        self.conn, self.query, self.deadline = conn, query, deadline
        self.started = False
        self.abandoned = False


class Dial:
    def __init__(self, targets, deadline):
        self.targets, self.deadline = list(targets), deadline
        self.at = 0
        self.sock = None
        self.failure = "connect_failed"


class Broker:
    """One running broker on `loop` (`watch`, `unwatch`). `record(event,
    deadline)` writes one event or returns False; `fail()` is the server's
    hook, called once when the broker fails closed."""

    def __init__(self, loop, policy, limits, post, relay_path, record, fail, clock,
                 lookup=system_lookup, dial_map=None, stopped=None, proxy=None):
        self.loop, self.policy, self.limits, self.post = loop, policy, limits, post
        self.relay_path, self._record, self.fail_hook = relay_path, record, fail
        self.clock = clock
        # The server's stop, as soon as it is known (main.py `halted`).
        self.external = stopped or (lambda: False)
        # Tests only: where a validated address is actually dialed. Never
        # set by the program (main.py).
        self.dial_map = dial_map
        # The CONNECT proxy's authority (policy.parse_grant), or None:
        # direct. Resolved and validated as a destination, never policed.
        self.proxy = proxy
        self.phase = "running"
        self.stopping = False
        self.admission_closed = False
        self.stop_deadline = None
        self.pending = self.slots = self.threads = self.posts = 0
        self.conns = {}
        self.tunnels = {}
        self.next_id = 1
        self.counters = dict(accepted=0, refused=0, tunnels_opened=0, tunnels_closed=0,
                             bytes_up=0, bytes_down=0, posts=0)
        self.listener = None
        self.address = None
        self.hook_called = False
        self.wake = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        self.resolver = Resolver(limits.max_resolutions, lookup, self.wake[1])
        self.waiting = []
        self.loop.watch(self.wake[0], selectors.EVENT_READ, self._woken)

    def _stopped(self):
        """This broker's stop or its server's: nothing is admitted, looked
        up, dialed or committed after either."""
        return self.stopping or self.external()

    # Records.

    def record(self, message, deadline=None):
        if self.admission_closed:
            return False
        now = self.clock()
        deadline = now + RECORD_WAIT if deadline is None else deadline
        if self.stop_deadline is not None:
            deadline = min(deadline, self.stop_deadline)
        if self._record(message, deadline):
            return True
        self.fail("recorder_failed")
        return False

    def fail(self, failure):
        self.halt("failed:" + failure)
        if not self.hook_called:
            self.hook_called = True
            self.fail_hook()
            if failure != "recorder_failed":
                self.record(event("broker.failed", "error", reason=failure))

    # Startup.

    def start(self, until, stopped):
        """The listener and the first record within `until` and
        `stopped()`: the bound address, or the fixed error."""
        if stopped():
            raise BrokerStartError("broker_start_cancelled")
        if self.clock() >= until:
            raise BrokerStartError("broker_start_timeout")
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listener.listen(self.limits.max_pending)
            listener.setblocking(False)
        except OSError:
            raise BrokerStartError("broker_listen_failed") from None
        self.listener = listener
        self.address = listener.getsockname()
        started = event("broker.started", "info", policy=self.policy.identity, mode=self.policy.mode,
                        grants=len(self.policy.grants), route="direct" if self.proxy is None else "proxy")
        now = self.clock()
        if not self._record(started, min(now + RECORD_WAIT, until)) or stopped() or self.clock() >= until:
            listener.close()
            self.listener = None
            raise BrokerStartError("recorder_failed")
        self.loop.watch(listener.fileno(), selectors.EVENT_READ, self._accept)
        return self.address

    def close_unstarted(self):
        """A broker whose start failed: nothing serves, its pipe closed."""
        self.stopping = True
        self.loop.unwatch(self.wake[0])
        for fd in self.wake:
            os.close(fd)

    # The loop.

    def _woken(self, _mask):
        while True:
            try:
                if not os.read(self.wake[0], 256):
                    break
            except BlockingIOError:
                break
        for job, answers in self.resolver.drain():
            self._looked_up(job, answers)
        self._grant_lookups()

    def tick(self):
        """Every deadline; called each loop slice."""
        now = self.clock()
        for conn in list(self.conns.values()):
            self._tick_conn(conn, now)
        for tunnel in list(self.tunnels.values()):
            self._tick_tunnel(tunnel, now)

    def _signal(self, tunnel, end):
        if tunnel.signal is None:
            tunnel.signal = end
            if tunnel.relay is not None:
                tunnel.relay.revoke(end)

    def _revoke_all(self, end):
        for tunnel in self.tunnels.values():
            self._signal(tunnel, end)

    # Clients.

    def _accept(self, _mask):
        if self.stopping:
            return
        try:
            sock, _ = self.listener.accept()
        except (BlockingIOError, InterruptedError, ConnectionAbortedError):
            return
        except OSError as error:
            if error.errno in (errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EPROTO):
                return
            self.fail("broker_accept_failed")
            return
        self.counters["accepted"] += 1
        ident = self.next_id
        self.next_id += 1
        started = self.clock()
        sock.setblocking(False)
        if self._stopped():
            refusal = "broker_stopping"
        elif not (self.pending < self.limits.max_pending
                  and self.threads < self.limits.max_pending + self.limits.max_tunnels):
            refusal = "pending_limit"
        else:
            refusal = None
        if refusal is not None:
            self._respond_now(sock, refusal)
            sock.close()
            self.counters["refused"] += 1
            self.record(Facts().event(ident, "refused", refusal, self.clock() - started))
            return
        self.pending += 1
        self.threads += 1
        conn = Conn(ident, sock, started)
        conn.deadline = self._guard_clip(started + self.limits.head_timeout)
        self.conns[ident] = conn
        self.loop.watch(sock.fileno(), selectors.EVENT_READ, lambda mask, c=conn: self._ready(c, mask))

    # The execution guard (a POST ingress present): its cutoff and end.

    def _guarded(self):
        return self.post is not None

    def _guard_clip(self, at):
        return self.post.clip(at) if self.post is not None else at

    def _guard_stopped(self):
        return self._stopped() or (self.post is not None and self.post.ended())

    def _late(self, now):
        return self._guard_stopped() or (self.post is not None and self.post.past(now))

    def _respond_now(self, sock, code):
        """A refusal's status without waiting: guarded, only before the
        cutoff and any stop; then the write side shut."""
        status = status_of(code)
        sent = self._send_status(sock, status)
        if sent:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        return sent

    def _send_status(self, sock, status):
        if status is None:
            return 0
        data = request.refusal(status)
        sent = 0
        while sent < len(data):
            if self._guarded() and self._late(self.clock()):
                break
            try:
                n = sock.send(data[sent:])
            except InterruptedError:
                continue
            except OSError:
                break
            if n == 0:
                break
            sent += n
        return sent

    def _refuse(self, conn, code):
        """Every refusal after accept: the status (if any), then a brief
        linger for the client to read it, then the close and the record."""
        conn.state = "linger"
        conn.refusal = code
        # A pending dial or proxy connection never outlives its refusal.
        self._drop_upstream(conn)
        sent = self._respond_now(conn.sock, code)
        if sent and status_of(code) is not None:
            conn.linger = [self._guard_clip(self.clock() + LINGER), 0]
            self.loop.watch(conn.sock.fileno(), selectors.EVENT_READ, lambda mask, c=conn: self._ready(c, mask))
        else:
            self._refused(conn)

    def _refused(self, conn):
        self._close_conn(conn)
        self.counters["refused"] += 1
        self.record(conn.facts.event(conn.id, "refused", conn.refusal, self.clock() - conn.started))
        self._exit_conn(conn)

    def _drop_upstream(self, conn):
        if conn.dial is not None and conn.dial.sock is not None:
            self.loop.unwatch(conn.dial.sock.fileno())
            conn.dial.sock.close()
            conn.dial.sock = None

    def _close_conn(self, conn):
        if conn.sock is not None:
            self.loop.unwatch(conn.sock.fileno())
            conn.sock.close()
            conn.sock = None
        self._drop_upstream(conn)
        if conn.lookup is not None:
            conn.lookup.abandoned = True
            if conn.lookup in self.waiting:
                self.waiting.remove(conn.lookup)
            conn.lookup = None
        tunnel = self.tunnels.pop(conn.id, None)
        if conn.pending:
            conn.pending = False
            self.pending -= 1
        if conn.slot:
            conn.slot = False
            self.slots -= 1
        return tunnel

    def _exit_conn(self, conn):
        self.conns.pop(conn.id, None)
        if conn.thread:
            conn.thread = False
            self.threads -= 1

    def _ready(self, conn, mask):
        if conn.sock is None:
            return
        if conn.state == "head":
            self._read_head(conn)
        elif conn.state == "linger":
            self._linger(conn)
        elif conn.state == "dial":
            self._dialed(conn)
        elif conn.state.startswith("post"):
            self._post_ready(conn, mask)

    def _tick_conn(self, conn, now):
        state = conn.state
        if state == "head":
            if self._guarded():
                if self._guard_stopped():
                    return self._refuse(conn, "broker_stopping")
            elif self._stopped():
                return self._refuse(conn, "broker_stopping")
            if now >= conn.deadline:
                self._refuse(conn, "request_timeout")
        elif state == "linger":
            if self._guard_stopped() or now >= conn.linger[0]:
                self._refused(conn)
        elif state == "resolve":
            if self._stopped():
                return self._refuse(conn, "broker_stopping")
            if now >= conn.lookup.deadline:
                lookup = conn.lookup
                self._refuse(conn, "dns_timeout" if lookup.started else "resolver_busy")
        elif state == "dial":
            if self._stopped():
                return self._refuse(conn, "broker_stopping")
            if now >= conn.dial.deadline:
                self._refuse(conn, "connect_timeout")
        elif state == "proxy":
            if self._stopped():
                return self._refuse(conn, "broker_stopping")
            if now >= conn.dial.deadline:
                self._refuse(conn, "proxy_timeout")
        elif state.startswith("post"):
            self._post_tick(conn, now)

    def _linger(self, conn):
        try:
            data = conn.sock.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        conn.linger[1] += len(data)
        if not data or conn.linger[1] >= LINGER_BYTES:
            self._refused(conn)

    def _read_head(self, conn):
        now = self.clock()
        if self._guarded():
            if self._guard_stopped():
                return self._refuse(conn, "broker_stopping")
            if now >= conn.deadline:
                return self._refuse(conn, "request_timeout")
        limits = self.limits.head()
        try:
            data = conn.sock.recv(limits.max_head_bytes - len(conn.buf))
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        if not data:
            return self._refuse(conn, "request_incomplete")
        before = len(conn.buf)
        conn.buf += data
        end = request.head_end(conn.buf, before)
        try:
            if end is not None:
                head, leftover = conn.buf[:end], conn.buf[end:]
                request.check_line(head, limits)
            else:
                request.check_line(conn.buf, limits)
                if len(conn.buf) == limits.max_head_bytes:
                    raise request.RequestError("request_head_too_large")
                return
        except request.RequestError as error:
            return self._refuse(conn, error.code)
        if self._guarded():
            if self._guard_stopped():
                return self._refuse(conn, "broker_stopping")
            if self.clock() >= conn.deadline:
                return self._refuse(conn, "request_timeout")
        conn.buf = b""
        self.loop.unwatch(conn.sock.fileno())
        try:
            kind, value = request.parse_request_head(head, limits)
        except request.RequestError as error:
            return self._refuse(conn, error.code)
        if kind == "post":
            return self._post_head(conn, value, leftover)
        conn.leftover = leftover
        self._connect(conn, value)

    def _connect(self, conn, authority):
        facts = conn.facts
        facts.port = authority.port
        facts.destination = destination_digest(authority)
        try:
            admission = self.policy.admit(authority)
            if self.proxy is not None:
                target = admission.proxied()
                conn.request = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
                # From here on the proxy is what is resolved and dialed.
                admission = policy_mod.Admission(None, self.proxy.host, self.proxy.port)
        except policy_mod.Denial as denial:
            return self._refuse(conn, denial.code)
        if self._stopped():
            return self._refuse(conn, "broker_stopping")
        if self.slots >= self.limits.max_tunnels:
            return self._refuse(conn, "tunnel_limit")
        self.slots += 1
        conn.slot = True
        conn.admission = admission
        query = admission.resolver_query()
        if query is None:
            return self._validate(conn, [])
        conn.state = "resolve"
        conn.lookup = Lookup(conn, query, self.clock() + self.limits.dns_timeout)
        if self.resolver.start(conn.lookup):
            conn.lookup.started = True
        else:
            self.waiting.append(conn.lookup)

    def _grant_lookups(self):
        while self.waiting and self.resolver.busy < self.resolver.max:
            lookup = self.waiting.pop(0)
            if self._stopped():
                self._refuse(lookup.conn, "broker_stopping")
            elif self.clock() >= lookup.deadline:
                self._refuse(lookup.conn, "resolver_busy")
            elif self.resolver.start(lookup):
                lookup.started = True

    def _looked_up(self, lookup, answers):
        conn = lookup.conn
        if lookup.abandoned or conn.lookup is not lookup or conn.state != "resolve":
            return
        if self._stopped():
            return self._refuse(conn, "broker_stopping")
        if self.clock() >= lookup.deadline:
            # Late answers are a timeout, whatever they say.
            return self._refuse(conn, "dns_timeout")
        conn.lookup = None
        if answers is None:
            return self._refuse(conn, "dns_failed")
        if self.proxy is None:
            conn.facts.answers = len(answers)
        self._validate(conn, answers)

    def _validate(self, conn, answers):
        try:
            targets = conn.admission.validate(answers)
        except policy_mod.Denial as denial:
            return self._refuse(conn, denial.code)
        conn.state = "dial"
        conn.dial = Dial(targets, self.clock() + self.limits.connect_timeout)
        self._dial_next(conn)

    def _dial_next(self, conn):
        dial = conn.dial
        while dial.at < len(dial.targets):
            if self._stopped():
                return self._refuse(conn, "broker_stopping")
            if self.clock() >= dial.deadline:
                return self._refuse(conn, "connect_timeout")
            ip, port = dial.targets[dial.at]
            dial.at += 1
            conn.facts.attempts += 1
            if self.dial_map is not None:
                mapped = self.dial_map((ip, port))
                if mapped is None:
                    dial.failure = "connect_failed"
                    continue
                ip, port = mapped
            family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
            try:
                sock = socket.socket(family, socket.SOCK_STREAM | socket.SOCK_NONBLOCK)
            except OSError:
                dial.failure = "connect_failed"
                continue
            code = sock.connect_ex((str(ip), port))
            if code == 0:
                dial.sock = sock
                return self._connected(conn)
            if code == errno.EINPROGRESS:
                dial.sock = sock
                self.loop.watch(sock.fileno(), selectors.EVENT_WRITE, lambda mask, c=conn: self._dialed(c))
                return
            sock.close()
            if code == errno.ETIMEDOUT:
                return self._refuse(conn, "connect_timeout")
            dial.failure = "connect_refused" if code == errno.ECONNREFUSED else "connect_failed"
        self._refuse(conn, dial.failure)

    def _dialed(self, conn):
        dial = conn.dial
        if conn.state != "dial" or dial.sock is None:
            return
        sock = dial.sock
        self.loop.unwatch(sock.fileno())
        code = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if code == 0:
            try:
                sock.getpeername()
            except OSError:
                code = errno.ENOTCONN
        if code == 0:
            return self._connected(conn)
        sock.close()
        dial.sock = None
        if code == errno.ETIMEDOUT:
            return self._refuse(conn, "connect_timeout")
        dial.failure = "connect_refused" if code == errno.ECONNREFUSED else "connect_failed"
        self._dial_next(conn)

    def _connected(self, conn):
        if self.proxy is not None:
            return self._proxy_start(conn)
        self._tunnel(conn)

    # Through a proxy: its CONNECT, then its response head, by the dial's
    # deadline.

    def _proxy_start(self, conn):
        if self._stopped():
            return self._refuse(conn, "broker_stopping")
        if self.clock() >= conn.dial.deadline:
            return self._refuse(conn, "connect_timeout")
        conn.state = "proxy"
        self.loop.watch(conn.dial.sock.fileno(), selectors.EVENT_WRITE, lambda mask, c=conn: self._proxy_ready(c))
        self._proxy_ready(conn)

    def _proxy_ready(self, conn):
        if conn.state != "proxy" or conn.dial.sock is None:
            return
        if self._stopped():
            return self._refuse(conn, "broker_stopping")
        if self.clock() >= conn.dial.deadline:
            return self._refuse(conn, "proxy_timeout")
        if conn.request:
            return self._proxy_send(conn)
        self._proxy_read(conn)

    def _proxy_send(self, conn):
        sock = conn.dial.sock
        try:
            n = sock.send(conn.request)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return self._refuse(conn, "proxy_failed")
        conn.request = conn.request[n:]
        if not conn.request:
            self.loop.watch(sock.fileno(), selectors.EVENT_READ, lambda mask, c=conn: self._proxy_ready(c))

    def _proxy_read(self, conn):
        """The head peeked, then taken exactly: all of it while its blank
        line is not seen (every such byte is head), else to that line's
        end, leaving what follows for the relay."""
        sock = conn.dial.sock
        before = len(conn.reply)
        try:
            data = sock.recv(self.limits.max_head_bytes - before, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return self._refuse(conn, "proxy_failed")
        if not data:
            return self._refuse(conn, "proxy_failed")
        end = request.head_end(conn.reply + data, before)
        want = len(data) if end is None else end - before
        try:
            taken = sock.recv(want)
        except OSError:
            taken = b""
        if len(taken) != want:
            return self._refuse(conn, "proxy_failed")
        conn.reply += taken
        if end is None:
            line = conn.reply.find(b"\r\n")
            if len(conn.reply) >= self.limits.max_head_bytes or line > self.limits.max_line_bytes \
                    or (line < 0 and len(conn.reply) > self.limits.max_line_bytes + 1):
                return self._refuse(conn, "proxy_malformed")
            return
        try:
            code = request.parse_proxy_head(conn.reply, self.limits.head())
        except request.RequestError:
            return self._refuse(conn, "proxy_malformed")
        if not 200 <= code < 300:
            return self._refuse(conn, "proxy_refused")
        conn.reply = b""
        self.loop.unwatch(sock.fileno())
        self._tunnel(conn)

    def _tunnel(self, conn):
        upstream = conn.dial.sock
        conn.dial.sock = None
        if self._stopped():
            upstream.close()
            return self._refuse(conn, "broker_stopping")
        if self.clock() >= conn.dial.deadline:
            # Connected, but only after its bound: never used.
            upstream.close()
            return self._refuse(conn, "connect_timeout" if self.proxy is None else "proxy_timeout")
        tunnel = Tunnel(conn)
        conn.state = "tunnel"
        self.tunnels[conn.id] = tunnel
        conn.pending = False
        self.pending -= 1
        if not self.record(conn.facts.event(conn.id, "tunnel", "allowed", self.clock() - conn.started)):
            upstream.close()
            return self._tunnel_ended(tunnel, tunnel.signal or "broker_stopped")
        end = self._commit(tunnel)
        if end is not None:
            upstream.close()
            return self._tunnel_ended(tunnel, end)
        try:
            # The commit again after the spawn and before each piece of the
            # handoff, START last: a stop meanwhile leaves the client
            # unstarted.
            relay = Relay.start(self.relay_path, conn.sock, upstream, conn.leftover,
                                self.limits.idle_timeout, self.limits.max_lifetime,
                                go=lambda: self._commit(tunnel))
        except RelayStopped as stopped:
            upstream.close()
            return self._tunnel_ended(tunnel, stopped.code)
        except RelayError as error:
            upstream.close()
            if error.answerable:
                # The child never started: still ours to refuse.
                self._respond_now(conn.sock, "broker_internal")
            else:
                # It may have started: closed unanswered.
                conn.sock = None
            return self._tunnel_ended(tunnel, "relay_failed")
        # Started: its client is the child's alone now.
        conn.sock = None
        tunnel.relay = relay
        self.loop.watch(relay.fileno(), selectors.EVENT_READ, lambda mask, t=tunnel: self._relay_said(t))

    def _commit(self, tunnel):
        if tunnel.signal is not None:
            return tunnel.signal
        if self.phase != "running" or self._stopped() or tunnel.conn.id not in self.tunnels:
            return "broker_stopped"
        return None

    def _relay_said(self, tunnel):
        relay = tunnel.relay
        ended = relay.read()
        if relay.opened and not tunnel.opened:
            tunnel.opened = True
            self.counters["tunnels_opened"] += 1
        if relay.result is not None and relay.result[0] == "closed" and tunnel.result is None:
            tunnel.result = relay.result
        if ended:
            self.loop.unwatch(relay.fileno())
            tunnel.reap_until = self.clock() + REAP_WAIT
            self._tick_tunnel(tunnel, self.clock())

    def _tick_tunnel(self, tunnel, now):
        relay = tunnel.relay
        if relay is None or tunnel.reap_until is None:
            return
        if relay.popen.poll() is None:
            if now < tunnel.reap_until:
                return
            relay.kill()
            relay.popen.wait()
        relay.control.close()
        if tunnel.result is not None:
            _, reason, up, down = tunnel.result
        else:
            reason, up, down = "relay_lost", 0, 0
        self.counters["bytes_up"] += up
        self.counters["bytes_down"] += down
        self._tunnel_ended(tunnel, reason, up, down)

    def _tunnel_ended(self, tunnel, reason, up=0, down=0):
        conn = tunnel.conn
        self._close_conn(conn)
        self.counters["tunnels_closed"] += 1
        self.record(event("broker.tunnel_closed", "info", connection=conn.id, reason=reason, bytes_up=up,
                          bytes_down=down, duration_ms=millis(self.clock() - conn.started)))
        self._exit_conn(conn)

    # POST.

    def _post_head(self, conn, length, leftover):
        if self.post is None:
            return self._refuse(conn, "post_unconfigured")
        refused = self.post.permit()
        if refused is not None:
            return self._refuse(conn, refused)
        if self._stopped():
            self.post.release_permit()
            return self._refuse(conn, "broker_stopping")
        # Out of the CONNECT allowances, into the POST permit.
        conn.pending = False
        self.pending -= 1
        conn.thread = False
        self.threads -= 1
        self.posts += 1
        conn.post = True
        self.counters["posts"] += 1
        conn.exchange = request.PostExchange(length, leftover)
        conn.body_deadline = self.post.clip(conn.started + self.limits.head_timeout)
        conn.state = "post_body"
        self.loop.watch(conn.sock.fileno(), selectors.EVENT_READ, lambda mask, c=conn: self._ready(c, mask))
        self._post_step(conn, conn.exchange.first)

    def _post_stop(self):
        return self._stopped() or self.post.ended()

    def _post_step(self, conn, step):
        """A body-phase step of the exchange."""
        kind = step[0]
        if kind == "pending":
            return
        if kind == "refused":
            return self._post_refused(conn, step[1])
        if kind != "body":
            return self._post_refused(conn, "request_incomplete")
        now = self.clock()
        if self._post_stop():
            return self._post_refused(conn, "broker_stopping")
        if now >= conn.body_deadline:
            return self._post_refused(conn, "request_timeout")
        admitted = self.post.admit(step[1], now)
        if admitted[0] == "refused":
            return self._post_refused(conn, admitted[1])
        if admitted[0] == "answer":
            _, status, body, until = admitted
            conn.answer = True
            return self._post_write(conn, status, body, until)
        conn.answer = False
        conn.ticket = admitted[1]
        conn.state = "post_wait"
        self._post_tick(conn, now)

    def _post_refused(self, conn, code):
        """A POST refused before dispatch: its status-only answer and
        linger, then its record."""
        self.counters["refused"] += 1
        self._post_end(conn, code, "warn", refusal=code)

    def _post_ready(self, conn, mask):
        state = conn.state
        if state == "post_body":
            now = self.clock()
            if self._post_stop():
                return self._post_refused(conn, "broker_stopping")
            if now >= conn.body_deadline:
                return self._post_refused(conn, "request_timeout")
            try:
                data = conn.sock.recv(BUFFER_BYTES)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return self._post_step(conn, conn.exchange.end(True))
            step = conn.exchange.input(data) if data else conn.exchange.end(False)
            return self._post_step(conn, step)
        if state in ("post_wait", "post_write"):
            end = self._peer(conn)
            if end is not None:
                return self._post_abandon(conn, end)
            if state == "post_write" and mask & selectors.EVENT_WRITE:
                self._post_flush(conn)
        elif state == "post_linger":
            self._post_linger_read(conn)

    def _peer(self, conn):
        """Peer input while a response is awaited or written: any byte,
        EOF or reset abandons the exchange."""
        try:
            data = conn.sock.recv(64)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            step = conn.exchange.end(True)
        else:
            step = conn.exchange.input(data) if data else conn.exchange.end(False)
        if step[0] == "abandoned":
            return {"eof": "peer_eof", "reset": "peer_reset", "extra_input": "extra_input"}[step[1]]
        return None

    def _post_tick(self, conn, now):
        state = conn.state
        if state == "post_body":
            if self._post_stop():
                return self._post_refused(conn, "broker_stopping")
            if now >= conn.body_deadline:
                return self._post_refused(conn, "request_timeout")
        elif state == "post_wait":
            if self._stopped():
                return self._post_abandon(conn, "post_stopped")
            step = self.post.next_step(conn.ticket)
            if step[0] == "closed":
                return self._post_abandon(conn, "post_stopped")
            if step[0] == "respond":
                _, status, body, until = step
                if now >= until:
                    return self._post_abandon(conn, "exchange_expired")
                return self._post_write(conn, status, body, until)
            if now >= step[1]:
                return self._post_abandon(conn, "exchange_expired")
        elif state == "post_write":
            if self._post_stop():
                return self._post_written(conn, "post_stopped")
            if now >= conn.write_deadline:
                return self._post_written(conn, "write_timeout")
        elif state == "post_linger":
            if self._guard_stopped() or now >= conn.linger[0]:
                self._post_finish(conn)

    def _post_write(self, conn, status, body, until):
        response = request.post_response(status, body)
        if response is None or not conn.exchange.respond(response):
            return self._post_written(conn, "write_failed")
        conn.write_deadline = min(self.clock() + ingress_mod.WRITE_TIMEOUT, until)
        conn.state = "post_write"
        self.loop.watch(conn.sock.fileno(), selectors.EVENT_READ | selectors.EVENT_WRITE,
                        lambda mask, c=conn: self._ready(c, mask))
        self._post_flush(conn)

    def _post_flush(self, conn):
        now = self.clock()
        if self._post_stop():
            return self._post_written(conn, "post_stopped")
        if now >= conn.write_deadline:
            return self._post_written(conn, "write_timeout")
        try:
            n = conn.sock.send(conn.exchange.output())
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return self._post_written(conn, "write_failed")
        if n == 0:
            return self._post_written(conn, "write_failed")
        if conn.exchange.wrote(n):
            # Complete only before the bound and any stop.
            now = self.clock()
            if self._post_stop():
                return self._post_written(conn, "post_stopped")
            if now >= conn.write_deadline:
                return self._post_written(conn, "write_timeout")
            self._post_written(conn, "written")

    def _post_written(self, conn, end):
        if conn.answer:
            reason = "answered" if end == "written" else "answer_unwritten"
            severity = "info" if end == "written" else "warn"
        else:
            reason = self.post.finish(conn.ticket, end)
            severity = "info" if end == "written" else "warn"
        if end == "written":
            try:
                conn.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        self._post_end(conn, reason, severity)

    def _post_abandon(self, conn, end):
        if conn.answer:
            return self._post_end(conn, "answer_unwritten", "warn")
        self.post.finish(conn.ticket, end)
        self._post_end(conn, end, "warn")

    def _post_end(self, conn, reason, severity, refusal=None):
        conn.post_reason = (reason, severity)
        if refusal is not None and self._send_post_refusal(conn, refusal):
            conn.state = "post_linger"
            conn.linger = [self.post.clip(self.clock() + LINGER), 0]
            self.loop.watch(conn.sock.fileno(), selectors.EVENT_READ, lambda mask, c=conn: self._ready(c, mask))
            return
        self._post_finish(conn)

    def _send_post_refusal(self, conn, code):
        status = status_of(code)
        sent = self._send_status(conn.sock, status)
        if sent:
            try:
                conn.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        return sent > 0

    def _post_linger_read(self, conn):
        try:
            data = conn.sock.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            data = b""
        conn.linger[1] += len(data)
        if not data or conn.linger[1] >= LINGER_BYTES:
            self._post_finish(conn)

    def _post_finish(self, conn):
        reason, severity = conn.post_reason
        self._close_conn(conn)
        self.conns.pop(conn.id, None)
        self.record({"event": "broker.post", "severity": severity,
                     "attributes": {"connection": conn.id, "reason": reason,
                                    "duration_ms": millis(self.clock() - conn.started)}})
        self.posts -= 1
        self.post.release_permit()

    # Stop.

    def halt(self, phase="stopped"):
        """No new client; every tunnel revoked, every pending client closed
        as refused; the POST ingress ended first. A failure wins."""
        if self.post is not None:
            self.post.stop()
        if not self.phase.startswith("failed") and (self.phase == "running" or phase.startswith("failed")):
            self.phase = phase
        if self.stopping:
            return
        self.stopping = True
        # Every pending client and dial shut at once, as the Rust broker's
        # tracked sockets: nothing more reaches them.
        for conn in self.conns.values():
            for sock in (conn.sock, conn.dial.sock if conn.dial is not None else None):
                if sock is not None and conn.state != "tunnel" and not conn.post:
                    try:
                        sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
        if self.listener is not None:
            self.loop.unwatch(self.listener.fileno())
            self.listener.close()
        self._revoke_all("broker_stopped")

    def stop_until(self, cutoff, pump):
        """Stops serving, closes the listener and every pending client,
        revokes every tunnel and waits for its child until `RECORD_WAIT`
        before the stop's deadline (`STOP_WAIT` from now or `cutoff`), then
        records `broker.stopped`: the report."""
        now = self.clock()
        deadline = min(now + STOP_WAIT, cutoff)
        late = now >= deadline
        if late:
            self.admission_closed = True
        self.stop_deadline = deadline
        self.halt()
        workers = max(now, deadline - RECORD_WAIT)
        while (self.conns or self.tunnels) and self.clock() < workers:
            pump(min(0.01, max(0.0, workers - self.clock())))
            self.tick()
        killed = 0
        for tunnel in list(self.tunnels.values()):
            if tunnel.relay is not None:
                tunnel.relay.kill()
                tunnel.relay.popen.wait()
                tunnel.relay.control.close()
                killed += 1
                self.tunnels.pop(tunnel.conn.id, None)
        for conn in list(self.conns.values()):
            self._close_conn(conn)
        connections = len(self.conns) + killed
        posts = self.posts
        resolutions = self.resolver.busy
        report = dict(state=self.phase.replace("failed:", ""), counters=dict(self.counters),
                      connections_outstanding=connections, posts_outstanding=posts,
                      resolutions_outstanding=resolutions)
        recorded = False
        if not late and self.clock() < deadline:
            stopped = event("broker.stopped", "info", connections_outstanding=connections,
                            posts_outstanding=posts, resolutions_outstanding=resolutions,
                            accepted=self.counters["accepted"], refused=self.counters["refused"],
                            tunnels_opened=self.counters["tunnels_opened"], bytes_up=self.counters["bytes_up"],
                            bytes_down=self.counters["bytes_down"], posts=self.counters["posts"])
            recorded = self.record(stopped, min(self.clock() + RECORD_WAIT, deadline))
        self.admission_closed = True
        self.loop.unwatch(self.wake[0])
        for fd in self.wake:
            os.close(fd)
        report["recorder_outstanding"] = False
        report["clean"] = connections == 0 and posts == 0 and resolutions == 0 and recorded
        return report


class BrokerStartError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code
