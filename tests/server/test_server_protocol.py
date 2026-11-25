"""The control protocol's black-box suite (docs/server-protocol.md): a
transport server as a process, driven by a fake controller over its private
stdio. Configuration, the artifact POST through its broker on loopback,
delivery through owned stand-ins for `scp` and `ssh` (found on `PATH`
like any trusted tool), revocation, violations and every stop. No network
beyond loopback, no real SSH, no provider. Bodies are built here, not by
the server's own codec.

The server under test: AGENTBOX_SERVER_UNDER_TEST (a path: an installed
`PREFIX/bin/agentbox-server`), else this checkout's (support.server()).

  cargo build --bin agentbox-relay
  python3 -I -B -W error::ResourceWarning -m unittest discover -s tests/server -t . -p test_server_protocol.py

Each case has its own directory under TMPDIR (use a short private one),
removed on success and kept, with the server's stderr, on failure.
"""
import hashlib
import itertools
import json
import os
import queue
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from tests import support

NONCE = "0123456789abcdef0123456789abcdef"
SESSION = "s-1"
WAIT = 10.0
# The server's own shutdown ceiling and the scheduling allowance.
EXIT_LIMIT = 5.0 + 2.0
_CASES = itertools.count()


def program():
    return os.environ.get("AGENTBOX_SERVER_UNDER_TEST") or support.server()


# The artifact POST's bodies (acquisitions/contracts/artifacts/post-v1), canonical.

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def request_sha256(client):
    return sha256(('{"client":"%s","handler":"npm","operation":"install","args":{}}' % client).encode())


def submit(client, args="{}"):
    return ('{"v":1,"type":"submit","session":"%s","client":"%s","handler":"npm","operation":"install",'
            '"args":%s}' % (NONCE, client, args)).encode()


def result_claim(client, request, artifact):
    return ('{"v":1,"type":"result","session":"%s","client":"%s","request":"%s","request_sha256":"%s",'
            '"sha256":"%s","status":"applied"}' % (NONCE, client, request, request_sha256(client),
                                                   sha256(artifact))).encode()


def ready_body(client, request, artifact):
    return ('{"v":1,"type":"ready","session":"%s","client":"%s","request":"%s","request_sha256":"%s",'
            '"handler":"npm","operation":"install","size":%d,"sha256":"%s","metadata":{}}'
            % (NONCE, client, request, request_sha256(client), len(artifact), sha256(artifact)))


def closed_body(client, request, outcome):
    reason = ',"reason":"delivery_failed"' if outcome == "denied" else ""
    return ('{"v":1,"type":"closed","session":"%s","client":"%s","request":"%s","request_sha256":"%s",'
            '"handler":"npm","outcome":"%s"%s}' % (NONCE, client, request, request_sha256(client), outcome, reason))


class Case:
    """One case's directory: stand-in tools, spool, guest tree, logs."""

    def __init__(self, test, name):
        self.dir = os.path.join(tempfile.gettempdir(), f"srv-{name}-{os.getpid()}-{next(_CASES)}")
        shutil.rmtree(self.dir, True)
        os.mkdir(self.dir)
        test.addCleanup(self._cleanup, test)
        for sub in ("bin", "spool", "guest"):
            os.mkdir(self.path(sub))
        os.chmod(self.path("spool"), 0o700)
        d = self.dir
        self.tool("ssh", "exit 1\n")
        self.tool("scp", f"""for f in /proc/$$/fd/*; do printf '%s %s\\n' "${{f##*/}}" "$(readlink "$f")"; done > {d}/scp-fds
printf '%s\\n' "$@" > {d}/scp-argv
for last; do :; done
dest={d}/guest${{last#*:}}
mode=ok; arg=
[ -e {d}/scp-mode ] && read -r mode arg other < {d}/scp-mode
case "$mode" in
hang) sleep 1000 & echo "$$ $!" > {d}/scp-pids; wait; exit 1 ;;
fail) exit 7 ;;
replace) mv "$other" "$arg" ;;
esac
mkdir -p "${{dest%/*}}" && cat /dev/fd/3 > "$dest"
""")

    def _cleanup(self, test):
        outcome = getattr(test, "_outcome", None)
        failed = outcome is not None and not outcome.success
        if failed:
            print(f"kept {self.dir}")
        else:
            shutil.rmtree(self.dir, True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def tool(self, name, body):
        path = self.path(f"bin/{name}")
        with open(path, "w") as stream:
            stream.write(f"#!/bin/sh\n{body}")
        os.chmod(path, 0o755)

    def spool(self, name, data):
        path = self.path(f"spool/{name}")
        with open(path, "wb") as stream:
            stream.write(data)
        os.chmod(path, 0o600)
        return path

    def configure(self, post, delivery):
        delivery = {"route": {"endpoint": {"host": "127.0.0.1", "port": 2222}}, "user": "agent",
                    "identity": self.path("id"), "known_hosts": self.path("known"), "host_key_alias": "jail",
                    "work_dir": "/work", "spool_root": self.path("spool")} if delivery else None
        return {"type": "configure", "id": 1, "v": 1, "session": SESSION, "run_id": f"r-{NONCE}",
                "execution_id": f"e-{NONCE}", "lifetime_ms": 600000,
                "policy": {"schema": "agentbox.network-policy.v1", "mode": "custom", "replace_model_only": True,
                           "destinations": [{"exact": "example.com", "ports": [443]}]},
                "post": {"nonce": NONCE, "delivery": delivery} if post else None}

    def await_file(self, name):
        end = time.monotonic() + WAIT
        while True:
            try:
                with open(self.path(name)) as stream:
                    text = stream.read()
                if text.endswith("\n"):
                    return text
            except FileNotFoundError:
                pass
            assert time.monotonic() < end, f"no {name}"
            time.sleep(0.01)

    def await_gone(self, name):
        pids = self.await_file(name).split()
        end = time.monotonic() + WAIT
        for pid in pids:
            while pid_alive(pid):
                assert time.monotonic() < end, f"pid {pid} of {name} survived"
                time.sleep(0.01)


def pid_alive(pid):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            return ") Z " not in stream.read()
    except OSError:
        return False


def spawn(case):
    stderr = open(case.path("stderr"), "wb")
    try:
        return subprocess.Popen([program()], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr,
                                env={"PATH": f"{case.path('bin')}:/usr/bin:/bin"})
    finally:
        stderr.close()


def read_message(stream):
    prefix = stream.read(4)
    if len(prefix) < 4:
        return None
    body = stream.read(struct.unpack(">I", prefix)[0])
    return json.loads(body)


def frame(value):
    body = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack(">I", len(body)) + body


class Server:
    """The fake controller: the server's stdin, its framed stdout (read by
    a thread), its stderr in the case directory."""

    def __init__(self, test, case):
        self.test = test
        self.proc = spawn(case)
        test.addCleanup(self._end)
        self.pipes = [os.fstat(self.proc.stdin.fileno()).st_ino, os.fstat(self.proc.stdout.fileno()).st_ino]
        self.messages = queue.Queue()
        self.events = []
        self.pending = []
        self.next = 1
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        while True:
            message = read_message(self.proc.stdout)
            if message is None:
                self.messages.put(None)
                return
            self.messages.put(message)

    def _end(self):
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait()
        for stream in (self.proc.stdin, self.proc.stdout):
            try:
                stream.close()
            except OSError:
                pass

    @classmethod
    def ready(cls, test, case, post, delivery):
        server = cls(test, case)
        server.send(case.configure(post, delivery))
        ready = server.expect("ready")
        test.assertEqual((ready["session"], ready["v"], ready["post"], ready["delivery"]),
                         (SESSION, 1, post, delivery))
        return server, (ready["broker"]["host"], ready["broker"]["port"])

    def raw(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def send(self, value):
        if isinstance(value.get("id"), int):
            self.next = value["id"] + 1
        self.raw(frame(value))

    def command(self, kind, **fields):
        ident = self.next
        self.send(dict({"type": kind, "id": ident}, **fields))
        return ident

    def _get(self, timeout):
        try:
            return self.messages.get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None

    def message(self):
        """The next message other than an event, within WAIT."""
        if self.pending:
            return self.pending.pop(0)
        end = time.monotonic() + WAIT
        while True:
            message = self._get(end - time.monotonic())
            if message is None:
                return None
            if message["type"] == "event":
                self.events.append(message)
            else:
                return message

    def expect(self, kind):
        message = self.message()
        self.test.assertIsNotNone(message, f"no {kind}")
        self.test.assertEqual(message["type"], kind, message)
        return message

    def result(self, ident):
        """Command `ident`'s result; other messages stay pending, in order."""
        for at, message in enumerate(self.pending):
            if message["type"] == "result" and message["id"] == ident:
                return self.pending.pop(at)
        passed = []
        end = time.monotonic() + WAIT
        while True:
            message = self._get(end - time.monotonic())
            self.test.assertIsNotNone(message, "no result")
            if message["type"] == "event":
                self.events.append(message)
            elif message["type"] == "result" and message["id"] == ident:
                break
            else:
                self.test.assertNotEqual(message["type"], "stopped", message)
                passed.append(message)
        self.pending.extend(passed)
        return message

    def ok(self, ident):
        result = self.result(ident)
        self.test.assertIs(result["ok"], True, result)

    def refused(self, ident, code):
        result = self.result(ident)
        self.test.assertEqual((result["ok"], result["code"]), (False, code), result)

    def close(self):
        self.proc.stdin.close()
        return time.monotonic()

    def exit(self, since, limit):
        try:
            code = self.proc.wait(max(0.0, since + limit - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.test.fail(f"no exit within {limit}")
        self.test.assertLess(time.monotonic() - since, limit)
        return code

    def stopped(self, since, reason):
        """`stopped` with `reason`, then the exit; nothing after it."""
        while True:
            message = self.message()
            self.test.assertIsNotNone(message, "no stopped")
            if message["type"] == "stopped":
                break
        self.test.assertEqual(message["reason"], reason, message)
        code = self.exit(since, EXIT_LIMIT)
        self.test.assertIsNone(self._get(WAIT), "output after stopped")
        return message, code


def post(address, body):
    """A guest client's POST: written whole, its write side kept open."""
    stream = socket.create_connection(address, timeout=WAIT)
    head = ("POST /agentbox/v1/request HTTP/1.1\r\nHost: agentbox\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    stream.sendall(head + body)
    return stream


def reply(stream):
    """Everything until the server closes."""
    data = b""
    with stream:
        while True:
            try:
                more = stream.recv(65536)
            except (ConnectionResetError, TimeoutError):
                break
            if not more:
                break
            data += more
    return data.decode("utf-8", "replace")


class Protocol(unittest.TestCase):

    def submitted(self, server, address, client):
        """A submit through the broker, seen by the controller: its exchange."""
        stream = post(address, submit(client))
        request = server.expect("post.request")
        self.assertIs(request["replay"], False)
        self.assertEqual(request["body"].encode(), submit(client))
        self.assertEqual(request["bytes"], len(request["body"]))
        return stream, request["exchange"]

    def deliver(self, server, exchange, request, name, artifact):
        return server.command("deliver", exchange=exchange, request=request, deadline_ms=60000, name=name,
                              size=len(artifact), sha256=sha256(artifact))

    def close_request(self, server, exchange, client, request, outcome):
        """The controller's end of a failed request: `closed`, answered to
        the guest, then the request revoked."""
        body = closed_body(client, request, outcome)
        server.ok(server.command("respond", exchange=exchange, body=body))
        self.assertEqual(server.expect("post.ended")["exchange"], exchange)
        server.ok(server.command("revoke", request=request))
        return body

    def uploaded(self, case, request):
        with open(case.path(f"guest/work/.agentbox-requests/{NONCE}-{request}.artifact"), "rb") as stream:
            return stream.read()

    def test_a_request_is_delivered_and_answered_end_to_end(self):
        case = Case(self, "e2e")
        server, address = Server.ready(self, case, True, True)
        stream, exchange = self.submitted(server, address, "c-1")
        artifact = b"artifact bytes\n"
        case.spool("a-1", artifact)
        # No ready before the upload completes.
        early = server.command("respond", exchange=exchange, body=ready_body("c-1", "q-1", artifact))
        server.refused(early, "ready_unbound")
        server.ok(self.deliver(server, exchange, "q-1", "a-1", artifact))
        self.assertEqual(self.uploaded(case, "q-1"), artifact)
        # The fixed profile: pinned host key, no configuration, the source
        # one argument after `--`.
        with open(case.path("scp-argv")) as stream_:
            argv = stream_.read().splitlines()
        for option in ("StrictHostKeyChecking=yes", "HostKeyAlias=jail", "User=agent"):
            self.assertIn(option, argv)
        self.assertEqual(argv[-3:], ["--", "/dev/fd/3", f"127.0.0.1:/work/.agentbox-requests/{NONCE}-q-1.artifact"])
        # The upload saw the artifact on fd 3, never a control pipe.
        with open(case.path("scp-fds")) as stream_:
            fds = stream_.read()
        for pipe in server.pipes:
            self.assertNotIn(f"pipe:[{pipe}]", fds)
        fd3 = next(line for line in fds.splitlines() if line.startswith("3 "))
        self.assertTrue(fd3.endswith("/spool/a-1"), fds)
        # A ready for another artifact or request, then the right one.
        server.refused(server.command("respond", exchange=exchange, body=ready_body("c-1", "q-1", b"other")),
                       "ready_unbound")
        server.refused(server.command("respond", exchange=exchange, body=ready_body("c-1", "q-2", artifact)),
                       "ready_unbound")
        server.ok(server.command("respond", exchange=exchange, body=ready_body("c-1", "q-1", artifact)))
        answer = reply(stream)
        self.assertTrue(answer.startswith("HTTP/1.1 200 OK\r\n"), answer)
        self.assertTrue(answer.endswith(ready_body("c-1", "q-1", artifact)))
        self.assertEqual(server.expect("post.ended"), {"type": "post.ended", "exchange": exchange, "end": "written"})
        # The guest's result claim, answered `recorded`.
        stream = post(address, result_claim("c-1", "q-1", artifact))
        claim = server.expect("post.request")
        body = closed_body("c-1", "q-1", "recorded")
        server.ok(server.command("respond", exchange=claim["exchange"], body=body))
        self.assertTrue(reply(stream).startswith("HTTP/1.1 200 OK\r\n"))
        server.expect("post.ended")
        # A stale exchange; then the request retired, once.
        server.refused(server.command("respond", exchange=exchange, body=body), "stale")
        server.ok(server.command("revoke", request="q-1"))
        server.refused(server.command("revoke", request="q-1"), "not_active")
        stopped, code = server.stopped(server.close(), "control_eof")
        self.assertIs(stopped["clean"], True, stopped)
        self.assertEqual(code, 0)
        self.assertTrue(any(event["event"] == "broker.started" for event in server.events))

    def test_delivery_refuses_bad_sources(self):
        """Opened beneath the spool root, without following a link or
        blocking on a FIFO; a regular file of the declared size."""
        case = Case(self, "sources")
        server, address = Server.ready(self, case, True, True)
        good = b"abc"
        spool = case.path("spool")
        case.spool("big", b"abcd")
        with open(case.path("outside"), "wb") as stream:
            stream.write(good)
        os.symlink(case.path("outside"), os.path.join(spool, "symlink"))
        os.mkfifo(os.path.join(spool, "fifo"), 0o600)
        os.mkdir(os.path.join(spool, "dir"))
        for n, (name, claimed, code) in enumerate((("missing", good, "source_missing"),
                                                   ("symlink", good, "source_invalid"),
                                                   ("fifo", good, "source_invalid"),
                                                   ("dir", good, "source_invalid"),
                                                   ("big", good, "size_mismatch"))):
            client, request = f"c-{n}", f"q-{n}"
            stream, exchange = self.submitted(server, address, client)
            server.refused(self.deliver(server, exchange, request, name, claimed), code)
            body = self.close_request(server, exchange, client, request, "denied")
            self.assertTrue(reply(stream).endswith(body))
        self.assertFalse(os.path.exists(case.path("scp-argv")), "an upload ran")
        server.stopped(server.close(), "control_eof")

    def test_delivery_uses_the_opened_descriptor_and_reports_failures(self):
        """The descriptor opened at `deliver`, never the name again; then a
        busy, a failed and an unconfigured delivery."""
        case = Case(self, "failures")
        server, address = Server.ready(self, case, True, True)
        artifact = b"content"
        source = case.spool("m", artifact)
        with open(case.path("other"), "wb") as stream:
            stream.write(b"replacement")
        with open(case.path("scp-mode"), "w") as stream:
            stream.write(f"replace {source} {case.path('other')}\n")
        stream, exchange = self.submitted(server, address, "c-1")
        server.ok(self.deliver(server, exchange, "q-1", "m", artifact))
        self.assertEqual(self.uploaded(case, "q-1"), artifact)
        with open(source, "rb") as replaced:
            self.assertEqual(replaced.read(), b"replacement")
        # One delivery per request.
        server.refused(self.deliver(server, exchange, "q-1", "m", artifact), "busy")
        server.ok(server.command("respond", exchange=exchange, body=ready_body("c-1", "q-1", artifact)))
        self.assertTrue(reply(stream).endswith(ready_body("c-1", "q-1", artifact)))
        server.expect("post.ended")
        server.ok(server.command("revoke", request="q-1"))
        with open(case.path("scp-mode"), "w") as stream:
            stream.write("fail\n")
        case.spool("f", artifact)
        stream, exchange = self.submitted(server, address, "c-2")
        server.refused(self.deliver(server, exchange, "q-2", "f", artifact), "transfer_failed")
        server.refused(server.command("respond", exchange=exchange, body=ready_body("c-2", "q-2", artifact)),
                       "ready_unbound")
        self.close_request(server, exchange, "c-2", "q-2", "denied")
        stream.close()
        server.stopped(server.close(), "control_eof")
        # POST without delivery.
        case = Case(self, "no-delivery")
        server, address = Server.ready(self, case, True, False)
        stream, exchange = self.submitted(server, address, "c-1")
        server.refused(self.deliver(server, exchange, "q-1", "x", artifact), "delivery_unconfigured")
        server.stopped(server.close(), "control_eof")
        stream.close()

    def test_revocation_and_end_of_input_cancel_a_running_upload(self):
        """Each kills a running upload's whole group promptly; no ready can
        follow."""
        for end_of_input in (False, True):
            case = Case(self, "cancel")
            with open(case.path("scp-mode"), "w") as stream:
                stream.write("hang\n")
            artifact = b"slow"
            case.spool("h", artifact)
            server, address = Server.ready(self, case, True, True)
            stream, exchange = self.submitted(server, address, "c-1")
            ident = self.deliver(server, exchange, "q-1", "h", artifact)
            case.await_file("scp-pids")
            if end_of_input:
                stopped, _ = server.stopped(server.close(), "control_eof")
                self.assertIs(stopped["delivery_outstanding"], False, stopped)
                self.assertFalse(reply(stream).startswith("HTTP/1.1 200"))
            else:
                server.ok(server.command("revoke", request="q-1"))
                server.refused(ident, "cancelled")
                server.refused(server.command("respond", exchange=exchange,
                                              body=ready_body("c-1", "q-1", artifact)), "ready_unbound")
                server.ok(server.command("respond", exchange=exchange, body=closed_body("c-1", "q-1", "cancelled")))
                self.assertTrue(reply(stream).endswith(closed_body("c-1", "q-1", "cancelled")))
            case.await_gone("scp-pids")

    def test_end_of_input_revokes_a_waiting_post(self):
        case = Case(self, "eof-post")
        server, address = Server.ready(self, case, True, False)
        stream, _ = self.submitted(server, address, "c-1")
        stopped, code = server.stopped(server.close(), "control_eof")
        self.assertIs(stopped["clean"], True, stopped)
        self.assertEqual(code, 0)
        answer = reply(stream)
        self.assertFalse(answer.startswith("HTTP/1.1 200"), answer)
        # Nothing listens any more.
        with self.assertRaises(OSError):
            socket.create_connection(address, timeout=WAIT).close()

    def test_terminating_signals_stop_the_server(self):
        """SIGTERM, SIGINT and SIGHUP stop as the end of input does."""
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            case = Case(self, "signal")
            server, address = Server.ready(self, case, True, False)
            stream, _ = self.submitted(server, address, "c-1")
            since = time.monotonic()
            server.proc.send_signal(number)
            _, code = server.stopped(since, "signal")
            self.assertEqual(code, 1)
            self.assertFalse(reply(stream).startswith("HTTP/1.1 200"))

    def test_violations_are_fatal(self):
        """Whatever the phase; reason "" is a truncated frame, then the end
        of input."""
        case = Case(self, "violations")
        violations = (
            (lambda s: s.raw(b"\0\0\0\0"), "control_oversize", False),
            (lambda s: s.raw(b"\x7f\0\0\0"), "control_oversize", False),
            (lambda s: s.raw(b"\0\0\0\x02["), "", False),
            (lambda s: s.raw(b"\0\0\0\x02[]"), "control_malformed", False),
            (lambda s: s.command("revoke", request="q-1"), "control_order", False),
            (lambda s: s.command("shutdown"), "control_unknown", True),
            (lambda s: s.command("revoke", request="q-1", extra=1), "control_malformed", True),
            (lambda s: s.send({"type": "revoke", "id": 1, "request": "q-1"}), "control_order", True),
            (lambda s: s.command("deliver", exchange=1, request="q-1", deadline_ms=1, name="../x", size=1,
                                 sha256="a" * 64), "control_malformed", True),
        )
        for violate, reason, configured in violations:
            server = Server.ready(self, case, False, False)[0] if configured else Server(self, case)
            violate(server)
            since = time.monotonic()
            if not reason:
                server.close()
                _, code = server.stopped(since, "control_truncated")
            else:
                _, code = server.stopped(since, reason)
            self.assertEqual(code, 1, reason)
        # A second configure.
        server, _ = Server.ready(self, case, False, False)
        again = case.configure(False, False)
        again["id"] = 2
        server.send(again)
        server.stopped(time.monotonic(), "control_order")
        # Session grants: bounded CONNECT authorities, never unspecified.
        for grants, reason in ((["0.0.0.0:22"], "configure_invalid"), (["[::]:22"], "configure_invalid"),
                               (["nas.lan"], "configure_invalid"), ("nas.lan:445", "control_malformed")):
            server = Server(self, case)
            server.send(dict(case.configure(False, False), grants=grants))
            _, code = server.stopped(time.monotonic(), reason)
            self.assertEqual(code, 1, grants)
        server = Server(self, case)
        server.send(dict(case.configure(False, False), grants=["nas.lan:445", "[fd00::1]:22", "127.0.0.1:8080"]))
        server.expect("ready")
        server.stopped(server.close(), "control_eof")

    def test_startup_failures_and_the_lifetime_stop_the_server(self):
        # A spool root that is a link is never followed.
        case = Case(self, "startup-failure")
        os.rename(case.path("spool"), case.path("real"))
        os.symlink(case.path("real"), case.path("spool"))
        server = Server(self, case)
        server.send(case.configure(True, True))
        _, code = server.stopped(time.monotonic(), "spool_invalid")
        self.assertEqual(code, 1)
        case = Case(self, "lifetime")
        server = Server(self, case)
        configure = case.configure(True, False)
        configure["lifetime_ms"] = 1000
        server.send(configure)
        server.expect("ready")
        _, code = server.stopped(time.monotonic(), "lifetime")
        self.assertEqual(code, 1)

    def test_a_null_lifetime_never_expires_and_eof_still_stops(self):
        """An untimed owner's session: no cutoff while the controller lives,
        with or without POST; the end of input still stops it, bounded."""
        case = Case(self, "untimed")
        server = Server(self, case)
        configure = case.configure(False, False)
        configure["lifetime_ms"] = None
        server.send(configure)
        ready = server.expect("ready")
        self.assertIs(ready["post"], False)
        address = (ready["broker"]["host"], ready["broker"]["port"])
        time.sleep(2.5)
        self.assertIsNone(server.proc.poll(), "untimed server exited")
        socket.create_connection(address, timeout=WAIT).close()
        stopped, code = server.stopped(server.close(), "control_eof")
        self.assertEqual((stopped["clean"], code), (True, 0), stopped)
        # With POST and delivery (a serving owner's acquisitions).
        case = Case(self, "untimed-post")
        server = Server(self, case)
        configure = case.configure(True, True)
        configure["lifetime_ms"] = None
        server.send(configure)
        ready = server.expect("ready")
        self.assertEqual((ready["post"], ready["delivery"]), (True, True))
        address = (ready["broker"]["host"], ready["broker"]["port"])
        time.sleep(1.5)
        self.assertIsNone(server.proc.poll(), "untimed server exited")
        stream, exchange = self.submitted(server, address, "c-1")
        artifact = b"untimed artifact\n"
        case.spool("a-1", artifact)
        server.ok(self.deliver(server, exchange, "q-1", "a-1", artifact))
        self.assertEqual(self.uploaded(case, "q-1"), artifact)
        server.ok(server.command("respond", exchange=exchange, body=ready_body("c-1", "q-1", artifact)))
        self.assertTrue(reply(stream).startswith("HTTP/1.1 200 OK\r\n"))
        server.expect("post.ended")
        server.ok(server.command("revoke", request="q-1"))
        stopped, code = server.stopped(server.close(), "control_eof")
        self.assertEqual((stopped["clean"], code), (True, 0), stopped)

    def test_the_broker_refuses_through_the_server(self):
        """POST without an ingress, a policy denial, an address literal;
        nothing resolved or dialed, only events reach the controller."""
        case = Case(self, "refusals")
        server, address = Server.ready(self, case, False, False)
        answer = reply(post(address, submit("c-1")))
        self.assertTrue(answer.startswith("HTTP/1.1 405 "), answer)
        for authority in ("denied.invalid:443", "127.0.0.1:443", "example.com:80"):
            stream = socket.create_connection(address, timeout=WAIT)
            stream.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
            answer = reply(stream)
            self.assertTrue(answer.startswith("HTTP/1.1 403 "), (authority, answer))
        while True:
            message = server._get(0.2)
            if message is None:
                break
            self.assertEqual(message["type"], "event", message)
        server.stopped(server.close(), "control_eof")

    def configured(self, case):
        """Spawned and configured by hand (POST, no delivery): the process
        and the broker's address."""
        proc = spawn(case)
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        self.addCleanup(proc.wait)
        proc.stdin.write(frame(case.configure(True, False)))
        proc.stdin.flush()
        while True:
            message = read_message(proc.stdout)
            if message["type"] == "ready":
                return proc, ("127.0.0.1", message["broker"]["port"])

    def assertFailedClosed(self, case, proc, since, limit, streams):
        try:
            code = proc.wait(max(0.0, since + limit - time.monotonic()))
        except subprocess.TimeoutExpired:
            self.fail(f"no exit within {limit}")
        self.assertEqual(code, 1)
        for stream in streams:
            self.assertFalse(reply(stream).startswith("HTTP/1.1 200"))
        with open(case.path("stderr")) as stream:
            stderr = stream.read()
        self.assertTrue("output_failed" in stderr or "broker_failed" in stderr, stderr)

    def test_lost_output_fails_closed(self):
        """Lost output stops the server and revokes its POSTs."""
        case = Case(self, "closed-output")
        proc, address = self.configured(case)
        proc.stdout.close()
        stream = post(address, submit("c-1"))
        self.assertFailedClosed(case, proc, time.monotonic(), EXIT_LIMIT, [stream])
        proc.stdin.close()

    def test_stalled_output_fails_closed(self):
        """A controller that stops reading: the pipe fills, the write
        times out."""
        case = Case(self, "stalled-output")
        proc, address = self.configured(case)
        since = time.monotonic()
        streams = [post(address, submit(f"c-{n}", '{"x":"%s"}' % ("y" * 60000))) for n in range(2)]
        # The write's own wait, then the shutdown.
        self.assertFailedClosed(case, proc, since, 2.0 + EXIT_LIMIT, streams)
        proc.stdin.close()
        proc.stdout.close()

    def test_the_body_bound_is_the_codec_bound(self):
        """64 KiB: a body one byte over is refused before the controller
        sees it (acquisitions/contracts/artifacts/post-v1)."""
        case = Case(self, "bound")
        server, address = Server.ready(self, case, True, False)
        filler = 65536 - len(submit("c-1", '{"x":""}'))
        stream = post(address, submit("c-1", '{"x":"%s"}' % ("y" * filler)))
        request = server.expect("post.request")
        self.assertEqual(request["bytes"], 65536)
        stream.close()
        stream = post(address, submit("c-2", '{"x":"%s"}' % ("y" * (filler + 1))))
        self.assertTrue(reply(stream).startswith("HTTP/1.1 413 "))
        server.stopped(server.close(), "control_eof")


if __name__ == "__main__":
    unittest.main()
