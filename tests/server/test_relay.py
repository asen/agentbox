"""The real agentbox-relay child through its launcher (relay.py), over
loopback TCP: malformed invocations, the handoff and START as the
ownership boundary (exactly one answer to the client), the 200,
half-close, revocation, its parent's death before and after START, its own
death by signal, its descriptor table, sibling isolation and bounded
memory.

  cargo build --bin agentbox-relay
  python3 -I -B -m unittest discover -s tests/server -t . -p test_relay.py

AGENTBOX_RELAY_STRESS=1 adds more than 2 GiB through concurrent children.
"""
import os
import select
import signal
import socket
import subprocess
import sys
import threading
import time
import unittest

from tests import support  # first: puts SRC on the path
from agentbox_server import relay
from agentbox_server.relay import Relay, RelayError

REFUSAL = b"HTTP/1.1 503 Service Unavailable\r\n\r\n"

WAIT = 5.0
ESTABLISHED = b"HTTP/1.1 200 Connection Established\r\n\r\n"
PARENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay_parent.py")
PERIOD = 251
CHUNK = 1 << 20
PATTERN = bytes(i % PERIOD for i in range(CHUNK + PERIOD))


def tcp():
    """Both ends of one loopback connection: (outside, to hand over)."""
    with socket.create_server(("127.0.0.1", 0)) as listener:
        outside = socket.create_connection(listener.getsockname())
        inside, _ = listener.accept()
    outside.settimeout(WAIT)
    return outside, inside


def exact(sock, count):
    data = b""
    while len(data) < count:
        more = sock.recv(count - len(data))
        if not more:
            break
        data += more
    return data


def read_all(sock):
    """Everything until the peer ends or resets."""
    data = b""
    while True:
        try:
            more = sock.recv(65536)
        except ConnectionResetError:
            return data
        if not more:
            return data
        data += more


def fill(sock):
    """Writes until the peer's and our buffers are full."""
    sock.setblocking(False)
    started, blocked = time.monotonic(), 0
    while blocked < 10:
        assert time.monotonic() - started < WAIT
        try:
            sock.send(b"x" * 65536)
            blocked = 0
        except BlockingIOError:
            blocked += 1
            time.sleep(0.01)
    sock.settimeout(WAIT)


def exited_within(pid, timeout):
    """Whether `pid`, not our child, exits within `timeout` seconds."""
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError:
        return True
    try:
        return bool(select.select([pidfd], [], [], timeout)[0])
    finally:
        os.close(pidfd)


def relay_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def socket_inodes(pid):
    targets = [os.readlink(f"/proc/{pid}/fd/{fd}") for fd in os.listdir(f"/proc/{pid}/fd")]
    return [target for target in targets if target.startswith("socket:")]


def peak_rss(pid):
    with open(f"/proc/{pid}/status", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("VmHWM:"):
                return int(line.split()[1]) * 1024
    raise AssertionError("no VmHWM")


def send_pattern(sock, length, errors):
    try:
        view = memoryview(PATTERN)
        sent = 0
        while sent < length:
            n = min(length - sent, CHUNK)
            at = sent % PERIOD
            sock.sendall(view[at:at + n])
            sent += n
    except Exception as error:  # noqa: BLE001 - reported by the test
        errors.append(error)


def check_pattern(sock, length, counts, errors):
    try:
        buf = bytearray(CHUNK)
        view = memoryview(buf)
        seen = 0
        while seen < length:
            n = sock.recv_into(view, min(CHUNK, length - seen))
            if n == 0:
                break
            at = seen % PERIOD
            if buf[:n] != PATTERN[at:at + n]:
                raise AssertionError(f"pattern broken at {seen}")
            seen += n
        counts.append(seen)
    except Exception as error:  # noqa: BLE001 - reported by the test
        errors.append(error)


class Tunnel:
    """Outside ends of a started child's two sockets."""

    def __init__(self, prefix=b"", idle=5, lifetime=60, before=None):
        self.client, client_in = tcp()
        self.upstream, upstream_in = tcp()
        if before:
            self.upstream.sendall(before)
        self.relay = Relay.start(support.relay(), client_in, upstream_in, prefix, idle, lifetime)
        # Handed over: none of our copies is left.
        assert client_in.fileno() == -1 and upstream_in.fileno() == -1

    def opened(self):
        return exact(self.client, len(ESTABLISHED)) == ESTABLISHED

    def close(self):
        self.client.close()
        self.upstream.close()
        if self.relay.popen.returncode is None:
            self.relay.kill()
        if self.relay.control.fileno() != -1:
            self.relay.finish(WAIT)


class RelayTest(unittest.TestCase):

    def tunnel(self, **kwargs):
        tunnel = Tunnel(**kwargs)
        self.addCleanup(tunnel.close)
        return tunnel

    def test_the_200_then_both_streams_with_half_close(self):
        t = self.tunnel(prefix=b"early", before=b"banner")
        self.assertTrue(t.opened())
        # A server-first upstream's bytes come after the 200, never before.
        self.assertEqual(exact(t.client, 6), b"banner")
        t.client.sendall(b" and more")
        t.client.shutdown(socket.SHUT_WR)
        self.assertEqual(read_all(t.upstream), b"early and more")
        t.upstream.sendall(b" bye")
        t.upstream.shutdown(socket.SHUT_WR)
        self.assertEqual(read_all(t.client), b" bye")
        self.assertEqual(t.relay.finish(WAIT), 0)
        self.assertTrue(t.relay.opened)
        self.assertEqual(t.relay.result, ("closed", "completed", 14, 10))

    def test_a_revocation_closes_an_open_tunnel(self):
        for reason in relay.REVOKE:
            t = self.tunnel()
            self.assertTrue(t.opened())
            t.relay.revoke(reason)
            self.assertEqual(read_all(t.client), b"")
            self.assertEqual(read_all(t.upstream), b"")
            self.assertEqual(t.relay.finish(WAIT), 0)
            self.assertEqual(t.relay.result, ("closed", reason, 0, 0))

    def test_an_idle_tunnel_ends(self):
        t = self.tunnel(idle=0.2)
        self.assertTrue(t.opened())
        self.assertEqual(read_all(t.client), b"")
        self.assertEqual(t.relay.finish(WAIT), 0)
        self.assertEqual(t.relay.result, ("closed", "idle_timeout", 0, 0))

    def test_a_failed_spawn_leaves_the_client_to_the_caller(self):
        client, client_in = tcp()
        upstream, upstream_in = tcp()
        with client, client_in, upstream, upstream_in:
            with self.assertRaises(RelayError) as raised:
                Relay.start("/nonexistent/agentbox-relay", client_in, upstream_in)
            self.assertEqual(raised.exception.code, "spawn_failed")
            # Still ours: the caller refuses it.
            client_in.sendall(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
            self.assertTrue(exact(client, 12).startswith(b"HTTP/1.1 503"))
            with self.assertRaises(RelayError):
                Relay.start(support.relay(), client_in, upstream_in, prefix=b"x" * (relay.MAX_PREFIX + 1))
            self.assertNotEqual(client_in.fileno(), -1)

    def run_child(self, args, pass_fds=()):
        """The binary with `args`, our control end: (relay, our end)."""
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with child:
            popen = subprocess.Popen([support.relay()] + [str(arg) for arg in args], stdin=child.fileno(),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={}, cwd="/",
                                     close_fds=True, pass_fds=pass_fds, start_new_session=True)
        spawned = Relay(popen, parent)
        self.addCleanup(lambda: spawned.control.fileno() == -1 or spawned.finish(0))
        return spawned, parent

    def assertUntouched(self, outside, inside):
        """Our copy still answers alone: the child wrote and shut nothing."""
        inside.sendall(REFUSAL)
        inside.close()
        self.assertEqual(read_all(outside), REFUSAL)

    def test_a_malformed_invocation_adopts_and_touches_nothing(self):
        client, client_in = tcp()
        upstream, upstream_in = tcp()
        listener = socket.create_server(("127.0.0.1", 0))
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.connect(("127.0.0.1", 9))
        read_end, write_end = os.pipe()
        self.addCleanup(os.close, read_end)
        self.addCleanup(os.close, write_end)
        with client, upstream, listener, udp:
            c, u = client_in.fileno(), upstream_in.fileno()
            closed = 1000
            while closed in (c, u) or relay_open(closed):
                closed += 1
            cases = [
                ([], ()), ([c], (c,)), ([c, u, u], (c, u)), ([f"{c}x", u], (c, u)), ([f"+{c}", u], (c, u)),
                ([f"0{c}", u], (c, u)), ([c, 1], (c,)), ([0, u], (u,)), ([c, c], (c,)), ([c, closed], (c,)),
                ([c, read_end], (c, read_end)), ([c, listener.fileno()], (c, listener.fileno())),
                ([c, udp.fileno()], (c, udp.fileno())), ([str(1 << 40), u], (u,)),
            ]
            for args, fds in cases:
                spawned, parent = self.run_child(args, fds)
                self.assertEqual(spawned.finish(WAIT), 2, args)
                self.assertEqual(spawned.result, ("refused", "invocation_invalid"), args)
            self.assertUntouched(client, client_in)
            self.assertUntouched(upstream, upstream_in)

    def test_before_start_the_child_only_drops_the_sockets(self):
        frame = relay.frame(b"pre", 1, 1)
        for name, data, shut, code, result in (
                ("invalid frame", b"XXXX" + frame[4:] + relay.START, False, 2, ("refused", "handoff_invalid")),
                ("a revocation byte for START", frame + b"S", False, 2, ("refused", "handoff_invalid")),
                ("nothing", b"", False, 2, ("refused", "handoff_timeout")),
                ("no START", frame, False, 2, ("refused", "handoff_timeout")),
                ("parent gone", frame[:5], True, 3, None)):
            client, client_in = tcp()
            upstream, upstream_in = tcp()
            with client, upstream:
                c, u = client_in.fileno(), upstream_in.fileno()
                spawned, parent = self.run_child([c, u], (c, u))
                parent.sendall(data)
                if shut:
                    parent.shutdown(socket.SHUT_WR)
                started = time.monotonic()
                self.assertEqual(spawned.finish(relay.HANDOFF_WAIT + WAIT), code, name)
                self.assertLess(time.monotonic() - started, relay.HANDOFF_WAIT + 1.5, name)
                self.assertEqual(spawned.result, result, name)
                # Ours alone again: exactly one answer, ours.
                self.assertUntouched(client, client_in)
                self.assertUntouched(upstream, upstream_in)

    def test_start_not_delivered_leaves_one_answer_to_the_caller(self):
        client, client_in = tcp()
        upstream, upstream_in = tcp()
        with client, upstream, client_in, upstream_in:
            spawned = Relay.spawn(support.relay(), client_in, upstream_in)
            spawned.kill()
            spawned.popen.wait()
            with self.assertRaises(RelayError) as raised:
                spawned.begin(relay.frame(b"", 1, 1) + relay.START, client_in, upstream_in)
            self.assertEqual((raised.exception.code, raised.exception.answerable), ("handoff_failed", True))
            self.assertEqual(spawned.control.fileno(), -1)
            self.assertUntouched(client, client_in)

    def test_a_stop_before_start_reaps_the_child_and_leaves_one_answer(self):
        """`go()` is read after the spawn and before each piece of the
        handoff, START last: an end there, from the first check (seen while
        it spawned) or from the last (the frame sent, START not), reaps the
        child and leaves the client the caller's."""
        for allowed in (0, 1):
            client, client_in = tcp()
            upstream, upstream_in = tcp()
            with client, upstream, client_in, upstream_in:
                checks = []

                def go():
                    checks.append(1)
                    return None if len(checks) <= allowed else "broker_stopped"
                with self.assertRaises(relay.RelayStopped) as raised:
                    Relay.start(support.relay(), client_in, upstream_in, b"pre", 1, 1, go=go)
                self.assertEqual((raised.exception.code, raised.exception.answerable), ("broker_stopped", True))
                self.assertEqual(len(checks), allowed + 1)
                self.assertUntouched(client, client_in)
                self.assertUntouched(upstream, upstream_in)

    def test_an_unknown_start_closes_unanswered(self):
        client, client_in = tcp()
        upstream, upstream_in = tcp()
        with client, upstream:
            spawned = Relay.spawn(support.relay(), client_in, upstream_in)
            calls = []

            def broken(data, deadline, go):
                # The frame out, then a failure that leaves START's fate
                # unknown.
                calls.append((data, go()))
                spawned.control.sendall(data[:-1])
                raise RuntimeError("unknown")
            spawned._send = broken
            data = relay.frame(b"", 1, 1) + relay.START
            with self.assertRaises(RelayError) as raised:
                spawned.begin(data, client_in, upstream_in)
            self.assertEqual(calls, [(data, None)], "the injected send ran, with the caller's go()")
            self.assertIsInstance(raised.exception.__context__, RuntimeError)
            self.assertEqual(str(raised.exception.__context__), "unknown")
            self.assertEqual((raised.exception.code, raised.exception.answerable), ("handoff_unknown", False))
            self.assertIsNotNone(spawned.popen.returncode, "reaped")
            self.assertEqual((client_in.fileno(), upstream_in.fileno()), (-1, -1))
            # Nobody answers: the client sees only its end.
            self.assertEqual(read_all(client), b"")
            self.assertEqual(read_all(upstream), b"")

    def test_a_parent_gone_before_start_leaves_no_answer(self):
        for mode in ("spawned", "partial"):
            client, client_in = tcp()
            upstream, upstream_in = tcp()
            argv = [sys.executable, "-I", "-B", PARENT, support.SRC, support.relay(),
                    str(client_in.fileno()), str(upstream_in.fileno()), mode]
            with client, upstream, subprocess.Popen(
                    argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    pass_fds=(client_in.fileno(), upstream_in.fileno())) as parent:
                client_in.close()
                upstream_in.close()
                pid = int(parent.stdout.readline())
                parent.send_signal(signal.SIGKILL)
                parent.wait()
                started = time.monotonic()
                self.assertTrue(exited_within(pid, 1.0), mode)
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertEqual(read_all(client), b"", mode)
                self.assertEqual(read_all(upstream), b"", mode)

    def test_a_killed_parent_ends_the_tunnel_though_both_peers_stall(self):
        for number in (signal.SIGKILL, signal.SIGTERM):
            client, client_in = tcp()
            upstream, upstream_in = tcp()
            argv = [sys.executable, "-I", "-B", PARENT, support.SRC, support.relay(),
                    str(client_in.fileno()), str(upstream_in.fileno()), "started"]
            with client, upstream, subprocess.Popen(
                    argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    pass_fds=(client_in.fileno(), upstream_in.fileno())) as parent:
                client_in.close()
                upstream_in.close()
                pid = int(parent.stdout.readline())
                self.assertEqual(exact(client, len(ESTABLISHED)), ESTABLISHED)
                fill(client)
                fill(upstream)
                parent.send_signal(number)
                parent.wait()
                started = time.monotonic()
                self.assertTrue(exited_within(pid, 1.0), number)
                self.assertLess(time.monotonic() - started, 1.0)
                # Both peers then see their end, after what was buffered.
                read_all(client)
                read_all(upstream)

    def test_a_killed_child_closes_both_peers_and_says_nothing(self):
        t = self.tunnel()
        self.assertTrue(t.opened())
        # Its "opened" follows the 200.
        deadline = time.monotonic() + WAIT
        while not t.relay.opened and not t.relay.read() and time.monotonic() < deadline:
            select.select([t.relay], [], [], 0.05)
        self.assertTrue(t.relay.opened)
        os.kill(t.relay.pid, signal.SIGKILL)
        self.assertEqual(read_all(t.client), b"")
        self.assertEqual(read_all(t.upstream), b"")
        self.assertEqual(t.relay.finish(WAIT), -signal.SIGKILL)
        self.assertIsNone(t.relay.result)

    def test_siblings_share_no_descriptors(self):
        first, second = self.tunnel(), self.tunnel()
        self.assertTrue(first.opened() and second.opened())
        # Each holds exactly: stdin (control), stdout and stderr on
        # /dev/null, its two adopted sockets and its control's duplicate.
        for t in (first, second):
            table = {int(fd): os.readlink(f"/proc/{t.relay.pid}/fd/{fd}")
                     for fd in os.listdir(f"/proc/{t.relay.pid}/fd")}
            self.assertEqual(len(table), 6, table)
            self.assertEqual((table[1], table[2]), ("/dev/null", "/dev/null"))
            self.assertTrue(table[0].startswith("socket:"))
        # Its control socket twice and its own two sockets, nothing of the
        # other's.
        held = [socket_inodes(t.relay.pid) for t in (first, second)]
        for inodes in held:
            self.assertEqual((len(inodes), len(set(inodes))), (4, 3))
        self.assertFalse(set(held[0]) & set(held[1]))
        os.kill(first.relay.pid, signal.SIGKILL)
        self.assertEqual(read_all(first.client), b"")
        second.client.sendall(b"ping")
        self.assertEqual(exact(second.upstream, 4), b"ping")
        second.upstream.sendall(b"pong")
        self.assertEqual(exact(second.client, 4), b"pong")

    def carry(self, tunnels, length):
        """`length` patterned bytes each way through every tunnel at once;
        returns each child's peak memory, sampled before they end."""
        errors, counts, threads = [], [], []
        for t in tunnels:
            for source, sink in ((t.client, t.upstream), (t.upstream, t.client)):
                threads.append(threading.Thread(target=send_pattern, args=(source, length, errors)))
                threads.append(threading.Thread(target=check_pattern, args=(sink, length, counts, errors)))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(errors, [])
        self.assertEqual(counts, [length] * 2 * len(tunnels))
        peaks = [peak_rss(t.relay.pid) for t in tunnels]
        for t in tunnels:
            t.client.shutdown(socket.SHUT_WR)
            t.upstream.shutdown(socket.SHUT_WR)
            self.assertEqual(read_all(t.client), b"")
            self.assertEqual(read_all(t.upstream), b"")
            self.assertEqual(t.relay.finish(WAIT), 0)
            self.assertEqual(t.relay.result, ("closed", "completed", length, length))
        return peaks

    def test_memory_does_not_grow_with_bytes_relayed(self):
        t = self.tunnel()
        self.assertTrue(t.opened())
        for peak in self.carry([t], 64 << 20):
            self.assertLess(peak, 32 << 20)

    @unittest.skipUnless(os.environ.get("AGENTBOX_RELAY_STRESS") == "1", "AGENTBOX_RELAY_STRESS=1")
    def test_more_than_the_old_total_through_concurrent_children(self):
        tunnels = [self.tunnel(idle=60) for _ in range(2)]
        for t in tunnels:
            self.assertTrue(t.opened())
        length = 600 << 20
        self.assertGreater(2 * 2 * length, 2 << 30)
        for peak in self.carry(tunnels, length):
            self.assertLess(peak, 32 << 20)


if __name__ == "__main__":
    unittest.main()
