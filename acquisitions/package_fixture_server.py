"""Test-only synthetic HTTPS file server for the package acquisition fixtures.

Not product code, never packaged and never a production listener: the
worker's tests (test_packages.py) and the Rust tests start it for one case,
over files they wrote. Python standard library only, loopback ephemeral
port only, one thread per connection.

    python3 -I -S -B package_fixture_server.py serve ROOT CERT KEY

`GET /MODE/REL` answers with the file `ROOT/REL` (plain segments only, a
segment's `%2f` kept literally, never another file; a directory's file is
`ROOT/REL/_doc`, so a registry's package document and its versions share a
name; `REL/` names only a directory's) as MODE says:

    ok          200, Content-Length, the body
    chunked     200, chunked in 1000-byte chunks
    close       200, no length, the body, then close
    http10      HTTP/1.0 200, no length, the body, then close
    interim     100 Continue, then as ok
    status      404 with the body
    redirect    302 to /ok/REL (a follow is recorded as such)
    gzip        as ok, with Content-Encoding: gzip
    te          200, Transfer-Encoding: gzip, chunked
    length      Content-Length one more than the body, the body, close
    twolengths  two Content-Length fields
    long        chunked, one byte more than the body
    longclose   no length, one byte more than the body, close
    short       Content-Length of the body, one byte less, close
    corrupt     as ok, its last byte flipped
    reset       half the body, 500 ms, then a TCP reset
    trickle     as close, one byte per 200 ms
    stall       the request read, never an answer
    headers     101 extra header fields
    garbage     a status line that is not HTTP
    close-length     as ok, with Connection: close
    close-trailing   as close-length, then bytes past the length
    close-corrupt    as close-length, its last byte flipped
    close-trickle    as close-length, one byte per 200 ms
    http10-length    HTTP/1.0 200 with Content-Length, the body, close
    http10-alive     as http10-length, with Connection: keep-alive
    chunked-close    as chunked, with Connection: close
    chunked-short    as chunked-close, cut inside its last chunk
    chunked-long     as chunked-close, one byte more than the body
    hidden-length    as ok, then a non-field line, then a second length
    hidden-coding    as ok, then a non-field line, then Content-Encoding: gzip
    hidden-status    as hidden-length, status 404
    spaced-name      as ok, then "Content-Length : N+1"
    lead-from        a "From x" line before the fields of ok
    trail-from       a "From x" line after the fields of ok
    lead-space       the first field of ok led by a space
    no-name          as ok, then ": v"

stdout: `ready <port>`, then, once stdin reaches EOF, one JSON line of
every request (method, path, mode and the headers that matter) and exit.
"""

import json
import os
import re
import socket
import ssl
import struct
import sys
import threading
import time

MAX_REQUEST = 16384
SEGMENT = re.compile(r"[A-Za-z0-9_~@+-][A-Za-z0-9._~@+%-]*")
WATCHED = ("host", "accept", "accept-encoding", "authorization", "proxy-authorization", "cookie",
           "user-agent", "connection")
DOCUMENT = "_doc"


class Server:
    def __init__(self, root, cert, key):
        self.root = root
        self.tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.tls.load_cert_chain(cert, key)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(16)
        self.lock = threading.Lock()
        self.requests = []
        self.connections = []
        self.threads = []

    def serve(self):
        while True:
            try:
                raw, _ = self.listener.accept()
            except OSError:
                return
            thread = threading.Thread(target=self.handle, args=(raw,), daemon=True)
            with self.lock:
                self.connections.append(raw)
                self.threads.append(thread)
            thread.start()

    def handle(self, raw):
        try:
            raw.settimeout(30)
            conn = self.tls.wrap_socket(raw, server_side=True)
        except (OSError, ssl.SSLError):
            with self.lock:
                self.requests.append({"handshake": "failed"})
            raw.close()
            return
        try:
            self.answer(conn)
        except (OSError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def answer(self, conn):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk or len(data) > MAX_REQUEST:
                return
            data += chunk
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
        method, target, version = head[0].split(" ", 2)
        headers = {}
        for line in head[1:]:
            name, _, value = line.partition(":")
            headers.setdefault(name.strip().lower(), []).append(value.strip())
        mode, _, rel = target[1:].partition("/")
        record = {"method": method, "path": target, "mode": mode, "version": version,
                  "headers": {name: headers[name] for name in WATCHED if name in headers}}
        with self.lock:
            self.requests.append(record)
        directory = rel.endswith("/")
        rel = rel[:-1] if directory else rel
        parts = rel.split("/")
        if not rel or not all(SEGMENT.fullmatch(part) for part in parts):
            return send(conn, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
        path = os.path.join(self.root, *parts)
        if os.path.isdir(path):
            path = os.path.join(path, DOCUMENT)
        elif directory:
            return send(conn, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        try:
            with open(path, "rb") as stream:
                body = stream.read()
        except OSError:
            return send(conn, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        respond(conn, mode, rel, body)

    def stop(self):
        try:
            self.listener.close()
        except OSError:
            pass
        with self.lock:
            threads = list(self.threads)
            for conn in self.connections:
                try:
                    conn.close()
                except OSError:
                    pass
        # A connection its client already gave up is recorded before the
        # report: each handler ends, bounded.
        for thread in threads:
            thread.join(5)
        with self.lock:
            return list(self.requests)


def send(conn, data):
    conn.sendall(data)


def head(status, fields):
    return ("%s\r\n%s\r\n" % (status, "".join("%s\r\n" % field for field in fields))).encode()


def chunked(body, extra=b""):
    data = body + extra
    out = b""
    for at in range(0, len(data), 1000):
        piece = data[at:at + 1000]
        out += b"%x\r\n" % len(piece) + piece + b"\r\n"
    return out + b"0\r\n\r\n"


MALFORMED = {
    "hidden-length": lambda kind, length, n: (
        "HTTP/1.1 200 OK", [kind, length, "bogus", "Content-Length: %d" % (n + 1)]),
    "hidden-coding": lambda kind, length, n: (
        "HTTP/1.1 200 OK", [kind, length, "bogus", "Content-Encoding: gzip"]),
    "hidden-status": lambda kind, length, n: (
        "HTTP/1.1 404 Not Found", [kind, length, "bogus", "Content-Length: %d" % (n + 1)]),
    "spaced-name": lambda kind, length, n: (
        "HTTP/1.1 200 OK", [kind, length, "Content-Length : %d" % (n + 1)]),
    "lead-from": lambda kind, length, n: ("HTTP/1.1 200 OK", ["From x", kind, length]),
    "trail-from": lambda kind, length, n: ("HTTP/1.1 200 OK", [kind, length, "From x"]),
    "lead-space": lambda kind, length, n: ("HTTP/1.1 200 OK", [" " + kind, length]),
    "no-name": lambda kind, length, n: ("HTTP/1.1 200 OK", [kind, length, ": v"]),
}


def respond(conn, mode, rel, body):
    ok = "HTTP/1.1 200 OK"
    kind = "Content-Type: application/octet-stream"
    length = "Content-Length: %d" % len(body)
    if mode == "ok":
        send(conn, head(ok, [kind, length]) + body)
    elif mode == "chunked":
        send(conn, head(ok, [kind, "Transfer-Encoding: chunked"]) + chunked(body))
    elif mode == "close":
        send(conn, head(ok, [kind, "Connection: close"]) + body)
    elif mode == "http10":
        send(conn, head("HTTP/1.0 200 OK", [kind]) + body)
    elif mode == "interim":
        send(conn, b"HTTP/1.1 100 Continue\r\n\r\n" + head(ok, [kind, length]) + body)
    elif mode == "status":
        send(conn, head("HTTP/1.1 404 Not Found", [length]) + body)
    elif mode == "redirect":
        send(conn, head("HTTP/1.1 302 Found", ["Location: /ok/" + rel, "Content-Length: 0"]))
    elif mode == "gzip":
        send(conn, head(ok, [kind, length, "Content-Encoding: gzip"]) + body)
    elif mode == "te":
        send(conn, head(ok, [kind, "Transfer-Encoding: gzip, chunked"]) + chunked(body))
    elif mode == "length":
        send(conn, head(ok, [kind, "Content-Length: %d" % (len(body) + 1), "Connection: close"])
             + body)
    elif mode == "twolengths":
        send(conn, head(ok, [kind, length, length]) + body)
    elif mode == "long":
        send(conn, head(ok, [kind, "Transfer-Encoding: chunked"]) + chunked(body, b"x"))
    elif mode == "longclose":
        send(conn, head(ok, [kind, "Connection: close"]) + body + b"x")
    elif mode == "short":
        send(conn, head(ok, [kind, length, "Connection: close"]) + body[:-1])
    elif mode == "corrupt":
        send(conn, head(ok, [kind, length]) + body[:-1] + bytes([body[-1] ^ 1]))
    elif mode == "reset":
        send(conn, head(ok, [kind, length]) + body[:len(body) // 2])
        time.sleep(0.5)
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    elif mode == "trickle":
        send(conn, head(ok, [kind, "Connection: close"]))
        for at in range(len(body)):
            send(conn, body[at:at + 1])
            time.sleep(0.2)
    elif mode == "stall":
        time.sleep(600)
    elif mode == "headers":
        send(conn, head(ok, [kind, length] + ["X-Pad-%d: v" % i for i in range(101)]) + body)
    elif mode == "close-length":
        send(conn, head(ok, [kind, length, "Connection: close"]) + body)
    elif mode == "close-trailing":
        send(conn, head(ok, [kind, length, "Connection: close"]) + body + b"trailing")
    elif mode == "close-corrupt":
        send(conn, head(ok, [kind, length, "Connection: close"]) + body[:-1]
             + bytes([body[-1] ^ 1]))
    elif mode == "close-trickle":
        send(conn, head(ok, [kind, length, "Connection: close"]))
        for at in range(len(body)):
            send(conn, body[at:at + 1])
            time.sleep(0.2)
    elif mode == "http10-length":
        send(conn, head("HTTP/1.0 200 OK", [kind, length]) + body)
    elif mode == "http10-alive":
        send(conn, head("HTTP/1.0 200 OK", [kind, length, "Connection: keep-alive"]) + body)
    elif mode == "chunked-close":
        send(conn, head(ok, [kind, "Transfer-Encoding: chunked", "Connection: close"])
             + chunked(body))
    elif mode == "chunked-short":
        send(conn, head(ok, [kind, "Transfer-Encoding: chunked", "Connection: close"])
             + chunked(body)[:-10])
    elif mode == "chunked-long":
        send(conn, head(ok, [kind, "Transfer-Encoding: chunked", "Connection: close"])
             + chunked(body, b"x"))
    elif mode in MALFORMED:
        status, fields = MALFORMED[mode](kind, length, len(body))
        send(conn, head(status, fields) + body)
    elif mode == "garbage":
        send(conn, b"SSH-2.0-nothing\r\n\r\n")
    else:
        send(conn, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")


def main(argv):
    if len(argv) != 4 or argv[0] != "serve":
        return 2
    server = Server(*argv[1:])
    threading.Thread(target=server.serve, daemon=True).start()
    sys.stdout.write("ready %d\n" % server.listener.getsockname()[1])
    sys.stdout.flush()
    while sys.stdin.buffer.read(4096):
        pass
    requests = server.stop()
    sys.stdout.write(json.dumps({"requests": requests}, sort_keys=True) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
