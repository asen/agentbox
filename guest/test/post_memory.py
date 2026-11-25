"""Memory doubles of the artifact POST client's seams (artifact_post_client.py):
a manual clock, a host whose connections the test answers by hand, and a
memory filesystem for the upload directory with injectable close and removal
failures. No socket, server, lookup or process; the socket guard refuses
every connect. Owned roots are made under TMPDIR and kept: nothing here
removes anything on disk."""

import asyncio
import errno
import os
import socket
import stat
import tempfile

from guest.src import artifact_post_protocol as post
from guest.src.artifact_post_client import Seams
from guest.src.artifact_post_context import request_context
from guest.src.protocol import Refused

SESSION = "0123456789abcdef0123456789abcdef"
MS_NS = 1_000_000


class SocketGuard:
    """Refuses every socket connect and bind in this process, counted and
    raised before anything is opened; installed once, never removed."""

    instance = None

    def __init__(self):
        self.denied = 0


def install_socket_guard():
    if SocketGuard.instance is not None:
        return SocketGuard.instance
    guard = SocketGuard()

    def refuse(*_args, **_kwargs):
        guard.denied += 1
        raise PermissionError(errno.EACCES, "socket denied by the test guard")

    socket.socket.connect = refuse
    socket.socket.connect_ex = refuse
    socket.socket.bind = refuse
    SocketGuard.instance = guard
    return guard


class ManualClock:
    """Time moves only when the test says; a wake at or before now fires at once, as production's."""

    def __init__(self, start=1_000_000 * MS_NS):
        self._now = start
        self._wakes = []

    def now(self):
        return self._now

    def wake(self, at, fire):
        if at <= self._now:
            fire()
            return lambda: None
        entry = [at, fire]
        self._wakes.append(entry)
        return lambda: self._wakes.remove(entry) if entry in self._wakes else None

    def advance(self, ns):
        """Moves time on, then fires every due wake in order."""
        self._now += ns
        for entry in sorted(self._wakes, key=lambda item: item[0]):
            if entry[0] > self._now or entry not in self._wakes:
                continue
            self._wakes.remove(entry)
            entry[1]()

    @property
    def pending(self):
        return len(self._wakes)


def response_bytes(response):
    """A complete canonical HTTP response."""
    body = post.encode_response(response)
    status = post.response_status(response)
    head = ("HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n"
            % (status, post.RESPONSE_STATUSES[status], len(body)))
    return head.encode("latin-1") + body


class MemoryConnection:
    """One memory connection: what the client wrote, and the events the test sends."""

    def __init__(self, events):
        self.writes = []
        self.destroyed = 0
        self._events = events

    @property
    def raw(self):
        return b"".join(self.writes)

    @property
    def request(self):
        """The body, decoded, when the written bytes are exactly one canonical head and body."""
        raw = self.raw
        end = raw.find(b"\r\n\r\n")
        if end < 0:
            return None
        body = raw[end + 4:]
        if post.encode_http_request(body) != raw:
            return None
        try:
            return post.decode_request(body)
        except Refused:
            return None

    def connect(self):
        self._events.connect()

    def data(self, data):
        self._events.data(data.encode("latin-1") if isinstance(data, str) else data)

    def end(self):
        self._events.end()

    def close(self):
        self._events.close()

    def respond(self, response, split=1 << 20):
        """The canonical response, in `split`-byte chunks, then the server's close."""
        data = response_bytes(response)
        for at in range(0, len(data), split):
            self.data(data[at:at + split])
        self.end()

    def refuse(self):
        """The host's empty 503, then its close."""
        self.data(post.REFUSAL_HEAD)
        self.end()


class _MemoryChannel:
    def __init__(self, host, connection):
        self.host = host
        self.connection = connection

    def write(self, data, done):
        self.connection.writes.append(bytes(data))

        def complete():
            done(True)
            self.host.answer(self.connection, self.connection.request)

        asyncio.get_running_loop().call_soon(complete)

    def destroy(self):
        self.connection.destroyed += 1


class MemoryHost:
    """The host: each dial is one connection, connected soon after; each write
    completes soon after, then `answer` gets the connection and the decoded
    request (None when not canonical)."""

    def __init__(self, answer, connect=True):
        self.connections = []
        self.answer = answer
        self._connect = connect

    def dial(self, events):
        connection = MemoryConnection(events)
        self.connections.append(connection)
        if self._connect:
            asyncio.get_running_loop().call_soon(connection.connect)
        return _MemoryChannel(self, connection)

    @property
    def requests(self):
        """The decoded requests, in order."""
        return [connection.request for connection in self.connections]


def seams_of(host, clock, ids=("c-1", "c-2", "c-3")):
    """Seams on `host` and `clock`, with fixed client ids in order."""
    remaining = list(ids)
    return Seams(host.dial, clock, lambda: remaining.pop(0) if remaining else "c-exhausted")


def owned_context(session=SESSION):
    """A fresh owned root with a private `work` directory, and its context; kept afterwards."""
    root = tempfile.mkdtemp(prefix="agentbox-post-")
    work = os.path.join(root, "work")
    os.mkdir(work, 0o700)
    os.chmod(work, 0o700)
    context = request_context(session, work)
    assert context is not None, "owned context"
    return root, work, context


def upload(directory, name, data):
    """Writes an upload as the host would, into its prepared directory."""
    path = os.path.join(directory, name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    return path


def ready(submission, client, request, delivery, session=SESSION):
    """The `ready` a host binds to `client`'s `submission` and `request`."""
    digest = post.request_sha256(client, submission)
    return dict({"v": 1, "type": "ready", "session": session, "client": client, "request": request,
                 "request_sha256": digest}, **delivery)


def closed_for(submission, client, request, outcome, session=SESSION, reason="fake_denied"):
    """The `closed` a host sends for `client`'s request."""
    digest = post.request_sha256(client, submission)
    closed = {"v": 1, "type": "closed", "session": session, "client": client, "request": request,
              "request_sha256": digest, "handler": submission["handler"], "outcome": outcome}
    if outcome == "denied":
        closed["reason"] = reason
    return closed


class _Stat:
    def __init__(self, mode, size=0, ino=1, uid=None):
        self.st_mode = mode
        self.st_size = size
        self.st_dev = 1
        self.st_ino = ino
        self.st_uid = os.geteuid() if uid is None else uid


class _MemoryHandle:
    def __init__(self, files, data, ino):
        self.files = files
        self.data = data
        self.ino = ino

    def stat(self):
        return _Stat(stat.S_IFREG | 0o600, len(self.data), self.ino)

    def read(self, size, position):
        return self.data[position:position + size]

    def close(self):
        self.files.closes += 1
        if self.files.close_rejects:
            raise OSError(errno.EIO, "close failed")


class MemoryFiles:
    """The upload directory's filesystem in memory: directories and regular
    files of this user, each file a fresh inode. `close_rejects` makes every
    handle's close fail (after counting it); `unlink_rejects` every removal."""

    def __init__(self, root):
        self.dirs = {root: 0o700}
        self.files = {}
        self.opened = []
        self.unlinked = []
        self.closes = 0
        self.close_rejects = False
        self.unlink_rejects = False
        self._ino = 100

    def put(self, path, data):
        """Writes a file as the host's upload would."""
        self._ino += 1
        self.files[path] = (bytes(data), self._ino)

    def lstat(self, path):
        if path in self.dirs:
            return _Stat(stat.S_IFDIR | self.dirs[path])
        if path in self.files:
            return _Stat(stat.S_IFREG | 0o600, len(self.files[path][0]), self.files[path][1])
        raise FileNotFoundError(errno.ENOENT, "absent")

    def mkdir(self, path, mode):
        if path in self.dirs or path in self.files:
            raise FileExistsError(errno.EEXIST, "exists")
        self.dirs[path] = mode

    def open(self, path, _flags):
        if path not in self.files:
            raise FileNotFoundError(errno.ENOENT, "absent")
        self.opened.append(path)
        data, ino = self.files[path]
        return _MemoryHandle(self, data, ino)

    def unlink(self, path):
        if self.unlink_rejects:
            raise PermissionError(errno.EACCES, "unlink failed")
        if self.files.pop(path, None) is None:
            raise FileNotFoundError(errno.ENOENT, "absent")
        self.unlinked.append(path)


def memory_context(session=SESSION):
    """A context on a memory working root; nothing on disk."""
    work = "/memory/agentbox/work"
    return work, request_context(session, work), MemoryFiles(work)


async def settle(rounds=8):
    """Lets queued callbacks run."""
    for _ in range(rounds):
        await asyncio.sleep(0)


def descriptors():
    """Open descriptors of this process."""
    return len(os.listdir("/proc/self/fd"))
