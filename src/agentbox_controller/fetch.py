"""Bounded, pinned host downloads into a directory of ours (the built-in
QEMU inputs, builtin.py): HTTPS only (redirects too), each response
streamed into a fresh private temp file beside its final name while
hashed, at most its pinned size (or bound), verified, synced, then
renamed into place. Nothing unverified ever has its final name; a
failure removes its temp file. Unpinned (no digest): a signed document,
bounded, its signature its caller's check. An interrupt (SIGINT, SIGTERM, SIGHUP)
cancels the transfer in flight (`cancelled`); a stalled read times out.
The host is trusted: its proxy settings and CA store apply.
"""
import base64
import hashlib
import http.client
import os
import secrets
import signal
import stat
import urllib.error
import urllib.request

from . import host
from .host import HostError

# Test seams (launch.py overrides): allowed URL schemes and URL prefix
# rewrites ({prefix: replacement}).
SCHEMES = ["https"]
REWRITE = {}
READ_TIMEOUT = 60
CHUNK = 1 << 20
TEMP_PREFIX = ".fetch-"


class Cancelled(BaseException):
    pass


class _Interrupt:
    """Interrupts raise Cancelled while a transfer runs (PEP 475: a
    handler's exception ends the blocked read); each is also counted in
    the shared list, so later steps see it."""

    def __enter__(self):
        signals = host.SHARED if host.SHARED is not None else []
        self.signals = signals

        def handler(number, _frame):
            signals.append(number)
            raise Cancelled()

        self.previous = {n: signal.signal(n, handler) for n in host.TERMINATING}
        if signals:
            self.__exit__()
            raise HostError("cancelled")
        return self

    def __exit__(self, *_):
        for number, previous in getattr(self, "previous", {}).items():
            signal.signal(number, previous)
        self.previous = {}


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _scheme(newurl) not in SCHEMES:
            raise urllib.error.HTTPError(newurl, code, "redirect refused", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _scheme(url):
    return url.split(":", 1)[0].lower() if ":" in url else ""


def rewrite(url):
    for prefix, replacement in REWRITE.items():
        if url.startswith(prefix):
            return replacement + url[len(prefix):]
    return url


class Digest:
    """`sha256:HEX` or an npm `sha512-BASE64` integrity."""

    def __init__(self, text):
        self.text = text
        if text.startswith("sha512-"):
            self.name, self.expected = "sha512", base64.b64decode(text[7:])
        elif text.startswith("sha256:"):
            self.name, self.expected = "sha256", bytes.fromhex(text[7:])
        else:
            raise ValueError(text)

    def matches(self, digest):
        return digest == self.expected


def _private(st):
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and st.st_uid == os.geteuid() \
        and not st.st_mode & 0o022


def verified(dir_fd, name, digest, size):
    """Whether `name` beneath `dir_fd` is a private regular single-link
    file of ours with exactly `size` bytes (None: any up to the bound
    checked by the caller) and `digest`."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not _private(st) or (size is not None and st.st_size != size):
            return False
        hasher = hashlib.new(digest.name)
        while True:
            data = os.read(fd, CHUNK)
            if not data:
                break
            hasher.update(data)
        return digest.matches(hasher.digest())
    except OSError:
        return False
    finally:
        os.close(fd)


def clean(dir_fd):
    """A crashed fetch's temp files in `dir_fd` removed."""
    for name in os.listdir(dir_fd):
        if name.startswith(TEMP_PREFIX):
            try:
                os.unlink(name, dir_fd=dir_fd)
            except OSError:
                pass


def fetch(dir_fd, name, urls, digest, size, bound, warn):
    """`name` beneath `dir_fd` from the first of `urls` that gives exactly
    the pinned bytes; its size: `size` exactly, else at most `bound`;
    `digest` None: any bytes within the bound (a signed document, checked
    by its caller). Returns the SHA-256 hex of what was written.
    Refusals: `input_unavailable` (no URL answered with it),
    `input_mismatch` (some answered other bytes), `cancelled`."""
    mismatch = False
    for url in urls:
        url = rewrite(url)
        if _scheme(url) not in SCHEMES:
            raise HostError("input_url_invalid")
        try:
            got = _one(dir_fd, name, url, digest, size, bound)
        except Cancelled:
            raise HostError("cancelled") from None
        if got not in ("unavailable", "mismatch"):
            return got
        mismatch = mismatch or got == "mismatch"
        warn(f"agentbox: fetch: {name}: {got} from {url.split('/')[2] if '//' in url else '?'}\n")
    raise HostError("input_mismatch" if mismatch else "input_unavailable")


def _one(dir_fd, name, url, digest, size, bound):
    temp = f"{TEMP_PREFIX}{secrets.token_hex(8)}"
    out = None
    try:
        with _Interrupt():
            opener = urllib.request.build_opener(_HttpsOnly())
            try:
                response = opener.open(urllib.request.Request(url, headers={"User-Agent": "agentbox"}),
                                       timeout=READ_TIMEOUT)
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError):
                return "unavailable"
            with response:
                if _scheme(response.geturl()) not in SCHEMES:
                    return "unavailable"
                limit = size if size is not None else bound
                length = response.headers.get("Content-Length")
                if length is not None and length.isdigit() and int(length) > limit:
                    return "mismatch"
                out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                              dir_fd=dir_fd)
                hasher = hashlib.new(digest.name if digest is not None else "sha256")
                total = 0
                while True:
                    try:
                        data = response.read(min(CHUNK, limit + 1 - total))
                    except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException):
                        # A truncated or malformed body (IncompleteRead,
                        # a bad chunk): this URL failed, its temp removed.
                        return "unavailable"
                    if not data:
                        break
                    total += len(data)
                    if total > limit:
                        return "mismatch"
                    hasher.update(data)
                    view = memoryview(data)
                    while view:
                        view = view[os.write(out, view):]
        if (size is not None and total != size) or (digest is not None and not digest.matches(hasher.digest())):
            return "mismatch"
        os.fsync(out)
        os.close(out)
        out = None
        os.rename(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        temp = None
        os.fsync(dir_fd)
        return hasher.hexdigest()
    except OSError:
        raise HostError("input_write_failed") from None
    finally:
        if out is not None:
            os.close(out)
        if temp is not None:
            try:
                os.unlink(temp, dir_fd=dir_fd)
            except OSError:
                pass
