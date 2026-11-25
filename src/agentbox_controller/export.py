"""Archive export of the jail's working directory (`jail export`, attached
runs; `jail exec --export-to`, any run): the jail's own GNU tar over a
fresh SSH session on the run's pinned connection, into one private partial
file beside the user's destination, published there by a no-replace
rename. The old CLI's export.rs and export/runner.rs are the reference.

```text
destination resolved lexically; parent pinned from / (no link, trusted,
  not the store); name absent; free space >= max_bytes
admission: [store lock] reservation {x-HEX, max_bytes, processes unknown}
.agentbox-export-HEX.partial   0600, O_EXCL|O_NOFOLLOW, in the pinned parent
ssh ... /bin/sh -s  <- the fixed script; stdout -> this process -> pwrite
  at the running offset, never past max_bytes; stderr bounded, never shown
deadline, signal, Stop or a sink failure -> the ssh group killed, reaped
-> processes settled -> success: partial checked (same inode, one link,
   length) -> renameat2 NOREPLACE -> PATH; failure: partial unlinked by
   its live descriptor's identity -> reservation cleared
   (publication or removal unconfirmed: the reservation stays)
```

Opaque and untrusted: the archive is the jail's claim, never parsed,
listed or extracted on the host. Only this process writes the partial
(the ssh child has a pipe, never the file), so its own cleanup is exact
while its descriptor lives. A crash leaves the reservation recorded (no
destination is stored, nothing is guessed or scanned): it blocks exec,
export and discard until the operator asserts that exact export's local
work ended (`jail stop --assert-local-ended x-HEX`, the user's decision);
a partial may then remain beside the destination, the operator's.
"""
import ctypes
import ctypes.util
import errno
import os
import secrets
import selectors
import stat
import time

from . import scopes, ssh as ssh_mod
from .host import Child, Drain, HostError, Loop, tool_env, write_some

MAX_BYTES = (10240, 64 << 30)
DEFAULT_MAX_BYTES = 4 << 30
TIMEOUT_MS = (1000, 86400000)
DEFAULT_TIMEOUT_MS = 600000
MAX_DESTINATION_BYTES = 4096
# An execution's export: kept after its cutoff for the teardown, and the
# command's shortest window (export/exec.rs).
STOP_RESERVE = 120.0
TASK_MIN = 60.0
PREFIX = ".agentbox-export-"
SUFFIX = ".partial"
# The remote script's own refusal: a replaced HOME or working directory.
REFUSED_EXIT = 3
DRAIN_WAIT = 1.0
CHUNK = 65536
READS_PER_TURN = 64
MAX_DIAGNOSTIC_BYTES = 4096
RENAME_NOREPLACE = 1


def new_export_id():
    return "x-" + secrets.token_hex(16)


def settings(config, max_bytes=None, timeout_ms=None):
    """The command's overrides, else the host configuration's, else the
    fixed defaults; checked."""
    chosen = {"max_bytes": max_bytes if max_bytes is not None else config.get("export_max_bytes",
                                                                                DEFAULT_MAX_BYTES),
              "timeout_ms": timeout_ms if timeout_ms is not None else config.get("export_timeout_ms",
                                                                                 DEFAULT_TIMEOUT_MS)}
    if not MAX_BYTES[0] <= chosen["max_bytes"] <= MAX_BYTES[1] \
            or not TIMEOUT_MS[0] <= chosen["timeout_ms"] <= TIMEOUT_MS[1]:
        raise HostError("export_settings_invalid")
    return chosen


def task_seconds(runtime, allowance_ms):
    """An execution's command window within its maximum runtime: what the
    allowance and STOP_RESERVE leave, at least TASK_MIN; else None."""
    task = runtime - allowance_ms / 1000.0 - STOP_RESERVE
    return task if task >= TASK_MIN else None


def destination(text, cwd):
    """(parent, name): `text` made absolute against `cwd`, resolved
    lexically (`.` dropped, `..` removing one component); a path naming a
    directory or over MAX_DESTINATION_BYTES refuses."""
    last = text.rsplit("/", 1)[-1] if isinstance(text, str) else ""
    if not text or last in ("", ".", "..") or "\0" in text:
        raise HostError("export_destination_invalid")
    if not text.startswith("/"):
        if cwd is None or not cwd.startswith("/"):
            raise HostError("export_cwd_unavailable")
        text = cwd + "/" + text
    parts = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    resolved = "/" + "/".join(parts)
    if not parts or len(resolved.encode("utf-8", "surrogateescape")) > MAX_DESTINATION_BYTES:
        raise HostError("export_destination_invalid")
    return "/" + "/".join(parts[:-1]), parts[-1]


def trusted(st):
    """A destination's ancestor (run.rs `trusted_ancestor`): a directory of
    root or this user; others' write only on root's sticky one; group
    write only for the root group or this user's group."""
    mode = st.st_mode
    return stat.S_ISDIR(mode) and st.st_uid in (0, os.geteuid()) \
        and (not mode & 0o002 or (st.st_uid == 0 and mode & stat.S_ISVTX)) \
        and (not mode & 0o020 or st.st_gid in (0, os.getegid()))


def _identity(st):
    return st.st_dev, st.st_ino


def pin(parent, name, store_path):
    """The destination's parent, opened from `/` one directory at a time
    without following links, each trusted and none the data store (by path,
    then identity); `name` absent. Its descriptor."""
    if parent == store_path or parent.startswith(store_path.rstrip("/") + "/"):
        raise HostError("export_destination_in_store")
    try:
        store_id = _identity(os.stat(store_path))
    except OSError:
        raise HostError("store_unavailable") from None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        if _identity(os.fstat(fd)) == store_id:
            raise HostError("export_destination_in_store")
        for part in [p for p in parent.split("/") if p]:
            try:
                entry = os.stat(part, dir_fd=fd, follow_symlinks=False)
            except OSError as error:
                raise HostError("export_destination_symlink_ancestor" if error.errno == errno.ELOOP
                                else "export_destination_unavailable") from None
            if stat.S_ISLNK(entry.st_mode):
                raise HostError("export_destination_symlink_ancestor")
            if not stat.S_ISDIR(entry.st_mode):
                raise HostError("export_destination_unavailable")
            try:
                following = os.open(part, flags, dir_fd=fd)
            except OSError as error:
                raise HostError("export_destination_symlink_ancestor" if error.errno == errno.ELOOP
                                else "export_destination_unavailable") from None
            os.close(fd)
            fd = following
            st = os.fstat(fd)
            if _identity(st) != _identity(entry):
                raise HostError("export_destination_unavailable")
            if not trusted(st):
                raise HostError("export_destination_untrusted")
            if _identity(st) == store_id:
                raise HostError("export_destination_in_store")
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return fd
        except OSError:
            raise HostError("export_destination_unavailable") from None
        raise HostError("export_destination_exists")
    except BaseException:
        os.close(fd)
        raise


def available(fd):
    st = os.fstatvfs(fd)
    return st.f_bavail * st.f_frsize


def script(home, work):
    """The fixed remote script (export/runner.rs `script`): HOME and every
    directory down to the working directory a directory, not a link (else
    REFUSED_EXIT, nothing sent); then GNU tar from a cleared environment
    of the whole working directory to stdout. Plain paths: their quotes
    need no escape."""
    if not work.startswith(home + "/"):
        raise HostError("export_layout_invalid")
    parts = " ".join(f"'{p}'" for p in work[len(home) + 1:].split("/"))
    return (f"d='{home}'\n"
            "real() { [ -d \"$d\" ] && [ ! -h \"$d\" ] || "
            f"{{ echo 'agentbox-export: working directory refused' >&2; exit {REFUSED_EXIT}; }}; }}\n"
            f"real; for p in {parts}; do d=\"$d/$p\"; real; done\n"
            "exec /usr/bin/env -i LC_ALL=C /usr/bin/tar --create --file=- --format=posix "
            f"--pax-option=delete=atime,delete=ctime --numeric-owner --directory='{work}' .\n")


_LIBC = None


def _renameat2(dir_fd, old, new):
    global _LIBC
    if _LIBC is None:
        _LIBC = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    try:
        call = _LIBC.renameat2
    except AttributeError:
        raise OSError(errno.ENOSYS, "renameat2") from None
    if call(dir_fd, os.fsencode(old), dir_fd, os.fsencode(new), RENAME_NOREPLACE) != 0:
        raise OSError(ctypes.get_errno(), "renameat2")


class Output:
    """The partial file, written only here at the running offset, never
    past `limit`. `sink`: open, complete (EOF, every byte written),
    overflow, no_space, quota, too_large, write_failed, read_failed."""

    def __init__(self, parent_fd, export_id, limit):
        self.parent, self.limit = parent_fd, limit
        self.name = PREFIX + export_id[2:] + SUFFIX
        try:
            self.fd = os.open(self.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=parent_fd)
        except FileExistsError:
            raise HostError("export_destination_exists") from None
        except OSError:
            raise HostError("export_partial_failed") from None
        self.bytes = 0
        self.sink = "open"
        # removed | left | kept | None (published, or never made)
        self.partial = "kept"

    def pump(self, fd):
        """At most READS_PER_TURN reads of `fd`, each written whole before
        the next: "open", "eof" or "stopped" (the sink's exact fact)."""
        if self.sink != "open":
            return "eof" if self.sink == "complete" else "stopped"
        for _ in range(READS_PER_TURN):
            try:
                data = os.read(fd, CHUNK)
            except BlockingIOError:
                return "open"
            except InterruptedError:
                continue
            except OSError:
                self.sink = "read_failed"
                return "stopped"
            if not data:
                self.sink = "complete"
                return "eof"
            if self.bytes + len(data) > self.limit:
                self.sink = "overflow"
                return "stopped"
            try:
                view = memoryview(data)
                offset = self.bytes
                while view:
                    written = os.pwrite(self.fd, view, offset)
                    view, offset = view[written:], offset + written
            except OSError as error:
                self.sink = {errno.ENOSPC: "no_space", errno.EDQUOT: "quota",
                             errno.EFBIG: "too_large"}.get(error.errno, "write_failed")
                return "stopped"
            self.bytes += len(data)
        return "open"

    def _same(self):
        try:
            entry = os.stat(self.name, dir_fd=self.parent, follow_symlinks=False)
            return _identity(entry) == _identity(os.fstat(self.fd))
        except OSError:
            return False

    def publish(self, name):
        """The checked partial renamed to `name`, never over anything."""
        st = os.fstat(self.fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size != self.bytes \
                or self.bytes > self.limit or not self._same():
            raise HostError("export_output_mismatch")
        try:
            _renameat2(self.parent, self.name, name)
        except OSError as error:
            raise HostError("export_destination_exists" if error.errno == errno.EEXIST
                            else "export_publish_failed") from None
        self.partial = None

    def remove(self):
        """One unlink, only while the name is still this descriptor's
        inode: never a replacement; else `left`."""
        if self.partial != "kept":
            return self.partial
        try:
            if self._same():
                os.unlink(self.name, dir_fd=self.parent)
                self.partial = "removed"
                return self.partial
        except OSError:
            pass
        self.partial = "left"
        return self.partial

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


class Transfer:
    """One export ssh on the loop: the script on its stdin, its stdout
    pumped into `output`, stderr bounded and never shown. `end`: an exit
    status, timeout, cancelled, failed or stopped (the sink's failure)."""

    def __init__(self, loop, child, output, script_text):
        self.loop, self.child, self.output = loop, child, output
        self.pending = script_text.encode()
        self.stdin = child.popen.stdin.fileno()
        self.stdout = child.popen.stdout.fileno()
        self.stderr = Drain(loop, child.popen.stderr.fileno(), MAX_DIAGNOSTIC_BYTES)
        self.eof = False
        self.stopped = False
        loop.watch(self.stdin, selectors.EVENT_WRITE, self._write)
        loop.watch(self.stdout, selectors.EVENT_READ, self._read)

    def _write(self, _mask):
        while self.pending:
            written = write_some(self.stdin, self.pending)
            if written is None:
                self.pending = b""
                break
            if written == 0:
                return
            self.pending = self.pending[written:]
        self.loop.unwatch(self.stdin)
        try:
            self.child.popen.stdin.close()
        except OSError:
            pass

    def _read(self, _mask):
        pumped = self.output.pump(self.stdout)
        if pumped == "eof":
            self.eof = True
            self.loop.unwatch(self.stdout)
        elif pumped == "stopped":
            self.stopped = True
            self.loop.unwatch(self.stdout)

    def run(self, deadline, stop, housekeeping=None):
        """Until EOF and exit, the sink's failure, `deadline` or `stop()`,
        `housekeeping()` each turn; the group always killed, the leader
        reaped. Its end."""
        end = None
        exited_at = None
        while end is None:
            if self.stopped:
                end = "stopped"
            elif self.eof and self.child.exited():
                end = "exited"
            elif stop():
                end = "cancelled"
            elif time.monotonic() >= deadline:
                end = "timeout"
            elif self.child.exited():
                # Exit without EOF: a descendant may hold the pipe.
                exited_at = exited_at or time.monotonic()
                if time.monotonic() >= exited_at + DRAIN_WAIT:
                    end = "exited"
            if end is None:
                if housekeeping is not None:
                    housekeeping()
                self.loop.step(0.05)
        for fd in (self.stdin, self.stdout):
            self.loop.unwatch(fd)
        self.stderr.close()
        self.child.kill_group()
        code = self.child.finish()
        if end == "exited":
            return code if code >= 0 else "failed"
        return end


def failure(end, sink):
    """The fixed code of a finished transfer; None for a success."""
    sinks = {"overflow": "export_limit", "no_space": "export_no_space", "quota": "export_quota",
             "too_large": "export_file_too_large", "write_failed": "export_write_failed",
             "read_failed": "export_read_failed"}
    if sink in sinks:
        return sinks[sink]
    if end == "timeout":
        return "export_timeout"
    if end == "cancelled":
        return "interrupted"
    if end == 0:
        return None if sink == "complete" else "export_incomplete"
    if isinstance(end, int):
        return "export_remote_failed"
    return "export_transfer_failed"


def line(export_id, code, written, exit_code, partial, cleared):
    """The export's own report line (cli.rs `add_export`)."""
    text = f"export: {export_id} outcome=published" if code is None \
        else f"agentbox: export: {export_id} outcome=failed code={code}"
    text += f" written_bytes={'unknown' if written is None else written}"
    if exit_code is not None:
        text += f" exit={exit_code}"
    if partial is not None:
        text += f" partial={partial}"
    return text + (" reservation=cleared" if cleared else " reservation=kept")


def rewrite(lease, export_id, update):
    """This export's reservation, still recorded, changed by `update`
    (None: cleared) under the store lock; whether written."""
    try:
        with lease.store.lock():
            value = lease.record["export"]
            if value is None or value["operation"] != export_id:
                return False
            lease.save(dict(lease.record, export=update(value)))
        return True
    except (OSError, HostError):
        return False


def run_export(system, store, lease, text, chosen, cwd):
    """`jail export JAIL --to PATH` of an attached run under its lease, by
    its own deadline from now: (exit status, report line). Refusals before
    the reservation raise."""
    deadline = time.monotonic() + chosen["timeout_ms"] / 1000.0
    record = lease.record
    if record["phase"] == "discarded":
        raise HostError("run_discarded")
    if record["kind"] != "attached":
        # A managed run's export is its execution's: jail exec --export-to.
        raise HostError("target_unsupported")
    if record["export"] is not None:
        raise HostError("export_unsettled")
    if record["inputs"] is not None and record["inputs"]["state"] == "staging":
        raise HostError("staging_unsettled")
    parent_path, name = destination(text, cwd)
    loop = Loop()
    loop.install_signals()
    parent = None
    try:
        parent = pin(parent_path, name, store.path)
        if available(parent) < chosen["max_bytes"]:
            raise HostError("export_space_insufficient")
        target = record["target"]
        layout = ssh_mod.Layout(target["remote_root"], None, record["worker_release"], secrets.token_hex(16),
                                attached=True)
        if layout.home != record["home"]:
            raise HostError("binding_mismatch")
        remote = script(layout.home, layout.work)
        ssh_program = system.tool("ssh")
        if loop.signals:
            raise HostError("interrupted")
        export_id = new_export_id()

        def publish():
            # Before the partial exists; no destination stored.
            lease.save(dict(lease.record, export={"operation": export_id, "max_bytes": chosen["max_bytes"],
                                                  "processes": "unknown"}))

        scopes.admit(store, None, publish, extra=chosen["max_bytes"])
        return _transfer(loop, lease, parent, name, export_id, chosen, target, ssh_program, remote, deadline)
    finally:
        if parent is not None:
            os.close(parent)
        loop.close()


def _transfer(loop, lease, parent, name, export_id, chosen, target, ssh_program, remote, deadline):
    output = child = None
    end = None
    code = None
    try:
        output = Output(parent, export_id, chosen["max_bytes"])
        session = lease.session_dir(export_id)
        alias = ssh_mod.alias(lease.run_id, export_id)
        known = ssh_mod.pin_host_key(session, alias, target["host_key"])
        connection = ssh_mod.Connection(target["user"], target["identity"], known, alias,
                                        endpoint=(target["host"], target["port"]), attached=True)
        if loop.signals:
            raise HostError("interrupted")
        child = Child(connection.bootstrap(ssh_program), connection.env(tool_env()))
        end = Transfer(loop, child, output, remote).run(deadline, lambda: bool(loop.signals))
        code = failure(end, output.sink)
    except HostError as error:
        code = error.code
    except OSError:
        code = "io_error"
    finally:
        if child is not None and not child.reaped:
            child.kill_group()
            child.finish()
    # Its one process group reaped (attached: no domain, the user's
    # decision B): settled before anything is published.
    rewrite(lease, export_id, lambda value: dict(value, processes="settled"))
    if code is None and loop.signals:
        code = "interrupted"
    if output is not None:
        if code is None:
            try:
                output.publish(name)
            except HostError as error:
                code = error.code
        if code is not None:
            output.remove()
        output.close()
    partial = None if output is None else output.partial
    cleared = partial in (None, "removed") and rewrite(lease, export_id, lambda value: None)
    lease.remove_session(export_id)
    exit_code = end if isinstance(end, int) and end != 0 else None
    text = line(export_id, code, None if output is None else output.bytes, exit_code, partial, cleared)
    return (0 if code is None else 1), text
