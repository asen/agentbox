"""A run owner's published records: its stop identity (`jail stop`) and a
serving owner's shell profile (`shell`, `jail shell-transport`). Files
only: no socket, request or reply; nothing here starts or keeps a process.

```text
DATA/controller-runs/RUN/owner/   0700, written only under the run's lease
  owner.json  {"schema", "execution": E, "serve", "pid", "boot", "start"}
              from before the task starts until the owner's end
  shell.json  {"schema", "execution": E, "profile": {user identity
              known_hosts alias launcher endpoint session}, "path": PATH | null}
              a serving owner's, from guest-ready until its teardown starts
jail stop (the lease busy): owner.json -> pidfd_open(pid) -> this boot and
          /proc/PID start time still the record's -> pidfd_send_signal
          SIGUSR1 -> "requested" (a request, never proof of an end)
owner     SIGUSR1 handler for the process's whole life, never the default
          action again: while an execution is published, a stop request
          (as a first SIGINT, never a second); otherwise ignored
shell     owner.json proven the live process -> shell.json, same execution
```

Every record: strict JSON (no duplicate key), exact keys, at most
MAX_RECORD bytes, a regular file of this user without group or world bits
in a 0700 directory, replaced atomically. A record left by a killed owner
names a process gone, or another one (start time, boot): refused, never
signalled. The next owner, holding the lease, removes both before it
publishes. A profile names the owner's own session files, user, launcher,
loopback endpoint and its current session nonce (the jail's request
context, a correlation id: a later session's broker refuses it); it grants
nothing (`shell` still pins the host key,
the jail's sshd authenticates). The only environment kept is the owner's
filtered PATH, for a stdio route's provider connect (the very programs its
start resolved); never the captured host environment. One process running
executions in sequence (an agent `run`) has one identity: a request sent
for its earlier execution and delivered during a later one of the same run
stops that one, as `jail stop JAIL` asks. Jail-to-world: nothing.
"""
import json
import os
import re
import signal

from .host import HostError, filter_path
from .store import _dump, _ensure_dir, _open_dir, _private_dir, _read, _replace, is_handle

OWNER_DIR = "owner"
OWNER = "owner.json"
SHELL = "shell.json"
OWNER_SCHEMA = "agentbox.controller-owner.v1"
SHELL_SCHEMA = "agentbox.controller-shell.v1"
MAX_RECORD = 16384
MAX_PATH_BYTES = 4096
MAX_PID = 1 << 22
STOP_SIGNAL = signal.SIGUSR1
BOOT_ID = "/proc/sys/kernel/random/boot_id"
OWNER_KEYS = {"schema", "execution", "serve", "pid", "boot", "start"}
SHELL_KEYS = {"schema", "execution", "profile", "path"}
PROFILE_KEYS = {"user", "identity", "known_hosts", "alias", "launcher", "endpoint", "session"}
_BOOT = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# Written by the handler alone (`requested`) and by `Publication`.
_STOP = {"installed": False, "active": False, "requested": False}


def _on_stop(_signum, _frame):
    # State only: no I/O, no event (it may run between any two bytecodes).
    if _STOP["active"]:
        _STOP["requested"] = True


def install():
    """The process's SIGUSR1 handler, once; never restored."""
    if not _STOP["installed"]:
        signal.signal(STOP_SIGNAL, _on_stop)
        _STOP["installed"] = True


def stop_requested():
    return _STOP["active"] and _STOP["requested"]


# -- identity --------------------------------------------------------------

def boot_id(path=BOOT_ID):
    try:
        with open(path, "rb") as stream:
            text = stream.read(64).decode().strip()
    except (OSError, UnicodeDecodeError):
        raise HostError("owner_unproven") from None
    if _BOOT.fullmatch(text) is None:
        raise HostError("owner_unproven")
    return text


def start_time(pid):
    """The process's start time (clock ticks after boot), or None."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as stream:
            data = stream.read(4096)
        return int(data.rsplit(b")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return None


def identity():
    pid = os.getpid()
    start = start_time(pid)
    if start is None:
        raise HostError("owner_unproven")
    return {"pid": pid, "boot": boot_id(), "start": start}


def pin(record):
    """A pidfd on the very process `record` names, or None. Opened first,
    then checked: a pid reused before the open shows another start time;
    one ended after it fails the signal."""
    try:
        fd = os.pidfd_open(record["pid"])
    except OSError:
        return None
    try:
        same = boot_id() == record["boot"] and start_time(record["pid"]) == record["start"]
    except HostError:
        same = False
    if not same:
        os.close(fd)
        return None
    return fd


# -- records ---------------------------------------------------------------

def _unique(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate")
    return dict(pairs)


def check_owner(value):
    return isinstance(value, dict) and set(value) == OWNER_KEYS and value["schema"] == OWNER_SCHEMA \
        and is_handle(value["execution"], "e") and type(value["serve"]) is bool \
        and type(value["pid"]) is int and 1 <= value["pid"] < MAX_PID \
        and isinstance(value["boot"], str) and _BOOT.fullmatch(value["boot"]) is not None \
        and type(value["start"]) is int and value["start"] >= 0


def check_shell(value):
    """The shape; the profile's own values are `shell.check_profile`'s."""
    if not isinstance(value, dict) or set(value) != SHELL_KEYS or value["schema"] != SHELL_SCHEMA \
            or not is_handle(value["execution"], "e") or not isinstance(value["profile"], dict) \
            or set(value["profile"]) != PROFILE_KEYS:
        return False
    path = value["path"]
    return path is None or (isinstance(path, str) and len(path.encode()) <= MAX_PATH_BYTES
                            and filter_path(path) == path)


def _unlink(directory, name):
    """True once `name` is absent."""
    try:
        os.unlink(name, dir_fd=directory)
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


class Publication:
    """An owner's records, under its lease: its stop identity from here to
    `close`; a serving owner's shell profile from `serving` to `withdraw`.
    A gone owner's records (the lease is ours) are removed first."""

    def __init__(self, lease, execution_id, serve):
        install()
        self.execution = execution_id
        self.dir = None
        try:
            self.dir = _ensure_dir(OWNER_DIR, lease.run)
            for name in (SHELL, OWNER):
                if not _unlink(self.dir, name):
                    raise HostError("owner_unpublished")
            record = dict(identity(), schema=OWNER_SCHEMA, execution=execution_id, serve=serve)
            # Active before the record exists: a request it permits is never
            # the default action. An earlier execution's request is dropped.
            _STOP["requested"] = False
            _STOP["active"] = True
            _replace(self.dir, OWNER, _dump(record))
        except (OSError, HostError):
            self.close()
            raise HostError("owner_unpublished") from None

    def serving(self, profile, path):
        record = {"schema": SHELL_SCHEMA, "execution": self.execution, "profile": dict(profile), "path": path}
        data = _dump(record)
        if self.dir is None or not check_shell(record) or len(data) > MAX_RECORD:
            raise HostError("shell_unpublished")
        try:
            _replace(self.dir, SHELL, data)
        except OSError:
            raise HostError("shell_unpublished") from None

    def withdraw(self):
        """The shell profile removed; True once absent."""
        return self.dir is None or _unlink(self.dir, SHELL)

    def close(self):
        """Inactive first (a request now is ignored), then both removed."""
        _STOP["active"] = False
        _STOP["requested"] = False
        if self.dir is not None:
            for name in (SHELL, OWNER):
                _unlink(self.dir, name)
            os.close(self.dir)
            self.dir = None


def _load(directory, name):
    """The strict object, or None when absent."""
    try:
        data = _read(directory, name, MAX_RECORD)
    except FileNotFoundError:
        return None
    except (OSError, HostError):
        raise HostError("owner_record_invalid") from None
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HostError("owner_record_invalid") from None
    return value


def records(store, run_id):
    """(owner record or None, shell record or None), each checked."""
    run = store._open_run(run_id)
    try:
        try:
            directory = _open_dir(OWNER_DIR, run)
        except FileNotFoundError:
            return None, None
        except OSError:
            raise HostError("owner_record_invalid") from None
    finally:
        os.close(run)
    try:
        if not _private_dir(os.fstat(directory)):
            raise HostError("owner_record_invalid")
        owner, shell = _load(directory, OWNER), _load(directory, SHELL)
    finally:
        os.close(directory)
    if (owner is not None and not check_owner(owner)) or (shell is not None and not check_shell(shell)):
        raise HostError("owner_record_invalid")
    return owner, shell


def request_stop(store, run_id):
    """`jail stop` on a busy run: SIGUSR1 to the owner its record names,
    proven that very process; `run_busy` without one (another operation
    holds the lease, or the record is a gone owner's). Never os.kill."""
    owner, _ = records(store, run_id)
    fd = None if owner is None else pin(owner)
    if fd is None:
        raise HostError("run_busy")
    try:
        signal.pidfd_send_signal(fd, STOP_SIGNAL)
    except ProcessLookupError:
        raise HostError("run_busy") from None
    except OSError:
        raise HostError("owner_unreachable") from None
    finally:
        os.close(fd)


def serving(store, run_id, execution=None):
    """(execution, profile, path) of the run's live serving owner; with
    `execution`, only that one's (`invocation_stale` otherwise)."""
    owner, shell = records(store, run_id)
    if owner is None:
        raise HostError("owner_unreachable")
    fd = pin(owner)
    if fd is None:
        raise HostError("owner_unreachable")
    os.close(fd)
    if not owner["serve"]:
        raise HostError("shell_unsupported")
    if shell is None:
        raise HostError("shell_not_ready")
    if shell["execution"] != owner["execution"] or (execution is not None and execution != owner["execution"]):
        raise HostError("invocation_stale")
    return owner["execution"], shell["profile"], shell["path"]
