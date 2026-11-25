"""A provider STATE in this store: its claim, its lease and its prepare
record (the old CLI's `image prepare` had no record; here a crash leaves an
exact domain to settle).

```text
DATA/controller-states/KEY/   KEY: the first 32 hex of SHA-256(STATE), 0700
  lease        0600 flock: held exclusively by each lifecycle operation on
               that provider (image prepare/recover, jail create, stop,
               discard, checkpoints) from before its growth admission to
               its end; held elsewhere: `state_busy`, never a wait
  state.json   0600 agentbox.controller-state.v1 {state, pending}
               pending: null | {op: prepare, operation, provider_sha256,
               recipe, domain, processes: unknown | settled}
STATE/.agentbox-controller.json  0600 the claim: {schema, store}, this
               store's id; made once, and only in a STATE holding none of
               the providers' allocation names (ALLOCATIONS): one already
               used (by the old CLI, another store or anyone) is never
               adopted (`state_unclaimed`); another store's claim refuses
               (`state_owned_elsewhere`)
```

The claim protects only against stores that honour it: the old CLI
does not read it, so a STATE must not be shared with it (documented, not
detectable once this store made its claim). Nothing in STATE but the claim
is written here; the operator's `inputs/` may be there before it (a
built-in profile's STATE: builtin.py writes `inputs/`, under this lease).
"""
import fcntl
import hashlib
import json
import os

from .host import HostError
from .store import STATES, _dump, _ensure_dir, _read, _replace, _write_new, is_handle

STATE_SCHEMA = "agentbox.controller-state.v1"
CLAIM_SCHEMA = "agentbox.controller-claim.v1"
CLAIM = ".agentbox-controller.json"
RECORD = "state.json"
LEASE = "lease"
MAX_RECORD_BYTES = 8192
# What the shipped providers allocate in STATE (providers/podman.py,
# qemu.py, common.py): any of them means the STATE is already in use.
ALLOCATIONS = ("images", "images.lock", "image-keys", "resources", "checkpoints", "bindings", "work")
PENDING_KEYS = {"op", "operation", "provider_sha256", "recipe", "domain", "processes"}


def key(state):
    return hashlib.sha256(state.encode()).hexdigest()[:32]


def _open_state(state):
    try:
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise HostError("provider_state_unavailable") from None
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        os.close(fd)
        raise HostError("provider_state_unavailable")
    return fd


def check_claim(store, state, make=False):
    """STATE claimed by this store; with `make`, a fresh one claimed now."""
    fd = _open_state(state)
    try:
        try:
            raw = _read(fd, CLAIM, 1024)
        except FileNotFoundError:
            if not make:
                raise HostError("state_unclaimed") from None
            if set(os.listdir(fd)) & set(ALLOCATIONS):
                raise HostError("state_unclaimed") from None
            try:
                _write_new(fd, CLAIM, _dump({"schema": CLAIM_SCHEMA, "store": store.id}), 0o600)
                os.fsync(fd)
                return
            except FileExistsError:
                raw = _read(fd, CLAIM, 1024)
        except (OSError, HostError):
            raise HostError("state_claim_invalid") from None
        try:
            value = json.loads(raw)
        except ValueError:
            value = None
        if not isinstance(value, dict) or value.get("schema") != CLAIM_SCHEMA:
            raise HostError("state_claim_invalid")
        if value.get("store") != store.id:
            raise HostError("state_owned_elsewhere")
    finally:
        os.close(fd)


class StateLease:
    """The exclusive lease of one STATE (`state_busy` if held) and its
    record."""

    def __init__(self, store, state):
        self.store, self.state = store, state
        parent = _ensure_dir(STATES, store.root)
        try:
            self.dir = _ensure_dir(key(state), parent)
        finally:
            os.close(parent)
        try:
            self.lease = os.open(LEASE, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                                 dir_fd=self.dir)
        except OSError:
            os.close(self.dir)
            raise HostError("store_invalid") from None
        try:
            fcntl.flock(self.lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.release()
            raise HostError("state_busy") from None
        try:
            self.record = self._load()
        except HostError:
            self.release()
            raise

    def _load(self):
        try:
            value = json.loads(_read(self.dir, RECORD, MAX_RECORD_BYTES))
        except FileNotFoundError:
            value = {"schema": STATE_SCHEMA, "state": self.state, "pending": None}
            _write_new(self.dir, RECORD, _dump(value), 0o600)
            return value
        except (OSError, ValueError, HostError):
            raise HostError("store_invalid") from None
        pending = value.get("pending") if isinstance(value, dict) else None
        if not isinstance(value, dict) or set(value) != {"schema", "state", "pending"} \
                or value["schema"] != STATE_SCHEMA or value["state"] != self.state \
                or (pending is not None and (not isinstance(pending, dict) or set(pending) != PENDING_KEYS
                                             or not is_handle(pending["operation"], "o")
                                             or pending["processes"] not in ("unknown", "settled"))):
            raise HostError("store_invalid")
        return value

    @property
    def pending(self):
        return self.record["pending"]

    def save_pending(self, pending):
        record = dict(self.record, pending=pending)
        _replace(self.dir, RECORD, _dump(record))
        self.record = record

    def release(self):
        for fd in (getattr(self, "lease", None), self.dir):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        self.lease = self.dir = None


def peek(store, state):
    """The STATE's recorded pending operation id, read without its lease
    and making nothing (None when absent or unreadable): a hint where to
    lease, the lease's record then the answer."""
    try:
        parent = os.open(STATES, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=store.root)
    except OSError:
        return None
    try:
        fd = os.open(key(state), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except OSError:
        return None
    finally:
        os.close(parent)
    try:
        value = json.loads(_read(fd, RECORD, MAX_RECORD_BYTES))
        pending = value["pending"] if value.get("state") == state else None
        return pending["operation"] if isinstance(pending, dict) else None
    except (OSError, ValueError, HostError, AttributeError, KeyError, TypeError):
        return None
    finally:
        os.close(fd)


def lease(store, state, claim=True):
    """The STATE's lease, then its claim checked (made when fresh and
    `claim`)."""
    held = StateLease(store, state)
    try:
        check_claim(store, state, make=claim)
    except HostError:
        held.release()
        raise
    return held
