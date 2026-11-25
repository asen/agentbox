"""Checkpoints (contracts/provider/v1 optional operations; checkpoint.rs and
operations.rs the behaviour reference): save-and-branch of a stopped
resource through a provider advertising `checkpoint`/`restore`. The data
is the provider's; this records what was asked and confirmed.

```text
DATA/controller-checkpoints/   0700
  C.lock    0600, C's lifetime lock (held by each operation on C; held
            elsewhere: checkpoint_busy, never a wait)
  C.json    0600, agentbox.controller-checkpoint.v1, written before the
            provider request (operation, domain, processes unknown)

create   run lease (stopped, ready, no mounts, clean or --allow-unclean
         GENERATION, inputs absent or set up ready) -> STATE lease -> D ->
         admission: C.json pending + the run's pending checkpoint, one
         operation -> checkpoint -> gate -> ready | failed (settled,
         unchanged: the contract's affirmative refusal); lost: both stay
         pending (processes settled once D read empty): `jail stop` of the
         source makes C `lost` (outcome unknown, never `failed`)
restore  C lock (ready, settled) -> STATE lease -> a new run (creating,
         origin C, the source's account, limits, project) -> D -> the run's
         pending create {D, C} -> C reading (holder: the new run) -> create
         -> gate -> the run's pending restore {fresh D} -> C's domain ->
         restore -> gate -> ready. Each binding is on the run before C
         names it. Lost: `jail stop` of the new run settles its D and C's
         reading by it; the run is partial
discard  C lock -> its recorded domain, if unsettled, adopted, killed and
         read empty -> D -> C discarding -> discard naming C -> gate ->
         discarded | retired (only a failed C's settled not_found: a lost
         or other C answered not_found keeps its metadata, refused)
```

A checkpoint is independent of its source run. A restore inherits no host
input grant: copied inputs ready on the source are saved as guest bytes
only. A run with mounts takes no checkpoint.
"""
import fcntl
import json
import os

from . import builtin, scopes, states
from .config import check_assets, check_recorded
from .host import HostError
from .lifecycle import (Custody, _end, _provider_error, baked_worker, commit_create, kill_recorded, pending,
                        CREATE_TIMEOUT_MS, DISCARD_TIMEOUT_MS)
from .store import (CHECKPOINTS, _dump, _ensure_dir, _read, _replace, _write_new, is_handle, new_id)

SCHEMA = "agentbox.controller-checkpoint.v1"
CHECKPOINT_TIMEOUT_MS = 3600 * 1000
RESTORE_TIMEOUT_MS = 3600 * 1000
MAX_RECORD_BYTES = 32 * 1024
MAX_ENTRIES = 4096
STATES = ("pending", "ready", "failed", "lost", "discarding", "discarded", "retired")
KEYS = {"schema", "checkpoint", "provider", "described", "source_run", "resource", "image", "worker_release",
        "retention", "limits", "user", "project", "generation", "storage", "state", "operation", "domain",
        "processes", "holder"}


def _dir(store):
    return _ensure_dir(CHECKPOINTS, store.root)


def _check(value, ident):
    if not isinstance(value, dict) or set(value) != KEYS or value["schema"] != SCHEMA \
            or value["checkpoint"] != ident or value["state"] not in STATES \
            or value["processes"] not in ("unknown", "settled") or value["storage"] not in ("clean", "unclean") \
            or not is_handle(value["source_run"], "r") or not is_handle(value["operation"], "o") \
            or (value["holder"] is not None and not is_handle(value["holder"], "r")):
        raise HostError("checkpoint_invalid")
    check_recorded(value["provider"])
    return value


def ids(store):
    directory = _dir(store)
    try:
        return sorted(n[:-5] for n in os.listdir(directory) if n.endswith(".json") and is_handle(n[:-5], "c"))
    finally:
        os.close(directory)


def read(store, ident):
    if not is_handle(ident, "c"):
        raise HostError("checkpoint_invalid")
    directory = _dir(store)
    try:
        return _check(json.loads(_read(directory, ident + ".json", MAX_RECORD_BYTES)), ident)
    except FileNotFoundError:
        raise HostError("checkpoint_not_found") from None
    except (OSError, ValueError):
        raise HostError("checkpoint_invalid") from None
    finally:
        os.close(directory)


def _write(store, value, first=False):
    directory = _dir(store)
    try:
        data = _dump(value)
        if len(data) > MAX_RECORD_BYTES:
            raise HostError("record_too_large")
        if first:
            _write_new(directory, value["checkpoint"] + ".json", data, 0o600)
            os.fsync(directory)
        else:
            _replace(directory, value["checkpoint"] + ".json", data)
    finally:
        os.close(directory)


def charges(store):
    """Every entry's record, at its bound."""
    try:
        return len(ids(store)) * MAX_RECORD_BYTES
    except OSError:
        raise HostError("store_invalid") from None


class _Lock:
    def __init__(self, store, ident):
        directory = _dir(store)
        try:
            self.fd = os.open(ident + ".lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                              dir_fd=directory)
        finally:
            os.close(directory)
        try:
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            raise HostError("checkpoint_busy") from None

    def release(self):
        os.close(self.fd)


def _update(store, ident, **fields):
    value = dict(read(store, ident), **fields)
    _write(store, value)
    return value


def creation_settled(store, ident, operation):
    """`jail stop` of a source whose checkpoint operation's domain was read
    empty: C, still pending under that operation, is `lost` (its processes
    settled, its outcome unknown: never restorable, never retired on a
    `not_found`; for `checkpoint discard`)."""
    lock = _Lock(store, ident)
    try:
        value = read(store, ident)
        if value["operation"] == operation and value["state"] == "pending":
            _update(store, ident, state="lost", processes="settled", domain=None)
    finally:
        lock.release()


def reader_settled(store, ident, run_id):
    """`jail stop` of a restored run whose domain was read empty: C's
    reading by that run settled."""
    lock = _Lock(store, ident)
    try:
        if read(store, ident)["holder"] == run_id:
            _update(store, ident, processes="settled", holder=None, domain=None)
    finally:
        lock.release()


def may_checkpoint(record):
    inputs = record["inputs"]
    if inputs is None:
        return
    if inputs["state"] == "staged" and inputs.get("delivery") == "ready":
        return
    if inputs["state"] == "staged" and inputs.get("delivery") == "attempted":
        raise HostError("inputs_setup_uncertain")
    raise HostError("inputs_not_deliverable")


def create(system, store, lease, allow_unclean):
    from .lifecycle import accept_unclean
    record = lease.record
    if record["kind"] != "managed":
        raise HostError("target_unsupported")
    if record["phase"] != "ready":
        raise HostError("run_not_ready")
    if "checkpoint" not in record["described"]["operations"]:
        raise HostError("checkpoint_unsupported")
    if record["mounts"]:
        raise HostError("mounts_checkpoint_unsupported")
    if record["pending"] is not None:
        raise HostError("resource_unsettled")
    unclean = accept_unclean(record, allow_unclean)
    may_checkpoint(record)
    config = builtin.resolve(record["provider"])
    check_assets(config["assets"])
    held = states.lease(store, config["state"], claim=False)
    custody = Custody(system, config, scopes.limits_path(store.path))
    ident = new_id("c")
    lock = None
    try:
        domain = custody.begin()
        operation = new_id("o")
        lock = _Lock(store, ident)
        entry = {"schema": SCHEMA, "checkpoint": ident, "provider": record["provider"],
                 "described": record["described"], "source_run": lease.run_id, "resource": record["resource"],
                 "image": record["image"],
                 "worker_release": record["worker_release"], "retention": record["retention"],
                 "limits": record["limits"], "user": record["user"], "project": record["project"],
                 "generation": record["generation"], "storage": record["storage"], "state": "pending",
                 "operation": operation, "domain": domain, "processes": "unknown", "holder": None}

        def publish():
            if len(ids(store)) >= MAX_ENTRIES:
                raise HostError("checkpoint_limit")
            _write(store, entry, first=True)
            lease.save(dict(lease.record, pending=pending("checkpoint", operation, record["generation"], domain,
                                                          checkpoint=ident)))

        scopes.admit(store, config["state"], publish, extra=MAX_RECORD_BYTES)
        outcome, result = custody.invoke({"v": 1, "type": "checkpoint", "operation": operation,
                                          "timeout_ms": CHECKPOINT_TIMEOUT_MS, "run": lease.run_id,
                                          "resource": record["resource"], "checkpoint": ident,
                                          "generation": record["generation"], "accept_unclean": unclean},
                                         record["described"])
        if not custody.settle():
            raise HostError("processes_unsettled")
        if result is not None and result.get("type") == "checkpointed":
            _update(store, ident, state="ready", generation=result["generation"], storage=result["storage"],
                    processes="settled", domain=None)
            lease.save(dict(lease.record, pending=None))
            return ident
        if outcome is not None and outcome["end"] == "failed" and outcome["settlement"] == "settled" \
                and outcome["durability"] == "unchanged":
            _update(store, ident, state="failed", processes="settled", domain=None)
            lease.save(dict(lease.record, pending=None))
        else:
            _update(store, ident, processes="settled", domain=None)
            lease.save(dict(lease.record, pending=dict(lease.record["pending"], processes="settled",
                                                       provider=_end(outcome))))
        raise _provider_error(outcome, custody)
    finally:
        if lock is not None:
            lock.release()
        custody.close()
        held.release()


def discard(system, store, ident):
    lock = _Lock(store, ident)
    custody = held = None
    try:
        entry = read(store, ident)
        if entry["state"] in ("discarded", "retired"):
            return "already_" + entry["state"]
        if entry["holder"] is not None:
            # A restore's reading not settled: `jail stop` of that run.
            raise HostError("checkpoint_unsettled")
        if entry["processes"] != "settled":
            if not kill_recorded(system, entry["domain"]):
                raise HostError("processes_unsettled")
            entry = _update(store, ident, processes="settled", domain=None)
        config = builtin.resolve(entry["provider"])
        check_assets(config["assets"])
        held = states.lease(store, config["state"], claim=False)
        custody = Custody(system, config, scopes.limits_path(store.path))
        domain = custody.begin()
        operation = new_id("o")
        # A failed or lost C keeps its state while discarding: only an
        # affirmative failure may later be retired.
        known_failed = entry["state"] == "failed"
        kept = entry["state"] if entry["state"] in ("failed", "lost") else "discarding"
        entry = _update(store, ident, state=kept, operation=operation, domain=domain, processes="unknown")
        outcome, result = custody.invoke({"v": 1, "type": "discard", "operation": operation,
                                          "timeout_ms": DISCARD_TIMEOUT_MS, "run": entry["source_run"],
                                          "resource": entry["resource"], "checkpoint": ident}, entry["described"])
        if not custody.settle():
            raise HostError("processes_unsettled")
        if result is not None and result.get("type") == "discarded":
            _update(store, ident, state="discarded", processes="settled", domain=None)
            return "discarded"
        if known_failed and outcome is not None and outcome["end"] == "failed" \
                and outcome["code"] == "not_found" and outcome["settlement"] == "settled":
            _update(store, ident, state="retired", processes="settled", domain=None)
            return "retired"
        _update(store, ident, processes="settled", domain=None)
        raise _provider_error(outcome, custody)
    finally:
        if custody is not None:
            custody.close()
        if held is not None:
            held.release()
        lock.release()


def restore(system, store, ident):
    """A new run from ready checkpoint `ident`; its id."""
    lock = _Lock(store, ident)
    custody = held = lease = None
    try:
        entry = read(store, ident)
        if entry["state"] != "ready":
            raise HostError("checkpoint_not_ready")
        if entry["processes"] != "settled" or entry["holder"] is not None:
            raise HostError("checkpoint_unsettled")
        if "restore" not in entry["described"]["operations"]:
            raise HostError("restore_unsupported")
        config = builtin.resolve(entry["provider"])
        check_assets(config["assets"])
        release, manifest = baked_worker(config["state"], entry["image"])
        if release != entry["worker_release"]:
            raise HostError("worker_invalid")
        held = states.lease(store, config["state"], claim=False)
        custody = Custody(system, config, scopes.limits_path(store.path))
        fields = {"provider": entry["provider"], "resource": new_id("res"), "image": entry["image"],
                  "limits": entry["limits"], "described": entry["described"], "user": entry["user"],
                  "retention": entry["retention"], "project": entry["project"],
                  "origin": {"checkpoint": ident, "source_run": entry["source_run"]}}
        created = []
        scopes.admit(store, config["state"], lambda: created.append(store.create_managed(fields, manifest, True)))
        run_id = created[0]
        lease = store.claim(run_id)
        domain = custody.begin()
        create_op, restore_op = new_id("o"), new_id("o")
        # The new run's binding (D, C) first: whatever stops here, `jail stop`
        # of that run finds D and C's reading by it; then C's holder. Nothing
        # is sent before both.
        lease.save(dict(lease.record, pending=pending("create", create_op, 0, domain, checkpoint=ident)))
        _update(store, ident, operation=restore_op, processes="unknown", holder=run_id, domain=domain)
        outcome, result = custody.invoke({"v": 1, "type": "create", "operation": create_op,
                                          "timeout_ms": CREATE_TIMEOUT_MS, "run": run_id,
                                          "resource": fields["resource"], "image": entry["image"],
                                          "retention": entry["retention"], "user": entry["user"]},
                                         entry["described"])
        try:
            commit_create(lease, outcome, result, custody, restoring=True)
        except HostError:
            if custody.domain is None:
                _update(store, ident, processes="settled", holder=None, domain=None)
            raise
        domain = custody.begin()
        lease.save(dict(lease.record, pending=pending("restore", restore_op, lease.record["generation"], domain,
                                                      checkpoint=ident)))
        _update(store, ident, domain=domain)
        outcome, result = custody.invoke({"v": 1, "type": "restore", "operation": restore_op,
                                          "timeout_ms": RESTORE_TIMEOUT_MS, "run": run_id,
                                          "resource": fields["resource"], "checkpoint": ident,
                                          "generation": lease.record["generation"]}, entry["described"])
        if not custody.settle():
            raise HostError("processes_unsettled")
        _update(store, ident, processes="settled", holder=None, domain=None)
        record = lease.record
        if result is not None and result.get("type") == "restored":
            lease.save(dict(record, phase="ready", pending=None, generation=result["generation"],
                            storage=result["storage"]))
            return run_id
        if outcome is not None and outcome["end"] == "failed" and outcome["settlement"] == "settled":
            lease.save(dict(record, phase="partial", pending=None))
        else:
            lease.save(dict(record, pending=dict(record["pending"], processes="settled", provider=_end(outcome))))
        raise _provider_error(outcome, custody)
    finally:
        if lease is not None:
            lease.release()
        if custody is not None:
            custody.close()
        if held is not None:
            held.release()
        lock.release()
