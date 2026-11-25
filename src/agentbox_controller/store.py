"""The new-path store: managed runs and attached records, their exclusive
leases, copied inputs, execution records and logs, checkpoints and the
providers' STATE claims, apart from the old CLI's state (never read,
migrated or written).

```text
DATA/                              0700, the operator's
  run-limits.json                  0600: max_reserved_bytes, storage_scopes
  controller-store.json            0600, agentbox.controller-store.v3: written
                                   first, into a root holding no controller-*
                                   entry; any other root refuses (no migration)
  controller-runs/                 0700
    .lock                          store lock: admission, creation and a name's lookup
    RUN_ID/                        0700
      run.json                     0600, agentbox.controller-run.v3, replaced atomically
      lease                        0600, flock inode, never replaced
      worker-manifest.json         0400, the worker's exact manifest (baked or bundled)
      executions/EXECUTION_ID.json 0600, agentbox.controller-execution.v2
      session/EXECUTION_ID/        0700, fresh SSH identity and known_hosts (x-HEX: an export's)
      owner/                       0700, the owner's records (owner.py): owner.json, shell.json
      inputs/                      0700, copied inputs: spool-ATTEMPT, archive-ATTEMPT (0400)
  controller-logs/RUN_ID/EXECUTION_ID/events.jsonl
  controller-spool/RUN_ID-EXECUTION_ID/   an execution's acquisition stages
                                   (or beneath its --acquisition-stage-root)
  controller-checkpoints/          checkpoints.py
  controller-states/KEY/           states.py: a provider STATE's lease, claim, prepare
```

A record is `managed` (a provider resource: provider, resource, image,
described capabilities, limits, account, mounts, project, `retention`) or
`attached` (an operator's SSH target, pinned by its canonical SHA-256;
retention `operator`). A managed run's `volume` (optional; absent or
null: none): its provider's display name of a retained HOME kept outside
the provider's STATE (`created.volume`, a shared Podman store), shown by
`jail status`, never used as a handle. `name` (optional; absent or null: unnamed): `jail
create -t NAME`, an image tag's rules, never shaped like a run id, held by
at most one live (not `discarded`) run: checked and the record published
under the store lock, so a name is free again only once its run is
discarded; the run's id never changes. `phase`: `creating` (recorded
before `create`), `partial` (only `jail discard` applies), `ready`,
`discarded`. `storage` `clean`/`unclean` with `generation`: an unclean
resource starts only with the operator's acknowledgement of that exact
generation.

Ownership: an operation holds an exclusive `flock` on the run's `lease`
for its whole life. A free lease and a `pending` operation mean the
controller is gone, never that anything stopped: `pending` is written
before the request that uses its handles and its cgroup domain before that
domain's first process, and is cleared only by the provider's answer
together with the domain killed and read empty (`processes: settled`).
Anything less stays pending for `jail stop`.

An execution's acquisition spool is reserved in its record (`spool`) from
admission until its directory is confirmed removed after everything that
could use it settled; a finished record keeps `spool` when that was not
confirmed. Managed: the run's domains read empty prove it. Attached runs
and input staging have no such proof (the user's decision: no delegation
required there): only the operator's explicit assertion of one exact id
(`jail stop --assert-local-ended`) releases them, recorded as asserted
(`local_end`, `asserted`), never as verified.

An export (export.py) reserves its byte limit in the run record (`export`:
operation `x-HEX`, `max_bytes`, `processes`) before its partial file
exists, until it is published or removed by its own live descriptor. No
destination is stored: a reservation left by a crash blocks exec, export
and discard until the operator's exact assertion (`jail stop
--assert-local-ended x-HEX`, the user's decision) releases it; a partial
may remain beside the destination then, the operator's.
"""
import errno
import fcntl
import json
import os
import re
import secrets
import shutil
import stat

from .assets import provider_protocol
from .config import check_recorded
from .host import HostError

STORE_SCHEMA = "agentbox.controller-store.v3"
RUN_SCHEMA = "agentbox.controller-run.v3"
EXECUTION_SCHEMA = "agentbox.controller-execution.v2"
MARKER = "controller-store.json"
RUNS = "controller-runs"
LOGS = "controller-logs"
SPOOL = "controller-spool"
CHECKPOINTS = "controller-checkpoints"
STATES = "controller-states"
OWN_ENTRIES = (RUNS, LOGS, SPOOL, CHECKPOINTS, STATES)
LOCK = ".lock"
RUN_FILE = "run.json"
LEASE = "lease"
MANIFEST = "worker-manifest.json"
EXECUTIONS = "executions"
SESSION = "session"
INPUTS = "inputs"
INPUT_SPOOL = "spool"
INPUT_ARCHIVE = "archive"
MAX_RUN_RECORD_BYTES = 32 * 1024
MAX_EXECUTION_RECORD_BYTES = 8192
MAX_MANIFEST_BYTES = 64 * 1024
MAX_MARKER_BYTES = 1024
SESSION_BYTES = 64 * 1024
LOG_BYTES = (1 << 20, 1 << 30)
DEFAULT_LOG_BYTES = 64 << 20
MAX_EXECUTIONS = 4096
MAX_ASSERTED = 64
_HEX = re.compile(r"[0-9a-f]{32}")
_SHA = re.compile(r"[0-9a-f]{64}")
PHASES = ("creating", "partial", "ready", "discarded")
STORAGE = ("clean", "unclean")
PENDING_OPS = ("start", "stop", "create", "restore", "discard", "checkpoint")
PENDING_KEYS = {"op", "operation", "execution", "instance", "generation", "domain", "processes",
                "provider", "settlement", "durability", "code", "checkpoint"}
DESCRIBED_KEYS = ("operations", "transport", "retention", "limits", "features")


def new_id(prefix):
    return f"{prefix}-{secrets.token_hex(16)}"


def is_handle(text, prefix):
    return isinstance(text, str) and text.startswith(prefix + "-") \
        and _HEX.fullmatch(text[len(prefix) + 1:]) is not None


def is_name(text):
    """A run name: an image tag's rules (images.TAG), never a run id."""
    from .images import TAG
    return isinstance(text, str) and TAG.fullmatch(text) is not None and not is_handle(text, "r")


def check_name(text):
    if not is_name(text):
        raise HostError("run_name_invalid")
    return text


def _private_dir(st):
    return stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700


def _open_dir(name, dir_fd):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)


def _ensure_dir(name, dir_fd):
    try:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
    except FileExistsError:
        pass
    fd = _open_dir(name, dir_fd)
    if not _private_dir(os.fstat(fd)):
        os.close(fd)
        raise HostError("store_invalid")
    return fd


def _read(dir_fd, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077 \
                or st.st_size > limit:
            raise HostError("store_invalid")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise HostError("store_invalid")
    return data


def _write_new(dir_fd, name, data, mode):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode,
                 dir_fd=dir_fd)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _replace(dir_fd, name, data):
    """Atomic: a fresh private file, synced, renamed over `name`, the
    directory synced."""
    temp = f".{name}.{secrets.token_hex(8)}"
    _write_new(dir_fd, temp, data, 0o600)
    try:
        os.rename(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except OSError:
        os.unlink(temp, dir_fd=dir_fd)
        raise
    os.fsync(dir_fd)


def _dump(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


COMMON_KEYS = {"schema", "run_id", "kind", "phase", "worker_release", "user", "home", "retention",
               "log_bytes", "generation", "storage", "pending", "inputs", "project", "asserted", "export"}
MANAGED_KEYS = COMMON_KEYS | {"provider", "provider_sha256", "resource", "image", "limits", "described",
                              "mounts", "origin", "create_refused"}
ATTACHED_KEYS = COMMON_KEYS | {"target", "target_sha256"}
INPUT_STATES = ("staging", "staged")
DELIVERIES = (None, "attempted", "ready")


def check_inputs(value):
    """`None`, a staging attempt (`s-HEX`; `local_end` once the operator
    asserted its worker ended) or a staged archive (inputs.py)."""
    from .inputs import check_settings
    if value is None:
        return
    keys = {"state", "attempt", "settings", "copies"}
    extra = {"archive_bytes", "counts", "delivery"} if value.get("state") == "staged" else set()
    if value.get("state") == "staging" and "local_end" in value:
        extra = {"local_end"}
    if not isinstance(value, dict) or value.get("state") not in INPUT_STATES \
            or set(value) != keys | extra or not is_handle(value["attempt"], "s") \
            or not isinstance(value["copies"], int) or not 1 <= value["copies"] <= 32 \
            or value.get("local_end", "asserted") != "asserted":
        raise HostError("run_invalid")
    check_settings(value["settings"])
    if value["state"] == "staged" and (type(value["archive_bytes"]) is not int or value["archive_bytes"] < 1
                                       or value["archive_bytes"] > value["settings"]["archive_bytes"]
                                       or not isinstance(value["counts"], dict)
                                       or value["delivery"] not in DELIVERIES):
        raise HostError("run_invalid")


def check_export(value):
    """`None` or an export's reservation (export.py)."""
    from .export import MAX_BYTES
    if value is None:
        return
    if not isinstance(value, dict) or set(value) != {"operation", "max_bytes", "processes"} \
            or not is_handle(value["operation"], "x") or type(value["max_bytes"]) is not int \
            or not MAX_BYTES[0] <= value["max_bytes"] <= MAX_BYTES[1] \
            or value["processes"] not in ("unknown", "settled"):
        raise HostError("run_invalid")


def is_project(text):
    return provider_protocol.is_project(text)


def check_described(value):
    if not isinstance(value, dict) or any(k not in value for k in DESCRIBED_KEYS) \
            or not all(isinstance(value[k], list) and all(isinstance(i, str) for i in value[k])
                       for k in ("operations", "retention", "limits", "features")) \
            or value["transport"] not in ("tcp", "stdio"):
        raise HostError("run_invalid")


def check_mounts(mounts):
    from .mounts import valid
    if not isinstance(mounts, list) or not valid(mounts):
        raise HostError("run_invalid")


def check_record(record):
    if not isinstance(record, dict) or record.get("schema") != RUN_SCHEMA \
            or record.get("kind") not in ("managed", "attached") \
            or set(record) - ({"name", "volume"} if record["kind"] == "managed" else {"name"}) \
            != (MANAGED_KEYS if record["kind"] == "managed" else ATTACHED_KEYS) \
            or not is_handle(record["run_id"], "r") \
            or (record.get("volume") is not None and not provider_protocol.is_volume(record["volume"])) \
            or (record.get("name") is not None and not is_name(record["name"])):
        raise HostError("run_invalid")
    if not isinstance(record["worker_release"], str) or _SHA.fullmatch(record["worker_release"]) is None \
            or not provider_protocol.is_user(record["user"]) \
            or record["phase"] not in PHASES or record["storage"] not in STORAGE \
            or (record["home"] is not None and not provider_protocol.is_path(record["home"])) \
            or (record["home"] is None and record["phase"] not in ("creating", "partial", "discarded")) \
            or type(record["log_bytes"]) is not int \
            or not LOG_BYTES[0] <= record["log_bytes"] <= LOG_BYTES[1] \
            or type(record["generation"]) is not int or record["generation"] < 0 \
            or (record["project"] is not None and not is_project(record["project"])) \
            or not isinstance(record["asserted"], list) or len(record["asserted"]) > MAX_ASSERTED \
            or not all(is_handle(i, "e") or is_handle(i, "s") or is_handle(i, "x") for i in record["asserted"]):
        raise HostError("run_invalid")
    if record["kind"] == "managed":
        check_recorded(record["provider"])
        check_described(record["described"])
        check_mounts(record["mounts"])
        origin = record["origin"]
        if not is_handle(record["resource"], "res") \
                or not isinstance(record["provider_sha256"], str) \
                or _SHA.fullmatch(record["provider_sha256"]) is None \
                or provider_digest(record["provider"]) != record["provider_sha256"] \
                or not isinstance(record["image"], str) or _SHA.fullmatch(record["image"]) is None \
                or record["retention"] not in provider_protocol.RETENTION \
                or not isinstance(record["limits"], dict) or type(record["create_refused"]) is not bool \
                or (record["mounts"] and record["retention"] == "none") \
                or (origin is not None and (not isinstance(origin, dict) or set(origin) != {"checkpoint", "source_run"}
                                            or not is_handle(origin["checkpoint"], "c")
                                            or not is_handle(origin["source_run"], "r"))):
            raise HostError("run_invalid")
        for key, value in record["limits"].items():
            if key not in provider_protocol.LIMIT_RANGES or type(value) is not int:
                raise HostError("run_invalid")
        pending = record["pending"]
        if pending is not None and (not isinstance(pending, dict) or set(pending) != PENDING_KEYS
                                    or pending["op"] not in PENDING_OPS
                                    or pending["processes"] not in ("unknown", "settled")):
            raise HostError("run_invalid")
    else:
        from .attached import check_target, target_digest
        check_target(record["target"])
        if record["target_sha256"] != target_digest(record["target"]) or record["retention"] != "operator" \
                or record["pending"] is not None or record["generation"] != 0 or record["storage"] != "clean" \
                or record["phase"] not in ("ready", "discarded") \
                or record["user"] != record["target"]["user"]:
            raise HostError("run_invalid")
    check_inputs(record["inputs"])
    check_export(record["export"])
    return record


def provider_digest(provider):
    import hashlib
    return hashlib.sha256(_dump(provider)).hexdigest()


class Store:
    """The opened data root. Its root must exist, ours, 0700, and be a v3
    store or hold no controller entry yet (then it becomes one: its marker
    first). Anything else refuses before any write."""

    def __init__(self, data):
        try:
            self.root = os.open(data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise HostError("store_unavailable") from None
        if not _private_dir(os.fstat(self.root)):
            os.close(self.root)
            raise HostError("store_invalid")
        self.path = data
        try:
            self.id = self._marker()
            self.runs = _ensure_dir(RUNS, self.root)
            self.logs = _ensure_dir(LOGS, self.root)
        except OSError:
            os.close(self.root)
            raise HostError("store_invalid") from None
        except HostError:
            os.close(self.root)
            raise

    def _marker(self):
        """The store's id from its marker; a fresh root gets one."""
        try:
            raw = _read(self.root, MARKER, MAX_MARKER_BYTES)
        except FileNotFoundError:
            names = set(os.listdir(self.root))
            if names & set(OWN_ENTRIES):
                # A B2 (v2) root or another layout: never migrated.
                raise HostError("store_version_unsupported") from None
            ident = secrets.token_hex(16)
            try:
                _write_new(self.root, MARKER, _dump({"schema": STORE_SCHEMA, "store": ident}), 0o600)
                os.fsync(self.root)
                return ident
            except FileExistsError:
                raw = _read(self.root, MARKER, MAX_MARKER_BYTES)
        return _check_marker(raw)

    def close(self):
        for fd in (self.runs, self.logs, self.root):
            os.close(fd)

    def lock(self):
        """The store lock (blocking flock), for admission and creation."""
        fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.runs)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return _Held(fd)

    def run_ids(self):
        names = os.listdir(self.runs)
        return [n for n in names if is_handle(n, "r")]

    def named(self, name):
        """The live (not discarded) runs named `name`; the caller holds the
        store lock. Every record read strictly: any unreadable one refuses
        (`run_invalid`), never an unproven answer."""
        found = []
        for run_id in self.run_ids():
            run = self._open_run(run_id)
            try:
                record = self.read_record(run, run_id)
            finally:
                os.close(run)
            if record.get("name") == name and record["phase"] != "discarded":
                found.append(run_id)
        return found

    def name_free(self, name):
        """`run_name_taken` if a live run holds `name`: a creation's early
        check, before any provider work (the binding one is its publish's)."""
        with self.lock():
            if self.named(name):
                raise HostError("run_name_taken")

    def resolve(self, text):
        """A run selector, once at a command's entry: a run id as is, else
        the id of the one live run named `text` (`run_unknown`: none;
        `run_name_ambiguous`: more); anything else `run_invalid`."""
        if is_handle(text, "r"):
            return text
        if not is_name(text):
            raise HostError("run_invalid")
        with self.lock():
            found = self.named(text)
        if not found:
            raise HostError("run_unknown")
        if len(found) > 1:
            raise HostError("run_name_ambiguous")
        return found[0]

    def create_managed(self, fields, manifest, locked=False):
        """Records a managed run (phase `creating`, nothing sent yet; or a
        test fixture's ready one). `fields`: every managed key but the
        common bookkeeping. Nothing is overwritten. `locked`: the caller
        holds the store lock (an admission's publish)."""
        check_recorded(fields["provider"])
        base = {"kind": "managed", "provider_sha256": provider_digest(fields["provider"]), "phase": "creating",
                "home": None, "generation": 0, "storage": "clean", "pending": None, "inputs": None,
                "project": None, "asserted": [], "export": None, "mounts": [], "origin": None,
                "create_refused": False, "name": None,
                "log_bytes": DEFAULT_LOG_BYTES}
        return self._create(manifest, dict(base, **fields), locked)

    def create_attached(self, target, manifest, home, log_bytes=DEFAULT_LOG_BYTES, name=None):
        """Records an attached run on a validated SSH target (attached.py):
        local state only, nothing contacted."""
        from .attached import target_digest
        return self._create(manifest, {
            "kind": "attached", "target": target, "target_sha256": target_digest(target), "phase": "ready",
            "user": target["user"], "home": home, "log_bytes": log_bytes, "retention": "operator",
            "generation": 0, "storage": "clean", "pending": None, "inputs": None, "project": None,
            "asserted": [], "export": None, "name": name}, False)

    def _create(self, manifest, fields, locked):
        import contextlib
        import hashlib
        from .assets import worker_layout
        text = manifest.encode() if isinstance(manifest, str) else manifest
        try:
            worker_layout.listing(text)
        except worker_layout.Refused:
            raise HostError("manifest_invalid") from None
        run_id = new_id("r")
        record = dict(fields, schema=RUN_SCHEMA, run_id=run_id, worker_release=hashlib.sha256(text).hexdigest())
        check_record(record)
        with (contextlib.nullcontext() if locked else self.lock()):
            if record["name"] is not None and self.named(record["name"]):
                raise HostError("run_name_taken")
            os.mkdir(run_id, 0o700, dir_fd=self.runs)
            run = _open_dir(run_id, self.runs)
            try:
                _write_new(run, LEASE, b"", 0o600)
                os.mkdir(EXECUTIONS, 0o700, dir_fd=run)
                _write_new(run, MANIFEST, text, 0o400)
                _write_new(run, RUN_FILE, _dump(record), 0o600)
                os.fsync(run)
            finally:
                os.close(run)
            os.fsync(self.runs)
        return run_id

    def _open_run(self, run_id):
        if not is_handle(run_id, "r"):
            raise HostError("run_invalid")
        try:
            fd = _open_dir(run_id, self.runs)
        except FileNotFoundError:
            raise HostError("run_unknown") from None
        except OSError:
            raise HostError("run_invalid") from None
        if not _private_dir(os.fstat(fd)):
            os.close(fd)
            raise HostError("run_invalid")
        return fd

    def read_record(self, run_fd, run_id):
        return _load_record(run_fd, run_id)

    def claim(self, run_id):
        """The run's exclusive lease, or `run_busy`."""
        run = self._open_run(run_id)
        try:
            lease = os.open(LEASE, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=run)
        except OSError:
            os.close(run)
            raise HostError("run_invalid") from None
        try:
            fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(lease)
            os.close(run)
            if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
                raise HostError("run_busy") from None
            raise HostError("run_invalid") from None
        return Lease(self, run_id, run, lease)

    def status(self, run_id):
        """`active` (a holder has the lease), else `abandoned` (no holder,
        a managed operation still pending: its resources may live),
        `interrupted` (no holder, an execution begun and never finished: its
        local processes may live; an attached run has no domain holding
        them) or `idle`; with the bytes still reserved for executions'
        acquisition spools. Of the local store only: never the jail's
        state."""
        run = self._open_run(run_id)
        try:
            record = self.read_record(run, run_id)
            lease = os.open(LEASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=run)
            try:
                try:
                    fcntl.flock(lease, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    held = False
                except OSError:
                    held = True
            finally:
                os.close(lease)
            begun, reserved, holding = self._executions(run)
        finally:
            os.close(run)
        if held:
            state = "active"
        elif record["pending"] is not None:
            state = "abandoned"
        elif begun:
            state = "interrupted"
        else:
            state = "idle"
        return {"state": state, "record": record, "spool_reserved": reserved, "holding": holding}

    def _executions(self, run):
        """(executions begun and never finished, the bytes every execution
        record still reserves for its acquisition spool, the ids of those
        holding a reservation)."""
        begun = reserved = 0
        holding = []
        for execution_id, value in _execution_records(run).items():
            begun += value.get("state") == "begun"
            if _spool(value):
                reserved += _spool(value)
                holding.append(execution_id)
        return begun, reserved, holding

    def charges(self):
        """The store's reservations, under the store lock: per run its
        record, manifest, session reserve, each execution's log budget and
        record (at least one), an unfinished execution's spool reservation
        and its copied inputs (a staging attempt at its archive limit), the
        latter whatever the run's phase until a confirmed removal clears
        them from the record; every run strictly validated."""
        total = 0
        for run_id in self.run_ids():
            run = self._open_run(run_id)
            try:
                record = self.read_record(run, run_id)
                executions = set(_names(_open_dir(EXECUTIONS, run), ".json"))
                total += self._executions(run)[1]
            finally:
                os.close(run)
            inputs = record["inputs"]
            if inputs is not None:
                total += inputs["archive_bytes"] if inputs["state"] == "staged" \
                    else inputs["settings"]["archive_bytes"]
            if record["export"] is not None:
                total += record["export"]["max_bytes"]
            try:
                logs = _open_dir(run_id, self.logs)
                executions |= set(_names(logs, ""))
            except FileNotFoundError:
                pass
            total += MAX_RUN_RECORD_BYTES + MAX_MANIFEST_BYTES + SESSION_BYTES \
                + (record["log_bytes"] + MAX_EXECUTION_RECORD_BYTES) * max(1, len(executions))
        from .checkpoints import charges as checkpoint_charges
        return total + checkpoint_charges(self)


def _load_record(run_fd, run_id):
    try:
        record = json.loads(_read(run_fd, RUN_FILE, MAX_RUN_RECORD_BYTES))
    except (OSError, ValueError, HostError):
        raise HostError("run_invalid") from None
    check_record(record)
    if record["run_id"] != run_id:
        raise HostError("run_invalid")
    return record


def _check_marker(raw):
    """The store's id from its marker's bytes."""
    try:
        value = json.loads(raw)
    except ValueError:
        value = None
    if not isinstance(value, dict) or value.get("schema") != STORE_SCHEMA \
            or not isinstance(value.get("store"), str) or _HEX.fullmatch(value["store"]) is None:
        raise HostError("store_version_unsupported")
    return value["store"]


def _shared(runs):
    """The existing store lock, held shared; None when absent (never
    made here)."""
    try:
        fd = os.open(LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=runs)
    except FileNotFoundError:
        return None
    except OSError:
        raise HostError("store_invalid") from None
    try:
        fcntl.flock(fd, fcntl.LOCK_SH)
    except OSError:
        os.close(fd)
        raise HostError("store_invalid") from None
    return fd


def listing(data):
    """`jail list`: every run's (id, record, or None when unreadable),
    ordered by id, read only: no root, marker, directory or lock file is
    ever made (an absent root or store: none). Runs are read only under
    the store lock (shared), so no creation is seen half made; run
    directories without that lock refuse (`store_invalid`)."""
    try:
        root = os.open(data, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return []
    except OSError:
        raise HostError("store_unavailable") from None
    try:
        if not _private_dir(os.fstat(root)):
            raise HostError("store_invalid")
        try:
            raw = _read(root, MARKER, MAX_MARKER_BYTES)
        except FileNotFoundError:
            if set(os.listdir(root)) & set(OWN_ENTRIES):
                raise HostError("store_version_unsupported") from None
            return []
        except OSError:
            raise HostError("store_invalid") from None
        _check_marker(raw)
        try:
            runs = _open_dir(RUNS, root)
        except FileNotFoundError:
            return []
        except OSError:
            raise HostError("store_invalid") from None
    finally:
        os.close(root)
    lock = None
    try:
        if not _private_dir(os.fstat(runs)):
            raise HostError("store_invalid")
        lock = _shared(runs)
        if lock is None:
            # No creation ever began, unless one is beginning now: it
            # makes the lock before its run's directory.
            if not any(is_handle(n, "r") for n in os.listdir(runs)):
                return []
            lock = _shared(runs)
            if lock is None:
                raise HostError("store_invalid")
        found = []
        for run_id in sorted(n for n in os.listdir(runs) if is_handle(n, "r")):
            try:
                run = _open_dir(run_id, runs)
                try:
                    record = _load_record(run, run_id) if _private_dir(os.fstat(run)) else None
                finally:
                    os.close(run)
            except (OSError, HostError):
                record = None
            found.append((run_id, record))
        return found
    finally:
        if lock is not None:
            os.close(lock)
        os.close(runs)


def absent(path):
    """Confirmed absence of `path` (no link followed): only ENOENT. Any
    other inspection error, or anything there (a broken link included),
    is not absent: what it would release stays reserved."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def spool_path(store, value, run_id, execution_id):
    """An execution's spool directory: beneath its recorded stage root
    (`--acquisition-stage-root`), else the store's own."""
    root = value.get("spool_root") or f"{store.path}/{SPOOL}"
    if not provider_protocol.is_path(root):
        raise HostError("run_invalid")
    return f"{root}/{run_id}-{execution_id}"


def _spool(value):
    spool = value.get("spool", 0)
    if type(spool) is not int or spool < 0:
        raise HostError("run_invalid")
    return spool


def _execution_records(run):
    """{execution id: its record}, each a JSON object."""
    executions = _open_dir(EXECUTIONS, run)
    found = {}
    try:
        for name in sorted(os.listdir(executions)):
            if not name.endswith(".json") or not is_handle(name[:-5], "e"):
                continue
            try:
                value = json.loads(_read(executions, name, MAX_EXECUTION_RECORD_BYTES))
            except (OSError, ValueError, HostError):
                raise HostError("run_invalid") from None
            if not isinstance(value, dict):
                raise HostError("run_invalid")
            found[name[:-5]] = value
    finally:
        os.close(executions)
    return found


def _names(fd, suffix):
    try:
        return [n[:len(n) - len(suffix)] if suffix else n for n in os.listdir(fd)
                if n.endswith(suffix) and is_handle(n[:len(n) - len(suffix)] if suffix else n, "e")]
    finally:
        os.close(fd)


class _Held:
    def __init__(self, fd):
        self.fd = fd

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)


class Lease:
    """An exclusive hold on one run, until `release`."""

    def __init__(self, store, run_id, run_fd, lease_fd):
        self.store, self.run_id, self.run, self.lease = store, run_id, run_fd, lease_fd
        self.record = store.read_record(run_fd, run_id)
        try:
            self.manifest = _read(run_fd, MANIFEST, MAX_MANIFEST_BYTES)
        except (OSError, HostError):
            raise HostError("run_invalid") from None

    def save(self, record):
        check_record(record)
        _replace(self.run, RUN_FILE, _dump(record))
        self.record = record

    def update_pending(self, **fields):
        record = dict(self.record)
        pending = dict(record["pending"])
        pending.update(fields)
        record["pending"] = pending
        self.save(record)

    def execution_count(self):
        return len(_names(_open_dir(EXECUTIONS, self.run), ".json"))

    def write_execution(self, execution_id, value, first=False):
        value = dict(value, schema=EXECUTION_SCHEMA, run_id=self.run_id, execution_id=execution_id)
        data = _dump(value)
        if len(data) > MAX_EXECUTION_RECORD_BYTES:
            raise HostError("record_too_large")
        executions = _open_dir(EXECUTIONS, self.run)
        try:
            if first:
                _write_new(executions, execution_id + ".json", data, 0o600)
                os.fsync(executions)
            else:
                _replace(executions, execution_id + ".json", data)
        finally:
            os.close(executions)

    def finalize_interrupted(self, settled):
        """Earlier executions, their controller gone (the lease is ours).
        A free lease is no settlement: an execution's spool reservation
        (`spool`: begun, or finished with its spool unconfirmed) is released
        only when `settled` (every process that could still use it proven
        ended: a managed run's domains killed and read empty, nothing
        pending) and its directory confirmed removed. Unsettled, a begun
        record stays begun (`interrupted`) with its reservation and files;
        one without a reservation is finished `interrupted`. Returns
        (records changed, records still begun, bytes still reserved)."""
        changed = begun = reserved = 0
        for execution_id, value in _execution_records(self.run).items():
            spool = _spool(value)
            if value.get("state") != "begun" and not spool:
                continue
            if spool and not settled:
                begun += value.get("state") == "begun"
                reserved += spool
                continue
            if spool:
                path = spool_path(self.store, value, self.run_id, execution_id)
                shutil.rmtree(path, ignore_errors=True)
                if not absent(path):
                    reserved += spool
                else:
                    spool = 0
            if self._settle_record(execution_id, value, spool):
                changed += 1
        return changed, begun, reserved

    def _settle_record(self, execution_id, value, spool, asserted=False):
        """A begun record finished `interrupted`; `spool` what stays
        reserved (its root kept with it); `asserted`: `local_end` recorded.
        Whether anything was written."""
        kept = {k: v for k, v in value.items() if k not in ("schema", "run_id", "execution_id")}
        if value.get("state") == "begun":
            update = {"state": "finished", "outcome": "interrupted"}
            if "local_end" in value:
                update["local_end"] = value["local_end"]
        else:
            update = {k: v for k, v in kept.items() if k not in ("spool", "spool_root")}
        if spool:
            update["spool"] = spool
            if "spool_root" in value:
                update["spool_root"] = value["spool_root"]
        if asserted:
            update["local_end"] = "asserted"
        if update == kept:
            return False
        self.write_execution(execution_id, update)
        return True

    def execution(self, execution_id):
        """One execution record, or None."""
        return _execution_records(self.run).get(execution_id)

    def assert_execution(self, execution_id):
        """The operator's assertion that execution `execution_id`'s local
        work ended (never verified): its exact spool removed; its reservation
        released only once that removal is confirmed. Recorded `local_end:
        asserted` on the execution and in the run's `asserted`. Returns
        whether the spool is gone."""
        value = self.execution(execution_id)
        spool = _spool(value)
        path = spool_path(self.store, value, self.run_id, execution_id)
        # The assertion recorded before its effect.
        self.note_asserted(execution_id)
        shutil.rmtree(path, ignore_errors=True)
        gone = absent(path)
        self._settle_record(execution_id, value, 0 if gone else spool, asserted=True)
        return gone

    def note_asserted(self, ident):
        asserted = list(self.record["asserted"])
        if ident not in asserted:
            if len(asserted) >= MAX_ASSERTED:
                raise HostError("assertion_limit")
            self.save(dict(self.record, asserted=asserted + [ident]))

    def log_dir(self, execution_id):
        """A fresh private log directory for the execution (its fd)."""
        run_logs = _ensure_dir(self.run_id, self.store.logs)
        try:
            os.mkdir(execution_id, 0o700, dir_fd=run_logs)
            return _open_dir(execution_id, run_logs)
        finally:
            os.close(run_logs)

    def session_dir(self, execution_id):
        """A fresh private directory for the execution's SSH files: its
        path (ssh reads them by path)."""
        session = _ensure_dir(SESSION, self.run)
        try:
            os.mkdir(execution_id, 0o700, dir_fd=session)
        finally:
            os.close(session)
        return f"{self.store.path}/{RUNS}/{self.run_id}/{SESSION}/{execution_id}"

    def remove_session(self, execution_id):
        """Best effort: the execution's SSH files."""
        try:
            session = _open_dir(SESSION, self.run)
        except OSError:
            return
        try:
            directory = _open_dir(execution_id, session)
            try:
                for name in os.listdir(directory):
                    os.unlink(name, dir_fd=directory)
            finally:
                os.close(directory)
            os.rmdir(execution_id, dir_fd=session)
        except OSError:
            pass
        finally:
            os.close(session)

    def remove_session_all(self):
        """Best effort: every execution's SSH files (no writer is left)."""
        try:
            session = _open_dir(SESSION, self.run)
        except OSError:
            return
        try:
            names = [n for n in os.listdir(session) if is_handle(n, "e") or is_handle(n, "x")]
        finally:
            os.close(session)
        for name in names:
            self.remove_session(name)

    def release(self):
        """Once; again: nothing."""
        if self.lease is None:
            return
        os.close(self.lease)
        os.close(self.run)
        self.lease = self.run = None
