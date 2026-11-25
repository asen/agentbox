"""Copied inputs (the Rust host's inputs.rs, for the new path): operator
selected host sources, staged once by the trusted input worker
(ASSETS/inputs/stage.py, unchanged) into one bounded archive, then uploaded
and set up in the guest before the command (`inputs_setup`).

```text
main.py inputs --run R [--workspace DIR] [--copy SRC=DEST]...
  lease; no inputs yet, no execution yet
  [store lock] admission: reservations + measured + archive limit <= max,
               record inputs = staging{attempt}
  INTERPRETER -I -S -B ASSETS/inputs/stage.py   own process group
    stdin request, stdout RUN/inputs/spool-ATTEMPT (RLIMIT_FSIZE = limit),
    fd 3 one result line; killed and reaped at its timeout or a signal
  spool: the result's size, 0400, renamed to RUN/inputs/archive-ATTEMPT
  (bound to its attempt: a stop between that rename and the record names
  both files by the recorded attempt alone)
  [store lock] inputs = staged{archive_bytes, counts, delivery: null}

exec (inputs staged):
  retention none          every execution: upload, setup (nothing recorded)
  retained / attached     delivery null: recorded `attempted`, upload, setup,
                          recorded `ready`; `attempted`: refused before anything
                          (inputs_setup_uncertain); `ready`: nothing
  upload: scp ARCHIVE -> HOME/.agentbox-inputs-EID.tar (fixed profile)
  guest: hello, inputs_setup{EID} -> its own tar -> inputs_ready, then exec
```

`--workspace DIR` is the copy `DIR -> work` (the default HOME/work; no
project location or mount on the new path before C), `--copy SRC=DEST` a
guest-home-relative destination; destinations never equal or contain each
other. Sources are resolved lexically; the worker refuses symlink
ancestors, special files and the data store. The stage worker spawns
nothing: its process group is all of it. An attempt is discarded only
after this controller reaped its worker. A controller killed meanwhile
leaves `staging`, its worker's end unknown: the attempt keeps its
reservation and spool, and `inputs` and `exec` refuse
(`inputs_staging_unsettled`) until C's explicit reconciliation. Errors are
fixed codes.
"""
import json
import os
import re
import selectors
import time

from .host import Child, Drain, HostError, Loop, read_some, write_some
from .store import INPUT_ARCHIVE, INPUT_SPOOL, INPUTS, _open_dir, _private_dir, is_handle, new_id

STAGE = "inputs/stage.py"
REQUEST_SCHEMA = "agentbox.inputs-request.v1"
RESULT_SCHEMA = "agentbox.inputs-result.v1"
MAX_COPIES = 32
MAX_DESTINATION_BYTES = 1024
MAX_COMPONENT_BYTES = 255
MAX_SOURCE_BYTES = 4096
MAX_RESULT_BYTES = 4096
RESERVED_PREFIX = ".agentbox-inputs-"
OUTSIDE_ROOT = ".agentbox-root"
WORKSPACE = "work"
DEFAULT_SETTINGS = {"archive_bytes": 2 << 30, "entries": 250000, "depth": 128, "path_bytes": 4096,
                    "prepare_timeout_ms": 600000, "upload_timeout_ms": 600000}
RANGES = {"archive_bytes": (1 << 20, 64 << 30), "entries": (1, 1000000), "depth": (1, 1024),
          "path_bytes": (1, 16384), "prepare_timeout_ms": (1000, 86400000),
          "upload_timeout_ms": (1000, 3600000)}
# The worker's own refusals (stage.py `CODES`), passed on as they are.
WORKER_CODES = frozenset((
    "input_request_invalid", "input_output_invalid", "input_source_unavailable",
    "input_source_not_directory", "input_source_symlink_ancestor", "input_source_overlaps_store",
    "input_source_unreadable", "input_source_changed", "input_special_file", "input_entry_limit",
    "input_depth_limit", "input_path_limit", "input_archive_limit", "input_io_error"))
COUNTS = ("entries", "directories", "files", "links", "body_bytes", "archive_bytes")


def check_settings(value):
    if not isinstance(value, dict) or set(value) != set(RANGES) \
            or any(type(value[k]) is not int or not low <= value[k] <= high for k, (low, high) in RANGES.items()):
        raise HostError("run_invalid")
    return value


def settings(overrides):
    """The defaults with the operator's overrides (`--max-archive-bytes`
    ...), each within its fixed range (`input_settings_invalid`)."""
    value = dict(DEFAULT_SETTINGS)
    for key, given in overrides.items():
        if key not in RANGES or type(given) is not int or not RANGES[key][0] <= given <= RANGES[key][1]:
            raise HostError("input_settings_invalid")
        value[key] = given
    return value


_PLAIN = re.compile(r"[A-Za-z0-9._-]{1,255}")


def project(workspace, home):
    """The project location of absolute, lexical `workspace` for the host
    HOME `home` (inputs.rs `project`): its path beneath `home`, else
    `.agentbox-root/` and its whole path."""
    def normal(path):
        return isinstance(path, str) and path.startswith("/") and path != "/" and resolve(path, None) == path
    if not normal(home):
        raise HostError("input_host_home_invalid")
    try:
        ok = normal(workspace)
    except HostError:
        ok = False
    if not ok or workspace == home:
        raise HostError("input_workspace_invalid")
    if workspace.startswith(home + "/"):
        prefix, rest = None, workspace[len(home) + 1:]
    else:
        prefix, rest = OUTSIDE_ROOT, workspace[1:]
    parts = rest.split("/")
    if any(not _PLAIN.fullmatch(p) or p in (".", "..") for p in parts):
        raise HostError("input_workspace_path_unsupported")
    if prefix is None and parts[0].startswith("."):
        raise HostError("input_workspace_hidden")
    location = "/".join(([prefix] if prefix else []) + parts)
    from .assets import provider_protocol
    if not provider_protocol.is_project(location):
        raise HostError("input_workspace_path_unsupported")
    return location


def placed(chosen, record, host_home):
    """`chosen` with the workspace at the run's project location
    (`project_layout`), and that location; a mounted project (fixed at
    creation) takes no workspace; no destination meets a mount's."""
    from .assets import provider_protocol
    managed = record["kind"] == "managed"
    layout = managed and "project_layout" in record["described"]["features"]
    mounts = record["mounts"] if managed else []
    index = next((i for i, (_, _, kind) in enumerate(chosen) if kind == "directory"), None)
    location = record["project"]
    if index is not None and location is not None and mounts:
        raise HostError("input_project_mounted")
    chosen = list(chosen)
    if index is not None and layout:
        location = project(chosen[index][0], host_home)
        chosen[index] = (chosen[index][0], location, "directory")
    for i, (_, dest, _) in enumerate(chosen):
        if any(overlap(dest, other) for _, other, _ in chosen[:i]):
            raise HostError("input_destination_conflict")
        if any(provider_protocol.overlap(dest, m["destination"]) for m in mounts):
            raise HostError("input_mount_conflict")
    return chosen, location


def _component(name):
    return bool(name) and name not in (".", "..") and len(name.encode()) <= MAX_COMPONENT_BYTES \
        and "/" not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name)


def destination(text):
    """A guest-home-relative destination (inputs.rs `destination`)."""
    if not text or len(text.encode()) > MAX_DESTINATION_BYTES or not all(map(_component, text.split("/"))):
        raise HostError("input_destination_invalid")
    if text.startswith(RESERVED_PREFIX) or text.split("/")[0] == OUTSIDE_ROOT:
        raise HostError("input_destination_invalid")
    return text


def overlap(a, b):
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def resolve(path, cwd):
    """Absolute against `cwd` when relative, then lexical: `.` dropped,
    `..` the previous component removed; `/` refused."""
    if not path:
        raise HostError("inputs_selection_invalid")
    if not path.startswith("/"):
        if not cwd or not cwd.startswith("/"):
            raise HostError("input_cwd_unavailable")
        path = f"{cwd}/{path}"
    parts = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    resolved = "/" + "/".join(parts)
    if resolved == "/" or len(resolved.encode()) > MAX_SOURCE_BYTES or "\0" in resolved:
        raise HostError("inputs_selection_invalid")
    return resolved


def selection(workspace, copies, cwd):
    """[(source, destination, kind)] in order: the workspace first."""
    chosen = []
    if workspace is not None:
        chosen.append((resolve(workspace, cwd), WORKSPACE, "directory"))
    for text in copies:
        source, sep, dest = text.partition("=")
        if not sep:
            raise HostError("inputs_selection_invalid")
        chosen.append((resolve(source, cwd), destination(dest), "any"))
    if not 1 <= len(chosen) <= MAX_COPIES:
        raise HostError("inputs_selection_invalid")
    for index, (_, dest, _) in enumerate(chosen):
        if any(overlap(dest, other) for _, other, _ in chosen[:index]):
            raise HostError("input_destination_conflict")
    return chosen


def guest_archive(home, execution_id):
    """The uploaded archive's guest path, from the execution id alone."""
    return f"{home}/{RESERVED_PREFIX}{execution_id}.tar"


def _hex(text):
    return text.encode("utf-8", "surrogateescape").hex()


class Paths:
    """A run's inputs directory (0700) below its run directory."""

    def __init__(self, lease):
        self.lease = lease
        self.root = f"{lease.store.path}/controller-runs/{lease.run_id}/{INPUTS}"

    def open(self, create=False):
        if create:
            try:
                os.mkdir(INPUTS, 0o700, dir_fd=self.lease.run)
            except FileExistsError:
                pass
        fd = _open_dir(INPUTS, self.lease.run)
        if not _private_dir(os.fstat(fd)):
            os.close(fd)
            raise HostError("store_invalid")
        return fd

    def archive(self):
        """The staged archive of the recorded attempt."""
        return f"{self.root}/{archive_name(self.lease.record['inputs']['attempt'])}"


def archive_name(attempt):
    return f"{INPUT_ARCHIVE}-{attempt}"


def _discard(lease, attempt):
    """An attempt whose worker this controller reaped (or never started),
    or the operator asserted ended: its spool, if any; the record's inputs
    back to none only once that file is confirmed gone. Whether it is."""
    paths = Paths(lease)
    try:
        fd = paths.open()
    except FileNotFoundError:
        # Confirmed absent: no spool can be left.
        fd = None
    except (OSError, HostError):
        # Inaccessible is not absent: record and reservation kept.
        return False
    if fd is not None:
        try:
            # Its spool, or the archive it became if publication stopped
            # between the rename and the record: this attempt's names only.
            for name in (f"{INPUT_SPOOL}-{attempt}", archive_name(attempt)):
                try:
                    os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    return False
        finally:
            os.close(fd)
    with lease.store.lock():
        lease.save(dict(lease.record, inputs=None))
    return True


def assert_staging(lease, attempt):
    """The operator's assertion that staging attempt `attempt`'s worker
    ended (never verified): recorded first (`local_end`, `asserted`), then
    its exact spool removed; the reservation released only once removed."""
    inputs = lease.record["inputs"]
    lease.note_asserted(attempt)
    with lease.store.lock():
        lease.save(dict(lease.record, inputs=dict(inputs, local_end="asserted")))
    return _discard(lease, attempt)


def stage(store, lease, chosen, settings, interpreter, assets, environ_path, host_home=None):
    """Stages `chosen` for the run held by `lease`; returns the staged
    record's inputs."""
    from .scopes import admit
    record = lease.record
    inputs = record["inputs"]
    if record["phase"] != "ready":
        raise HostError("run_not_ready")
    if inputs is not None and inputs["state"] == "staging":
        # Its controller is gone, its worker may still write: kept.
        raise HostError("inputs_staging_unsettled")
    if inputs is not None:
        raise HostError("inputs_already_configured")
    if record["kind"] == "managed" and record["origin"] is not None:
        # A restored run inherits no host-input grant.
        raise HostError("inputs_run_restored")
    if lease.execution_count():
        raise HostError("inputs_run_has_history")
    check_settings(settings)
    chosen, location = placed(chosen, record, host_home)
    attempt = new_id("s")
    pending = {"state": "staging", "attempt": attempt, "settings": dict(settings), "copies": len(chosen)}
    data_root = store.path

    def publish():
        lease.save(dict(lease.record, inputs=pending))

    admit(store, None, publish, extra=settings["archive_bytes"])
    paths = Paths(lease)
    directory = paths.open(create=True)
    spool_name = f"{INPUT_SPOOL}-{attempt}"
    try:
        spool = os.open(spool_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                        dir_fd=directory)
    except OSError:
        os.close(directory)
        _discard(lease, attempt)
        raise HostError("io_error") from None
    request = {"schema": REQUEST_SCHEMA, "store_hex": _hex(data_root),
               "copies": [{"source_hex": _hex(src), "destination": dest, "kind": kind}
                          for src, dest, kind in chosen],
               "limits": {k: settings[k] for k in ("archive_bytes", "entries", "depth", "path_bytes")}}
    try:
        result = _run_worker(interpreter, assets, environ_path, request, spool, settings)
        size = os.fstat(spool).st_size
        if result.get("ok") is not True:
            code = result.get("code")
            raise HostError(code if code in WORKER_CODES else "input_worker_failed")
        counts = {k: result[k] for k in COUNTS}
        if counts["archive_bytes"] != size or size > settings["archive_bytes"]:
            raise HostError("input_output_invalid")
        os.fchmod(spool, 0o400)
        os.fsync(spool)
    except BaseException:
        os.close(spool)
        os.close(directory)
        _discard(lease, attempt)
        raise
    os.close(spool)
    try:
        with store.lock():
            os.rename(spool_name, archive_name(attempt), src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
            staged = dict(pending, state="staged", archive_bytes=size, counts=counts, delivery=None)
            lease.save(dict(lease.record, inputs=staged, project=location))
    finally:
        os.close(directory)
    return staged


def _run_worker(interpreter, assets_root, environ_path, request, spool, settings):
    """The worker's one result object, or a fixed refusal."""
    data = json.dumps(request, separators=(",", ":")).encode()
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    loop = Loop()
    loop.install_signals()
    child = None
    try:
        env = {"LC_ALL": "C"}
        if environ_path:
            env["PATH"] = environ_path
        try:
            child = Child([interpreter, "-I", "-S", "-B", os.path.join(assets_root, STAGE)], env,
                          stdout_fd=spool, result_fd=write_end, fsize=settings["archive_bytes"])
        finally:
            os.close(write_end)
        os.set_blocking(read_end, False)
        stdin = child.popen.stdin.fileno()
        err = Drain(loop, child.popen.stderr.fileno(), 4096)
        state = {"pending": data, "result": b"", "ended": False}

        def feed(_mask):
            while state["pending"]:
                written = write_some(stdin, state["pending"])
                if written is None:
                    state["pending"] = b""
                    break
                if written == 0:
                    return
                state["pending"] = state["pending"][written:]
            loop.unwatch(stdin)
            child.popen.stdin.close()

        def collect(_mask):
            chunk = read_some(read_end)
            if chunk is None:
                return
            if not chunk:
                state["ended"] = True
                loop.unwatch(read_end)
                return
            state["result"] += chunk[:MAX_RESULT_BYTES + 1 - len(state["result"])]

        loop.watch(stdin, selectors.EVENT_WRITE, feed)
        loop.watch(read_end, selectors.EVENT_READ, collect)
        deadline = time.monotonic() + settings["prepare_timeout_ms"] / 1000.0
        finished = loop.run(lambda: (state["ended"] and child.exited()) or bool(loop.signals), deadline)
        done = finished and not loop.signals and child.exited()
        err.close()
        if not child.exited():
            child.kill_group()
        code = child.finish()
        if loop.signals:
            raise HostError("interrupted")
        if not done:
            raise HostError("input_prepare_timeout")
        line = state["result"]
        if len(line) > MAX_RESULT_BYTES or not line.endswith(b"\n") or line.count(b"\n") != 1:
            raise HostError("input_worker_failed")
        try:
            result = json.loads(line)
        except ValueError:
            raise HostError("input_worker_failed") from None
        if not isinstance(result, dict) or result.get("schema") != RESULT_SCHEMA:
            raise HostError("input_worker_failed")
        if result.get("ok") is True:
            if set(result) != {"schema", "ok"} | set(COUNTS) or code != 0 \
                    or any(type(result[k]) is not int or result[k] < 0 for k in COUNTS):
                raise HostError("input_worker_failed")
        elif set(result) != {"schema", "ok", "code"} or result["ok"] is not False \
                or result["code"] not in WORKER_CODES:
            raise HostError("input_worker_failed")
        return result
    finally:
        if child is not None and not child.reaped:
            child.stop()
        os.close(read_end)
        loop.close()


def delivery_plan(record):
    """None (nothing to set up), "fresh" (every execution) or "once"
    (retained: recorded attempted, then ready). `attempted` refuses."""
    inputs = record["inputs"]
    if inputs is None:
        return None
    if inputs["state"] != "staged":
        raise HostError("inputs_staging_unsettled")
    if record["retention"] == "none":
        return "fresh"
    if inputs["delivery"] == "ready":
        return None
    if inputs["delivery"] == "attempted":
        raise HostError("inputs_setup_uncertain")
    return "once"


def mark(lease, delivery):
    """The retained run's delivery record (`attempted`, `ready`)."""
    with lease.store.lock():
        inputs = dict(lease.record["inputs"], delivery=delivery)
        lease.save(dict(lease.record, inputs=inputs))


def is_execution(text):
    return is_handle(text, "e")
