"""The managed lifecycle (contracts/provider/v1; the old CLI's
operations.rs is the behaviour reference): image prepare and recover, jail
create, stop and discard, and the operator's explicit assertion.

```text
image prepare  STATE lease -> capabilities -> D -> prepare record {D,
               processes unknown} -> prepare (leaf of D) -> D killed, read
               empty -> record cleared -> image counted once its worker
               metadata reads back with the reported release
image recover  STATE lease -> the recorded D adopted, killed, read empty
jail create    STATE lease -> capabilities -> checks (retention, limits,
               user, mounts) -> admission + record (creating) -> D ->
               pending create {D, unknown} -> create -> gate -> ready |
               partial (settled failed; a CREATE_REFUSALS code, unchanged:
               create_refused)
jail stop      lease -> pending: the recorded D killed and read empty
               (processes settled) -> by op: start/stop a standalone stop
               in a fresh D; create/restore partial (discard only);
               checkpoint released (its entry failed); discard kept for
               `jail discard` -> earlier executions' spools released
               (managed: the domains read empty). Unproven local work
               (attached executions, input staging, a left export
               reservation) is listed, never settled here:
               --assert-local-ended ID
jail discard   lease -> nothing unsettled -> STATE lease -> D -> pending
               discard -> discard -> gate -> discarded (a create_refused
               partial run's settled not_found: retired); then the run's
               copied inputs and session files removed; records stay
```

The gate: a transition commits only once its domain was killed and read
empty (`processes: settled`); otherwise the record keeps the pending
operation, its domain and `unknown`. Every refusal before the record is
written leaves nothing. A signal cancels the in-flight request (one grace,
CANCEL_GRACE); a second ends the wait at once, the domain then killed.
"""
import os
import time

from . import builtin, cgroups, provider, scopes, states
from .assets import provider_protocol, worker_layout
from .config import check_assets, legacy_data_dirs, read_private
from .host import HostError, Loop, capture_host
from .store import PENDING_KEYS, _spool, is_handle, new_id, provider_digest

PREPARE_TIMEOUT_MS = 4 * 3600 * 1000
CREATE_TIMEOUT_MS = 600000
DISCARD_TIMEOUT_MS = 600000
KILL_TIMEOUT = 10.0
METADATA_SCHEMA = "agentbox.worker-build.v2"
METADATA_FILE = "worker-metadata.json"
MAX_METADATA_BYTES = 1 << 20
# A plain create's provider refusals that made nothing (settled,
# unchanged): the run is marked `create_refused`, retired by discard on the
# provider's settled not_found. The mount codes: the provider's own check
# of each source (Podman's shared store adds its store's paths there only).
CREATE_REFUSALS = ("user_conflict", "mount_source_unavailable", "mount_source_unsupported",
                   "mount_source_protected", "mount_source_overlap")


def pending(op, operation, generation, domain, **fields):
    value = {k: None for k in PENDING_KEYS}
    value.update(op=op, operation=operation, generation=generation, domain=domain, processes="unknown",
                 provider="requested")
    value.update(fields)
    return value


# A provider that keeps nothing between executions.
NO_RETENTION_HINT = ("this provider keeps no HOME between executions: agentbox run AGENT --discard (no --export-to, "
                     "no mounts), or agentbox jail create without --retention")
# A provider whose retained storage is made only when asked for by name
# (`explicit_retention`: Podman's shared store).
EXPLICIT_RETENTION_HINT = ("this provider keeps a HOME only when asked: agentbox jail create -t NAME --retention home, "
                           "then agentbox run AGENT --jail NAME ...")


def baked_worker(state, image):
    """(release, manifest) of a prepared image, from
    STATE/images/IMAGE/worker-metadata.json (worker_bundle.rs)."""
    import hashlib
    import json
    if not isinstance(image, str) or len(image) != 64 or any(c not in "0123456789abcdef" for c in image):
        raise HostError("image_invalid")
    try:
        raw = read_private(f"{state}/images/{image}/{METADATA_FILE}", MAX_METADATA_BYTES, "worker_invalid")
        value = json.loads(raw)
    except (HostError, ValueError):
        raise HostError("worker_invalid") from None
    if not isinstance(value, dict) or value.get("schema") != METADATA_SCHEMA \
            or value.get("install_root") != worker_layout.INSTALL_ROOT \
            or not isinstance(value.get("manifest"), str) or not isinstance(value.get("release"), str):
        raise HostError("worker_invalid")
    manifest = value["manifest"].encode()
    try:
        worker_layout.listing(manifest)
    except worker_layout.Refused:
        raise HostError("worker_invalid") from None
    if hashlib.sha256(manifest).hexdigest() != value["release"]:
        raise HostError("worker_invalid")
    return value["release"], manifest


def accept_unclean(record, allow):
    """Whether a start or checkpoint accepts unclean storage: only with
    the operator's acknowledgement of exactly the recorded generation
    (`--allow-unclean GENERATION`); a clean one needs none."""
    if allow is not None and (not allow.isdigit() or str(int(allow)) != allow):
        raise HostError("allow_unclean_invalid")
    if record["storage"] == "clean":
        return False
    if allow is None:
        raise HostError("storage_unclean")
    if int(allow) != record["generation"]:
        raise HostError("generation_mismatch")
    return True


def described_view(frame):
    return {k: list(frame[k]) if isinstance(frame[k], list) else frame[k]
            for k in ("operations", "transport", "retention", "limits", "features")}


class Custody:
    """One lifecycle operation's loop (signals counted) and, once
    `begin` ran, its fresh domain D under the delegated scope."""

    def __init__(self, system, config, limits_path):
        self.system, self.config, self.limits = system, config, limits_path
        self.loop = Loop()
        self.loop.install_signals()
        self.domain = None

    def stopping(self):
        return bool(self.loop.signals)

    def forced(self):
        return len(self.loop.signals) >= 2

    def capabilities(self):
        """The provider's `described` (its own process group, as B1)."""
        described = provider.capabilities(self.loop, self.config, self.limits, new_id("o"),
                                          stop=self.stopping, force=self.forced)
        if self.stopping():
            raise HostError("cancelled")
        return described

    def begin(self):
        self.system.enter()
        self.domain = cgroups.Domain.create(self.system.cgroups, cgroups.envelope({}, self.config.get("guard")))
        return self.domain.record()

    def invoke(self, request, described, worker=None):
        """One request in a fresh leaf of D, awaited to its terminal frame
        (timeout or signal: cancel, one grace). (outcome or None, terminal
        frame or None)."""
        leaf = self.domain.leaf()
        try:
            invocation = provider.Invocation(self.loop, self.config, self.limits, request, described, worker,
                                             leaf=leaf, custody=self.domain.path)
        except provider_protocol.ProtocolError:
            raise HostError("provider_refused") from None
        finally:
            os.close(leaf)
        try:
            invocation.wait(lambda: invocation.settled_answer() is not None, request["timeout_ms"],
                            stop=self.stopping, force=self.forced)
            outcome = invocation.settled_answer()
        finally:
            invocation.end()
        result = invocation.exchange.result
        return outcome, result if isinstance(result, dict) else None

    def settle(self):
        """The gate: D killed, read empty, removed (a later `begin` makes
        a fresh one). False leaves it as it is, recorded."""
        if self.domain is None:
            return True
        if not self.domain.kill_until(time.monotonic() + KILL_TIMEOUT):
            return False
        self.domain.remove()
        self.domain = None
        return True

    def close(self):
        if self.domain is not None:
            self.domain.close()
        self.loop.close()


def kill_recorded(system, record):
    """A recorded domain adopted by exact path and identity, killed, read
    empty, removed. True once its removal is confirmed (absent: a removed
    cgroup holds no process). A shell transport's slot or member appearing
    meanwhile is killed again and the removal retried, all within one
    KILL_TIMEOUT."""
    if record is None:
        return True
    domain = cgroups.Domain.adopt(system.cgroups, record)
    if domain is None:
        return True
    deadline = time.monotonic() + KILL_TIMEOUT
    try:
        while True:
            if not domain.kill_until(deadline):
                return False
            if domain.remove():
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(cgroups.KILL_POLL)
    finally:
        domain.close()


def _failed(outcome, custody):
    """The fixed refusal for a non-success outcome."""
    if custody.stopping():
        return HostError("cancelled")
    if outcome is None or outcome["end"] in ("lost", "error"):
        return HostError("provider_unanswered")
    return HostError("provider_failed")


# The operator's next step for a provider's closed code (Podman's shared
# store), shown with `provider_code`.
PROVIDER_HINTS = {
    "shared_store_uninitialized": "the shared Podman store needs its rootless helper running outside agentbox: "
                                  "run any rootless podman command yourself first (e.g. podman info), then retry; "
                                  "if it still refuses, this Podman's helper is not recognized: use the private "
                                  "store, agentbox image prepare podman --store private",
    "shared_image_missing": "the prepared image is not in your Podman store (removed or pruned?): agentbox image "
                            "prepare podman --store shared (with the tag's -t and --preset), then a new run",
    "retained_home_missing": "the jail's HOME volume (agentbox jail status shows its name) is gone from your Podman "
                             "store (removed or pruned?); agentbox never makes it again: agentbox jail discard, "
                             "then a new jail",
}


class Failed(HostError):
    """A provider's validated `failed`, its closed code kept."""

    def __init__(self, code, provider_code):
        super().__init__(code)
        self.provider_code = provider_code


def _provider_error(outcome, custody):
    error = _failed(outcome, custody)
    if outcome is not None and outcome["end"] == "failed" and error.code == "provider_failed":
        return Failed("provider_failed", outcome["code"])
    return error


# -- protected roots ------------------------------------------------------

def protected_roots(store, config):
    """What no mount source may meet: this store, the legacy store's
    default roots, the provider's STATE and assets, every declared scope
    (an unreadable limits file refuses)."""
    declared, _ = scopes.read_limits(store.path)
    roots = [store.path, config["state"], config["assets"]] + legacy_data_dirs(dict(capture_host()))
    return roots + [scope["path"] for scope in declared]


# -- image ------------------------------------------------------------------

def prepare(system, store, config, recipe):
    """(image, release, agents or None) of a newly prepared image: agents
    the provider's `prepared.agents` ({agent: npm version})."""
    check_assets(config["assets"])
    if not provider_protocol.is_path(recipe):
        raise HostError("recipe_invalid")
    held = states.lease(store, config["state"])
    custody = None
    try:
        if held.pending is not None:
            raise HostError("prepare_unsettled")
        limits = scopes.limits_path(store.path)
        scopes.admit(store, config["state"], lambda: None)
        custody = Custody(system, config, limits)
        described = custody.capabilities()
        operation = new_id("o")
        domain = custody.begin()
        held.save_pending({"op": "prepare", "operation": operation, "provider_sha256": provider_digest(config),
                           "recipe": recipe, "domain": domain, "processes": "unknown"})
        outcome, result = custody.invoke({"v": 1, "type": "prepare", "operation": operation,
                                          "timeout_ms": PREPARE_TIMEOUT_MS, "recipe": recipe,
                                          "worker": config["assets"]}, described)
        if not custody.settle():
            raise HostError("processes_unsettled")
        held.save_pending(None)
        if result is None or result.get("type") != "prepared":
            raise _provider_error(outcome, custody)
        release, _ = baked_worker(config["state"], result["image"])
        if release != result["worker_sha256"]:
            raise HostError("worker_invalid")
        return result["image"], release, result.get("agents")
    finally:
        if custody is not None:
            custody.close()
        held.release()


def recover_prepare(system, store, config, operation):
    """The recorded prepare `operation`'s domain killed and read empty."""
    held = states.lease(store, config["state"], claim=False)
    try:
        current = held.pending
        if not is_handle(operation, "o"):
            raise HostError("operation_invalid")
        if current is None or current["operation"] != operation:
            raise HostError("operation_unknown")
        if not kill_recorded(system, current["domain"]):
            raise HostError("processes_unsettled")
        held.save_pending(None)
        return "recovered"
    finally:
        held.release()


# -- jail create ----------------------------------------------------------

def create(system, store, recorded, image, retention, limits, user, mounts, project, project_host, name=None,
           require=()):
    """A new managed run from a tag's `recorded` provider (recorded as
    is, resolved for this create); its id. `mounts`, `project`, `project_host`:
    mounts.select's lexical selection. `name`: claimed with the record's
    publish (store.py), before any create is sent. `retention` one, or a
    preference tuple (`run AGENT`): the first the provider advertises,
    never retained storage of an `explicit_retention` provider (only
    `none`, if listed). `require`: features the provider must advertise
    now (else `features_missing`, nothing recorded). A failure after the
    record exists carries its `run_id` (the caller's to discard)."""
    from . import mounts as mounts_mod
    config = builtin.resolve(recorded)
    check_assets(config["assets"])
    if any(provider_protocol.overlap(store.path, config[k]) for k in ("state", "assets")):
        raise HostError("data_overlaps_provider")
    release, manifest = baked_worker(config["state"], image)
    held = states.lease(store, config["state"])
    custody = lease = None
    created = []
    try:
        limits_path = scopes.limits_path(store.path)
        custody = Custody(system, config, limits_path)
        frame = custody.capabilities()
        described = described_view(frame)
        if any(feature not in described["features"] for feature in require):
            raise HostError("features_missing")
        if isinstance(retention, tuple):
            explicit = "explicit_retention" in described["features"]
            chosen = next((r for r in retention if r in described["retention"] and (r == "none" or not explicit)),
                          None)
            if chosen is None and explicit:
                raise builtin.hinted("retention_explicit", EXPLICIT_RETENTION_HINT)
            retention = chosen
        if retention not in described["retention"]:
            if described["retention"] == ["none"]:
                raise builtin.hinted("retention_unsupported", NO_RETENTION_HINT)
            raise HostError("retention_unsupported")
        if any(k not in described["limits"] for k in limits):
            raise HostError("limit_unsupported")
        if user != provider_protocol.DEFAULT_USER and "select_user" not in described["features"]:
            raise HostError("user_unsupported")
        if mounts:
            if "host_mounts" not in described["features"]:
                raise HostError("mounts_unsupported")
            if retention == "none":
                raise HostError("mounts_need_retention")
            mounts_mod.check_host(mounts, project_host, protected_roots(store, config))
        fields = {"provider": recorded, "resource": new_id("res"), "image": image, "limits": dict(limits),
                  "described": described, "user": user, "retention": retention, "mounts": mounts,
                  "project": project, "name": name}
        scopes.admit(store, config["state"], lambda: created.append(store.create_managed(fields, manifest, True)))
        run_id = created[0]
        lease = store.claim(run_id)
        domain = custody.begin()
        operation = new_id("o")
        lease.save(dict(lease.record, pending=pending("create", operation, 0, domain)))
        request = {"v": 1, "type": "create", "operation": operation, "timeout_ms": CREATE_TIMEOUT_MS,
                   "run": run_id, "resource": fields["resource"], "image": image, "retention": retention,
                   "user": user}
        if mounts:
            request["mounts"] = mounts
        outcome, result = custody.invoke(request, frame)
        commit_create(lease, outcome, result, custody)
        return run_id
    except HostError as error:
        if created:
            error.run_id = created[0]
        raise
    finally:
        if lease is not None:
            lease.release()
        if custody is not None:
            custody.close()
        held.release()


def commit_create(lease, outcome, result, custody, restoring=False):
    """A create's answer through the gate: `created` ready (a restore's:
    its restore pending next); a settled `failed` partial (create_refused
    for a CREATE_REFUSALS code, unchanged, never a restore's); else pending
    stays."""
    settled = custody.settle()
    record = lease.record
    if not settled:
        raise HostError("processes_unsettled")
    if result is not None and result.get("type") == "created":
        if result["user"] != record["user"] or not provider_protocol.is_path(result["home"]):
            lease.save(dict(record, phase="partial", pending=None))
            raise HostError("account_invalid")
        # A retained HOME outside the provider's STATE: its name, shown only.
        volume = {"volume": result["volume"]} if "volume" in result else {}
        if restoring:
            lease.save(dict(record, home=result["home"], generation=result["generation"], **volume,
                            pending=dict(record["pending"], processes="settled", provider="created")))
            return
        lease.save(dict(record, phase="ready", home=result["home"], generation=result["generation"],
                        storage="clean", pending=None, **volume))
        return
    if outcome is not None and outcome["end"] == "failed" and outcome["settlement"] == "settled":
        refused = not restoring and outcome["code"] in CREATE_REFUSALS and outcome["durability"] == "unchanged"
        lease.save(dict(record, phase="partial", pending=None, create_refused=refused))
        raise _provider_error(outcome, custody)
    lease.save(dict(record, pending=dict(record["pending"], processes="settled", provider=_end(outcome),
                                         settlement=None if outcome is None else outcome["settlement"])))
    raise _provider_error(outcome, custody)


def _end(outcome):
    return "unanswered" if outcome is None or outcome["end"] in ("lost", "error") else outcome["end"]


# -- jail stop ------------------------------------------------------------

def unproven(lease):
    """Local work no domain proves ended: (id, what, state) of every
    attached execution still holding a spool, an input staging and an
    export's reservation (its partial's fate unknown)."""
    from .store import _execution_records
    found = []
    record = lease.record
    if record["kind"] == "attached":
        for execution_id, value in sorted(_execution_records(lease.run).items()):
            if _spool(value):
                found.append((execution_id, "execution", value.get("state")))
    inputs = record["inputs"]
    if inputs is not None and inputs["state"] == "staging":
        found.append((inputs["attempt"], "staging", "staging"))
    export = record["export"]
    if export is not None:
        found.append((export["operation"], "export", export["processes"]))
    return found


def stop(system, store, lease):
    """Settles what the record proves: (outcome, unproven local work)."""
    record = lease.record
    if record["kind"] == "attached":
        changed, _, _ = lease.finalize_interrupted(settled=False)
        return ("idle" if not changed else "recovered"), unproven(lease)
    outcome = "idle"
    current = record["pending"]
    if current is not None:
        outcome = _stop_pending(system, store, lease, current)
    changed, _, unremoved = lease.finalize_interrupted(settled=lease.record["pending"] is None
                                                       or lease.record["pending"]["processes"] == "settled")
    if unremoved:
        raise HostError("spool_unremoved")
    if changed and outcome == "idle":
        outcome = "recovered"
    return outcome, unproven(lease)


def _stop_pending(system, store, lease, current):
    from . import checkpoints
    if current["processes"] != "settled":
        if not kill_recorded(system, current["domain"]):
            raise HostError("processes_unsettled")
        lease.save(dict(lease.record, pending=dict(current, processes="settled")))
        current = lease.record["pending"]
    op = current["op"]
    if op in ("create", "restore"):
        # Lost or unanswered: the resource may be partial; only discard.
        if current["checkpoint"] is not None:
            checkpoints.reader_settled(store, current["checkpoint"], lease.run_id)
        lease.save(dict(lease.record, phase="partial", pending=None, storage="unclean"))
        return "partial"
    if op == "checkpoint":
        checkpoints.creation_settled(store, current["checkpoint"], current["operation"])
        lease.save(dict(lease.record, pending=None))
        return "recovered"
    if op == "discard":
        return "discard_pending"
    if current["settlement"] == "settled":
        lease.save(dict(lease.record, pending=None))
        return "recovered"
    return _standalone_stop(system, store, lease, current)


def _standalone_stop(system, store, lease, current):
    """A lost instance's exact standalone `stop` in a fresh D, its own
    operation recorded first; only `stopped` (or a settled failure)
    through the gate clears it, with its generation and storage."""
    record = lease.record
    config = builtin.resolve(record["provider"])
    check_assets(config["assets"])
    held = states.lease(store, config["state"])
    custody = Custody(system, config, scopes.limits_path(store.path))
    try:
        domain = custody.begin()
        operation = new_id("o")
        lease.save(dict(record, pending=dict(current, op="stop", operation=operation, domain=domain,
                                             processes="unknown", provider="requested", settlement=None,
                                             durability=None, code=None)))
        request = {"v": 1, "type": "stop", "operation": operation, "timeout_ms": provider.STOP_TIMEOUT_MS,
                   "run": lease.run_id, "resource": record["resource"], "execution": current["execution"],
                   "instance": current["instance"], "generation": current["generation"]}
        outcome, result = custody.invoke(request, record["described"])
        settled = custody.settle()
    finally:
        custody.close()
        held.release()
    record = lease.record
    fields = {"processes": "settled" if settled else "unknown", "provider": _end(outcome),
              "settlement": None if outcome is None else outcome["settlement"],
              "durability": None if outcome is None else outcome["durability"],
              "code": None if outcome is None else outcome["code"]}
    generation, storage = record["generation"], record["storage"]
    if result is not None and result.get("type") == "stopped":
        generation, storage = result["generation"], result["storage"]
    elif outcome is not None and outcome["durability"] == "uncertain":
        storage = "unclean"
    if not settled or outcome is None or outcome["settlement"] != "settled":
        lease.save(dict(record, generation=generation, storage=storage, pending=dict(record["pending"], **fields)))
        raise HostError("processes_unsettled" if not settled else "provider_unsettled")
    lease.save(dict(record, pending=None, generation=generation, storage=storage))
    lease.remove_session_all()
    return "recovered"


# -- the operator's assertion ----------------------------------------------

def assert_local(lease, ident, say):
    """`jail stop --assert-local-ended ID`: the operator's assertion,
    never verified, that one exact attached execution's or input staging's
    local work ended; only that work's own spool is removed, its
    reservation released once removed. Remote state is untouched."""
    from . import inputs as inputs_mod
    record = lease.record
    if is_handle(ident, "e"):
        value = lease.execution(ident)
        if value is None:
            raise HostError("assertion_id_unknown")
        if record["kind"] != "attached":
            # A managed run's domains prove it: `jail stop` alone.
            raise HostError("assertion_not_applicable")
        if not _spool(value):
            raise HostError("assertion_id_stale")
        say(f"agentbox: warning: asserting, unverified, that local work of {ident} ended "
            f"(state={value.get('state')} spool_reserved={_spool(value)}); its files are removed\n")
        if not lease.assert_execution(ident):
            raise HostError("spool_unremoved")
        return "asserted"
    if is_handle(ident, "s"):
        inputs = record["inputs"]
        if inputs is None or inputs["attempt"] != ident:
            raise HostError("assertion_id_unknown")
        if inputs["state"] != "staging":
            raise HostError("assertion_id_stale")
        say(f"agentbox: warning: asserting, unverified, that input staging {ident} ended "
            f"(state=staging reserved={inputs['settings']['archive_bytes']}); its spool is removed\n")
        if not inputs_mod.assert_staging(lease, ident):
            raise HostError("spool_unremoved")
        return "asserted"
    if is_handle(ident, "x"):
        return _assert_export(lease, ident, say)
    raise HostError("assertion_id_invalid")


def _assert_export(lease, ident, say):
    """The user's decision: the operator's word that export `ident`'s local
    work ended releases its reservation. Nothing is verified, no path is
    stored or guessed, nothing deleted: its partial may remain beside the
    destination first selected, the operator's. Recorded (`asserted`)
    before the charge is released."""
    record = lease.record
    export = record["export"]
    if export is None or export["operation"] != ident:
        raise HostError("assertion_id_stale" if ident in record["asserted"] else "assertion_id_unknown")
    pending = record["pending"]
    if pending is not None and pending["processes"] != "settled":
        # A managed execution's export ran in its domain: `jail stop` first.
        raise HostError("processes_unsettled")
    partial = ".agentbox-export-" + ident[2:] + ".partial"
    say(f"agentbox: warning: asserting, unverified, that local work of export {ident} ended "
        f"(processes={export['processes']} reserved={export['max_bytes']}); its reservation is released. "
        f"Not verified: no process termination, no file cleanup. A partial file {partial} may remain "
        f"beside the destination you selected; it is yours to remove\n")
    lease.note_asserted(ident)
    with lease.store.lock():
        if lease.record["export"] is None or lease.record["export"]["operation"] != ident:
            raise HostError("assertion_id_stale")
        lease.save(dict(lease.record, export=None))
    return "asserted"


# -- jail discard ---------------------------------------------------------

def discard(system, store, lease):
    """`discarded`, `retired` (a refused create's run, metadata only) or
    `already_discarded`."""
    record = lease.record
    inputs = record["inputs"]
    if inputs is not None and inputs["state"] == "staging":
        raise HostError("staging_unsettled")
    if record["export"] is not None:
        # Its partial's fate unknown: `jail stop` names it.
        raise HostError("export_unsettled")
    if record["phase"] == "discarded":
        _discard_record(lease)
        return "already_discarded"
    if record["kind"] == "attached":
        lease.finalize_interrupted(settled=False)
        if unproven(lease):
            # An execution's spool still reserved (begun or finished
            # unconfirmed): its server's scp or a worker may still use it
            # and the session files. `jail stop --assert-local-ended` first.
            raise HostError("local_work_unproven")
        # Local metadata only; the operator's jail is neither observed nor
        # stopped. The terminal phase first, then the local files.
        lease.save(dict(lease.record, phase="discarded"))
        _discard_record(lease)
        return "discarded"
    current = record["pending"]
    if current is not None and current["op"] == "start":
        raise HostError("resource_unsettled")
    if current is not None and current["processes"] != "settled":
        raise HostError("processes_unsettled")
    if current is not None and current["op"] != "discard":
        raise HostError("resource_unsettled")
    lease.finalize_interrupted(settled=True)
    # Nothing made: a refused create, or a record whose create was never
    # sent (its controller gone before the intent).
    retirable = (record["create_refused"] and record["phase"] == "partial") \
        or (record["phase"] == "creating" and current is None)
    config = builtin.resolve(record["provider"])
    check_assets(config["assets"])
    held = states.lease(store, config["state"])
    custody = Custody(system, config, scopes.limits_path(store.path))
    try:
        domain = custody.begin()
        operation = new_id("o")
        lease.save(dict(record, pending=pending("discard", operation, record["generation"], domain)))
        outcome, result = custody.invoke({"v": 1, "type": "discard", "operation": operation,
                                          "timeout_ms": DISCARD_TIMEOUT_MS, "run": lease.run_id,
                                          "resource": record["resource"]}, record["described"])
        settled = custody.settle()
        record = lease.record
        if not settled:
            raise HostError("processes_unsettled")
        if result is not None and result.get("type") == "discarded":
            lease.save(dict(record, phase="discarded", pending=None, create_refused=False))
            end = "discarded"
        elif retirable and outcome is not None and outcome["end"] == "failed" and outcome["code"] == "not_found" \
                and outcome["settlement"] == "settled":
            lease.save(dict(record, phase="discarded", pending=None))
            end = "retired"
        else:
            lease.save(dict(record, pending=dict(record["pending"], processes="settled", provider=_end(outcome))))
            raise _provider_error(outcome, custody)
    finally:
        custody.close()
        held.release()
    _discard_record(lease)
    return end


def _discard_record(lease):
    """Copied inputs and session files removed (no writer is left: the
    lease is exclusive, nothing unsettled); records and logs stay."""
    from .inputs import Paths, archive_name
    lease.remove_session_all()
    paths = Paths(lease)
    try:
        fd = paths.open()
    except FileNotFoundError:
        fd = None
    except (OSError, HostError):
        # Inaccessible is not absent: the inputs stay recorded and charged.
        raise HostError("inputs_unremoved") from None
    if fd is not None:
        try:
            inputs = lease.record["inputs"]
            for name in ([archive_name(inputs["attempt"])] if inputs is not None else []):
                try:
                    os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    pass
                except OSError:
                    raise HostError("inputs_unremoved") from None
        finally:
            os.close(fd)
    if lease.record["inputs"] is not None:
        with lease.store.lock():
            lease.save(dict(lease.record, inputs=None))
