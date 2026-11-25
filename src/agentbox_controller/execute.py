"""One headless execution (B1 managed, B2 attached, copied inputs and the
acquisition lane).

```text
lease (flock) -> admission + execution record (store lock) -> capture
managed:  capabilities -> delegated unit + domain D (limits read back)
          -> pending {domain, processes: unknown} recorded -> keygen
          -> start owner in D/h-1 -> started (pinned host key)
attached: the bundle re-validated (its recorded release) -> the target's
          host key pinned; no provider, scope or domain
-> agentbox-server (managed: in D) [POST + delivery when a lane is selected]
-> bootstrap: prepare [attached: sftp upload] verify, over ssh
-> [copied inputs: scp archive -> HOME/.agentbox-inputs-EID.tar]
-> session ssh -R -> hello [inputs_setup -> inputs_ready] exec, output,
   stdin, exit; the lane pumped meanwhile (cancel on signal or deadline)
teardown, always, in order, each bounded:
   lane closed (workers reaped, results awaited) -> guest session closed
   -> server end of input -> managed: provider stop -> D killed, read
   empty, removed; attached: every local child reaped (no remote effect)
   -> lane disposed (its spool removed only once nothing can use it)
   -> managed: pending cleared only if provider AND processes settled
-> execution record (its spool reservation kept unless removed)
-> execution record, capture closed, final line
```

The owner publishes its stop identity (owner.py) for its whole life:
`jail stop` signals it (SIGUSR1: a stop request, as a first signal, never a
second). `jail serve` runs no command: its session holds at guest-ready,
the broker forward up, untimed, until a signal, a stop request or a
failure; from guest-ready until its teardown starts it publishes its shell
profile (its session nonce included: the logins' request context), which
`shell` reads without asking it anything. A disconnecting shell stops
nothing. With an acquisition lane, every login and an interactive agent
share it: one grant (MAX_REQUESTS, MAX_ACQUIRED_BYTES) and one active
request for the whole session, never reset by a reconnect. Through a
stdio provider the shell's ssh runs `jail shell-transport`, which joins a
slot of D itself and becomes the provider's connect (shell.py; 32 slots
per execution in all, never refunded, each kept until D's removal). The profile is withdrawn
before D is killed; a transport joining late is killed with D or exits,
and D's kill and removal are retried within KILL_TIMEOUT: a removal not
confirmed leaves the run pending (`host.domain.residue`). An exec owner
publishes no profile (`shell_unsupported`).

`--export-to` (export.py): its reservation recorded with the admission,
its partial made first; with `--timeout`, the command's own window is the
runtime less the allowance and STOP_RESERVE; untimed, the command has no
window and the export only its own allowance. Only the command's own
exit (`exited`, any code), before any stop, runs the export over a fresh
ssh; a signaled, failed or cancelled end never does. The acquisition lane is closed first
(its active request cancelled and revoked, nothing new admitted) and only
drained meanwhile; publication waits for the teardown's confirmed host
cleanup and no cancellation.

Admission reserves 2 GiB for a lane's spool: one artifact at the HTTP
ceiling. It is a lower bound, said at run time (`host.storage.warning`,
the final line's `storage=`): a stage's other files are the trusted
handler's; an unmetered handler's (Git: its clone beside its bundle) are
unbounded.

An untimed owner (`timeout` None: `jail serve`, an interactive agent, an
exec or headless agent without `--timeout`; server `lifetime_ms` null) is
untimed only once its guest is ready: until then one fixed setup deadline
(SETUP_TIMEOUT, plus a delivered input's upload allowance), never renewed
by frames, output or requests; past it setup stops (`timeout`). Every
acquisition request keeps its own finite deadline (acquisition.py; the
server bounds each exchange too); a timed execution's cutoff caps it.

A second signal skips the remaining waits and kills D at once. Nothing is
claimed that was not observed: a lost provider, an unconfirmed kill or a
missing answer leaves a managed run pending (`jail stop`). An attached run's
jail is the operator's: its final line says `provider=attached`, its
cleanup is of this host's own processes and files only.
"""
import os
import secrets
import selectors
import time

from . import capture as capture_mod
from . import acquisition, attached, builtin, cgroups, display, export as export_mod, inputs as inputs_mod, \
    lifecycle, owner as owner_mod, provider, scopes, ssh, states
from .assets import provider_protocol, guest_protocol
from .config import check_assets, check_server, recorded_name
from .display import Input, Surface
from .guest import Guest
from .host import Child, Drain, HostError, Loop, find_tool, host_path, read_some, tool_env, write_some
from .server import Server
from .store import MAX_EXECUTIONS, SPOOL, absent, new_id

KEYGEN_TIMEOUT = 10.0
STAGE_TIMEOUT = 60.0
SESSION_END_TIMEOUT = 5.0
CANCEL_GRACE = 15.0
KILL_TIMEOUT = 10.0
LEAF_KILL_TIMEOUT = 2.0
DISPLAY_TIMEOUT = 2.0
SERVER_MARGIN_MS = 60000
# An untimed owner's setup, until its guest is ready:
# the provider's start allowance and the old startup window (120 s), plus
# a delivered input's upload allowance; fixed once, never renewed.
SETUP_TIMEOUT = provider.START_TIMEOUT_MS / 1000.0 + 120.0


# A Podman start that failed: each start unpacks the whole image into a
# store on its engine root's tmpfs (2 GiB free admitted first,
# providers/podman.py STORE_MIN_FREE), which a built-in profile's runtime
# tmpfs may lack (the provider's code does not say).
PODMAN_START_FAILED = ("agentbox: hint: if Podman's engine root ran out of space (each start unpacks the whole "
                       "image on its tmpfs), set podman_engine_root in the controller config to a larger private "
                       "directory on a tmpfs without noexec, declare it in run-limits.json, then run image "
                       "prepare podman again\n")


class Report:
    def __init__(self, serve=False):
        # A serving execution: no command; its expected end is a stop.
        self.serve = serve
        self.reason = None
        self.provider_code = None
        self.exit = None
        self.host_cleanup = False
        self.provider = "no_instance"
        self.durability = None
        self.output = None
        self.capture_complete = False
        # An acquisition lane's own cleanup (its workers reaped, its spool
        # removed); True without one.
        self.lane_clean = True
        # A lane's admitted spool reservation: `lower_bound` or `unbounded`.
        self.storage = None

    def fail(self, code):
        if self.reason is None:
            self.reason = code

    def outcome(self):
        if self.reason in ("cancelled", "timeout"):
            return "cancelled"
        if self.reason == "completed":
            return "completed"
        return "failed"

    def line(self):
        exit_text = "none"
        if self.exit is not None:
            exit_text = str(self.exit["code"]) if self.exit["outcome"] == "exited" else self.exit["outcome"]
        text = (f"{'serve' if self.serve else 'execution'}: outcome={self.outcome()} reason={self.reason} "
                f"exit={exit_text} "
                f"host_cleanup={'confirmed' if self.host_cleanup else 'unconfirmed'} provider={self.provider}")
        if self.durability:
            text += f" durability={self.durability}"
        if self.provider_code:
            text += f" provider_code={self.provider_code}"
        text += f" output={'complete' if self.output is None else 'incomplete'}"
        if self.output is not None:
            text += f" output_code={self.output}"
        if not self.capture_complete:
            text += " capture=incomplete"
        if not self.lane_clean:
            text += " acquisition_cleanup=unconfirmed"
        if self.storage is not None:
            text += f" storage={self.storage}"
        return text

    def confirmed(self):
        """Everything but how it ended: cleanup, output and capture."""
        return (self.host_cleanup and self.provider in ("settled", "attached") and self.output is None
                and self.capture_complete and self.lane_clean)

    def exited(self):
        """The command's own exit code, only for a completed command with
        everything else confirmed; else None (`run -- ARG...`)."""
        if self.serve or self.reason != "completed" or self.exit is None or self.exit["outcome"] != "exited" \
                or not self.confirmed():
            return None
        return self.exit["code"]

    def ok(self):
        if self.serve:
            # Ended by a stop (a signal or `jail stop`), recorded cancelled,
            # never relabelled completed; a deadline is no success.
            return self.reason == "cancelled" and self.exit is None and self.confirmed()
        return self.exited() == 0


def check_stage_root(path):
    """An acquisition stage root: an existing directory of this user, not
    a link, not group/world accessible (`acquisition_stage_root_invalid`);
    its storage scope is checked by the admission."""
    import stat
    try:
        st = os.lstat(path)
    except OSError:
        raise HostError("acquisition_stage_root_invalid") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise HostError("acquisition_stage_root_invalid")


def run_child(loop, argv, env, leaf, data, timeout, limit=4096, stop=None):
    """A short child: `data` its whole stdin, stdout kept to `limit` + 1
    bytes, stderr drained; returns (exit status or None, stdout). Killed
    unfinished at `timeout` or once `stop()` holds."""
    child = Child(argv, env, leaf=leaf)
    stdin, stdout = child.popen.stdin.fileno(), child.popen.stdout.fileno()
    err = Drain(loop, child.popen.stderr.fileno(), 4096)
    out = bytearray()
    state = {"pending": data, "out_end": False}

    def write(_mask):
        while state["pending"]:
            written = write_some(stdin, state["pending"])
            if written is None:
                state["pending"] = b""
                break
            if written == 0:
                return
            state["pending"] = state["pending"][written:]
        loop.unwatch(stdin)
        try:
            child.popen.stdin.close()
        except OSError:
            pass

    def read(_mask):
        chunk = read_some(stdout)
        if chunk is None:
            return
        if not chunk:
            state["out_end"] = True
            loop.unwatch(stdout)
            return
        out.extend(chunk[:max(0, limit + 1 - len(out))])

    loop.watch(stdin, selectors.EVENT_WRITE, write)
    loop.watch(stdout, selectors.EVENT_READ, read)
    def ended():
        return state["out_end"] and child.exited()

    loop.run(lambda: ended() or (stop is not None and stop()), time.monotonic() + timeout)
    finished = ended()
    loop.unwatch(stdin)
    loop.unwatch(stdout)
    err.close()
    if not finished:
        child.kill_group()
    code = child.finish()
    return (code if finished else None), bytes(out)


class System:
    """The host seams: the kernel/user-manager (`cgroups.Cgroups`) and the
    trusted tools found on the captured PATH. Tests substitute both."""

    def __init__(self, cgroup_host=None, tools=None):
        self.cgroups = cgroup_host or cgroups.Cgroups()
        self.tools = tools or {}
        self.entered = False

    def tool(self, name):
        if name not in self.tools:
            self.tools[name] = find_tool(name)
        return self.tools[name]

    def enter(self, idle=time.sleep):
        if not self.entered:
            cgroups.enter(self.cgroups, idle)
            self.entered = True


class Execution:
    def __init__(self, system, controller, store, lease, argv, env, use_stdin, timeout, selection=None,
                 out_fd=1, err_fd=2, in_fd=0, allow_unclean=None, stage_root=None, serve=False,
                 export=None, python=False, client=None, report_err=False):
        self.system, self.controller, self.store, self.lease = system, controller, store, lease
        # Its own lines on stderr only (`run -- ARG...`: stdout only the
        # command's rendered output).
        self.report_err = report_err
        self.argv, self.env, self.use_stdin, self.timeout = argv, env, use_stdin, timeout
        self.selection = selection
        self.fds = (in_fd, out_fd, err_fd)
        self.report = Report(serve)
        self.serve = serve
        # `argv` the jail Python's arguments: the target's interpreter
        # bound first (an agent's runner).
        self.python = python
        # A serving owner's in-process client (an interactive agent's
        # session, agentrun.py): `turn(stopping)` each pass once ready (True:
        # done), `end()` bounded and idempotent. An owner with `timeout`
        # None (`lifetime_ms` null) is untimed only once its guest is ready:
        # setup until then is bounded (SETUP_TIMEOUT); staging, requests and
        # teardown keep their own bounds.
        self.client = client
        self.client_done = False
        # The target's jail Python words (bootstrap plan), once known.
        self.python_words = None
        self.client_code = None
        # {"parent": pinned directory fd, "name", "settings"} (export.py)
        self.export = export
        self.export_id = None
        self.output = None
        self.export_end = None
        self.export_result = None
        self.stop_requested = False
        self.tearing_down = False
        self.publication = None
        self.profile = None
        # The shell profile published once (or its publication failed).
        self.shell_published = False
        self.loop = None
        self.capture = None
        self.domain = None
        self.owner = None
        self.server = None
        self.guest = None
        self.lane = None
        self.children = []
        self.execution_id = new_id("e")
        self.instance = new_id("i")
        self.nonce = secrets.token_hex(16)
        self.run_id = lease.run_id
        self.started = None
        self.surfaces = None
        self.session_dir = None
        self.delivery = None
        self.spool = None
        self.reserve = 0
        # The spool gone (or never made): no reservation stays.
        self.spool_released = True
        self.attached = lease.record["kind"] == "attached"
        self.allow_unclean, self.stage_root = allow_unclean, stage_root
        self.unclean = False

    # -- helpers ---------------------------------------------------------

    def event(self, kind, severity="info", **attributes):
        if self.capture is not None:
            self.capture.record("host.supervisor", kind, severity, attributes)

    def broker_event(self, message):
        name = message.get("event")
        attributes = message.get("attributes")
        if not isinstance(name, str) or not isinstance(attributes, dict) or len(name) > 64:
            return
        kept = {k: v for k, v in attributes.items()
                if isinstance(k, str) and isinstance(v, (str, int, bool)) and len(k) <= 64}
        severity = message.get("severity") if message.get("severity") in capture_mod.SEVERITY else "info"
        self.capture.record("host.broker", name, severity, kept)

    def stopping(self):
        return self.cancelled() or time.monotonic() >= self.deadline

    def cancelled(self):
        """A signal, a stop request (`jail stop`) or the client's end."""
        if not self.stop_requested and owner_mod.stop_requested():
            self.stop_requested = True
            self.event("host.stop.requested")
        return bool(self.loop.signals) or self.stop_requested or self.client_done

    def forced(self):
        return len(self.loop.signals) >= 2

    def stop_reason(self):
        return "cancelled" if self.cancelled() else "timeout"

    def checkpoint(self):
        """After a wait: a cancel or the cutoff stops setup here."""
        if self.stopping():
            raise HostError(self.stop_reason())

    def leaf(self):
        """A fresh leaf of D for one child (fd, name); None when attached."""
        return None if self.domain is None else self.domain.named_leaf()

    def kill_leaf(self, name):
        return self.domain is None or self.domain.kill_leaf(name, time.monotonic() + LEAF_KILL_TIMEOUT, self.idle)

    def idle(self, seconds):
        """A pause of a blocking poll (scope entry, a leaf's or D's kill):
        no callback run."""
        time.sleep(seconds)

    def housekeeping(self):
        """Every turn of the owner's own waits after the task started: the
        provider's frames, the lane (closed: only results, cancels and
        cleanup)."""
        if self.owner is not None:
            self.owner.pump()
        if self.lane is not None:
            self.lane.pump()

    def spawn(self, argv, env, **options):
        """An owned child in a fresh leaf (managed)."""
        leaf = self.leaf()
        try:
            return Child(argv, env, leaf=None if leaf is None else leaf[0], **options)
        finally:
            if leaf is not None:
                os.close(leaf[0])

    def short(self, argv, env, data, timeout, limit=4096):
        """A short child (bootstrap stage, upload) in a fresh leaf."""
        leaf = self.leaf()
        try:
            return run_child(self.loop, argv, env, None if leaf is None else leaf[0], data, timeout, limit,
                             stop=self.stopping)
        finally:
            if leaf is not None:
                os.close(leaf[0])

    # -- the execution ---------------------------------------------------

    def run(self):
        """The final line and the exit status."""
        record = self.lease.record
        if record["phase"] == "discarded":
            raise HostError("run_discarded")
        if record["phase"] != "ready":
            raise HostError("run_not_ready")
        if record["pending"] is not None:
            raise HostError("run_unsettled")
        if self.lease.execution_count() >= MAX_EXECUTIONS:
            raise HostError("execution_limit")
        if record["export"] is not None:
            # An earlier export's reservation: `jail stop` names it.
            raise HostError("export_unsettled")
        if self.export is not None:
            if record["kind"] == "managed" and record["retention"] == "none":
                raise HostError("export_retention_unsupported")
            if self.timeout is not None \
                    and export_mod.task_seconds(self.timeout, self.export["settings"]["timeout_ms"]) is None:
                raise HostError("export_window_insufficient")
        if self.argv and guest_protocol.validate_argv(self.argv) is not None:
            raise HostError("argv_invalid")
        # Earlier executions whose controller is gone (the lease is ours,
        # nothing pending). Managed: every domain was read empty, their
        # spools released if removed. Attached: nothing proves its
        # processes ended; one still holding a spool blocks.
        _, begun, _ = self.lease.finalize_interrupted(settled=not self.attached)
        if begun:
            raise HostError("run_interrupted")
        self.delivery = inputs_mod.delivery_plan(record)
        state = None
        if self.attached:
            self.bundle = attached.bundle(record["target"], record["worker_release"])
        else:
            config = builtin.resolve(record["provider"])
            check_assets(config["assets"])
            state = config["state"]
            states.check_claim(self.store, state)
            self.unclean = lifecycle.accept_unclean(record, self.allow_unclean)
        self.limits_path = scopes.limits_path(self.store.path)
        required = []
        reserve = 0
        unmetered = []
        if self.selection is not None:
            spool_parent = self.stage_root or f"{self.store.path}/{SPOOL}"
            if self.stage_root is None:
                try:
                    os.mkdir(spool_parent, 0o700)
                except FileExistsError:
                    pass
            check_stage_root(spool_parent)
            self.spool_parent = spool_parent
            required = [spool_parent]
            reserve = self.reserve = acquisition.MAX_ARTIFACT_BYTES
            unmetered = sorted(i for i, h in self.selection.handlers.items() if h.metering != "http")
            self.report.storage = "unbounded" if unmetered else "lower_bound"
        log = {}
        export_bytes = 0
        if self.export is not None:
            self.export_id = export_mod.new_export_id()
            export_bytes = self.export["settings"]["max_bytes"]

        def publish():
            begun = {"state": "begun"}
            if reserve:
                begun["spool"] = reserve
                if self.stage_root is not None:
                    # The execution's binding: its spool's exact root.
                    begun["spool_root"] = self.stage_root
            self.lease.write_execution(self.execution_id, begun, first=True)
            if export_bytes:
                # Before its partial exists; no destination stored.
                self.lease.save(dict(self.lease.record, export={
                    "operation": self.export_id, "max_bytes": export_bytes, "processes": "unknown"}))
            log["fd"] = self.lease.log_dir(self.execution_id)

        growth = scopes.admit(self.store, state, publish, extra=reserve + export_bytes, required=required)
        record = self.lease.record
        self.loop = Loop()
        self.loop.install_signals()
        try:
            self.capture = capture_mod.Capture(log["fd"], self.run_id, self.execution_id, record["log_bytes"],
                                               acquisition.LANE_RESERVE if self.selection is not None else 0)
            os.close(log["fd"])
            self.surfaces = {"stdout": Surface(self.loop, self.fds[1]),
                             "stderr": Surface(self.loop, self.fds[2])}
            now = time.monotonic()
            self.hard_deadline = float("inf") if self.timeout is None else now + self.timeout
            self.deadline = self.hard_deadline
            if self.timeout is None:
                # Untimed only once its guest is ready (`_watch_guest`).
                self.deadline = now + SETUP_TIMEOUT + (
                    0.0 if self.delivery is None else record["inputs"]["settings"]["upload_timeout_ms"] / 1000.0)
            if self.export is not None and self.timeout is not None:
                # The command's window: the allowance and the stop reserve
                # carved from the runtime, never added to it. Untimed: the
                # setup bound stays whole, the export keeps its allowance.
                self.deadline -= self.export["settings"]["timeout_ms"] / 1000.0 + export_mod.STOP_RESERVE
            self.event("host.storage.admitted", **growth)
            if reserve:
                # The spool's reservation is no quota: what a stage writes
                # beside its artifact is the handler's, unmetered ones'
                # without any bound.
                self.event("host.storage.warning", "warn", code=f"acquisition_storage_{self.report.storage}",
                           spool_reserved=reserve, unmetered=",".join(unmetered))
            self.event("host.execution.started", run_kind=record["kind"])
            # A cancel or the cutoff, once it holds, is the reason: whatever
            # its interruption made fail after it is not.
            try:
                self.publication = owner_mod.Publication(self.lease, self.execution_id, self.serve)
                if self.export is not None:
                    self.output = export_mod.Output(self.export["parent"], self.export_id,
                                                    self.export["settings"]["max_bytes"])
                if self.attached:
                    self._attached(record)
                else:
                    self._begin(config, record)
            except HostError as error:
                self.report.fail(self.stop_reason() if self.stopping() else error.code)
            except (OSError, provider_protocol.ProtocolError, guest_protocol.Refused):
                # Never a path or tool text: the teardown still runs and
                # the record stays truthful.
                self.report.fail(self.stop_reason() if self.stopping() else "internal")
            finally:
                self._teardown()
            if self.export is not None:
                self._conclude_export()
            return self._finish()
        finally:
            if self.publication is not None:
                self.publication.close()
            self.loop.close()

    def _keygen(self):
        self.session_dir = self.lease.session_dir(self.execution_id)
        code, _ = run_child(self.loop, ssh.keygen_argv(self.system.tool("ssh-keygen"), self.session_dir),
                            tool_env(), None, b"", KEYGEN_TIMEOUT, stop=self.stopping)
        self.checkpoint()
        if code != 0:
            raise HostError("keygen_failed")
        return ssh.read_public(self.session_dir)

    def _begin(self, config, record):
        described = provider.capabilities(self.loop, config, self.limits_path, new_id("o"),
                                           stop=self.stopping, force=self.forced)
        self.checkpoint()
        self.event("host.startup.step", step="capabilities")
        self.system.enter(self.idle)
        env = cgroups.envelope(record["limits"], config.get("guard"))
        self.domain = cgroups.Domain.create(self.system.cgroups, env)
        operation = new_id("o")
        pending = {"op": "start", "operation": operation, "execution": self.execution_id,
                   "instance": self.instance, "generation": record["generation"],
                   "domain": self.domain.record(), "processes": "unknown", "provider": "requested",
                   "settlement": None, "durability": None, "code": None, "checkpoint": None}
        # Recorded before the domain's first process.
        self.lease.save(dict(record, pending=pending))
        self.event("host.startup.step", step="domain", **{f"envelope_{k}": v for k, v in env.items()})
        public = self._keygen()
        start = {"v": 1, "type": "start", "operation": operation, "timeout_ms": provider.START_TIMEOUT_MS,
                 "run": self.run_id, "resource": record["resource"], "execution": self.execution_id,
                 "instance": self.instance, "generation": record["generation"], "accept_unclean": self.unclean,
                 "authorized_key": public, "limits": dict(record["limits"])}
        leaf = self.domain.leaf()
        try:
            self.owner = provider.Invocation(self.loop, config, self.limits_path, start, described,
                                             record["worker_release"], leaf=leaf, custody=self.domain.path)
        except provider_protocol.ProtocolError:
            raise HostError("provider_refused") from None
        finally:
            os.close(leaf)
        self.event("host.startup.step", step="provider_start")
        self.owner.wait(lambda: self.owner.exchange.waiting or self.owner.exchange.result is not None,
                        provider.START_TIMEOUT_MS, stop=self.stopping, force=self.forced)
        if not self.owner.exchange.waiting:
            outcome = self.owner.settled_answer()
            if outcome is not None and outcome["code"]:
                self.report.provider_code = outcome["code"]
            if self.stopping():
                raise HostError(self.stop_reason())
            raise HostError("provider_failed" if self.owner.error is None else "provider_protocol")
        self.lease.update_pending(provider="started")
        started = self.started = self.owner.started
        if started["user"] != record["user"] or started["home"] != record["home"]:
            raise HostError("binding_mismatch")
        alias = ssh.alias(self.run_id, self.execution_id)
        known = ssh.pin_host_key(self.session_dir, alias, started["host_key"])
        transport = started["transport"]
        identity = f"{self.session_dir}/{ssh.IDENTITY}"
        if transport["kind"] == "tcp":
            connection = ssh.Connection(started["user"], identity, known, alias,
                                        endpoint=(transport["host"], transport["port"]))
        else:
            connection = ssh.Connection(
                started["user"], identity, known, alias,
                proxy=provider.connect_words(config, self.run_id, self.execution_id, self.instance),
                proxy_env=provider.environment(self.limits_path, self.domain.path))
        layout = ssh.Layout(started["control"], started["home"], record["worker_release"], secrets.token_hex(16),
                            project=record["project"], mount=self._mount(record))
        plan = ssh.Plan(layout, manifest=self.lease.manifest, shims=self._shims(), session=self._session_entry())
        self._session(connection, plan, None)

    def _attached(self, record):
        target = record["target"]
        self.report.provider = "attached"
        self.event("host.startup.step", step="bundle", release=record["worker_release"])
        self.session_dir = self.lease.session_dir(self.execution_id)
        alias = ssh.alias(self.run_id, self.execution_id)
        known = ssh.pin_host_key(self.session_dir, alias, target["host_key"])
        connection = ssh.Connection(target["user"], target["identity"], known, alias,
                                    endpoint=(target["host"], target["port"]), attached=True)
        _, manifest, files = self.bundle
        layout = ssh.Layout(target["remote_root"], None, record["worker_release"], secrets.token_hex(16),
                            attached=True)
        if layout.home != record["home"]:
            raise HostError("binding_mismatch")
        plan = ssh.Plan(layout, manifest=manifest, files=files, python=target.get("python"), shims=self._shims(),
                        session=self._session_entry())
        self._session(connection, plan, target["bundle"])

    @staticmethod
    def _mount(record):
        """The host mount holding the run's project location, if any."""
        from .mounts import mount_of
        if record["project"] is None or not record["mounts"]:
            return None
        return mount_of(record["mounts"], record["project"])

    def _shims(self):
        return [] if self.selection is None else self.selection.shims()

    def _session_entry(self):
        return None if self.selection is None else self.selection.session()

    def _session(self, connection, plan, bundle):
        layout = plan.layout
        ssh_env = connection.env(tool_env())
        ssh_program = self.system.tool("ssh")
        leaf = self.leaf()
        try:
            self.server = Server(self.loop, check_server(self.controller["server"]), None if leaf is None else leaf[0],
                                 tool_env(), self.broker_event)
        finally:
            if leaf is not None:
                os.close(leaf[0])
        post = None
        if self.selection is not None:
            self.spool = f"{self.spool_parent}/{self.run_id}-{self.execution_id}"
            os.mkdir(self.spool, 0o700)
            if connection.proxy is not None:
                route = {"proxy": {"words": list(connection.proxy),
                                   "env": sorted([k, v] for k, v in connection.proxy_env.items() if k != "SHELL")
                                   + [["LC_ALL", "C"]]}}
            else:
                route = {"endpoint": {"host": connection.endpoint[0], "port": connection.endpoint[1]}}
            post = {"nonce": self.nonce, "delivery": {
                "route": route, "user": connection.user, "identity": connection.identity,
                "known_hosts": connection.known_hosts, "host_key_alias": connection.alias,
                "work_dir": layout.work, "spool_root": self.spool}}
        # Untimed: no session cutoff (POST included: each exchange and
        # upload keeps the server's own bounds, each request the lane's).
        lifetime = None if self.timeout is None \
            else int(max(1.0, self.hard_deadline - time.monotonic()) * 1000) + SERVER_MARGIN_MS
        port = self.server.configure(self.execution_id, self.run_id, self.execution_id, lifetime,
                                     self.controller["policy"], stop=self.stopping, post=post,
                                     grants=self.controller.get("grants", []),
                                     proxy=self.controller.get("connect_proxy"))
        self.event("host.startup.step", step="server")
        if self.selection is not None:
            self.lane = acquisition.Lane(self, self.selection, self.nonce, self.spool)
        self.event("host.bootstrap.started", release=layout.release, attempt=layout.name[-32:])
        self._stage(connection, ssh_program, ssh_env, "prepare", plan.prepare_script(), layout)
        if bundle is not None:
            self.checkpoint()
            argv, batch = connection.sftp_batch(self.system.tool("sftp"), ssh_program, plan.uploads(bundle))
            # The bundle checked again just before its upload: it must
            # still be the recorded release.
            attached.bundle(self.lease.record["target"], self.lease.record["worker_release"])
            code, _ = self.short(argv, ssh_env, batch.encode(), STAGE_TIMEOUT, 0)
            self.checkpoint()
            if code != 0:
                self.event("host.bootstrap.failed", "warn", stage="upload", guest_reason="none")
                raise HostError("bootstrap_failed")
        self._stage(connection, ssh_program, ssh_env, "verify", plan.verify_script(), layout)
        self.event("host.bootstrap.ready_claimed")
        inputs = None
        if self.delivery is not None:
            inputs = self._upload_inputs(connection, ssh_program, ssh_env, layout)
        child = self.spawn(connection.session(ssh_program, layout.launcher, port), ssh_env)
        self.children.append(child)
        self.event("host.execution.ssh_started")
        task_input = Input(self.fds[0]) if self.use_stdin else None
        if task_input is not None and task_input.failed:
            raise HostError("stdin_unsupported")
        if self.serve:
            # What `shell` is told: the owner's own bindings, nothing else
            # (published once its guest is ready).
            self.profile = {"user": connection.user, "identity": connection.identity,
                            "known_hosts": connection.known_hosts, "alias": connection.alias,
                            "launcher": layout.launcher,
                            "endpoint": None if connection.proxy is not None else list(connection.endpoint),
                            "session": self.nonce}
        argv = None if self.serve else self.argv
        if self.python and argv is not None:
            argv = list(plan.command_python()) + argv
            if guest_protocol.validate_argv(argv) is not None:
                raise HostError("argv_invalid")
        self.python_words = list(plan.command_python())
        self.guest = Guest(self.loop, child, self.capture, self.surfaces, self.nonce,
                           "x-1", argv, self.env, task_input, inputs=inputs)
        self._watch_guest()
        if self.export is not None and self._orderly() and not self.stopping():
            self._export_phase(child, connection, ssh_program, ssh_env, layout)

    def _stage(self, connection, ssh_program, ssh_env, stage, script, layout):
        self.checkpoint()
        code, out = self.short(connection.bootstrap(ssh_program), ssh_env, script.encode(), STAGE_TIMEOUT,
                               ssh.MAX_REPLY_BYTES)
        self.checkpoint()
        ok, reason = ssh.reply_ok(stage, layout, code, out)
        if not ok:
            self.event("host.bootstrap.failed", "warn", stage=stage, guest_reason=reason or "none")
            raise HostError("bootstrap_failed")

    def _upload_inputs(self, connection, ssh_program, ssh_env, layout):
        """The staged archive to the guest's own path for this execution;
        a retained run's attempt recorded first."""
        record = self.lease.record
        settings = record["inputs"]["settings"]
        if self.delivery == "once":
            inputs_mod.mark(self.lease, "attempted")
        self.event("host.inputs.upload", archive_bytes=record["inputs"]["archive_bytes"])
        argv = connection.scp(self.system.tool("scp"), ssh_program, inputs_mod.Paths(self.lease).archive(),
                              inputs_mod.guest_archive(layout.home, self.execution_id))
        code, _ = self.short(argv, ssh_env, b"", settings["upload_timeout_ms"] / 1000.0, 0)
        self.checkpoint()
        if code != 0:
            raise HostError("inputs_upload_failed")
        return self.execution_id

    def _watch_guest(self):
        guest = self.guest
        cancel_at = None
        while not guest.done():
            if guest.ready and self.deadline < self.hard_deadline and self.timeout is None and not self.stopping():
                # Ready within its setup: from now on untimed.
                self.deadline = self.hard_deadline
            if self.owner is not None and (self.owner.exchange.result is not None or self.owner.error is not None
                                           or self.owner.child.exited()):
                self.report.fail("provider_lost")
                break
            if self.server.failed():
                self.report.fail("server_lost")
                break
            if self.stopping() and cancel_at is None:
                self.report.fail(self.stop_reason())
                if guest.ready and not self.serve:
                    guest.cancel()
                    cancel_at = time.monotonic() + CANCEL_GRACE
                else:
                    break
            if cancel_at is not None and (time.monotonic() >= cancel_at or self.forced()):
                break
            if guest.ready and self.serve and not self.shell_published and not self.stopping():
                self._publish_shell()
            if self.client is not None and guest.ready and not self.client_done and self.client.turn(False):
                # The interactive session ended: the serving owner stops.
                self.client_done = True
                self.event("host.agent.session_ended")
            self.housekeeping()
            self.loop.step(0.05)
        if guest.inputs_ready and self.delivery == "once":
            inputs_mod.mark(self.lease, "ready")
        if guest.exit is not None:
            self.report.fail("completed")
            self.report.exit = guest.exit
        elif guest.failure is not None:
            self.report.fail(guest.failure)
        else:
            self.report.fail("session_unfinished")

    # -- the shell profile -------------------------------------------------

    def _publish_shell(self):
        """The serving owner's profile, once its guest is ready; with a
        stdio route also its filtered PATH (the transport's provider
        connect resolves the very programs its start did)."""
        self.shell_published = True
        path = host_path() if self.profile["endpoint"] is None else None
        try:
            self.publication.serving(self.profile, path)
        except HostError as error:
            self.event("host.shell.unpublished", "warn", code=error.code)
            return
        self.event("host.shell.published")

    # -- the execution's export --------------------------------------------

    def _orderly(self):
        """The command's own exit (any code): the only start of an export.
        A signaled, failed or cancelled end is not."""
        return self.guest is not None and self.guest.exit is not None and self.guest.exit["outcome"] == "exited"

    def _export_phase(self, session, connection, ssh_program, ssh_env, layout):
        """After the command's exit: the lane closed (its active request
        cancelled, nothing new admitted; results and cleanup still drained),
        the session ended, then the export's own ssh, by min(its allowance,
        the runtime less STOP_RESERVE); a stop or signal aborts it."""
        if self.lane is not None:
            self.lane.close(self.forced)
        self.guest.close()
        until = time.monotonic() + SESSION_END_TIMEOUT
        while not (session.exited() or self.cancelled()) and time.monotonic() < until:
            self.housekeeping()
            self.loop.step(0.05)
        if self.cancelled():
            return
        allowance = self.export["settings"]["timeout_ms"] / 1000.0
        cutoff = min(time.monotonic() + allowance, self.hard_deadline - export_mod.STOP_RESERVE)
        script = export_mod.script(layout.home, layout.work)
        child = self.spawn(connection.bootstrap(ssh_program), ssh_env)
        self.children.append(child)
        self.event("host.export.started")
        self.export_end = export_mod.Transfer(self.loop, child, self.output, script).run(
            cutoff, self.cancelled, self.housekeeping)
        self.event("host.export.ended", end=str(self.export_end), sink=self.output.sink,
                   written_bytes=self.output.bytes)

    def _conclude_export(self):
        """Publication only after a terminal exit's export, confirmed host
        cleanup and no cancellation; else the partial removed by its live
        descriptor. The reservation cleared once its partial is published
        or removed; kept otherwise (`jail stop` names it)."""
        output = self.output
        code = None
        if output is None:
            code = self.report.reason if self.report.reason not in (None, "completed") else "export_not_run"
        elif self.export_end is None or not self._orderly():
            code = "export_not_run"
        else:
            code = export_mod.failure(self.export_end, output.sink)
        if code is None and self.cancelled():
            code = "interrupted"
        if code is None and not self.report.host_cleanup:
            code = "cleanup_unconfirmed"
        exit_code = self.export_end if isinstance(self.export_end, int) and self.export_end != 0 else None
        if output is not None:
            if self.report.host_cleanup:
                export_mod.rewrite(self.lease, self.export_id, lambda value: dict(value, processes="settled"))
            if code is None:
                try:
                    output.publish(self.export["name"])
                except HostError as error:
                    code = error.code
            if code is not None:
                output.remove()
            output.close()
        partial = None if output is None else output.partial
        cleared = partial in (None, "removed") and export_mod.rewrite(self.lease, self.export_id, lambda value: None)
        written = None if output is None else output.bytes
        self.export_result = (code, written, exit_code, partial, cleared)
        self.event("host.export.finished", "info" if code is None else "warn", code=code or "none",
                   partial=partial or "none", cleared=cleared)

    # -- teardown --------------------------------------------------------

    def _teardown(self):
        self.tearing_down = True
        # No shell transport admitted from here: withdrawn before D's kill.
        if self.publication is not None and not self.publication.withdraw():
            self.event("host.shell.withdraw_failed", "warn")
        if self.client is not None:
            # Its SSH children end first (bounded), the terminal set back.
            self.client.end()
        self.teardown_signals = len(self.loop.signals)
        self.event("host.execution.stopping", reason=self.report.reason or "internal")
        if self.lane is not None:
            self.lane.close(self.forced)
        if self.guest is not None:
            self.guest.close()
        for child in self.children:
            if not self.forced():
                self.loop.run(lambda: child.exited() or self.forced(), time.monotonic() + SESSION_END_TIMEOUT)
            if not child.exited():
                child.kill_group()
            child.finish()
        server_clean = True
        if self.server is not None:
            server_clean = self.server.shutdown(force=self.forced)
        self._stop_provider()
        processes = self._kill_domain()
        self.report.host_cleanup = processes and server_clean
        if self.lane is not None:
            self.report.lane_clean = self.lane.dispose(server_clean, self.domain is not None and processes)
            self.spool_released = self.lane.released
        elif self.spool is not None:
            # Made, never used: no worker or upload ran.
            import shutil
            shutil.rmtree(self.spool, ignore_errors=True)
            self.spool_released = absent(self.spool)
        self._settle(processes)
        if self.session_dir is not None and processes:
            self.lease.remove_session(self.execution_id)

    def _stop_provider(self):
        """The owner's `stop`, awaited for its own timeout. A signal arriving
        during teardown cancels it (one grace, never renewed); the
        execution's second signal ends the wait at once, the provider then
        unanswered and the run pending for `jail stop`."""
        owner = self.owner
        if owner is None:
            return
        base = self.teardown_signals
        if owner.exchange.waiting and owner.error is None and not owner.channel.ended:
            stop = {"v": 1, "type": "stop", "operation": new_id("o"), "timeout_ms": provider.STOP_TIMEOUT_MS,
                    "run": owner.request["run"], "resource": owner.request["resource"],
                    "execution": owner.request["execution"], "instance": owner.request["instance"],
                    "generation": owner.request["generation"]}
            try:
                owner.host(stop)
            except provider_protocol.ProtocolError:
                owner.error = "stop_refused"
            owner.wait(lambda: owner.exchange.result is not None, provider.STOP_TIMEOUT_MS,
                       stop=lambda: len(self.loop.signals) > base, force=self.forced)
        elif owner.exchange.result is None:
            # A start still in flight: cancelled (once) and awaited for what
            # is left of that one grace.
            owner.wait(lambda: owner.exchange.result is not None, 0, force=self.forced)
        owner.end()

    def _kill_domain(self):
        """D killed, read empty and removed, within KILL_TIMEOUT: a shell
        transport joining between the kill and the removal (a slot made,
        a member) is killed again and the removal retried. Settled only
        once D's removal is confirmed; else the run stays pending."""
        if self.domain is None:
            return True
        deadline = time.monotonic() + KILL_TIMEOUT
        while True:
            if not self.domain.kill_until(deadline, self.idle):
                return False
            if self.domain.remove():
                return True
            if time.monotonic() >= deadline:
                self.event("host.domain.residue", "warn")
                return False
            self.idle(cgroups.KILL_POLL)

    def _settle(self, processes):
        """The run's record: pending cleared only on both settlements."""
        record = self.lease.record
        pending = record["pending"]
        if pending is None:
            return
        outcome = self.owner.settled_answer() if self.owner is not None else None
        fields = {"processes": "settled" if processes else "unknown"}
        generation = record["generation"]
        if outcome is None:
            fields.update(provider="unanswered", settlement="unknown")
        else:
            fields.update(provider=outcome["end"], settlement=outcome["settlement"],
                          durability=outcome["durability"], code=outcome["code"])
            if outcome["code"] and self.report.provider_code is None:
                self.report.provider_code = outcome["code"]
            if outcome["end"] == "stopped":
                generation = self.owner.exchange.result["generation"]
        settled = processes and outcome is not None and outcome["settlement"] == "settled"
        storage = record["storage"]
        if outcome is not None and outcome["end"] == "stopped":
            storage = self.owner.exchange.result["storage"]
        elif outcome is None or outcome["durability"] == "uncertain":
            # Possibly written, never confirmed: never promoted clean.
            storage = "unclean"
        if outcome is not None:
            self.report.provider = outcome["settlement"] if outcome["settlement"] in ("settled", "unsettled") \
                else "unknown"
            self.report.durability = outcome["durability"]
        else:
            self.report.provider = "unknown"
        if settled:
            self.lease.save(dict(record, pending=None, generation=generation, storage=storage))
        else:
            self.lease.save(dict(record, generation=generation, storage=storage, pending=dict(pending, **fields)))

    def _finish(self):
        report = self.report
        if report.reason is None:
            report.reason = "internal"
        self.event("host.execution.finished", "info" if report.ok() else "warn", reason=report.reason,
                   cleanup_confirmed=report.host_cleanup)
        deadline = time.monotonic() + DISPLAY_TIMEOUT
        for surface in self.surfaces.values():
            incomplete = surface.finish(deadline)
            if incomplete is not None and report.output is None:
                report.output = incomplete
        report.capture_complete = self.capture.close()
        state = {"state": "finished", "outcome": report.outcome(), "reason": report.reason,
                 "exit": None if report.exit is None else report.exit.get("code", report.exit["outcome"]),
                 "host_cleanup": report.host_cleanup, "provider": report.provider}
        if self.reserve and not self.spool_released:
            # Its storage still outstanding: reserved until removed, with
            # the exact root it lives under (never the current default).
            state["spool"] = self.reserve
            if self.stage_root is not None:
                state["spool_root"] = self.stage_root
        try:
            self.lease.write_execution(self.execution_id, state)
        except (OSError, HostError):
            report.capture_complete = False
        # On the stream it belongs to, on its own line, bounded: a reader
        # that stopped reading loses it, never holds the lease.
        if self.client is not None:
            # The agent's own line first (its SSH ended, the terminal set
            # back), then the owner's.
            self.client_code = self.client.report(lambda text: display.emit(self.fds[1], text.encode()),
                                                  lambda text: display.emit(self.fds[2], text.encode()))
        line = report.line()
        stream = "stdout" if report.ok() and not self.report_err else "stderr"
        prefix = "" if self.surfaces[stream].tail in (None, ord("\n")) else "\n"
        display.emit(self.fds[1] if stream == "stdout" else self.fds[2], (prefix + line + "\n").encode())
        ok = report.ok()
        if not ok and report.reason == "provider_failed" and report.provider_code in ("prerequisite", "failed") \
                and self.lease.record["kind"] == "managed" \
                and recorded_name(self.lease.record["provider"]) == "podman":
            display.emit(self.fds[2], PODMAN_START_FAILED.encode())
        elif not ok and report.reason == "provider_failed" and report.provider_code in lifecycle.PROVIDER_HINTS:
            display.emit(self.fds[2], f"agentbox: hint: {lifecycle.PROVIDER_HINTS[report.provider_code]}\n".encode())
        if self.export_result is not None:
            # Its own line; a failed export fails the command, whatever
            # the command's exit.
            code, written, exit_code, partial, cleared = self.export_result
            text = export_mod.line(self.export_id, code, written, exit_code, partial, cleared)
            display.emit(self.fds[1] if code is None else self.fds[2], (text + "\n").encode())
            ok = ok and code is None
            line += "\n" + text
        return (0 if ok else 1), line
