"""`run AGENT ...`: one coding-agent task as the existing operations
in order, in this one process, each with its own custody, bounds and
report (the old CLI's cli_agent.rs; docs/agents.md). Headless with a
prompt; without one, interactive on this terminal (interactive.py).

```text
local checks: prompt, --env values, sources, credential path,
              export destination, the agent's tools
adapter (agent.py) -> plan; credential expiry; input framed (interactive:
         staged, with --env); headless --env in its exec frame
[--install-agent] the packaged npm handler, its packaged registry policy
target   --jail JAIL         the existing run, by id or name (unclean refuses);
                             its mounts checked under its lease
         --ssh-target FILE   jail create --ssh-target (id printed)
         [--image NAME]      jail create of the tag's image (else `default`),
                             owned by this command; its mounts checked first
mounts   the credential's destination or the managed install's
         (INSTALL_ROOT/AGENT) meeting a mount's: auth_location_mounted,
         install_location_mounted, before anything reaches the jail
[--workspace/--copy] jail inputs
headless     jail exec of the runner: stdin = the input, [--export-to],
             [installer lane]; untimed, or --timeout S enforced (the
             export's share carved from it)
interactive  jail serve, untimed (lifetime null), its client the session:
             staging SSH, the terminal's SSH, unstaging SSH; [its lane:
             --acquisition-config, else acquisition.json, else the packaged
             defaults (handlers.py), shared with `shell` logins]
owned:   headless: export published, or none asked -> jail discard; else
         kept, recovery printed; interactive: retained (reopen printed), or
         discarded with --discard or when the provider kept no storage
         (an `explicit_retention` provider: HOME only by jail create
         --retention, so --export-to and mounts refuse); an unsettled
         execution keeps it
```

One interrupt list for the whole command (host.share_signals): an
interrupt stops the running step or the next before it starts, and stays
asked; an owned run's cleanup then still runs, a fresh list counting only
interrupts during it. Selecting the target is the authorization. Attached
and existing runs are never stopped, discarded or cleaned up by this
command. One delegated scope for the process (System.enter, once): every
managed step gets its own fresh domain in it, settled before the next.
"""
import os

from . import agent as agent_mod
from . import export as export_mod
from . import handlers, host, inputs as inputs_mod, interactive, lifecycle, mounts as mounts_mod, shell
from .assets import ASSETS, guest_protocol, provider_protocol
from .config import host_config, input_tools
from .display import emit
from .execute import Execution
from .host import HostError, capture_host, host_path

# Retained storage for an owned run's export, mounts or interactive work,
# in preference order; interactive work falls back to none (an
# `explicit_retention` provider's: a disposable run).
RETAINED = ("home", "home_tmp", "disk")
# The longest interpreter path a target may bind (ssh.Layout's root bound),
# for the headless frame's check before any target.
LONGEST_PYTHON = "/" + "p" * 1023


def check_mounted(plan, agent, mounts):
    """Neither the copied credential nor a managed install is written into
    a host mount (ro or rw): its location equal to, inside or containing a
    mount's destination refuses."""
    for mount in mounts:
        destination = mount["destination"]
        if plan.credential_path is not None and provider_protocol.overlap(plan.credential_path, destination):
            raise HostError("auth_location_mounted")
        if plan.install and provider_protocol.overlap(f"{agent_mod.INSTALL_ROOT}/{agent}", destination):
            raise HostError("install_location_mounted")


def _say(stream, text):
    try:
        emit(stream.fileno(), text.encode())
    except (AttributeError, OSError, ValueError):
        stream.write(text)


def _cwd():
    try:
        return os.getcwd()
    except OSError:
        return None


def _host_home():
    home = dict(capture_host()).get("HOME")
    return home if home and provider_protocol.is_path(home) else None


def check_options(options):
    """The argument rules (cli_agent.rs `parse`): one target (an owned run
    unless --jail or --ssh-target), the account and mounts only for an
    owned run, one prompt at most; headless: no
    --discard, trailing words or custom acquisition lane (its lane is the
    installer's); interactive: no install, export or timeout."""
    agent = options["positional"][0]
    if agent not in agent_mod.AGENTS:
        from .builtin import hinted
        # Never a command: that is `run -- ARG...`.
        raise hinted("agent_unknown", f"agents: {', '.join(agent_mod.AGENTS)}; a command: agentbox run -- ARG...")
    targets = ["--image" in options, "--jail" in options, "--ssh-target" in options]
    if sum(targets) > 1:
        raise HostError("target_conflict")
    owned = "--jail" not in options and "--ssh-target" not in options
    if "--user" in options and not owned:
        raise HostError("user_requires_provider")
    if (options["--mount-ro"] or options["--mount-rw"] or "--project" in options) and not owned:
        raise HostError("mount_requires_provider")
    if "--project" in options and not (options["--mount-ro"] or options["--mount-rw"]):
        raise HostError("project_requires_mount")
    if "--project" in options and "--workspace" in options:
        raise HostError("project_with_workspace")
    if "--prompt" in options and "--prompt-file" in options:
        raise HostError("prompt_conflict")
    if "--agent-version" in options and "--install-agent" not in options:
        raise HostError("agent_version_requires_install")
    if "--keep-auth" in options and "--copy-auth" not in options:
        raise HostError("keep_auth_requires_copy_auth")
    if "--model" in options and not agent_mod.is_model(options["--model"]):
        raise HostError("invalid_model")
    if "--prompt" in options and not options["--prompt"]:
        raise HostError("invalid_prompt")
    if "--prompt" in options and len(options["--prompt"].encode()) > agent_mod.MAX_PROMPT_BYTES:
        raise HostError("prompt_too_large")
    headless = "--prompt" in options or "--prompt-file" in options
    args = options["argv"] or []
    if args and guest_protocol.validate_argv(args) is not None:
        raise HostError("invalid_argv")
    if headless and ("--discard" in options or args):
        raise HostError("headless_unexpected_argument")
    if not headless and "--install-agent" in options:
        raise HostError("interactive_install_unsupported")
    if not headless and "--export-to" in options:
        raise HostError("interactive_export_unsupported")
    if not headless and "--timeout" in options:
        raise HostError("interactive_timeout_unsupported")
    if headless and "--acquisition-config" in options:
        raise HostError("headless_acquisition_unsupported")
    if "--discard" in options and not owned:
        raise HostError("discard_requires_provider")
    return agent, headless, owned


def read_prompt(options, cwd):
    if "--prompt" in options:
        return options["--prompt"]
    path = inputs_mod.resolve(options["--prompt-file"], cwd) if options["--prompt-file"] else ""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except (OSError, ValueError):
        raise HostError("prompt_unreadable") from None
    try:
        import stat
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise HostError("prompt_unreadable")
        data = os.read(fd, agent_mod.MAX_PROMPT_BYTES + 1)
    finally:
        os.close(fd)
    if len(data) > agent_mod.MAX_PROMPT_BYTES:
        raise HostError("prompt_too_large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HostError("invalid_prompt") from None
    if not text:
        raise HostError("invalid_prompt")
    return text


class AgentRun:
    def __init__(self, system, controller, store, options, environ, out, err):
        self.system, self.controller, self.store = system, controller, store
        self.options, self.environ, self.out, self.err = options, environ, out, err
        self.exported = None
        # An owned run's retention (target).
        self.retention = None

    def say(self, text):
        _say(self.out, text)

    def warn(self, text):
        _say(self.err, text)

    def interrupted(self):
        return bool(host.SHARED)

    # -- steps ----------------------------------------------------------

    def prepare(self, agent, headless):
        """Every local check, the adapter's plan and the framed input; the
        installer's selection. Nothing is created yet."""
        from .cli import select_env
        options, cwd = self.options, _cwd()
        prompt = read_prompt(options, cwd) if headless else None
        self.env = select_env(options["--env"], self.environ)
        self.chosen = None
        if "--workspace" in options or options["--copy"]:
            self.chosen = inputs_mod.selection(options.get("--workspace"), options["--copy"], cwd)
        auth = None
        if "--copy-auth" in options:
            try:
                auth = (inputs_mod.resolve(options["--copy-auth"], cwd), "--keep-auth" in options)
            except HostError:
                raise HostError("credential_unreadable") from None
        config = host_config(options.get("--host-config"), self.environ)
        # None: untimed once its guest is ready (interactive: always).
        self.timeout = int(options["--timeout"]) if "--timeout" in options else None
        self.exported = None
        if "--export-to" in options:
            chosen = export_mod.settings(config)
            if self.timeout is not None and export_mod.task_seconds(self.timeout, chosen["timeout_ms"]) is None:
                raise HostError("export_window_insufficient")
            parent_path, name = export_mod.destination(options["--export-to"], cwd)
            parent = export_mod.pin(parent_path, name, self.store.path)
            self.exported = {"parent": parent, "name": name, "settings": chosen}
            if export_mod.available(parent) < chosen["max_bytes"]:
                raise HostError("export_space_insufficient")
        self.interpreter, self.assets = agent_mod.tools(config, ASSETS, agent)
        request = agent_mod.request(agent, options.get("--model"),
                                    (options.get("--agent-version") if "--install-agent" in options else False),
                                    auth, None if headless else (options["argv"] or []))
        self.agent = agent
        self.plan = agent_mod.prepare(self.interpreter, self.assets, request,
                                      lambda line: self.warn(f"agentbox: agent adapter diagnostic: {line}\n"))
        plan = self.plan
        plan.check_expiry()
        if headless:
            self.input = agent_mod.framed(plan, prompt)
            if self.env:
                words = [LONGEST_PYTHON] + agent_mod.runner_argv(plan, "headless")
                try:
                    guest_protocol.encode_host_frame({"type": "exec", "id": "x-1", "argv": words, "stdin": True,
                                                      "env": tuple(sorted(self.env.items()))})
                except guest_protocol.Refused:
                    raise HostError("env_limit_exceeded") from None
        else:
            if plan.install:
                raise HostError("adapter_plan_invalid")
            agent_mod.framed(plan, "", ("0" * 32, self.env))
        self.installer = None
        # An interactive session's lane (refused headless: check_options),
        # the default one included; a headless run's is its installer's alone.
        from .cli import acquisition_selection
        self.selection, self.stage_root = acquisition_selection(options, self.environ, implicit=not headless,
                                                                interpreter=lambda: self.interpreter)
        if plan.install:
            self.installer = handlers.packaged(self.interpreter, self.assets, agent_mod.INSTALLER,
                                               agent_mod.REGISTRY_POLICY)
        if self.interrupted():
            raise HostError("interrupted")
        self.config = config

    def target(self, owned):
        """(run id, owned): the selected run."""
        options, store = self.options, self.store
        if "--jail" in options:
            run_id = store.resolve(options["--jail"])
            record = store.status(run_id)["record"]
            if record["phase"] == "discarded":
                raise HostError("run_discarded")
            if record["storage"] == "unclean":
                self.warn(f"agentbox: the run's storage is unclean: check it with agentbox jail status {run_id}, then "
                          f"agentbox jail exec {run_id} --allow-unclean GENERATION -- true\n")
                raise HostError("agent_jail_unclean")
            if self.plan.credential_path is not None or self.plan.install:
                lease = store.claim(run_id)
                try:
                    check_mounted(self.plan, self.agent, lease.record["mounts"])
                finally:
                    lease.release()
            return run_id, False
        if "--ssh-target" in options:
            from .attached import attach
            run_id = attach(store, options["--ssh-target"])
            self.say(f"run: created id={run_id} kind=attached\n")
            return run_id, False
        from .cli import resolve_user
        config = self.tag["provider"]
        user = resolve_user(options.get("--user"))
        args = [mounts_mod.parse(v, "ro") for v in options["--mount-ro"]] \
            + [mounts_mod.parse(v, "rw") for v in options["--mount-rw"]]
        selected, project, project_host = mounts_mod.select(args, options.get("--project"), _cwd(), _host_home())
        check_mounted(self.plan, self.agent, selected)
        headless = "--prompt" in options or "--prompt-file" in options
        needed = "--export-to" in options or bool(selected)
        keep = not headless and "--discard" not in options
        retention = RETAINED if needed else RETAINED + ("none",) if keep else "none"
        try:
            run_id = lifecycle.create(self.system, store, config, self.tag["image"], retention, {}, user,
                                      selected, project, project_host)
        except HostError as error:
            run_id = getattr(error, "run_id", None)
            if run_id is not None:
                # Nothing of the task in it: discarded (a pending one is
                # refused, reported).
                self.warn(f"agentbox: jail create failed (code={error.code})\n")
                self.discard(run_id)
                raise HostError("run_create_failed") from None
            raise
        lease = store.claim(run_id)
        try:
            retained = lease.record["retention"]
        finally:
            lease.release()
        self.retention = retained
        self.say(f"run: created id={run_id} kind=managed owned=true retention={retained}\n")
        return run_id, True

    def stage_inputs(self, run_id):
        lease = self.store.claim(run_id)
        try:
            interpreter, assets = input_tools(self.config, ASSETS)
            staged = inputs_mod.stage(self.store, lease, self.chosen, inputs_mod.settings({}), interpreter, assets,
                                      host_path(), _host_home())
            self.say(f"inputs: {run_id} staged archive_bytes={staged['archive_bytes']}\n")
        finally:
            lease.release()

    def discard(self, run_id):
        """An owned run's discard, only an interrupt during it stopping it;
        its exit status."""
        host.share_signals()
        try:
            lease = self.store.claim(run_id)
            try:
                result = lifecycle.discard(self.system, self.store, lease)
            finally:
                lease.release()
        except HostError as error:
            self.warn(f"agentbox: jail discard failed (code={error.code}); the owned run {run_id} remains: check "
                      f"agentbox jail status {run_id}, then agentbox jail stop {run_id} if an instance is pending, "
                      f"and agentbox jail discard {run_id}\n")
            return 1
        self.say(f"discard: {run_id} {result}\n")
        return 0

    def kept(self, run_id, why):
        self.warn(f"agentbox: the owned run {run_id} {why}\n")

    # -- the task ---------------------------------------------------------

    def headless(self, run_id):
        """The runner's execution: (exit status, settled, published)."""
        store, plan = self.store, self.plan
        lease = store.claim(run_id)
        try:
            plan.check_expiry()
            source = agent_mod.filled(self.input)
            try:
                execution = Execution(self.system, self.controller, store, lease,
                                      agent_mod.runner_argv(plan, "headless"), self.env, True, self.timeout,
                                      self.installer, in_fd=source, export=self.exported,
                                      python=plan.python)
                code, _ = execution.run()
            finally:
                os.close(source)
            settled = lease.record["pending"] is None and execution.report.host_cleanup
            published = execution.export_result is not None and execution.export_result[0] is None
            reason = execution.report.reason
        finally:
            lease.release()
        return code, settled, published, reason

    def interactive(self, run_id, lease=None):
        """The serving owner with its session client: (status, settled).
        `lease`: the run's, already held by the caller (released here)."""
        store, plan = self.store, self.plan
        nonce = agent_mod.new_nonce()
        plan.check_expiry()
        payload = agent_mod.framed(plan, "", (nonce, self.env))
        session = interactive.Session(plan, nonce, payload, self.system.tool("ssh"), shell.term(self.environ),
                                      self.controller.get("config_path"), self.environ)
        lease = store.claim(run_id) if lease is None else lease
        try:
            execution = Execution(self.system, self.controller, store, lease, None, {}, False, None, self.selection,
                                  stage_root=self.stage_root, serve=True, client=session)
            session.bind(execution)
            serve_code, _ = execution.run()
            settled = lease.record["pending"] is None and execution.report.host_cleanup
        finally:
            lease.release()
        code = 1 if execution.client_code is None else execution.client_code
        if "--keep-auth" in self.options and session.agent[0] == "ended":
            self.warn("agentbox: note: --keep-auth: the copied credential stays in the jail\n")
        return (code if code != 0 else serve_code), settled

    def ready(self):
        """Every check before a target: the options, the terminal, the tag
        (owned), the adapter's plan. (agent, headless, owned)."""
        options = self.options
        agent, headless, owned = check_options(options)
        if not headless and not interactive.foreground_terminal():
            raise HostError("interactive_terminal_required")
        if owned:
            from . import images
            self.tag = images.resolve(self.store.path, options.get("--image"))
        host.share_signals()
        self.prepare(agent, headless)
        return agent, headless, owned

    def run(self):
        try:
            agent, headless, owned = self.ready()
            run_id, owned = self.target(owned)
            return self.task(run_id, owned, headless)
        finally:
            if self.exported is not None:
                os.close(self.exported["parent"])

    def task(self, run_id, owned, headless, lease=None):
        """`lease`: an interactive run's, held by the caller (who releases
        it again if the agent's execution never took it)."""
        export = "--export-to" in self.options

        def before(code):
            """Failed or interrupted before the agent's execution."""
            if not owned:
                return code
            if export:
                self.kept(run_id, f"is kept (an export was asked for; the agent did not run): "
                                  f"agentbox jail status {run_id}, then agentbox run AGENT --jail {run_id} "
                                  f"... --export-to PATH, or agentbox jail discard {run_id}")
                return code
            return self.discard(run_id) or code

        if owned and headless and not export:
            self.warn("agentbox: warning: no --export-to: the owned run's jail-local storage is discarded on "
                      "cleanup; changes to writable host mounts remain\n")
        try:
            if self.interrupted():
                raise HostError("interrupted")
            if self.chosen is not None:
                self.stage_inputs(run_id)
            if self.interrupted():
                raise HostError("interrupted")
        except HostError as error:
            self.warn(f"agentbox: agent run failed (code={error.code}); the agent was not started\n")
            return before(1)
        if not headless:
            try:
                code, settled = self.interactive(run_id, lease)
            except HostError as error:
                self.warn(f"agentbox: agent run failed (code={error.code}); the agent was not started\n")
                return before(1)
            if not owned:
                return code
            if not settled:
                self.kept(run_id, f"is kept: its execution is not confirmed settled; agentbox jail status {run_id}, "
                                  f"agentbox jail stop {run_id}, then agentbox jail discard {run_id}")
                return 1
            if "--discard" in self.options or self.retention == "none":
                # Nothing kept to reopen.
                return self.discard(run_id) or code
            self.say(f"run: retained id={run_id}; reopen with agentbox run {self.options['positional'][0]} "
                     f"--jail {run_id} [-- ARG...]\n")
            return code
        try:
            code, settled, published, reason = self.headless(run_id)
        except HostError as error:
            self.warn(f"agentbox: agent run failed (code={error.code}); the agent was not started\n")
            return before(1)
        discarding = owned and settled and (not export or published)
        if "--copy-auth" in self.options and not discarding:
            if "--keep-auth" in self.options:
                self.warn("agentbox: note: --keep-auth: the copied credential stays in the jail\n")
            elif reason != "completed":
                self.warn("agentbox: warning: the agent did not end on its own: the copied credential may "
                          "remain in the jail\n")
        if not owned:
            return code
        if discarding:
            return self.discard(run_id) or code
        if not settled:
            self.kept(run_id, f"is kept: its execution is not confirmed settled; agentbox jail status {run_id}, "
                              f"agentbox jail stop {run_id}, then agentbox jail discard {run_id}")
        else:
            self.kept(run_id, f"is kept (its export was not published): recover with agentbox jail exec "
                              f"{run_id} --export-to PATH -- true, then agentbox jail discard {run_id}")
        return code or 1


def run(system, controller, store, options, environ, out, err):
    return AgentRun(system, controller, store, options, environ, out, err).run()
