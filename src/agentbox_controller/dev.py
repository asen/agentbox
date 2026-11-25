"""`dev AGENT`: one retained jail per project directory on the built-in
Podman shared store, its agent on this terminal as `run AGENT --jail`
(agentrun.py); `dev setup --share-agent-dirs`: the one-time opt-in that
mounts the host's agent directories into every new dev jail.

```text
dev AGENT  every agent check first (agentrun.AgentRun.ready: options,
           terminal, adapter plan); nothing created before
           PROJECT  realpath(cwd); never /, HOME or a directory holding it
           expected PROJECT rw at its project location
                    + dev.json agent_dirs rw at .pi .codex .claude
                      (none with --no-harness-mount)
                    + --mount-ro / --mount-rw
           NAME     --jail NAME, else dev-SLUG-HASH (SHA-256 of PROJECT)
           NAME live: its recorded facts, never the tag: built-in Podman,
                    shared-store capabilities, retention home with its
                    volume, project and mounts exactly the expected set (any
                    order); else refused with the difference. Busy: refused
                    (`shell` hinted only while a live session serves it).
           none:    tag `dev` (built-in Podman): jail create -t NAME
                    --retention home, the expected mounts, the shared
                    store's capabilities required now (else nothing recorded)
           agent    its lease taken (busy: refused as above), then run AGENT
                    --jail NAME, interactive, on that lease; the jail kept on
                    any outcome, a partial one never discarded here
dev setup  --share-agent-dirs: ~/.pi ~/.codex ~/.claude each an existing
           directory (none made), resolved, recorded in dev.json; its
           other settings kept; at most MAX_BYTES (else the old file
           stays); existing jails unchanged
dev.json   $XDG_CONFIG_HOME/agentbox/dev.json, else ~/.config/agentbox/dev.json:
           yours, 0600, agentbox.dev-config.v1 {"schema"[, "agent_dirs":
           {"pi": ABS, "codex": ABS, "claude": ABS}][, "acquisition_config": ABS
           [, "acquisition_stage_root": ABS]]} (the lane: --acquisition-config overrides)
```

Sharing is a host mount like any `--mount-rw` (mounts.py): no copy, no
credential handling, no egress. What it exposes is the operator's
choice, stated by setup before it writes (WARNING).
"""
import fcntl
import hashlib
import os
import re
import secrets
import stat

from . import images, lifecycle, mounts as mounts_mod
from .assets import provider_protocol
from .builtin import hinted
from .config import _location, read_private, strict_json
from .host import HostError, capture_host

TAG = "dev"
SCHEMA = "agentbox.dev-config.v1"
FILE = "dev.json"
MAX_BYTES = 8192
# The host agent directories setup shares, each at HOME/.NAME, mounted at .NAME.
AGENT_DIRS = ("pi", "codex", "claude")
# What a dev jail's provider advertises: Podman's shared store.
SHARED = ("explicit_retention", "host_mounts", "project_layout")
MAX_SLUG = 40
IMAGE_HINT = "prepare it once: agentbox image prepare podman --store shared --preset dev -t dev"
WARNING = ("agentbox: warning: every new dev jail mounts ~/.pi, ~/.codex and ~/.claude read-write: any process in "
           "it can read the credentials and refresh tokens there and change the configuration, hooks, extensions and "
           "code your host's pi, codex and claude load and run. The project directory is mounted read-write as "
           "well: the jail can change its code and git hooks the same way.\n")


def path(environ):
    return _location(environ, "XDG_CONFIG_HOME", f"agentbox/{FILE}", f".config/agentbox/{FILE}",
                     "dev_config_location_invalid")


def check(value):
    keys = {"schema", "agent_dirs", "acquisition_config", "acquisition_stage_root"}
    dirs = value.get("agent_dirs") if isinstance(value, dict) else None
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or not set(value) <= keys \
            or ("agent_dirs" in value and (not isinstance(dirs, dict) or set(dirs) != set(AGENT_DIRS)
                                           or not all(provider_protocol.is_path(p) for p in dirs.values()))) \
            or any(k in value and not provider_protocol.is_path(value[k])
                   for k in ("acquisition_config", "acquisition_stage_root")) \
            or ("acquisition_stage_root" in value and "acquisition_config" not in value):
        raise HostError("dev_config_invalid")
    return value


def load(location):
    """dev.json's checked value; {} when absent."""
    if not os.path.lexists(location):
        return {}
    return check(strict_json(read_private(location, MAX_BYTES, "dev_config_unreadable"), "dev_config_invalid"))


def _home():
    home = dict(capture_host()).get("HOME")
    if not home or not provider_protocol.is_path(home):
        raise hinted("dev_home_invalid", "HOME must be an absolute path")
    return home


# -- setup -------------------------------------------------------------------

def setup(environ, share, say, warn):
    """`dev setup --share-agent-dirs`: the three directories recorded,
    resolved, once each is an existing directory; dev.json's other
    settings kept (under a lock on its directory), written atomically."""
    if not share:
        raise hinted("dev_setup_opt_in_required",
                     "agentbox dev setup --share-agent-dirs: every new dev jail then mounts your ~/.pi, ~/.codex "
                     "and ~/.claude read-write, exposing their tokens and letting the jail change what your host "
                     "runs (agentbox --help)")
    home = _home()
    location = path(environ)
    found, missing = {}, []
    for name in AGENT_DIRS:
        try:
            real = os.path.realpath(f"{home}/.{name}", strict=True)
            ok = stat.S_ISDIR(os.stat(real).st_mode) and provider_protocol.is_path(real)
        except (OSError, ValueError):
            ok = False
        if ok:
            found[name] = real
        else:
            missing.append(f"~/.{name}")
    if missing:
        raise hinted("agent_dirs_missing",
                     f"not an existing directory: {', '.join(missing)}. Log in with that agent on this host (it "
                     f"makes its directory) or make it yourself (mkdir -m 700 {missing[0]}), then run setup again; "
                     "setup makes nothing")
    directory = os.path.dirname(location)
    try:
        os.makedirs(directory, 0o700, exist_ok=True)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise HostError("dev_config_unwritable") from None
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        data = _dump(check(dict(load(location) or {"schema": SCHEMA}, agent_dirs=found)))
        # Never more than a later read accepts: the old file kept.
        if len(data) > MAX_BYTES:
            raise hinted("dev_config_too_large", f"dev.json would exceed {MAX_BYTES} bytes: shorten the paths in it")
        warn(WARNING)
        _replace(fd, FILE, data)
    finally:
        os.close(fd)
    say(f"dev setup: {location} agent_dirs={','.join(AGENT_DIRS)}\n")
    warn("agentbox: note: existing dev jails keep their mounts: one made without these now refuses until you reuse "
         "it with --no-harness-mount, pick another --jail NAME, or discard and recreate it\n")


def _dump(value):
    import json
    return (json.dumps(value, indent=1, sort_keys=True) + "\n").encode()


def _replace(dir_fd, name, data):
    temp = f".{name}.{secrets.token_hex(8)}"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                     dir_fd=dir_fd)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rename(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except OSError:
            os.unlink(temp, dir_fd=dir_fd)
            raise
        os.fsync(dir_fd)
    except OSError:
        raise HostError("dev_config_unwritable") from None


# -- the agent -----------------------------------------------------------------

def project_dir(home):
    """The canonical project directory: this process's, resolved; never /,
    HOME or a directory holding it."""
    try:
        project = os.path.realpath(os.getcwd(), strict=True)
    except (OSError, ValueError):
        raise HostError("dev_project_unavailable") from None
    homes = {home}
    try:
        homes.add(os.path.realpath(home, strict=True))
    except (OSError, ValueError):
        pass
    if project == "/" or any(h == project or h.startswith(project + "/") for h in homes):
        raise hinted("dev_project_invalid", "run agentbox dev from a project directory: not /, your HOME or a "
                                            "directory holding it")
    return project


def default_name(project):
    """dev-SLUG-HASH: the directory's name made a run name, and the first
    12 hex of its path's SHA-256."""
    slug = re.sub(r"[^a-z0-9]+", "-", os.path.basename(project).lower()).strip("-")[:MAX_SLUG].strip("-")
    return f"dev-{slug or 'project'}-{hashlib.sha256(project.encode()).hexdigest()[:12]}"


def expected(options, settings, project, home):
    """(mounts, project location): mounts.select of the project, the
    shared agent directories (unless opted out) and the extras."""
    shared = []
    if "agent_dirs" in settings and not options.get("--no-harness-mount"):
        shared = [(settings["agent_dirs"][name], f".{name}", "rw") for name in AGENT_DIRS]
    args = [(project, None, "rw")] + shared + [mounts_mod.parse(v, "ro") for v in options["--mount-ro"]] \
        + [mounts_mod.parse(v, "rw") for v in options["--mount-rw"]]
    selected, location, _ = mounts_mod.select(args, project, project, home)
    return selected, location


def _lookup(store, name):
    try:
        return store.resolve(name)
    except HostError as error:
        if error.code == "run_unknown":
            return None
        raise


def _shown(mount):
    return f"{mount[2]} {mount[0]} -> {mount[1]}"


class Dev:
    def __init__(self, system, controller, store, options, environ, out, err):
        from .agentrun import _say
        self.system, self.controller, self.store = system, controller, store
        self.options, self.environ = options, environ
        self.say = lambda text: _say(out, text)
        self.warn = lambda text: _say(err, text)
        self.out, self.err = out, err

    def agent_options(self, settings):
        """`run AGENT --jail` options: the agent's own, the lane (the
        command's, else dev.json's); the target set once selected."""
        options = self.options
        chosen = {"positional": list(options["positional"]), "argv": options["argv"], "--env": list(options["--env"]),
                  "--copy": [], "--mount-ro": [], "--mount-rw": [], "--jail": None}
        if "--model" in options:
            chosen["--model"] = options["--model"]
        if "--acquisition-config" in options:
            chosen["--acquisition-config"] = options["--acquisition-config"]
            if "--acquisition-stage-root" in options:
                chosen["--acquisition-stage-root"] = options["--acquisition-stage-root"]
        elif "acquisition_config" in settings:
            chosen["--acquisition-config"] = settings["acquisition_config"]
            if "acquisition_stage_root" in settings:
                chosen["--acquisition-stage-root"] = settings["acquisition_stage_root"]
        return chosen

    def run(self):
        from .agentrun import AgentRun
        from .store import check_name
        options = self.options
        agent = options["positional"][0]
        settings = load(path(self.environ))
        runner = AgentRun(self.system, self.controller, self.store, self.agent_options(settings), self.environ,
                          self.out, self.err)
        runner.ready()
        home = _home()
        project = project_dir(home)
        selected, location = expected(options, settings, project, home)
        name = check_name(options["--jail"]) if "--jail" in options else default_name(project)
        run_id = _lookup(self.store, name)
        created = False
        if run_id is None:
            run_id = self.create(name, selected, location, project)
            created = run_id is not None
            if run_id is None:
                # Another command took the name first: its jail, checked.
                run_id = _lookup(self.store, name)
                if run_id is None:
                    raise HostError("run_name_taken")
        if not created:
            self.check(run_id, name, agent, selected, location)
        # Held from here to the agent's execution: busy now is as busy above.
        lease = self.claim(run_id, name, agent)
        try:
            self.say(f"dev: {'created' if created else 'jail'} {name} id={run_id} project={project}\n")
            runner.options["--jail"] = run_id
            run_id, _ = runner.target(False)
            return runner.task(run_id, False, False, lease)
        finally:
            lease.release()

    def claim(self, run_id, name, agent):
        """The run's lease, or the busy refusal."""
        try:
            return self.store.claim(run_id)
        except HostError as error:
            if error.code != "run_busy":
                raise
        raise self.busy(run_id, name, agent)

    def busy(self, run_id, name, agent):
        """`dev_jail_busy`: `shell` suggested only while a live serving
        owner publishes its profile (read once: best effort, the holder may
        change right after)."""
        from . import owner
        try:
            owner.serving(self.store, run_id)
        except HostError:
            return hinted("dev_jail_busy", f"another command holds {name}: agentbox jail status {name}, retry once "
                                           f"it ends, or agentbox dev {agent} --jail OTHER for another jail")
        return hinted("dev_jail_busy", f"an agent session serves {name}: agentbox shell {name} opens a login there; "
                                       f"agentbox dev {agent} --jail OTHER for another jail")

    def create(self, name, selected, location, project):
        """A new dev jail named `name`; None when another command's run took
        the name first. A failed create's run stays (partial), reported."""
        tag = images.read(self.store.path, TAG)
        if tag is None:
            raise hinted("dev_image_missing", IMAGE_HINT)
        if tag["provider"].get("builtin") != "podman":
            raise hinted("dev_image_unsupported", "the dev tag must be a built-in Podman image: " + IMAGE_HINT)
        try:
            return lifecycle.create(self.system, self.store, tag["provider"], tag["image"], "home", {},
                                    provider_protocol.DEFAULT_USER, selected, location, project, name,
                                    require=SHARED)
        except HostError as error:
            run_id = getattr(error, "run_id", None)
            if error.code == "run_name_taken" and run_id is None:
                return None
            if error.code == "features_missing":
                raise hinted("dev_store_not_shared", "dev jails need Podman's shared store: " + IMAGE_HINT) from None
            if run_id is not None:
                self.warn(f"agentbox: dev: jail create failed (code={error.code}); {name} ({run_id}) keeps its "
                          f"name: agentbox jail status {name}, then agentbox jail discard {name}\n")
            raise

    def check(self, run_id, name, agent, selected, location):
        """An existing run's recorded facts against this request; read
        without its lease (fixed at creation), so a busy one is checked
        too."""
        status = self.store.status(run_id)
        record = status["record"]
        if record["kind"] != "managed" or record["provider"].get("builtin") != "podman" \
                or record["retention"] != "home" \
                or any(feature not in record["described"]["features"] for feature in SHARED):
            raise hinted("dev_jail_unsuitable", f"{name} is not a dev jail (built-in Podman, shared store, retained "
                                                f"HOME): agentbox dev {agent} --jail OTHER")
        if record["phase"] == "partial":
            raise hinted("dev_jail_partial", f"{name}'s create did not complete: agentbox jail status {name}, then "
                                             f"agentbox jail discard {name}")
        if record["phase"] == "creating":
            if status["state"] == "active":
                raise hinted("dev_jail_busy", f"{name} is being created by another command: retry once it ends")
            raise hinted("dev_jail_unsettled", f"agentbox jail status {name}, then agentbox jail stop {name}")
        want = {(m["source"], m["destination"], m["access"]) for m in selected}
        have = {(m["source"], m["destination"], m["access"]) for m in record["mounts"]}
        if want != have or record["project"] != location or not record.get("volume"):
            lines = [f"agentbox: dev: {name} differs from this request:\n"]
            lines += [f"  jail only:      {_shown(m)}\n" for m in sorted(have - want)]
            lines += [f"  requested only: {_shown(m)}\n" for m in sorted(want - have)]
            if record["project"] != location:
                lines.append(f"  project:        jail {record['project']}, requested {location}\n")
            if not record.get("volume"):
                lines.append("  HOME:           no shared-store volume recorded\n")
            self.warn("".join(lines))
            raise hinted("dev_jail_mismatch",
                         f"repeat the jail's extra mounts (--mount-ro/--mount-rw; --no-harness-mount for one "
                         f"without agent directories), use another jail (agentbox dev {agent} --jail OTHER), or "
                         f"recreate it: agentbox jail discard {name} (its HOME is deleted)")
        if status["state"] == "active":
            raise self.busy(run_id, name, agent)
        if status["state"] == "abandoned":
            raise hinted("dev_jail_unsettled", f"agentbox jail status {name}, then agentbox jail stop {name}")


def run(system, controller, store, options, environ, out, err):
    return Dev(system, controller, store, options, environ, out, err).run()
