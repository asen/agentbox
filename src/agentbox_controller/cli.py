"""Agentbox's command line: `bin/agentbox` (the packaged entry, PREFIX/bin)
or `python3 -I -B src/main.py` from a source tree (ASSETS/controller/main.py
installed).

```text
agentbox --help | --version
agentbox doctor           [--config FILE]
agentbox image prepare    [--config FILE] [-t NAME] PROVIDER [--preset NAME]
                          [--store shared|private | --provider-config FILE [--recipe PATH]]
agentbox image list       [--config FILE]
agentbox image recover    [--config FILE] PROVIDER [--store shared|private | --provider-config FILE]
                          OPERATION_ID
agentbox jail create      [--config FILE] [-t NAME] ([--image NAME] [--retention R]
                          [--cpus N] [--memory-mib N] [--pids N] [--disk-mib N]
                          [--user NAME|current] [--mount-ro SOURCE[=DEST]]...
                          [--mount-rw SOURCE[=DEST]]... [--project DIR] | --ssh-target FILE)
agentbox jail list        [--config FILE] [--all]
agentbox jail inputs      [--config FILE] JAIL [--workspace DIR] [--copy SRC=DEST]...
                          [--host-config FILE] [--max-archive-bytes N] [--max-entries N]
                          [--max-depth N] [--max-path-bytes N] [--prepare-timeout-ms N]
                          [--upload-timeout-ms N]
agentbox jail exec        [--config FILE] JAIL [--allow-unclean GENERATION]
                          [--env NAME]... [--stdin] [--timeout SECONDS] [--allow-connect HOST:PORT]...
                          [--insecure-open]
                          [--acquisition-config FILE [--acquisition-stage-root DIR]]
                          [--export-to PATH [--export-max-bytes N] [--export-timeout-ms N]] -- ARG...
agentbox jail serve       [--config FILE] JAIL [--allow-unclean GENERATION] [--allow-connect HOST:PORT]...
                          [--insecure-open]
                          [--acquisition-config FILE [--acquisition-stage-root DIR]]
agentbox jail export      [--config FILE] JAIL --to PATH [--host-config FILE] [--max-bytes N]
                          [--timeout-ms N]
agentbox shell            [--config FILE] JAIL [-- ARG...]
agentbox jail status      [--config FILE] JAIL
agentbox jail stop        [--config FILE] JAIL [--assert-local-ended ID]
agentbox jail discard     [--config FILE] JAIL
agentbox checkpoint create   [--config FILE] JAIL [--allow-unclean GENERATION]
agentbox checkpoint status   [--config FILE] CHECKPOINT_ID
agentbox checkpoint list     [--config FILE]
agentbox checkpoint discard  [--config FILE] CHECKPOINT_ID
agentbox checkpoint restore  [--config FILE] CHECKPOINT_ID
agentbox run AGENT        [--config FILE] ([--image NAME] [--user NAME|current]
                          [--mount-ro SOURCE[=DEST]]... [--mount-rw SOURCE[=DEST]]... [--project DIR]
                          | --jail JAIL | --ssh-target FILE)
                          [--prompt TEXT | --prompt-file FILE] [--model ID] [--workspace DIR]
                          [--copy SRC=DEST]... [--install-agent [--agent-version V]]
                          [--copy-auth FILE [--keep-auth]] [--export-to PATH] [--env NAME]...
                          [--host-config FILE] [--timeout SECONDS] [--discard] [--allow-connect HOST:PORT]...
                          [--insecure-open]
                          [--acquisition-config FILE [--acquisition-stage-root DIR]] [-- ARG...]
agentbox run              [--config FILE] [--image NAME | --jail JAIL] [--env NAME]... [--stdin]
                          [--timeout SECONDS] [--allow-connect HOST:PORT]... [--insecure-open] -- ARG...
agentbox dev AGENT        [--config FILE] [--jail NAME] [--model ID] [--env NAME]... [--allow-connect HOST:PORT]...
                          [--insecure-open]
                          [--mount-ro SOURCE[=DEST]]... [--mount-rw SOURCE[=DEST]]... [--no-harness-mount]
                          [--acquisition-config FILE [--acquisition-stage-root DIR]] [-- ARG...]
agentbox dev setup        [--config FILE] --share-agent-dirs
                          (every new dev jail then mounts ~/.pi ~/.codex ~/.claude read-write: their
                          tokens exposed to it, and it can change code and hooks your host runs)
```

`image prepare PROVIDER` (podman, qemu: the packaged built-in profile,
builtin.py; any provider with `--provider-config FILE`, the operator's own
configuration and STATE) builds the provider's canonical recipe, or the
preset `--preset NAME` names (builtin.PRESETS: podman `dev`; `default`
the same as none; never with `--recipe`), Podman's in the STATE of its
engine store (`--store`, else the controller config's `podman_store`,
else shared; never with qemu or `--provider-config`), and publishes tag NAME (`-t`, else `default`) in
DATA/images/ once it succeeded (images.py), printing the image and, when
the provider measured them (the canonical Podman recipe), its agents'
versions; `image list` prints the tags
(never creating DATA). `jail create` and `run` without a target use
the tag `--image NAME`, else `default`: its recorded provider
configuration and image; they never prepare or fetch.
JAIL: a jail's run id, or the name `jail create -t NAME` gave it (an image tag's
rules, never shaped like a run id), resolved once as the command starts:
the command then uses that id throughout. A name belongs to one live run;
creating another live run with it refuses (`run_name_taken`, before any
provider work); only a discarded run's name is free again (its run stays
reachable by id). `jail list` (never creating DATA) prints each run's
name, id, provider (`attached` for an attached run, no target detail) and
phase, discarded runs only with `--all`; an unreadable record is listed
`invalid`.
`--config`: else $XDG_CONFIG_HOME/agentbox/controller.json, else
~/.config/agentbox/controller.json; absent: data
$XDG_DATA_HOME/agentbox-controller (else ~/.local/share/agentbox-controller),
the packaged bin/agentbox-server (config.py). `--timeout` (exec, a
command or headless agent `run`; 1 s to 7 days) is the command's enforced maximum
runtime; without it the command is untimed once its guest is ready (its
setup, every step and its teardown keep their own bounds). `jail serve` and
an interactive agent `run` are always untimed: they end on a stop, a
signal, the agent's end or a failure. The session's acquisition lane (exec,
serve, an interactive agent `run`, `dev`; shared by every `shell` login and
the agent): `--acquisition-config FILE`, else
$XDG_CONFIG_HOME/agentbox/acquisition.json (else ~/.config/...), else, only
while that file does not exist, the packaged npm, pip and read-only GitHub
Git handlers (git needed on PATH; `"handlers": {}` enables none; handlers.py,
docs/artifact-requests.md). A headless agent `run` has no lane;
`--install-agent` enables npm alone. Exit 0 only for a completed
command (exec: one that exited 0 with confirmed host cleanup, the
provider's settlement or an attached run, complete output and capture, and
a published export if asked; serve: one ended by a stop, recorded
cancelled, with the same cleanup); 1 for any failure, the line saying
which; 2 for usage. `jail stop` on a run an execution holds signals its
owner, proven the very process its record names (owner.py), to stop
(`requested`: not yet settled). Errors are fixed codes, never
paths, values or tool text. `--assert-local-ended` is the operator's
unverified word (the user's decision for attached runs and input
staging, which need no delegation): see lifecycle.py `assert_local`.
`--allow-connect HOST:PORT` (exec, serve, `run`, `dev`; repeatable, at most
32): one more exact CONNECT endpoint for every session this invocation
starts (an agent's install included; `shell` logins share their serving
session's), never saved: a DNS name, an IPv4 literal or a bracketed
IPv6 one, loopback included; no wildcard or port range; an unspecified
literal (0.0.0.0, ::) is a usage error. Under an Open policy it adds
nothing. A grant to another proxy or service delegates whatever it
offers: name the one intended endpoint.
`--insecure-open` (the same commands): the Open policy for this
invocation's sessions instead of the configured one, never saved; the
same identity and behavior as `"mode": "open"`. Allows workloads to
connect to host-local services, including services that trust local
callers. `--allow-connect` grants are still checked, and never narrow it.
A configured `connect_proxy` (config.py) carries every session's CONNECTs:
host-local then means the proxy's.
`run AGENT`: agentrun.py and docs/agents.md. `run -- ARG...` (no
agent): commandrun.py; its exit status is the command's own, else 125.
`dev AGENT`, `dev setup`: dev.py (the project's retained jail on the
shared Podman store, tag `dev`; never prepared here).
"""
import io
import os
import sys

from .assets import guest_protocol, provider_protocol
from .config import (POLICY_SCHEMA, config_path, ensure_data, host_config, input_tools, load_controller,
                     load_provider, recorded_name)
from .display import emit
from .execute import Execution, System
from .host import HostError, capture_host
from .store import Store, is_handle

USAGE = __doc__.split("```text\n", 1)[1].split("```", 1)[0]
VERSION = "0.1.0"
# One-word commands; the rest are `GROUP COMMAND`.
SINGLE = ("doctor", "shell", "run", "dev")
MAX_TIMEOUT = 7 * 24 * 3600
INPUT_LIMITS = {"--max-archive-bytes": "archive_bytes", "--max-entries": "entries", "--max-depth": "depth",
                "--max-path-bytes": "path_bytes", "--prepare-timeout-ms": "prepare_timeout_ms",
                "--upload-timeout-ms": "upload_timeout_ms"}
LIMIT_FLAGS = {"--cpus": "cpus", "--memory-mib": "memory_mib", "--pids": "pids", "--disk-mib": "disk_mib"}
# command: (single-valued options, repeatable, flags, positional count(s), needed)
COMMANDS = {
    ("image", "prepare"): (("--config", "-t", "--provider-config", "--recipe", "--preset", "--store"), (), (), 1,
                           ()),
    ("image", "list"): (("--config",), (), (), 0, ()),
    ("image", "recover"): (("--config", "--provider-config", "--store"), (), (), 2, ()),
    ("jail", "create"): (("--config", "-t", "--image", "--retention", "--user", "--project", "--ssh-target")
                         + tuple(LIMIT_FLAGS), ("--mount-ro", "--mount-rw"), (), 0, ()),
    ("jail", "list"): (("--config",), (), ("--all",), 0, ()),
    ("jail", "inputs"): (("--config", "--workspace", "--host-config") + tuple(INPUT_LIMITS), ("--copy",), (), 1,
                         ()),
    ("jail", "exec"): (("--config", "--allow-unclean", "--timeout", "--acquisition-config",
                        "--acquisition-stage-root", "--export-to", "--export-max-bytes", "--export-timeout-ms"),
                       ("--env", "--allow-connect"), ("--stdin", "--insecure-open"), 1, ()),
    ("jail", "serve"): (("--config", "--allow-unclean", "--acquisition-config", "--acquisition-stage-root"),
                        ("--allow-connect",), ("--insecure-open",), 1, ()),
    ("jail", "export"): (("--config", "--to", "--host-config", "--max-bytes", "--timeout-ms"), (), (), 1,
                         ("--to",)),
    # Hidden: `shell`'s ProxyCommand (shell.py).
    ("jail", "shell-transport"): (("--config",), (), (), 2, ()),
    ("shell",): (("--config",), (), (), 1, ()),
    ("doctor",): (("--config",), (), (), 0, ()),
    # AGENT: an agent's options (agentrun.py); none: a command's (COMMAND_RUN).
    ("run",): (("--config", "--image", "--jail", "--ssh-target", "--prompt",
                "--prompt-file", "--model", "--workspace", "--agent-version", "--copy-auth", "--export-to",
                "--host-config", "--user", "--project", "--timeout", "--acquisition-config",
                "--acquisition-stage-root"),
               ("--copy", "--env", "--mount-ro", "--mount-rw", "--allow-connect"),
               ("--install-agent", "--keep-auth", "--discard", "--stdin", "--insecure-open"), (0, 1), ()),
    # AGENT, or `setup` (its own options only: dev.py).
    ("dev",): (("--config", "--jail", "--model", "--acquisition-config", "--acquisition-stage-root"),
               ("--env", "--mount-ro", "--mount-rw", "--allow-connect"),
               ("--no-harness-mount", "--share-agent-dirs", "--insecure-open"), 1, ()),
    ("jail", "status"): (("--config",), (), (), 1, ()),
    ("jail", "stop"): (("--config", "--assert-local-ended"), (), (), 1, ()),
    ("jail", "discard"): (("--config",), (), (), 1, ()),
    ("checkpoint", "create"): (("--config", "--allow-unclean"), (), (), 1, ()),
    ("checkpoint", "status"): (("--config",), (), (), 1, ()),
    ("checkpoint", "list"): (("--config",), (), (), 0, ()),
    ("checkpoint", "discard"): (("--config",), (), (), 1, ()),
    ("checkpoint", "restore"): (("--config",), (), (), 1, ()),
}
# `run -- ARG...`'s options (no agent).
COMMAND_RUN = ("--config", "--image", "--jail", "--env", "--stdin", "--timeout", "--allow-connect",
               "--insecure-open")
# Commands whose first positional is a run: an id or a live run's name.
SELECTING = (("jail", "inputs"), ("jail", "exec"), ("jail", "serve"), ("jail", "export"), ("jail", "status"),
             ("jail", "stop"), ("jail", "discard"), ("shell",), ("checkpoint", "create"))


class Usage(Exception):
    pass


def say(stream, text):
    """A report line: bounded on a real descriptor (display.emit), never a
    blocking write; as is to an in-memory stream."""
    try:
        fd = stream.fileno()
    except (AttributeError, io.UnsupportedOperation):
        stream.write(text)
        return
    emit(fd, text.encode())


def parse(args):
    """(command pair, options): `options` maps each given single option to
    its value, each repeatable to its list, each flag to True,
    `positional` and `argv` (exec's, after `--`)."""
    if args and args[0] in SINGLE:
        command, rest = (args[0],), list(args[1:])
    elif len(args) >= 2 and (args[0], args[1]) in COMMANDS:
        command, rest = (args[0], args[1]), list(args[2:])
    else:
        raise Usage()
    single, repeated, flags, count, needed = COMMANDS[command]
    options = {name: [] for name in repeated}
    options.update(positional=[], argv=None)
    while rest:
        word = rest.pop(0)
        if word == "--" and command in (("jail", "exec"), ("shell",), ("run",), ("dev",)):
            options["argv"] = rest
            break
        if word in flags:
            options[word] = True
            continue
        if word == "-u" or word.startswith("--user="):
            value = word[len("--user="):] if word.startswith("--user=") else (rest.pop(0) if rest else None)
            word = "--user"
            if value is None or "--user" not in single or word in options:
                raise Usage()
            options[word] = value
            continue
        if word.startswith("-"):
            if not rest:
                raise Usage()
            value = rest.pop(0)
            if word in single and word not in options:
                options[word] = value
            elif word in repeated:
                options[word].append(value)
            else:
                raise Usage()
            continue
        options["positional"].append(word)
    if len(options["positional"]) not in (count if isinstance(count, tuple) else (count,)) \
            or any(flag not in options for flag in needed):
        raise Usage()
    if command == ("run",):
        given = [name for name, value in options.items() if name not in ("positional", "argv") and value != []]
        if options["positional"] and "--stdin" in options:
            raise Usage()
        if not options["positional"] and (not options["argv"] or any(name not in COMMAND_RUN for name in given)
                                          or "--image" in options and "--jail" in options):
            raise Usage()
    if command == ("jail", "exec") and not options["argv"]:
        raise Usage()
    if command == ("dev",):
        given = {name for name, value in options.items() if name not in ("positional", "argv") and value != []}
        setup = options["positional"] == ["setup"]
        if setup and (given - {"--config", "--share-agent-dirs"} or options["argv"] is not None) \
                or not setup and "--share-agent-dirs" in given:
            raise Usage()
    if command == ("image", "prepare") and "--recipe" in options and "--provider-config" not in options:
        raise Usage()
    if command == ("jail", "create"):
        attached = "--ssh-target" in options
        if attached and any(k in options for k in ("--image", "--retention", "--user", "--project")
                            + tuple(LIMIT_FLAGS)) \
                or attached and (options["--mount-ro"] or options["--mount-rw"]):
            raise Usage()
    if command == ("jail", "inputs") and "--workspace" not in options and not options["--copy"]:
        raise Usage()
    if "--acquisition-stage-root" in options and "--acquisition-config" not in options:
        raise Usage()
    if ("--export-max-bytes" in options or "--export-timeout-ms" in options) and "--export-to" not in options:
        raise Usage()
    if "--timeout" in options:
        value = options["--timeout"]
        if not value.isdigit() or not 1 <= int(value) <= MAX_TIMEOUT:
            raise Usage()
    if "--allow-connect" in options:
        options["--allow-connect"] = connect_grants(options["--allow-connect"])
    return command, options


def connect_grants(values):
    """`--allow-connect`: the canonical session grants, duplicates merged,
    in the server's own grammar (a CONNECT authority, never an unspecified
    literal); any refusal is a usage error."""
    from agentbox_server.address import authority_text
    from agentbox_server.policy import MAX_GRANTS, PolicyError, parse_grant
    grants = []
    for value in values:
        try:
            text = authority_text(parse_grant(value))
        except PolicyError:
            raise Usage() from None
        if text not in grants:
            grants.append(text)
    if len(grants) > MAX_GRANTS:
        raise Usage()
    return grants


def number(value):
    if not value.isdigit() or str(int(value)) != value:
        raise Usage()
    return int(value)


def select_env(names, environ):
    """The explicit selection: this process's value of each name, refused
    before anything starts (environment.rs); values never recorded."""
    selected = {}
    for name in names:
        if name in selected or name not in environ:
            raise HostError("env_invalid")
        selected[name] = environ[name]
    if selected:
        try:
            guest_protocol.encode_host_frame({"type": "exec", "id": "x-1", "argv": ["true"],
                                              "env": tuple(sorted(selected.items()))})
        except guest_protocol.Refused:
            raise HostError("env_invalid") from None
    return selected


def resolve_user(value):
    """`--user NAME|current`: `current` is the real uid's passwd login."""
    import pwd
    if value is None:
        return provider_protocol.DEFAULT_USER
    if value != "current":
        if not provider_protocol.is_user(value):
            raise HostError("user_invalid")
        return value
    try:
        name = pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        raise HostError("user_current_unavailable") from None
    if not provider_protocol.is_user(name):
        raise HostError("user_current_unsupported")
    return name


def status_line(run_id, status):
    record = status["record"]
    line = f"run: {run_id}" + (f" name={record['name']}" if record.get("name") else "")
    line += f" state={status['state']} kind={record['kind']} phase={record['phase']}"
    if record["kind"] == "managed":
        line += f" generation={record['generation']} storage={record['storage']} retention={record['retention']}"
        if record.get("volume"):
            # The provider's name of the retained HOME (recorded, not probed).
            line += f" volume={record['volume']}"
        if record["mounts"]:
            line += f" mounts={len(record['mounts'])}"
        if record["create_refused"]:
            line += " create=refused"
    if record["project"] is not None:
        line += f" project={record['project']}"
    inputs = record["inputs"]
    if inputs is None:
        line += " inputs=none"
    else:
        line += f" inputs={inputs['state']}"
        if inputs["state"] == "staging":
            line += f" staging={inputs['attempt']}"
            if "local_end" in inputs:
                line += " local_end=asserted"
        if inputs["state"] == "staged" and record["retention"] != "none":
            line += f" delivery={inputs['delivery'] or 'none'}"
    pending = record["pending"]
    if pending is not None:
        line += (f" pending={pending['op']} operation={pending['operation']} processes={pending['processes']}"
                 f" provider={pending['provider']} settlement={pending['settlement']}")
    if status["spool_reserved"]:
        # Acquisition spools not confirmed removed: still reserved.
        line += f" spool_reserved={status['spool_reserved']} holding={','.join(status['holding'])}"
    export = record["export"]
    if export is not None:
        # Reserved until published or removed, else until asserted.
        line += (f" export={export['operation']} export_processes={export['processes']}"
                 f" export_reserved={export['max_bytes']}")
    if record["asserted"]:
        line += f" asserted={','.join(record['asserted'])}"
    if record["kind"] == "attached":
        # The local store only: the operator's jail is never observed.
        line += " jail=unobserved"
    return line


def checkpoint_line(entry):
    return (f"checkpoint: {entry['checkpoint']} state={entry['state']} source={entry['source_run']} "
            f"generation={entry['generation']} storage={entry['storage']} processes={entry['processes']}"
            + (f" holder={entry['holder']}" if entry["holder"] else ""))


# Commands that only read the store: never create a default data root.
READING = (("jail", "status"), ("checkpoint", "status"), ("checkpoint", "list"), ("shell",),
           ("jail", "shell-transport"), ("image", "list"), ("jail", "list"))


def main(args, system=None, environ=None, out=None, err=None, prefix=None):
    """`prefix`: the packaged entry's (bin/agentbox), whose
    bin/agentbox-server is the default server; None from a source tree."""
    environ = os.environ if environ is None else environ
    out = out or sys.stdout
    err = err or sys.stderr
    capture_host(environ)
    if list(args) in (["--help"], ["-h"], ["help"]):
        say(out, "usage:\n" + USAGE)
        return 0
    if list(args) in (["--version"], ["-V"]):
        say(out, f"agentbox {VERSION} (Python controller; server protocol v1)\n")
        return 0
    try:
        command, options = parse(args)
    except Usage:
        say(err, "usage:\n" + USAGE)
        return 2
    system = system or System()
    store = None
    held = []
    words = " ".join(command)
    # `run -- ARG...`: any failure of its own 125, apart from the command's
    # exit statuses (commandrun.py).
    failed = 125 if command == ("run",) and not options["positional"] else 1
    if command == ("doctor",):
        from . import doctor
        return doctor.main(options.get("--config"), environ, lambda text: say(out, text), prefix)

    def claim(run_id):
        held.append(store.claim(run_id))
        return held[-1]

    try:
        path, explicit = config_path(options.get("--config"), environ)
        controller = load_controller(path, environ, prefix, explicit)
        # The transport (`shell`, an interactive agent) resolves it the same way.
        controller["config_path"] = path if explicit else None
        # This invocation's sessions only, never saved.
        controller["grants"] = options.get("--allow-connect", [])
        if options.get("--insecure-open"):
            controller["policy"] = {"schema": POLICY_SCHEMA, "mode": "open"}
        if command == ("image", "list"):
            return _list(controller, out)
        if command == ("jail", "list"):
            return _runs(controller, options.get("--all", False), out)
        if command == ("dev",) and options["positional"] == ["setup"]:
            from . import dev
            dev.setup(environ, options.get("--share-agent-dirs", False), lambda text: say(out, text),
                      lambda text: say(err, text))
            return 0
        if command in (("image", "prepare"), ("image", "recover")):
            # `--store` checked before anything is made.
            from . import builtin
            builtin.store_mode(options["positional"][0], options.get("--store"), "--provider-config" in options)
        if controller["data_default"] and command not in READING:
            ensure_data(controller["data"])
        if command not in READING:
            from . import builtin
            builtin.refresh(controller, environ)
        store = Store(controller["data"])
        return _dispatch(command, options, controller, store, system, environ, out, err, claim)
    except HostError as error:
        line = f"agentbox: {words} refused: {error.code}"
        code = getattr(error, "provider_code", None)
        if code:
            line += f" provider_code={code}"
        hint = getattr(error, "hint", None)
        if hint is None and code:
            from .lifecycle import PROVIDER_HINTS
            hint = PROVIDER_HINTS.get(code)
        say(err, line + "\n" + (f"agentbox: hint: {hint}\n" if hint else ""))
        return failed
    except Usage:
        say(err, "usage:\n" + USAGE)
        return 2
    finally:
        for lease in held:
            lease.release()
        if store is not None:
            store.close()


def _dispatch(command, options, controller, store, system, environ, out, err, claim):
    from . import checkpoints, lifecycle
    positional = options["positional"]
    if command in SELECTING:
        positional[0] = store.resolve(positional[0])
    if command == ("image", "prepare"):
        return _prepare(options, controller, store, system, environ, out, err)
    if command == ("image", "recover"):
        config = _recovering(options, controller, store, environ)
        result = lifecycle.recover_prepare(system, store, config, positional[1])
        say(out, f"image recover: {positional[1]} {result}\n")
        return 0
    if command == ("jail", "create"):
        return _create(options, store, system, environ, out)
    if command == ("checkpoint", "list"):
        for ident in checkpoints.ids(store):
            say(out, checkpoint_line(checkpoints.read(store, ident)) + "\n")
        return 0
    if command == ("checkpoint", "status"):
        say(out, checkpoint_line(checkpoints.read(store, positional[0])) + "\n")
        return 0
    if command == ("checkpoint", "discard"):
        result = checkpoints.discard(system, store, positional[0])
        say(out, f"checkpoint discard: {positional[0]} {result}\n")
        return 0
    if command == ("checkpoint", "restore"):
        run_id = checkpoints.restore(system, store, positional[0])
        say(out, f"restored: {run_id} from={positional[0]}\n")
        return 0
    if command == ("jail", "status"):
        say(out, status_line(positional[0], store.status(positional[0])) + "\n")
        return 0
    if command == ("shell",):
        from . import shell
        shell.shell(system, store, controller["config_path"], positional[0], options["argv"] or [], environ)
        return 1
    if command == ("run",) and positional:
        from . import agentrun
        return agentrun.run(system, controller, store, options, environ, out, err)
    if command == ("dev",):
        from . import dev
        return dev.run(system, controller, store, options, environ, out, err)
    if command == ("run",):
        from . import commandrun
        return commandrun.run(system, controller, store, options, environ, err)
    if command == ("jail", "shell-transport"):
        from . import shell
        if not is_handle(positional[1], "e"):
            raise HostError("invocation_invalid")
        shell.transport(system, store, positional[0], positional[1])
        return 1
    try:
        lease = claim(positional[0])
    except HostError as error:
        if error.code != "run_busy" or command != ("jail", "stop") or "--assert-local-ended" in options:
            raise
        return _stop_owner(store, positional[0], out)
    if command == ("checkpoint", "create"):
        ident = checkpoints.create(system, store, lease, options.get("--allow-unclean"))
        say(out, f"checkpoint: {ident} source={positional[0]}\n")
        return 0
    if command == ("jail", "stop"):
        if "--assert-local-ended" in options:
            result = lifecycle.assert_local(lease, options["--assert-local-ended"], lambda text: say(err, text))
            say(out, f"stop: {positional[0]} {result} {options['--assert-local-ended']}\n")
            return 0
        result, unproven = lifecycle.stop(system, store, lease)
        for ident, what, state in unproven:
            say(err, f"agentbox: unproven local work: {ident} {what} state={state} "
                     f"(agentbox jail stop --assert-local-ended {ident} once you confirmed it ended)\n")
        say(out, f"stop: {positional[0]} {result}\n")
        return 1 if unproven else 0
    if command == ("jail", "discard"):
        result = lifecycle.discard(system, store, lease)
        say(out, f"discard: {positional[0]} {result}\n")
        return 0
    if command == ("jail", "inputs"):
        return _inputs(options, store, lease, environ, out)
    if command == ("jail", "export"):
        from . import export
        chosen = export.settings(host_config(options.get("--host-config"), environ),
                                 _optional(options, "--max-bytes"), _optional(options, "--timeout-ms"))
        code, line = export.run_export(system, store, lease, options["--to"], chosen, _cwd())
        say(out if code == 0 else err, line + "\n")
        return code
    # None: untimed once the guest is ready (`jail serve` always).
    timeout = int(options["--timeout"]) if "--timeout" in options else None
    if command == ("jail", "serve"):
        selection, stage_root = acquisition_selection(options, environ)
        code, _ = Execution(system, controller, store, lease, None, {}, False, None, selection,
                            allow_unclean=options.get("--allow-unclean"), stage_root=stage_root, serve=True).run()
        return code
    # jail exec
    if guest_protocol.validate_argv(options["argv"]) is not None:
        raise HostError("argv_invalid")
    env = select_env(options["--env"], environ)
    selection, stage_root = acquisition_selection(options, environ)
    exported = _export_to(options, store, environ, timeout)
    try:
        # The execution writes its own final line (bounded).
        code, _ = Execution(system, controller, store, lease, options["argv"], env, options.get("--stdin", False),
                            timeout, selection, allow_unclean=options.get("--allow-unclean"),
                            stage_root=stage_root, export=exported).run()
    finally:
        if exported is not None:
            os.close(exported["parent"])
    return code


def _provider(options, controller, environ):
    """`PROVIDER [--provider-config FILE]`: the operator's configuration
    (naming that provider), else the built-in profile's."""
    from . import builtin
    provider = options["positional"][0]
    if "--provider-config" in options:
        config = load_provider(options["--provider-config"])
        if config["provider"] != provider:
            raise HostError("provider_mismatch")
        return config
    return builtin.config(provider, controller, environ, options.get("--store"))


def _recovering(options, controller, store, environ):
    """`image recover`'s configuration (_provider): built-in Podman's of
    the selected store; an operation pending only in the old single
    Podman STATE, that one's (read without a lease first, the lease's
    record then deciding)."""
    from . import builtin, states
    config = _provider(options, controller, environ)
    operation = options["positional"][1]
    if "--provider-config" in options or options["positional"][0] != "podman" \
            or states.peek(store, config["state"]) == operation:
        return config
    legacy = builtin.legacy_podman(controller, environ)
    return legacy if states.peek(store, legacy["state"]) == operation else config


def _prepare(options, controller, store, system, environ, out, err):
    """`image prepare`: the provider's prepare, then the tag published
    (only after it succeeded)."""
    from . import builtin, host, images, lifecycle
    name = images.check_name(options.get("-t", images.DEFAULT))
    provider = options["positional"][0]
    # The preset: one of the provider's packaged canonical recipes, never
    # beside the operator's own (--recipe).
    preset = options.get("--preset")
    if preset is not None and "--recipe" in options:
        raise builtin.hinted("preset_conflict", "--preset names a packaged recipe, --recipe your own: give one")
    canonical = builtin.preset_recipe(provider, "default" if preset is None else preset) \
        if preset is not None or builtin.is_builtin(provider) else None
    if "--provider-config" in options:
        config = _provider(options, controller, environ)
        recipe = options.get("--recipe")
        if recipe is None:
            if canonical is None:
                raise builtin.hinted("recipe_required", "name the recipe: --recipe PATH")
            recipe = f"{config['assets']}/{canonical}"
        profile = "custom"
    else:
        # A fetch's interrupt stays asked for the provider step after it.
        host.share_signals()
        config = builtin.prepare(store, controller, environ, provider, lambda text: say(err, text),
                                 options.get("--store"))
        recipe = f"{config['assets']}/{canonical}"
        profile = "builtin"
    image, release, agents = lifecycle.prepare(system, store, config, recipe)
    if profile == "builtin":
        # Identity and STATE, never this install's paths (builtin.resolve);
        # the recipe the tag's own preset's.
        images.publish(store.path, name, builtin.recorded(config), image, release, canonical, profile)
    else:
        images.publish(store.path, name, config, image, release, recipe, profile)
    say(out, f"image: {name} provider={provider} id={image} worker_release={release}\n")
    if agents is not None:
        # The provider's measured versions (protocol-checked: fixed names,
        # plain npm versions).
        say(out, "agents: " + " ".join(f"{agent}={agents[agent]}" for agent in provider_protocol.AGENTS) + "\n")
    return 0


def _list(controller, out):
    from . import images
    found = images.entries(controller["data"])
    rows = [("NAME", "PROVIDER", "IMAGE ID")]
    rows += [(name, recorded_name(record["provider"]), record["image"]) if record else (name, "-", "invalid")
             for name, record in found]
    width = [max(len(row[i]) for row in rows) for i in range(2)]
    for row in rows:
        say(out, f"{row[0]:<{width[0]}}  {row[1]:<{width[1]}}  {row[2]}\n")
    return 0


def _runs(controller, everything, out):
    """`jail list`: the local records only (store.listing), no provider
    asked, no lease probed; an attached run's target never shown."""
    from .store import listing
    rows = []
    for run_id, record in listing(controller["data"]):
        if record is None:
            rows.append(("-", run_id, "-", "invalid"))
        elif everything or record["phase"] != "discarded":
            provider = recorded_name(record["provider"]) if record["kind"] == "managed" else "attached"
            rows.append((record.get("name") or "-", run_id, provider, record["phase"]))
    rows = [("NAME", "JAIL ID", "PROVIDER", "PHASE")] + sorted(rows, key=lambda row: (row[0] == "-", row))
    width = [max(len(row[i]) for row in rows) for i in range(3)]
    for row in rows:
        say(out, f"{row[0]:<{width[0]}}  {row[1]:<{width[1]}}  {row[2]:<{width[2]}}  {row[3]}\n")
    return 0


def acquisition_selection(options, environ, implicit=True, interpreter=None):
    """(the session's handler selection or None, the spool's stage root or
    None): `--acquisition-config FILE`, else (`implicit`: a session that
    may have a lane) acquisition.json, else the packaged defaults
    (handlers.py). `interpreter()`: the default interpreter (else
    host.json's, else /usr/bin/python3)."""
    from . import handlers
    from .config import DEFAULT_INTERPRETER
    if interpreter is None:
        def interpreter():
            return host_config(None, environ).get("interpreter", DEFAULT_INTERPRETER)
    selection = None
    if "--acquisition-config" in options:
        selection = handlers.read(options["--acquisition-config"], interpreter)
    elif implicit:
        selection = handlers.implicit(environ, interpreter)
    stage_root = options.get("--acquisition-stage-root")
    if stage_root is not None and not provider_protocol.is_path(stage_root):
        raise HostError("acquisition_stage_root_invalid")
    return selection, stage_root


def _optional(options, flag):
    return number(options[flag]) if flag in options else None


def _export_to(options, store, environ, timeout):
    """`--export-to`: settings, window (a timed command's) and destination
    checked before anything starts; the pinned parent's descriptor."""
    from . import export
    if "--export-to" not in options:
        return None
    chosen = export.settings(host_config(None, environ), _optional(options, "--export-max-bytes"),
                             _optional(options, "--export-timeout-ms"))
    if timeout is not None and export.task_seconds(timeout, chosen["timeout_ms"]) is None:
        raise HostError("export_window_insufficient")
    parent_path, name = export.destination(options["--export-to"], _cwd())
    parent = export.pin(parent_path, name, store.path)
    try:
        if export.available(parent) < chosen["max_bytes"]:
            raise HostError("export_space_insufficient")
    except BaseException:
        os.close(parent)
        raise
    return {"parent": parent, "name": name, "settings": chosen}


def _stop_owner(store, run_id, out):
    """A busy run: its owner signalled to stop (owner.py; `run_busy` when an
    operation without one holds it). Requested, not settled: the owner's
    own final line says how it ended."""
    from . import owner
    owner.request_stop(store, run_id)
    say(out, f"stop: {run_id} requested\n")
    return 0


def _cwd():
    try:
        return os.getcwd()
    except OSError:
        return None


def _host_home():
    home = dict(capture_host()).get("HOME")
    return home if home and provider_protocol.is_path(home) else None


def _create(options, store, system, environ, out):
    from . import lifecycle, mounts
    from .store import check_name
    run_name = check_name(options["-t"]) if "-t" in options else None
    if run_name is not None:
        # Early, before any provider work; the publish's own check binds.
        store.name_free(run_name)
    named = f" name={run_name}" if run_name is not None else ""
    if "--ssh-target" in options:
        from .attached import attach
        say(out, f"created: {attach(store, options['--ssh-target'], run_name)} kind=attached{named}\n")
        return 0
    from . import images
    tag = images.resolve(store.path, options.get("--image"))
    config = tag["provider"]
    limits = {name: number(options[flag]) for flag, name in LIMIT_FLAGS.items() if flag in options}
    for name, value in limits.items():
        low, high = provider_protocol.LIMIT_RANGES[name]
        if not low <= value <= high:
            raise HostError("limit_invalid")
    retention = options.get("--retention", "none")
    if retention not in provider_protocol.RETENTION:
        raise HostError("retention_invalid")
    user = resolve_user(options.get("--user"))
    args = [mounts.parse(v, "ro") for v in options["--mount-ro"]] \
        + [mounts.parse(v, "rw") for v in options["--mount-rw"]]
    selected, project, project_host = mounts.select(args, options.get("--project"), _cwd(), _host_home())
    run_id = lifecycle.create(system, store, config, tag["image"], retention, limits, user, selected,
                              project, project_host, run_name)
    say(out, f"created: {run_id} kind=managed{named}\n")
    return 0


def _inputs(options, store, lease, environ, out):
    from . import inputs
    from .assets import ASSETS
    overrides = {name: number(options[flag]) for flag, name in INPUT_LIMITS.items() if flag in options}
    settings = inputs.settings(overrides)
    interpreter, assets = input_tools(host_config(options.get("--host-config"), environ), ASSETS)
    chosen = inputs.selection(options.get("--workspace"), options["--copy"], _cwd())
    from .host import host_path
    staged = inputs.stage(store, lease, chosen, settings, interpreter, assets, host_path(), _host_home())
    say(out, f"inputs: {lease.run_id} staged archive_bytes={staged['archive_bytes']}"
             f" entries={staged['counts']['entries']}"
             + (f" project={lease.record['project']}" if lease.record["project"] else "") + "\n")
    return 0
