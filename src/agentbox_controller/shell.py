"""`shell JAIL [-- ARG...]`: an ordinary interactive SSH login with a PTY
into the jail a serving owner holds (`jail serve`, an interactive agent),
with the profile it published (owner.py); and `jail shell-transport`, the
hidden ProxyCommand of a managed stdio route. The old CLI's shell.rs is the
reference.

```text
shell:     owner.json (live) + shell.json (owner.py) -> [stdio: enter a
             delegated unit] -> exec ssh -F /dev/null -l USER [-p PORT]
             -o ...RequestTTY=force ClearAllForwardings=yes
             [ProxyCommand=TRANSPORT] IdentityFile= UserKnownHostsFile=
             HostKeyAlias= DEST LAUNCHER shell TERM SESSION 'ARG'...
transport: (ssh's ProxyCommand: ssh runs `exec TRANSPORT` and signals it
             SIGHUP at its end) run record: the managed run's pending
             start of EXECUTION; owner and shell records of EXECUTION ->
             D adopted by its recorded path and identity -> mkdir s-K
             (K <= 32, cumulative) -> this process joins it, read back ->
             shell.json still EXECUTION's -> execve the provider's
             connect words (PATH the owner's, the scopes, AGENTBOX_CUSTODY
             = D) on ssh's own pipes
```

SESSION is the owner's current session nonce: the guest builds the
login's request context from it and the launcher's own WORK and MOUNT
(guest/src/worker_profile.py), so the login's `agentbox-request` and
shims reach that owner's acquisition lane, if it has one, and share its
grant. A login outliving its owner (an endpoint route) keeps a nonce no
later session's broker accepts.

No terminal relay: this process becomes ssh; the jail's output reaches the
terminal unfiltered, as any SSH login's. Disconnecting stops nothing. The
transport becomes the provider's bridge: no child, relay or supervisor of
its own. It is D's member before the provider starts, so the owner's
teardown (the profile withdrawn first, then D killed) ends it; a late one
finds the profile gone and exits, or is killed with D. An endpoint route
(attached, or a TCP provider) connects directly and needs no delegation;
such a login may outlive the owner, without the broker. The TRANSPORT
words are this controller's own interpreter, entry and configuration,
each checked inert and every `%` doubled (ssh expands `%` tokens): no
shell injection or substitution through ProxyCommand.
"""
import os
import re
import sys

from . import builtin, cgroups, owner as owner_mod, provider, scopes, ssh as ssh_mod
from .assets import guest_protocol, provider_protocol
from .host import OWN_PREFIX, HostError, capture_host, tool_env

FALLBACK_TERM = "dumb"
_TERM = re.compile(r"[A-Za-z0-9._+-]{1,64}")
_WORD = re.compile(r"[A-Za-z0-9._/:=,+@%-]+")
_SESSION = re.compile(r"[0-9a-f]{32}")
GUEST_SHELL = "shell"
TRANSPORT = "shell-transport"
MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
# This controller's entry words: main.py (tests: their launcher).
ENTRY = (MAIN,)


def term(environ):
    value = environ.get("TERM", "")
    return value if _TERM.fullmatch(value) else FALLBACK_TERM


def quote(word):
    return "'" + word.replace("'", "'\\''") + "'"


def transport_words(config, run_id, execution_id, executable=None, entry=None):
    """This controller's own `jail shell-transport` invocation, every word
    shell-inert (ProxyCommand runs through a shell)."""
    entry = list(entry or ENTRY)
    words = [executable or sys.executable, "-I", "-B"] + entry + ["jail", TRANSPORT] \
        + ([] if config is None else ["--config", config]) + [run_id, execution_id]
    if not all(provider_protocol.is_path(w) for w in [words[0]] + entry + ([] if config is None else [config])) \
            or not all(_WORD.fullmatch(w) for w in words):
        raise HostError("shell_transport_unavailable")
    return words


def proxy_command(words):
    """ProxyCommand's value: the words, `%` doubled (ssh's own escape)."""
    return " ".join(w.replace("%", "%%") for w in words)


def check_profile(profile, attached):
    """The owner's profile, checked as a connection's (ssh.py)."""
    endpoint = profile["endpoint"]
    if endpoint is not None and (not isinstance(endpoint, list) or len(endpoint) != 2):
        raise HostError("owner_record_invalid")
    try:
        connection = ssh_mod.Connection(
            profile["user"], profile["identity"], profile["known_hosts"], profile["alias"],
            endpoint=None if endpoint is None else tuple(endpoint),
            proxy=["/bin/false"] if endpoint is None else None, attached=attached)
        ssh_mod.plain_path(profile["launcher"])
    except (HostError, TypeError):
        raise HostError("owner_record_invalid") from None
    if not isinstance(profile["session"], str) or _SESSION.fullmatch(profile["session"]) is None:
        raise HostError("owner_record_invalid")
    return connection


def argv(ssh, profile, term_name, args, transport=None, tty=True):
    """ssh's interactive argv (runtime/ssh.rs `interactive`, `tty`); without
    `tty` (an agent's staging) `-T` and RequestTTY=no."""
    head = [ssh, "-F", "/dev/null"] + ([] if tty else ["-T"]) + ["-l", profile["user"]]
    if profile["endpoint"] is not None:
        head += ["-p", str(profile["endpoint"][1])]
    for option in ssh_mod.OPTIONS:
        if option == "RequestTTY=no" and tty:
            option = "RequestTTY=force"
        elif option == "ProxyCommand=none" and transport is not None:
            option = "ProxyCommand=" + proxy_command(transport)
        head += ["-o", option]
    head += ["-o", "ClearAllForwardings=yes"]
    for option in (f"IdentityFile={profile['identity']}", f"UserKnownHostsFile={profile['known_hosts']}",
                   f"HostKeyAlias={profile['alias']}"):
        head += ["-o", option]
    destination = profile["alias"] if transport is not None else profile["endpoint"][0]
    return head + [destination, profile["launcher"], GUEST_SHELL, term_name, profile["session"]] \
        + [quote(a) for a in args]


def environment(term_name, transport):
    """ssh's whole environment. Direct: a host tool's (the captured PATH,
    LC_ALL=C) and TERM. With a transport, which inherits it (and so the
    provider's connect, as an owner's start inherits its own): this
    process's captured environment (host.capture_host: no AGENTBOX_*, PATH
    filtered) without SHELL (ssh would run its ProxyCommand through it)
    and without HOME, XDG_CONFIG_HOME or XDG_DATA_HOME unless absolute (the
    transport resolves the same configuration), then the tool's PATH,
    LC_ALL=C and TERM. The transport sets the owner's PATH, scopes and
    custody over it; nothing of it is published."""
    env = {}
    if transport:
        env = {k: v for k, v in capture_host() if k != "SHELL" and not k.startswith(OWN_PREFIX)}
        for name in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            if name in env and not provider_protocol.is_path(env[name]):
                del env[name]
    env.update(tool_env())
    env["TERM"] = term_name
    return env


def shell(system, store, config, run_id, args, environ, execve=os.execve):
    """The live serving owner's profile, then this process becomes ssh.
    Returns only on a refusal (raised)."""
    if args and guest_protocol.validate_argv(args) is not None:
        raise HostError("argv_invalid")
    status = store.status(run_id)
    if status["state"] != "active":
        raise HostError("run_not_serving")
    execution, profile, _ = owner_mod.serving(store, run_id)
    check_profile(profile, status["record"]["kind"] == "attached")
    transport = None
    if profile["endpoint"] is None:
        config = None if config is None else os.path.abspath(config)
        transport = transport_words(config, run_id, execution)
        # The transport joins the owner's domain: ssh (its parent) first in
        # a delegated unit of this user's manager, as an owner enters one.
        system.enter()
    ssh = system.tool("ssh")
    name = term(environ)
    execve(ssh, argv(ssh, profile, name, args, transport), environment(name, transport is not None))
    raise HostError("ssh_not_run")


def transport(system, store, run_id, execution, execve=os.execve):
    """`jail shell-transport`: this process, in a fresh slot of the serving
    owner's domain, becomes that owner's provider connect. Returns only on
    a refusal (raised): nothing written to stdout."""
    status = store.status(run_id)
    if status["state"] != "active":
        raise HostError("run_not_serving")
    record = status["record"]
    pending = record["pending"]
    if record["kind"] != "managed" or pending is None or pending.get("op") != "start" \
            or pending.get("execution") != execution or pending.get("domain") is None:
        raise HostError("invocation_stale")
    _, profile, path = owner_mod.serving(store, run_id, execution)
    if profile["endpoint"] is not None:
        raise HostError("shell_unsupported")
    domain = cgroups.Domain.adopt(system.cgroups, pending["domain"])
    if domain is None:
        raise HostError("run_not_serving")
    try:
        domain.join_slot()
    finally:
        domain.close()
    # A member of D now: its teardown withdraws the profile before the kill.
    owner_mod.serving(store, run_id, execution)
    words = provider.connect_words(builtin.resolve(record["provider"]), run_id, execution, pending["instance"])
    env = provider.environment(scopes.limits_path(store.path), pending["domain"]["path"])
    env.pop("PATH", None)
    if path is not None:
        env["PATH"] = path
    try:
        execve(words[0], words, env)
    except OSError:
        pass
    raise HostError("shell_transport_failed")
