"""`run AGENT`'s host pieces (the old CLI's agent.rs): the trusted adapter
run, its checked plan, the task's framed input and the runner's mode
words. Agent semantics are the adapter's (ASSETS/agents/AGENT/adapter.py,
unchanged), carried out in the jail by the common runner
(ASSETS/agents/jail/run.py) from the plan's private settings.

```text
adapter   INTERPRETER -I -S -B ASSETS/agents/AGENT/adapter.py, its own
          process group (no cgroup), empty environment, `/`, 30 s:
            stdin  <- request {schema, agent, model, install, auth, interactive}
            stdout -> a private memory file (memfd, RLIMIT_FSIZE 64 KiB): the plan
            fd 3   -> one result line, a fixed code on refusal
          reaped (group killed) before the plan is read
plan      {argv: the runner (jail Python's args), python, settings: opaque
           but for a credential's `auth.path` (checked: kept off host
           mounts), credential: secret, not_after_ms, install: bool (exactly
           as asked)}
install   the packaged npm handler with REGISTRY_POLICY (ASSETS-relative):
          the jail's npm installs the agent through the npm lane
input     HEADER {schema, prompt_bytes, credential_bytes, settings} LF
          PROMPT CREDENTIAL: one pipe, sized and filled before the execution
staged    interactive: the same HEADER with `stage` NONCE and `env` (the
          selected --env values), no prompt: the staging SSH's stdin
runner    [jail python] PLAN.argv + MODE NONCE RECEIPT
```

The prompt, model, credential and staged values never reach argv, a host
process's environment, a record, the capture or a diagnostic: the plan
lives in a memory file, the input in a pipe. No secure erasure is claimed.
A credential is the adapter's copy of the one file the user named
(`--copy-auth`), never anything discovered.
"""
import fcntl
import json
import os
import re
import secrets
import selectors
import stat
import time

from .assets import guest_protocol
from .host import Child, Drain, HostError, Loop, install_owner, read_some, write_some

AGENTS = ("pi", "codex", "claude")
REQUEST_SCHEMA = "agentbox.agent-request.v1"
PLAN_SCHEMA = "agentbox.agent-plan.v1"
RESULT_SCHEMA = "agentbox.agent-result.v1"
INPUT_SCHEMA = "agentbox.agent-input.v3"
MAX_PROMPT_BYTES = 64 * 1024
MAX_MODEL_BYTES = 256
MAX_CREDENTIAL_BYTES = 16 * 1024
MAX_SETTINGS_BYTES = 8 * 1024
MAX_PLAN_BYTES = 64 * 1024
MAX_INPUT_BYTES = MAX_PROMPT_BYTES + MAX_CREDENTIAL_BYTES + MAX_SETTINGS_BYTES + 1024
MAX_RESULT_BYTES = 512
MAX_DIAGNOSTIC_BYTES = 2048
ADAPTER_TIMEOUT = 30.0
CREDENTIAL_MARGIN_MS = 10 * 60 * 1000
# `--install-agent`: the npm handler, its packaged registry policy.
INSTALLER = "npm"
REGISTRY_POLICY = "agents/npm-registry.json"
# The runner's managed installs, HOME-relative (agents/jail/run.py AGENTS):
# AGENT's beneath it.
INSTALL_ROOT = ".local/share/agentbox-agents"
_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_RECEIPT = re.compile(r"[0-9]{1,20}(:[0-9]{1,20}){3}")
_DIAGNOSTIC = re.compile(r"[ -~]{1,240}")


def is_model(text):
    """A model forwarded as given: printable, no whitespace, not an option."""
    return isinstance(text, str) and 0 < len(text.encode()) <= MAX_MODEL_BYTES and not text.startswith("-") \
        and all(ch.isprintable() and not ch.isspace() for ch in text)


def tools(config, default_assets, agent):
    """(interpreter, assets) for `agent`'s adapter, checked as the input
    worker's (config.input_tools): the interpreter an executable regular
    file; the asset root, agents/, the adapter and the runner ours or
    root's, with installed-code ownership and no link."""
    from .config import DEFAULT_INTERPRETER
    if agent not in AGENTS:
        raise HostError("agent_unknown")
    interpreter = config.get("interpreter", DEFAULT_INTERPRETER)
    assets = config.get("assets", default_assets)
    try:
        real = os.path.realpath(interpreter, strict=True)
        st = os.stat(real)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise OSError
        for path in (assets, f"{assets}/agents", f"{assets}/agents/{agent}", f"{assets}/agents/{agent}/adapter.py",
                     f"{assets}/agents/jail", f"{assets}/agents/jail/run.py"):
            st = os.lstat(path)
            if not install_owner(st) or stat.S_ISLNK(st.st_mode):
                raise OSError
    except OSError:
        raise HostError("host_tools_untrusted") from None
    return interpreter, assets


class Plan:
    def __init__(self, value):
        if not isinstance(value, dict) or not {"schema", "argv", "settings", "credential", "not_after_ms",
                                               "install"} <= set(value) \
                or not set(value) <= {"schema", "argv", "python", "settings", "credential", "not_after_ms",
                                      "install"} \
                or value["schema"] != PLAN_SCHEMA or not isinstance(value["argv"], list) or not value["argv"] \
                or guest_protocol.validate_argv(value["argv"]) is not None \
                or type(value.get("python", False)) is not bool or not isinstance(value["settings"], dict) \
                or len(_dump(value["settings"])) > MAX_SETTINGS_BYTES:
            raise HostError("adapter_plan_invalid")
        credential = value["credential"]
        expiry = value["not_after_ms"]
        if credential is not None and (not isinstance(credential, str) or not credential
                                       or len(credential.encode()) > MAX_CREDENTIAL_BYTES) \
                or expiry is not None and (type(expiry) is not int or expiry < 0) \
                or type(value["install"]) is not bool:
            raise HostError("adapter_plan_invalid")
        self.argv = list(value["argv"])
        self.python = value.get("python", False)
        self.settings = value["settings"]
        self.credential = credential
        self.not_after_ms = expiry
        self.install = value["install"]
        # A credential's HOME-relative destination (the runner's
        # `settings.auth.path`): a plain relative path.
        self.credential_path = None
        if credential is not None:
            auth = value["settings"].get("auth")
            path = auth.get("path") if isinstance(auth, dict) else None
            if not isinstance(path, str) or "\0" in path \
                    or any(part in ("", ".", "..") for part in path.split("/")):
                raise HostError("adapter_plan_invalid")
            self.credential_path = path

    def __repr__(self):
        # Never the credential or the settings (the model among them).
        return f"Plan(argv={len(self.argv)} words, credential={'yes' if self.credential else 'no'})"

    def check_expiry(self, now_ms=None):
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        if self.not_after_ms is not None and self.not_after_ms <= now_ms + CREDENTIAL_MARGIN_MS:
            raise HostError("credential_expired")


def _dump(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def request(agent, model, install, auth, interactive):
    """The adapter's request: `install` None or the version (None: its
    default); `auth` None or (absolute path, keep); `interactive` None or
    the trailing arguments."""
    return {"schema": REQUEST_SCHEMA, "agent": agent, "model": model,
            "install": None if install is False else {"version": install},
            "auth": None if auth is None else {"path": auth[0], "keep": auth[1]},
            "interactive": None if interactive is None else {"args": list(interactive)}}


def prepare(interpreter, assets, value, diagnostic, timeout=ADAPTER_TIMEOUT):
    """The adapter run on `value`: its checked plan, or its refusal's own
    code. `diagnostic(line)` gets its printable stderr lines."""
    agent = value["agent"]
    data = _dump(value)
    plan_fd = os.memfd_create("agentbox-agent-plan", os.MFD_CLOEXEC)
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    loop = Loop()
    loop.install_signals()
    child = None
    try:
        try:
            child = Child([interpreter, "-I", "-S", "-B", f"{assets}/agents/{agent}/adapter.py"], {},
                          stdout_fd=plan_fd, result_fd=write_end, fsize=MAX_PLAN_BYTES)
        finally:
            os.close(write_end)
        os.set_blocking(read_end, False)
        stdin = child.popen.stdin.fileno()
        err = Drain(loop, child.popen.stderr.fileno(), MAX_DIAGNOSTIC_BYTES)
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
        finished = loop.run(lambda: (state["ended"] and child.exited()) or bool(loop.signals),
                            time.monotonic() + timeout)
        done = finished and not loop.signals and child.exited()
        loop.run(lambda: err.ended, time.monotonic() + 0.2)
        err.close()
        if not child.exited():
            child.kill_group()
        code = child.finish()
        for line in bytes(err.kept).decode("ascii", "replace").splitlines():
            if _DIAGNOSTIC.fullmatch(line):
                diagnostic(line)
        if loop.signals:
            raise HostError("interrupted")
        if not done:
            raise HostError("adapter_failed")
        result = _result(state["result"])
        if result is None:
            raise HostError("adapter_failed")
        if result["outcome"] == "error":
            if code != 1:
                raise HostError("adapter_failed")
            raise HostError(result["code"])
        if code != 0:
            raise HostError("adapter_failed")
        length = os.fstat(plan_fd).st_size
        if not 0 < length <= MAX_PLAN_BYTES:
            raise HostError("adapter_plan_invalid")
        raw = os.pread(plan_fd, length, 0)
        try:
            plan = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise HostError("adapter_plan_invalid") from None
        plan = Plan(plan)
        # The lane only when asked: never the adapter's choice alone.
        if plan.install != (value["install"] is not None):
            raise HostError("adapter_plan_invalid")
        return plan
    finally:
        if child is not None and not child.reaped:
            child.stop()
        os.close(read_end)
        os.close(plan_fd)
        loop.close()


def _unique(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate")
    return dict(pairs)


def _result(line):
    if len(line) > MAX_RESULT_BYTES or not line.endswith(b"\n") or line.count(b"\n") != 1:
        return None
    try:
        value = json.loads(line, object_pairs_hook=_unique)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != RESULT_SCHEMA:
        return None
    if value.get("outcome") == "ok" and set(value) == {"schema", "outcome"}:
        return value
    if value.get("outcome") == "error" and set(value) == {"schema", "outcome", "code"} \
            and isinstance(value["code"], str) and _CODE.fullmatch(value["code"]):
        return value
    return None


def framed(plan, prompt, stage=None):
    """The task's input (`agentbox.agent-input.v3`); `stage` (nonce, env)
    for the interactive payload: no prompt, `stage` and `env` in the
    header. Too large: `agent_input_too_large`; for a staged payload that
    fits only without its `env`: `env_limit_exceeded`."""
    credential = (plan.credential or "").encode()
    prompt_bytes = prompt.encode()
    header = {"schema": INPUT_SCHEMA, "prompt_bytes": len(prompt_bytes), "credential_bytes": len(credential),
              "settings": plan.settings}
    if stage is not None:
        header["stage"] = stage[0]
        header["env"] = dict(stage[1])
    data = _dump(header) + b"\n" + prompt_bytes + credential
    if len(prompt_bytes) > MAX_PROMPT_BYTES or len(data) > MAX_INPUT_BYTES:
        if stage is not None and stage[1] and len(framed(plan, prompt, (stage[0], {}))) <= MAX_INPUT_BYTES:
            raise HostError("env_limit_exceeded")
        raise HostError("agent_input_too_large")
    return data


def runner_argv(plan, mode, nonce="-", receipt="-"):
    """The plan's runner argv and its mode words (headless - -, stage N -,
    run N R, unstage N R)."""
    return plan.argv + [mode, nonce, receipt]


def new_nonce():
    return secrets.token_hex(16)


def receipt(data):
    """The runner's staging receipt `DEV:INO:DIRDEV:DIRINO`: exactly one
    such line, nothing else; None otherwise."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not text.endswith("\n") or _RECEIPT.fullmatch(text[:-1]) is None \
            or any(int(p) >= 1 << 64 for p in text[:-1].split(":")):
        return None
    return text[:-1]


def filled(data):
    """`data` in one pipe sized for all of it (else
    `agent_input_pipe_unavailable`), written and its write end closed: the
    read end (close-on-exec), never blocking anyone."""
    read_end, write_end = os.pipe2(os.O_CLOEXEC)
    try:
        try:
            fcntl.fcntl(write_end, fcntl.F_SETPIPE_SZ, max(1, len(data)))
            capacity = fcntl.fcntl(write_end, fcntl.F_GETPIPE_SZ)
        except OSError:
            raise HostError("agent_input_pipe_unavailable") from None
        if capacity < len(data):
            raise HostError("agent_input_pipe_unavailable")
        view = memoryview(data)
        while view:
            view = view[os.write(write_end, view):]
    except BaseException:
        os.close(read_end)
        raise
    finally:
        os.close(write_end)
    return read_end
