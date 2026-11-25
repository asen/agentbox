"""Trusted host adapter of the `pi` coding agent (`agentbox run pi`).

Run by the host's guard like the input worker (host_tools.rs): standalone,
`INTERPRETER -I -S -B ASSETS/agents/pi/adapter.py`, empty environment, `/`
as working directory, its own custody leaf. It turns one request into one
plan; it never contacts anything and runs nothing.

    stdin   <- {"schema":"agentbox.agent-request.v1","agent":"pi",
                "model":STR|null,"install":{"version":STR|null}|null,
                "auth":{"path":ABS,"keep":BOOL}|null,
                "interactive":{"args":[STR...]}|null}
    stdout  -> {"schema":"agentbox.agent-plan.v1","argv":[...],"python":true,
                "settings":{...},"credential":STR|null,
                "not_after_ms":INT|null,"install":BOOL}
               (the host's private memory file; nothing else is written)
    fd 3    -> {"schema":"agentbox.agent-result.v1","outcome":"ok"} or
               {"schema":...,"outcome":"error","code":CODE}

argv is the common jail runner (agents/jail/run.py) as the jail Python's
arguments (`"python": true`: the execution's target binds its interpreter
before them), run from its own argv chunks; settings (`pi --offline -p
[--model M]`, the credential's destination, the package), prompt and
credential reach it on stdin only (src/agentbox_controller/agent.py).
`install` asks the host for its npm lane: the runner installs PACKAGE
(`--agent-version`, else latest) with the jail's npm.

Interactive (`interactive`, no prompt): `pi --offline [--model M] ARG...`,
the trailing arguments literal and last, staged by the host and run on the
terminal (the runner's `stage`/`run`); never with an install
(`interactive_install_unsupported`). Settings past MAX_SETTINGS_BYTES
refuse (`settings_too_large`).

Credentials: only the file the user selected, opened without following a
final link, a private regular file of at most MAX_AUTH_BYTES, strict JSON.
One provider entry is selected (the model's `PROVIDER/` prefix, else the
file's only entry) and copied with a fixed field allowlist: OAuth for the
providers in OAUTH_FIELDS with `refresh` emptied (the jail never gets the
host's refresh token, so it cannot rotate the host's login), or a literal
API key (a `!command` key refused). An OAuth access token expiring within
EXPIRY_MARGIN_MS refuses. Errors are fixed codes: no value, key, path or
traceback ever reaches stdout, stderr or the result.
"""

import json
import os
import re
import stat
import sys
import time

REQUEST_SCHEMA = "agentbox.agent-request.v1"
PLAN_SCHEMA = "agentbox.agent-plan.v1"
RESULT_SCHEMA = "agentbox.agent-result.v1"
AGENT = "pi"
MAX_REQUEST_BYTES = 64 * 1024
MAX_AUTH_BYTES = 1024 * 1024
MAX_CREDENTIAL_BYTES = 16 * 1024
MAX_SETTINGS_BYTES = 8 * 1024
MAX_PLAN_BYTES = 64 * 1024
MAX_MODEL_BYTES = 256
MAX_WRAPPER_BYTES = 26 * 1024
EXPIRY_MARGIN_MS = 10 * 60 * 1000
# `--offline`: none of Pi's own automatic requests; `-p`: the prompt from
# stdin, the answer printed.
FLAGS = ["--offline", "-p"]
# Interactive (no prompt): Pi's own terminal interface, the trailing
# arguments (`--continue`, `--resume`...) after these.
INTERACTIVE = ["--offline"]
CREDENTIAL_PATH = ".pi/agent/auth.json"
# The npm package and its command (the runner's package).
PACKAGE = "@earendil-works/pi-coding-agent"
BIN = "pi"
# Guest argv items are at most 4096 bytes (contracts/v1); the wrapper is
# ASCII, cut into chunks below that and joined again by LOADER.
CHUNK_BYTES = 4000
# The runner's mode words follow the chunks (agents/jail/run.py): the host
# appends them.
LOADER = 'import sys;exec("".join(sys.argv[1:-3]))'
RESULT_FD = 3
HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(os.path.dirname(HERE), "jail", "run.py")
# The jail interpreter's isolation, as every worker entrypoint's.
PYTHON_FLAGS = ["-I", "-S", "-B", "-X", "utf8"]
# Per provider, the OAuth fields copied besides `type` and an empty
# `refresh`.
OAUTH_FIELDS = {"openai-codex": ("access", "expires", "accountId")}
PROVIDER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
# An exact npm version for `--agent-version` (the jail's npm installs it).
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-[0-9A-Za-z.-]{1,40})?")


class Refused(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def strict(data, code):
    """One JSON object, no duplicate key, no NaN or Infinity."""
    def pairs(items):
        keys = [key for key, _ in items]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate")
        return dict(items)

    def constant(_):
        raise ValueError("constant")

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Refused(code) from None
    if not isinstance(value, dict):
        raise Refused(code)
    return value


def exact(obj, fields):
    return isinstance(obj, dict) and set(obj) == set(fields)


def read_request(stream):
    data = stream.read(MAX_REQUEST_BYTES + 1)
    if len(data) > MAX_REQUEST_BYTES:
        raise Refused("request_invalid")
    request = strict(data, "request_invalid")
    if not exact(request, ("schema", "agent", "model", "install", "auth", "interactive")) \
            or request["schema"] != REQUEST_SCHEMA:
        raise Refused("request_invalid")
    interactive = request["interactive"]
    if interactive is not None and (not exact(interactive, ("args",))
                                    or not isinstance(interactive["args"], list)
                                    or not all(literal(arg) for arg in interactive["args"])):
        raise Refused("request_invalid")
    if request["agent"] != AGENT:
        raise Refused("agent_unknown")
    model = request["model"]
    if model is not None and not model_text(model):
        raise Refused("model_invalid")
    install = request["install"]
    if install is not None and (not exact(install, ("version",)) or not (
            install["version"] is None or isinstance(install["version"], str))):
        raise Refused("request_invalid")
    auth = request["auth"]
    if auth is not None and (not exact(auth, ("path", "keep"))
                             or not isinstance(auth["path"], str)
                             or not os.path.isabs(auth["path"])
                             or "\0" in auth["path"]
                             or not isinstance(auth["keep"], bool)):
        raise Refused("request_invalid")
    return request


def model_text(model):
    """Forwarded as given (the agent resolves it): printable, no space."""
    return isinstance(model, str) and 0 < len(model.encode()) <= MAX_MODEL_BYTES \
        and model.isprintable() and not any(ch.isspace() for ch in model) \
        and not model.startswith("-")

def literal(arg):
    """A trailing argument, literal: strict UTF-8 text without NUL."""
    if not isinstance(arg, str) or "\0" in arg:
        return False
    try:
        arg.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def sized(settings):
    """The runner's settings within the host's MAX_SETTINGS_BYTES, as sent."""
    text = json.dumps(settings, separators=(",", ":"), ensure_ascii=False)
    if len(text.encode("utf-8")) > MAX_SETTINGS_BYTES:
        raise Refused("settings_too_large")
    return settings


def provider_of(model):
    if model is None or "/" not in model:
        return None
    provider = model.split("/", 1)[0]
    return provider if PROVIDER.fullmatch(provider) else None


def package(request):
    """The runner's package: the agent's npm package and bin, and the
    install `--install-agent` asked for (its version exact, else latest)."""
    install = request["install"]
    if install is not None and install["version"] is not None \
            and VERSION.fullmatch(install["version"]) is None:
        raise Refused("agent_version_invalid")
    return {"agent": AGENT, "name": PACKAGE, "bin": BIN, "install": install and dict(install)}


def read_auth(path):
    """The selected file's bytes: a regular private file, no final link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise Refused("credential_unreadable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise Refused("credential_unreadable")
        if info.st_mode & 0o077:
            raise Refused("credential_not_private")
        if info.st_size > MAX_AUTH_BYTES:
            raise Refused("credential_too_large")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_AUTH_BYTES:
                raise Refused("credential_too_large")
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError:
        raise Refused("credential_unreadable") from None
    finally:
        os.close(fd)


def select(document, model, now_ms):
    """(provider, the copied entry, its expiry or None)."""
    if not document or not all(isinstance(key, str) for key in document):
        raise Refused("credential_invalid")
    provider = provider_of(model)
    if provider is None:
        if len(document) != 1:
            raise Refused("credential_ambiguous")
        provider = next(iter(document))
    elif provider not in document:
        raise Refused("credential_provider_missing")
    entry = document[provider]
    if not isinstance(entry, dict):
        raise Refused("credential_invalid")
    kind = entry.get("type")
    if kind == "api_key":
        key = entry.get("key")
        if not isinstance(key, str) or not key:
            raise Refused("credential_invalid")
        if key.startswith("!"):
            raise Refused("credential_command_unsupported")
        return provider, {"type": "api_key", "key": key}, None
    if kind == "oauth":
        fields = OAUTH_FIELDS.get(provider)
        if fields is None:
            raise Refused("credential_type_unsupported")
        copied = {"type": "oauth"}
        for field in fields:
            if field not in entry:
                raise Refused("credential_invalid")
            copied[field] = entry[field]
        copied["refresh"] = ""
        access, expires = copied.get("access"), copied.get("expires")
        if not isinstance(access, str) or not access \
                or isinstance(expires, bool) or not isinstance(expires, (int, float)) \
                or expires != expires or expires in (float("inf"), float("-inf")):
            raise Refused("credential_invalid")
        if not all(isinstance(copied[field], str) for field in fields if field != "expires"):
            raise Refused("credential_invalid")
        if expires <= now_ms + EXPIRY_MARGIN_MS:
            raise Refused("credential_expired")
        return provider, copied, int(expires)
    raise Refused("credential_type_unsupported")


def credential(auth, model, now_ms):
    document = strict(read_auth(auth["path"]), "credential_invalid")
    provider, entry, expires = select(document, model, now_ms)
    text = json.dumps({provider: entry}, separators=(",", ":"), ensure_ascii=False)
    if len(text.encode()) > MAX_CREDENTIAL_BYTES:
        raise Refused("credential_too_large")
    return text, expires


def wrapper_argv():
    """`-I -S -B -X utf8 -c LOADER CHUNK...`, the jail Python's arguments:
    the common runner's text in argv chunks."""
    try:
        fd = os.open(WRAPPER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise Refused("wrapper_invalid") from None
    try:
        data = os.read(fd, MAX_WRAPPER_BYTES + 1)
    finally:
        os.close(fd)
    if not data or len(data) > MAX_WRAPPER_BYTES or not data.isascii() or b"\0" in data:
        raise Refused("wrapper_invalid")
    text = data.decode("ascii")
    chunks = [text[at:at + CHUNK_BYTES] for at in range(0, len(text), CHUNK_BYTES)]
    return PYTHON_FLAGS + ["-c", LOADER] + chunks


def plan(request, now_ms):
    interactive = request["interactive"]
    if interactive is not None and request["install"] is not None:
        raise Refused("interactive_install_unsupported")
    chosen = package(request)
    text, expires = (None, None)
    auth = request["auth"]
    if auth is not None:
        text, expires = credential(auth, request["model"], now_ms)
    argv = ["pi"] + (INTERACTIVE if interactive else FLAGS)
    if request["model"] is not None:
        argv += ["--model", request["model"]]
    if interactive:
        argv += interactive["args"]
    return {"schema": PLAN_SCHEMA,
            "argv": wrapper_argv(),
            "python": True,
            "settings": sized({"argv": argv,
                               "auth": auth and {"path": CREDENTIAL_PATH, "keep": auth["keep"]},
                               "package": chosen}),
            "credential": text,
            "not_after_ms": expires,
            "install": request["install"] is not None}


def result(fields):
    line = json.dumps(dict({"schema": RESULT_SCHEMA}, **fields), separators=(",", ":"))
    os.write(RESULT_FD, line.encode() + b"\n")


def main():
    try:
        request = read_request(sys.stdin.buffer)
        document = plan(request, int(time.time() * 1000))
        # Unescaped UTF-8: a credential's non-ASCII text stays its own bytes
        # (`\uXXXX` escapes would triple it past the host's MAX_PLAN_BYTES);
        # strict, so nothing invalid is written.
        plan_text = json.dumps(document, separators=(",", ":"), ensure_ascii=False)
        data = plan_text.encode("utf-8")
        # The whole plan as written within the host's MAX_PLAN_BYTES (its
        # parts' own caps together, JSON escapes included), else refused.
        if len(data) > MAX_PLAN_BYTES:
            raise Refused("plan_too_large")
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    except Refused as refused:
        result({"outcome": "error", "code": refused.code})
        return 1
    except Exception:  # noqa: BLE001 - a fixed code, never a traceback
        result({"outcome": "error", "code": "adapter_failed"})
        return 1
    result({"outcome": "ok"})
    return 0


if __name__ == "__main__":
    sys.exit(main())
