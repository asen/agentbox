"""The session's handler selection (the Rust host's handlers.rs): the
trusted manifests a configuration enables, one policy per handler,
snapshotted once per execution and never reopened.

```text
chosen   --acquisition-config FILE (dev: else dev.json's), else
         CONFIG = $XDG_CONFIG_HOME/agentbox/acquisition.json (else
         ~/.config/...); only its absence (ENOENT) selects the packaged
         defaults: git, npm and pip with their packaged policies
FILE     {"schema":"agentbox.acquisition-config.v2"[,"interpreter":ABS][,"assets":ABS],
          "handlers":{"ID":{["policy":ABS][,"operations":[..]]}}}
         interpreter: else host.json's, else /usr/bin/python3; assets: else
         the packaged tree; no policy (PACKAGED only, the packaged tree
         only): ASSETS/acquisitions/ID/policy.json; "handlers":{}: no lane
ASSETS/acquisitions/ID/manifest.json   agentbox.handler-manifest.v1
ASSETS/acquisitions/ID/...             its listed files (entry among them)
ASSETS/acquisitions/lib/               the workers' trusted import directory
```

Registration grants nothing: a manifest only makes its handler
selectable; the configuration (or its absence) enables it with its policy
and the operations it permits (omitted: all; `[]`: none). Manifest limits
only narrow the ceilings. Trust is a point-in-time check of trusted host
code, as for providers: the interpreter's whole chain, each listed file
and everything in `lib` regular or a directory, root's or ours, not group
or world writable, no link in the tree; each manifest tool found on the
captured PATH (absent: `acquisition_tool_missing`, Git's own hinted
`acquisition_git_missing`; not trusted: `acquisition_worker_untrusted`).
At most one enabled handler's jail module may be the session wrapper
(`jail.session`), put before every command (`bin/agentbox-session`).
Errors are fixed codes.
"""
import hashlib
import json
import os
import re
import stat

from .assets import ASSETS, provider_protocol
from .config import DEFAULT_INTERPRETER, _location
from .host import HostError, find_tool, install_owner

CONFIG_SCHEMA = "agentbox.acquisition-config.v2"
MANIFEST_SCHEMA = "agentbox.handler-manifest.v1"
MAX_CONFIG_BYTES = 16384
MAX_MANIFEST_BYTES = 16384
MAX_HANDLERS = 8
MAX_OPERATIONS = 16
MAX_FILES = 64
MAX_TOOLS = 4
MAX_SHIMS = 8
MAX_DEPTH = 16
MAX_LIB_ENTRIES = 256
MAX_LIB_DEPTH = 8
MAX_HOPS = 40
CEILINGS = {"policy_bytes": 128 * 1024, "args_bytes": 60 * 1024, "metadata_bytes": 62 * 1024,
            "acquisition_seconds": 600}
# The session wrapper's name (`Selection.session`) is the host's alone.
SESSION_WRAPPER = "agentbox-session"
# The packaged defaults: these handlers, each with ASSETS/acquisitions/ID/policy.json.
PACKAGED = ("git", "npm", "pip")
# The packaged tree (test seam: launch.py overrides).
PACKAGED_ASSETS = ASSETS
GIT_HINT = ("Git acquisition is enabled, but git was not found on the host PATH: install git, or leave git out of "
            "your acquisition config ($XDG_CONFIG_HOME/agentbox/acquisition.json, else "
            "~/.config/agentbox/acquisition.json, or --acquisition-config FILE), e.g. "
            '{"schema": "agentbox.acquisition-config.v2", "handlers": {"npm": {}, "pip": {}}}')
RESERVED_SHIMS = frozenset((
    "agentbox-request", "agentbox-guest", SESSION_WRAPPER, "node", "sh", "bash", "dash", "env", "sudo", "su",
    "login", "ssh", "scp", "sftp", "ssh-keygen", "cat", "cp", "mv", "rm", "ln", "ls", "mkdir", "chmod", "chown",
    "id", "kill", "ps", "test", "true", "false", "python", "python3"))
_ID = re.compile(r"[a-z][a-z0-9-]{0,31}")
_TOOL = re.compile(r"[a-z][a-z0-9.-]{0,31}")
_SHIM = re.compile(r"[a-z][a-z0-9._-]{0,31}")
_VERSION = re.compile(r"[A-Za-z0-9.+-]{1,32}")
_PART = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]*")


def _unique(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate")
    return dict(pairs)


def _depth(value):
    if isinstance(value, dict):
        return 1 + max((_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_depth(v) for v in value), default=0)
    return 0


def _no_float(_):
    raise ValueError("number")


def strict_object(data, limit):
    """Strict UTF-8 JSON of at most `limit` bytes and MAX_DEPTH levels: no
    duplicate key, constant, non-integer or unsafe number; an object."""
    if len(data) > limit:
        raise ValueError("size")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_no_float,
                       parse_float=_no_float)
    if not isinstance(value, dict) or _depth(value) > MAX_DEPTH:
        raise ValueError("shape")
    json.dumps(value, ensure_ascii=False).encode("utf-8")

    def safe(item):
        if isinstance(item, bool) or item is None or isinstance(item, str):
            return
        if isinstance(item, int):
            if abs(item) > (1 << 53) - 1:
                raise ValueError("number")
            return
        for child in (item.values() if isinstance(item, dict) else item):
            safe(child)
    safe(value)
    return value


def _trusted_owner(st):
    return st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022


def operator_file(path, limit, code, *, installed=False):
    """Read a bounded regular file without following a final link."""
    if not provider_protocol.is_path(path):
        raise HostError(code)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise HostError(code) from None
    try:
        st = os.fstat(fd)
        owner = install_owner if installed else _trusted_owner
        if not stat.S_ISREG(st.st_mode) or not owner(st) or st.st_size > limit:
            raise HostError(code)
        data = os.read(fd, limit + 1)
    except OSError:
        raise HostError(code) from None
    finally:
        os.close(fd)
    if len(data) > limit:
        raise HostError(code)
    return data


def _relative(text):
    return isinstance(text, str) and len(text) <= 160 and len(text.split("/")) <= 8 \
        and all(_PART.fullmatch(p) and p not in (".", "..") for p in text.split("/"))


def _words(items, pattern, maximum, allow_empty=False):
    return isinstance(items, list) and (allow_empty or items) and len(items) <= maximum \
        and len(set(map(str, items))) == len(items) \
        and all(isinstance(i, str) and pattern.fullmatch(i) for i in items)


def walk(path):
    """`path` resolved through its links, every directory on the way root's
    or ours with installed-code ownership (or root's and sticky), every
    link root's or ours (provider_config.rs `walk`); a fixed refusal."""
    if not isinstance(path, str) or not path.startswith("/"):
        raise HostError("acquisition_worker_untrusted")
    pending = [p for p in path.split("/") if p][::-1]
    current = "/"
    hops = 0
    while pending:
        name = pending.pop()
        if name == ".":
            continue
        if name == "..":
            current = os.path.dirname(current) or "/"
            continue
        try:
            parent = os.lstat(current)
        except OSError:
            raise HostError("acquisition_worker_untrusted") from None
        if not stat.S_ISDIR(parent.st_mode) or not (
                install_owner(parent) or (parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX)):
            raise HostError("acquisition_worker_untrusted")
        nxt = os.path.join(current, name)
        try:
            st = os.lstat(nxt)
        except OSError:
            raise HostError("acquisition_worker_untrusted") from None
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if hops > MAX_HOPS or st.st_uid not in (0, os.geteuid()):
                raise HostError("acquisition_worker_untrusted")
            target = os.readlink(nxt)
            if target.startswith("/"):
                current = "/"
            pending.extend([p for p in target.split("/") if p][::-1])
            continue
        current = nxt
    return current


def _trusted(path, kind):
    try:
        st = os.lstat(path)
    except OSError:
        raise HostError("acquisition_worker_untrusted") from None
    setid = st.st_mode & (stat.S_ISUID | stat.S_ISGID)
    shape = {"file": stat.S_ISREG(st.st_mode) and not setid,
             "exec": stat.S_ISREG(st.st_mode) and st.st_mode & 0o111 and not setid,
             "dir": stat.S_ISDIR(st.st_mode)}[kind]
    if not shape or not install_owner(st):
        raise HostError("acquisition_worker_untrusted")


def _plain(path, kind):
    if walk(path) != path:
        raise HostError("acquisition_worker_untrusted")
    _trusted(path, kind)


def _tree(path, depth, budget):
    try:
        entries = list(os.scandir(path))
    except OSError:
        raise HostError("acquisition_worker_untrusted") from None
    for entry in entries:
        budget[0] -= 1
        if budget[0] < 0:
            raise HostError("acquisition_worker_untrusted")
        if entry.is_dir(follow_symlinks=False):
            if depth >= MAX_LIB_DEPTH:
                raise HostError("acquisition_worker_untrusted")
            _trusted(entry.path, "dir")
            _tree(entry.path, depth + 1, budget)
        elif entry.is_file(follow_symlinks=False):
            _trusted(entry.path, "file")
        else:
            raise HostError("acquisition_worker_untrusted")


class Handler:
    def __init__(self, ident, manifest, permitted, policy, policy_text):
        self.id = ident
        self.version = manifest["version"]
        self.entry = manifest["entry"]
        self.files = manifest["files"]
        self.operations = manifest["operations"]
        self.permitted = permitted
        self.metering = manifest["metering"]
        self.tool_names = manifest.get("tools", [])
        self.tools = {}
        self.limits = dict(CEILINGS, **manifest.get("limits", {}))
        self.jail = manifest.get("jail")
        self.policy = policy
        self.policy_sha256 = hashlib.sha256(policy_text).hexdigest()


def _manifest(assets, ident):
    try:
        value = strict_object(operator_file(f"{assets}/acquisitions/{ident}/manifest.json", MAX_MANIFEST_BYTES,
                                            "handler_manifest_invalid", installed=True), MAX_MANIFEST_BYTES)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HostError("handler_manifest_invalid") from None
    required = {"schema", "id", "version", "entry", "files", "operations", "metering"}
    limits = value.get("limits", {})
    jail = value.get("jail")
    valid = (required <= set(value) and set(value) <= required | {"tools", "limits", "jail"}
             and value["schema"] == MANIFEST_SCHEMA and value["id"] == ident
             and isinstance(value["version"], str) and _VERSION.fullmatch(value["version"])
             and isinstance(value["files"], list) and 1 <= len(value["files"]) <= MAX_FILES
             and all(map(_relative, value["files"])) and len(set(value["files"])) == len(value["files"])
             and value["entry"] in value["files"] and value["entry"].endswith(".py")
             and _words(value["operations"], _ID, MAX_OPERATIONS)
             and value["metering"] in ("http", "none")
             and _words(value.get("tools", []), _TOOL, MAX_TOOLS, allow_empty=True)
             and isinstance(limits, dict) and set(limits) <= set(CEILINGS)
             and all(type(v) is int for v in limits.values()))
    if valid:
        resolved = dict(CEILINGS, **limits)
        valid = all((1 if k == "acquisition_seconds" else 2) <= resolved[k] <= CEILINGS[k] for k in CEILINGS)
    if valid and jail is not None:
        entry = jail.get("entry") if isinstance(jail, dict) else None
        valid = (isinstance(jail, dict) and set(jail) <= {"entry", "shims", "session"} and isinstance(entry, str)
                 and type(jail.get("session", False)) is bool
                 and entry.startswith(f"acquisitions/{ident}/jail/") and len(entry) > len(f"acquisitions/{ident}/jail/")
                 and entry.endswith(".py") and _relative(entry)
                 and _words(jail.get("shims", []), _SHIM, MAX_SHIMS, allow_empty=True)
                 and not set(jail.get("shims", [])) & RESERVED_SHIMS)
    if not valid:
        raise HostError("handler_manifest_invalid")
    return value


class Selection:
    """One execution's handlers: the trusted interpreter and asset tree,
    each enabled handler by id."""

    def __init__(self, interpreter, assets, handlers):
        self.interpreter, self.assets, self.handlers = interpreter, assets, handlers
        self.lib = f"{assets}/acquisitions/lib"

    def entry(self, handler):
        return f"{self.assets}/acquisitions/{handler.entry}"

    def shims(self):
        """[(name, jail entry)] of every enabled handler's jail commands."""
        found = []
        for ident in sorted(self.handlers):
            jail = self.handlers[ident].jail
            if jail:
                found += [(name, jail["entry"]) for name in jail.get("shims", [])]
        return found

    def session(self):
        """The jail entry of the one enabled handler whose module wraps every
        command (`jail.session`), or None."""
        found = [handler.jail["entry"] for _, handler in sorted(self.handlers.items())
                 if handler.jail and handler.jail.get("session") is True]
        return found[0] if found else None


def location(environ):
    return _location(environ, "XDG_CONFIG_HOME", "agentbox/acquisition.json", ".config/agentbox/acquisition.json",
                     "acquisition_config_location_invalid")


def implicit(environ, interpreter=None):
    """The persistent configuration, else (absent: ENOENT only) the
    packaged defaults. `interpreter()`: the default interpreter."""
    path = location(environ)
    try:
        os.lstat(path)
    except FileNotFoundError:
        return select({"schema": CONFIG_SCHEMA, "handlers": {ident: {} for ident in PACKAGED}}, interpreter)
    except OSError:
        pass
    return read(path, interpreter)


def read(path, interpreter=None):
    """The configuration at `path` (`select`)."""
    try:
        value = strict_object(operator_file(path, MAX_CONFIG_BYTES, "acquisition_config_unreadable"),
                              MAX_CONFIG_BYTES)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HostError("acquisition_config_invalid") from None
    return select(value, interpreter)


def select(value, interpreter=None):
    """A configuration's selection, every manifest and policy read once,
    then the trust checks; None when it enables no handler.
    `interpreter()`: the default interpreter (None: /usr/bin/python3)."""
    handlers = value.get("handlers")
    if not {"schema", "handlers"} <= set(value) <= {"schema", "interpreter", "assets", "handlers"} \
            or value["schema"] != CONFIG_SCHEMA \
            or any(k in value and not provider_protocol.is_path(value[k]) for k in ("interpreter", "assets")) \
            or not isinstance(handlers, dict) or len(handlers) > MAX_HANDLERS \
            or any(not _ID.fullmatch(i) or i == "lib" for i in handlers) \
            or any(not isinstance(e, dict) or not set(e) <= {"policy", "operations"}
                   or "policy" in e and not provider_protocol.is_path(e["policy"]) for e in handlers.values()):
        raise HostError("acquisition_config_invalid")
    if not handlers:
        return None
    assets = value.get("assets", PACKAGED_ASSETS)
    for ident, entry in handlers.items():
        # A packaged policy only from the packaged tree, never an override's.
        if "policy" not in entry and (ident not in PACKAGED or assets != PACKAGED_ASSETS):
            raise HostError("handler_policy_required")
    enabled = {}
    for ident in sorted(handlers):
        entry = handlers[ident]
        manifest = _manifest(assets, ident)
        listed = entry.get("operations")
        if listed is None:
            permitted = list(manifest["operations"])
        else:
            if not _words(listed, re.compile(r".*"), MAX_OPERATIONS, allow_empty=True):
                raise HostError("acquisition_config_invalid")
            if any(op not in manifest["operations"] for op in listed):
                raise HostError("handler_operation_unknown")
            permitted = [op for op in manifest["operations"] if op in listed]
        limit = dict(CEILINGS, **manifest.get("limits", {}))["policy_bytes"]
        if "policy" in entry:
            text = operator_file(entry["policy"], limit, "handler_policy_unreadable")
        else:
            text = operator_file(f"{assets}/acquisitions/{ident}/policy.json", limit, "handler_policy_unreadable",
                                 installed=True)
        try:
            policy = strict_object(text, limit)
        except (ValueError, UnicodeDecodeError, RecursionError):
            raise HostError("handler_policy_invalid") from None
        enabled[ident] = Handler(ident, manifest, permitted, policy, text)
    if "interpreter" in value:
        chosen = value["interpreter"]
    else:
        chosen = interpreter() if interpreter is not None else DEFAULT_INTERPRETER
    selection = Selection(chosen, assets, enabled)
    seen = set()
    for name, _ in selection.shims():
        if name in RESERVED_SHIMS or name in seen:
            raise HostError("handler_shim_conflict")
        seen.add(name)
    if sum(1 for handler in enabled.values() if handler.jail and handler.jail.get("session") is True) > 1:
        raise HostError("handler_session_conflict")
    check(selection)
    return selection


def check(selection):
    """The point-in-time trust checks, then each manifest tool on the
    captured PATH."""
    interpreter = walk(selection.interpreter)
    _trusted(interpreter, "exec")
    if not provider_protocol.is_path(interpreter):
        raise HostError("acquisition_worker_untrusted")
    selection.interpreter = interpreter
    _plain(selection.assets, "dir")
    _plain(f"{selection.assets}/acquisitions", "dir")
    if os.path.lexists(selection.lib):
        _plain(selection.lib, "dir")
        _tree(selection.lib, 0, [MAX_LIB_ENTRIES])
    for handler in selection.handlers.values():
        _plain(f"{selection.assets}/acquisitions/{handler.id}/manifest.json", "file")
        for name in handler.files:
            _plain(f"{selection.assets}/acquisitions/{name}", "file")
        for tool in handler.tool_names:
            try:
                found = find_tool(tool)
            except HostError as error:
                if error.code != "tool_missing":
                    raise HostError("acquisition_worker_untrusted") from None
                if (handler.id, tool) != ("git", "git"):
                    raise HostError("acquisition_tool_missing") from None
                missing = HostError("acquisition_git_missing")
                missing.hint = GIT_HINT
                raise missing from None
            _plain(walk(found), "exec")
            handler.tools[tool] = found


def packaged(interpreter, assets, ident, policy):
    """One packaged handler enabled with a packaged policy (`run AGENT
    --install-agent`'s npm and its registry, ASSETS-relative): every
    operation of its manifest, then the trust checks."""
    path = f"{assets}/{policy}"
    if not provider_protocol.is_path(interpreter) or not provider_protocol.is_path(assets) \
            or not _ID.fullmatch(ident) or ident == "lib" or not provider_protocol.is_path(path):
        raise HostError("acquisition_config_invalid")
    manifest = _manifest(assets, ident)
    limit = dict(CEILINGS, **manifest.get("limits", {}))["policy_bytes"]
    text = operator_file(path, limit, "handler_policy_unreadable", installed=True)
    try:
        value = strict_object(text, limit)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HostError("handler_policy_invalid") from None
    selection = Selection(interpreter, assets, {ident: Handler(ident, manifest, list(manifest["operations"]),
                                                               value, text)})
    check(selection)
    return selection
