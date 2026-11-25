"""The operator's files: the controller configuration, the provider
configuration a prepared run copies and the host configuration.

```text
agentbox.controller-config.v1   {"schema"[, "data"][, "server"][, "network_policy"][, "connect_proxy"]
                                 [, "state_root"][, "podman_engine_root"][, "podman_store"]}: --config FILE,
                                else $XDG_CONFIG_HOME/agentbox/controller.json, else
                                ~/.config/agentbox/controller.json (absent: defaults);
                                data: $XDG_DATA_HOME/agentbox-controller, else
                                ~/.local/share/agentbox-controller; server: the packaged
                                prefix's bin/agentbox-server (a source checkout's main.py
                                has none: configure it); state_root, podman_engine_root,
                                podman_store (shared | private; absent: shared;
                                `image prepare --store` overrides it):
                                the built-in profiles' (builtin.py); connect_proxy: a plain
                                HTTP CONNECT proxy's HOST:PORT (a name, an IPv4 or a bracketed
                                IPv6 literal, not unspecified; no TLS, no authentication) every
                                session's broker tunnels through, never directly; absent: direct
agentbox.provider-config.v1     as the Rust host's (provider_config.rs)
recorded provider               a custom configuration as given, or a built-in's
                                {"builtin": podman | qemu, "state"} (check_recorded)
agentbox.host-config.v1         {"schema"[, "interpreter"][, "assets"][, "export_max_bytes"]
                                 [, "export_timeout_ms"]}: --host-config FILE, else
                                 $XDG_CONFIG_HOME/agentbox/host.json, else
                                 ~/.config/agentbox/host.json (absent: defaults)
```

Every path is absolute and shell-inert (providers/protocol.py `is_path`).
`data` is the new-path data root: never the old CLI's store (its default
location, or any root holding the old `runs/` layout), never inside or
around a provider's STATE or ASSETS. A private regular file is read without
following a final link, ours, not group or world writable, bounded.
Errors are fixed codes.
"""
import json
import os
import re
import stat

from .assets import provider_protocol
from .host import HostError, install_owner

CONTROLLER_SCHEMA = "agentbox.controller-config.v1"
# The built-in Podman profile's engine stores (builtin.PODMAN_STATES).
PODMAN_STORES = ("private", "shared")
DEFAULT_PODMAN_STORE = "shared"
HOST_SCHEMA = "agentbox.host-config.v1"
DEFAULT_INTERPRETER = "/usr/bin/python3"
EXPORT_MAX_BYTES = (10240, 64 << 30)
EXPORT_TIMEOUT_MS = (1000, 86400000)
PROVIDER_SCHEMA = "agentbox.provider-config.v1"
BUILTIN_PROVIDERS = ("podman", "qemu")
POLICY_SCHEMA = "agentbox.network-policy.v1"
MAX_CONFIG_BYTES = 8192
MAX_POLICY_BYTES = 64 * 1024
MAX_ASSET_ENTRIES = 4096
MAX_ASSET_DEPTH = 16
GUARD = {"cpus": (1, 256), "memory_mib": (256, 1048576), "pids": (64, 1048576)}
# The server's default: Model Only, the default provider set
# (network/provider_sets.rs DEFAULT_MODEL_ONLY), as the old worker uses.
DEFAULT_POLICY = {"schema": POLICY_SCHEMA, "mode": "model_only",
                  "provider_sets": [{"name": "openai-codex", "version": 1}]}


def _unique(pairs):
    if len({k for k, _ in pairs}) != len(pairs):
        raise ValueError("duplicate")
    return dict(pairs)


def read_private(path, limit, code):
    """A regular file of ours, not group/world writable, at most `limit`
    bytes, opened without following a final link."""
    if not provider_protocol.is_path(path):
        raise HostError(code)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except OSError:
        raise HostError(code) from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022 \
                or st.st_size > limit:
            raise HostError(code)
        data = os.read(fd, limit + 1)
    except OSError:
        raise HostError(code) from None
    finally:
        os.close(fd)
    if len(data) > limit:
        raise HostError(code)
    return data


def strict_json(data, code):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise HostError(code) from None


def _nested(a, b):
    return a == b or a.startswith(b + "/") or b.startswith(a + "/")


def legacy_data_dirs(environ):
    """The old CLI's default store locations (the providers' own rule:
    common.legacy_store_roots, read again at every mount resolution)."""
    from .assets import provider_common
    return provider_common.legacy_store_roots(environ)


def _location(environ, xdg_name, xdg_rel, home_rel, code):
    xdg, home = environ.get(xdg_name), environ.get("HOME")
    if xdg:
        if not provider_protocol.is_path(xdg):
            raise HostError(code)
        return f"{xdg}/{xdg_rel}"
    if home and provider_protocol.is_path(home):
        return f"{home}/{home_rel}"
    raise HostError(code)


def config_path(explicit, environ):
    """(path, explicit): `--config FILE`, else the default location (which
    may be absent)."""
    if explicit is not None:
        return explicit, True
    return _location(environ, "XDG_CONFIG_HOME", "agentbox/controller.json", ".config/agentbox/controller.json",
                     "config_location_invalid"), False


def default_state(environ):
    return _location(environ, "XDG_STATE_HOME", "agentbox", ".local/state/agentbox", "state_location_invalid")


def default_data(environ):
    return _location(environ, "XDG_DATA_HOME", "agentbox-controller", ".local/share/agentbox-controller",
                     "data_location_invalid")


def load_controller(path, environ, prefix=None, explicit=True):
    """The controller configuration: an explicit file must exist; the
    default one may be absent (every default then). `prefix`: the packaged
    entry's, whose bin/agentbox-server is the default server; without one
    (a source checkout) an unconfigured server is None, refused where it
    is needed (`server_unconfigured`)."""
    if not explicit and not os.path.lexists(path):
        value = {"schema": CONTROLLER_SCHEMA}
    else:
        value = strict_json(read_private(path, MAX_CONFIG_BYTES, "config_unreadable"), "config_invalid")
    if not isinstance(value, dict) or value.get("schema") != CONTROLLER_SCHEMA \
            or not set(value) <= {"schema", "data", "server", "network_policy", "connect_proxy", "state_root",
                                  "podman_engine_root", "podman_store"}:
        raise HostError("config_invalid")
    if value.get("podman_store", DEFAULT_PODMAN_STORE) not in PODMAN_STORES:
        raise HostError("config_invalid")
    proxy = None
    if "connect_proxy" in value:
        from agentbox_server.address import authority_text
        from agentbox_server.policy import PolicyError, parse_grant
        try:
            proxy = authority_text(parse_grant(value["connect_proxy"]))
        except PolicyError:
            raise HostError("config_invalid") from None
    for key in ("data", "server", "network_policy", "state_root", "podman_engine_root"):
        if key in value and not provider_protocol.is_path(value[key]):
            raise HostError("config_invalid")
    data = value["data"] if "data" in value else default_data(environ)
    if any(_nested(data, legacy) for legacy in legacy_data_dirs(environ)) \
            or os.path.lexists(data + "/runs"):
        raise HostError("data_legacy")
    server = value.get("server")
    if server is None and prefix is not None:
        server = f"{prefix}/bin/agentbox-server"
        if not provider_protocol.is_path(server):
            raise HostError("server_untrusted")
    policy = DEFAULT_POLICY
    if "network_policy" in value:
        policy = strict_json(read_private(value["network_policy"], MAX_POLICY_BYTES,
                                          "policy_unreadable"), "policy_invalid")
        if not isinstance(policy, dict) or policy.get("schema") != POLICY_SCHEMA:
            raise HostError("policy_invalid")
    return {"data": data, "server": server, "policy": policy, "connect_proxy": proxy,
            "data_default": "data" not in value,
            "state_root": value.get("state_root"), "podman_engine_root": value.get("podman_engine_root"),
            "podman_store": value.get("podman_store", DEFAULT_PODMAN_STORE)}


def check_server(path):
    """The transport server: configured, a plain path to a regular
    executable file (no final link) with installed-code ownership."""
    if path is None:
        raise HostError("server_unconfigured")
    try:
        st = os.lstat(path)
    except OSError:
        raise HostError("server_missing") from None
    if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111 or not install_owner(st):
        raise HostError("server_untrusted")
    return path


def ensure_data(path):
    """The default data root, made private (0700, missing parents too)
    when a command needs it; never an existing one changed."""
    if os.path.lexists(path):
        return
    try:
        os.makedirs(path, 0o700)
        os.chmod(path, 0o700)
    except FileExistsError:
        pass
    except OSError:
        raise HostError("store_unavailable") from None


def check_provider(value):
    """A provider configuration's closed shape (the Rust host's rules)."""
    keys = {"schema", "provider", "interpreter", "entry", "state", "assets"}
    if not isinstance(value, dict) or value.get("schema") != PROVIDER_SCHEMA \
            or not keys <= set(value) or not set(value) <= keys | {"guard"}:
        raise HostError("provider_config_invalid")
    if not isinstance(value["provider"], str) or re.fullmatch(r"[a-z][a-z0-9-]{0,31}", value["provider"]) is None:
        raise HostError("provider_config_invalid")
    for key in ("interpreter", "entry", "state", "assets"):
        if not provider_protocol.is_path(value[key]):
            raise HostError("provider_config_invalid")
    assets, state = value["assets"], value["state"]
    if not value["entry"].startswith(assets + "/") or _nested(assets, state):
        raise HostError("provider_config_invalid")
    guard = value.get("guard", {})
    if not isinstance(guard, dict) or not set(guard) <= set(GUARD) \
            or any(type(v) is not int or not GUARD[k][0] <= v <= GUARD[k][1] for k, v in guard.items()):
        raise HostError("provider_config_invalid")
    return value


def check_recorded(value):
    """A tag's, run's or checkpoint's provider: a custom configuration
    (check_provider, its paths used as recorded), or a built-in profile's
    identity and STATE `{"builtin": NAME, "state": STATE}`, its code
    resolved in the running install at each use (builtin.resolve)."""
    if isinstance(value, dict) and "builtin" in value:
        if set(value) != {"builtin", "state"} or value["builtin"] not in BUILTIN_PROVIDERS \
                or not provider_protocol.is_path(value["state"]):
            raise HostError("provider_config_invalid")
        return value
    return check_provider(value)


def recorded_name(value):
    """The provider's name of a recorded provider (check_recorded)."""
    return value["builtin"] if "builtin" in value else value["provider"]


def check_assets(root):
    """The provider's asset tree before an invocation: bounded, no link or
    special file, every entry with installed-code ownership."""
    count = 0

    def check(st):
        if not install_owner(st):
            raise HostError("provider_untrusted")

    try:
        check(os.lstat(root))
        stack = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            if depth > MAX_ASSET_DEPTH:
                raise HostError("provider_untrusted")
            with os.scandir(directory) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_ASSET_ENTRIES:
                        raise HostError("provider_untrusted")
                    st = entry.stat(follow_symlinks=False)
                    check(st)
                    if stat.S_ISDIR(st.st_mode):
                        stack.append((entry.path, depth + 1))
                    elif not stat.S_ISREG(st.st_mode):
                        raise HostError("provider_untrusted")
    except OSError:
        raise HostError("provider_untrusted") from None


def load_provider(path):
    """An operator's provider configuration file."""
    return check_provider(strict_json(read_private(path, MAX_CONFIG_BYTES, "provider_config_unreadable"),
                                      "provider_config_invalid"))


def host_config(explicit, environ):
    """The host configuration (host_tools.rs `HostConfig`): `explicit`
    (which must exist), else the default file, absent allowed."""
    path = explicit
    if path is None:
        xdg, home = environ.get("XDG_CONFIG_HOME"), environ.get("HOME")
        if xdg:
            if not provider_protocol.is_path(xdg):
                raise HostError("host_config_location_invalid")
            path = xdg + "/agentbox/host.json"
        elif home and provider_protocol.is_path(home):
            path = home + "/.config/agentbox/host.json"
        else:
            raise HostError("host_config_location_invalid")
        if not os.path.lexists(path):
            return {}
    value = strict_json(read_private(path, MAX_CONFIG_BYTES, "host_config_unreadable"), "host_config_invalid")
    keys = {"interpreter", "assets", "export_max_bytes", "export_timeout_ms"}
    if not isinstance(value, dict) or value.get("schema") != HOST_SCHEMA or not set(value) <= keys | {"schema"} \
            or any(k in value and not provider_protocol.is_path(value[k]) for k in ("interpreter", "assets")) \
            or any(k in value and (type(value[k]) is not int or not low <= value[k] <= high)
                   for k, (low, high) in (("export_max_bytes", EXPORT_MAX_BYTES),
                                          ("export_timeout_ms", EXPORT_TIMEOUT_MS))):
        raise HostError("host_config_invalid")
    return value


def input_tools(config, default_assets):
    """(interpreter, assets) for the input worker, checked: the
    interpreter an executable regular file, the asset root and its worker
    with installed-code ownership (`host_tools_untrusted`)."""
    interpreter = config.get("interpreter", DEFAULT_INTERPRETER)
    assets = config.get("assets", default_assets)
    try:
        real = os.path.realpath(interpreter, strict=True)
        st = os.stat(real)
        if not stat.S_ISREG(st.st_mode) or not st.st_mode & 0o111:
            raise OSError
        for path in (assets, assets + "/inputs", assets + "/inputs/stage.py"):
            st = os.lstat(path)
            if not install_owner(st) or stat.S_ISLNK(st.st_mode):
                raise OSError
    except OSError:
        raise HostError("host_tools_untrusted") from None
    return interpreter, assets
