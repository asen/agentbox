"""The built-in provider profiles: `image prepare podman|qemu` without
`--provider-config`. The packaged asset tree this controller runs from is
the provider's; its STATE and inputs are the controller's.

```text
STATE_ROOT/              0700: controller config `state_root`, else
                         $XDG_STATE_HOME/agentbox, else ~/.local/state/agentbox;
                         disjoint from DATA, the assets and the old CLI's roots
  podman-shared/         the built-in Podman STATE of each engine store (MODE),
  podman-private/        one per mode, never another's:
    inputs/podman-inputs.json   written here: storage_root ENGINE, no build
                                args, store: MODE (shared: the user's own
                                rootless store,
                                providers/README.md#shared-store-store-shared)
  podman/                the old single Podman STATE: never written here again;
                         the tags, runs and checkpoints recording it resolve to it
                         as ever, its inputs' store theirs
  qemu/                  the built-in QEMU STATE
    inputs/              qemu-build-inputs.json (written last) and its files:
                         base-SHA256.img (the current Ubuntu base, resolved
                         at every prepare), cloud-SHA256SUMS{,.gpg} (its
                         signed manifest), node-vX-linux-x64.tar.xz (the
                         current Node release of the pinned line, resolved
                         at every prepare), node-SHASUMS256.txt{,.sig} (its
                         signed manifest): each verified before reuse, else
                         fetched (fetch.py) and verified first; superseded
                         top-level files removed (an older agents/ directory
                         is left alone)
ENGINE                   0700, controller config `podman_engine_root`, else
                         $XDG_RUNTIME_DIR/agentbox-podman: a private directory on
                         a tmpfs without noexec (Podman's execution stores)
DATA/run-limits.json     made only when absent (link of a complete temp file:
                         never replaced, never broadened): 64 GiB admission over
                         STATE_ROOT (tree; */resources, */work uncapped), ENGINE
                         (filesystem, when available) and DATA/controller-spool
```

MODE: `image prepare podman --store MODE`, else the controller config's
`podman_store`, else shared. A Podman STATE's resources/ and work/ hold
what its user cannot read (a build store, a private retained HOME): an
existing limits file must leave both uncapped (`check_uncapped`), else
the prepare refuses before the provider runs, naming what to add; that
file is the operator's, never changed here.

QEMU's inputs: ASSETS/images/qemu/default/inputs.lock.json
(agentbox.qemu-input-pins.v3). Both are resolved, not pinned, at every
prepare, each from its signed manifest (`resolve_base`, `resolve_node`): `base`, the current
Ubuntu 26.04 amd64 cloud image (SHA256SUMS, its detached signature checked against the
packaged keyring holding only the pinned signer); `node`, the current
release of the pinned Node line (latest-vMAJOR.x/SHASUMS256.txt, its
detached signature by one of the pinned Node releasers, the packaged
keyring holding exactly them). gpgv checks each, a strong digest
(SHA-256/384/512); the file is fetched (bounded, admitted) unless a
verified one of that digest is here. The coding agents are no input: the
canonical build resolves their npm `latest` in the guest
(images/agents/README.md). A `--provider-config` STATE is the operator's:
nothing here writes it.

Identity, not location: a built-in prepare's tag, and the runs and
checkpoints made from it, record `{"builtin": NAME, "state": STATE}`
(`recorded`); every later use (`resolve`) takes the provider's entry,
asset tree and recipe from the running install and the interpreter from
the host configuration, STATE as recorded. Upgrading or moving the
install therefore keeps them; a custom configuration keeps its own
recorded paths, whatever its provider's name.
"""
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile

from . import fetch, host, scopes, states
from .assets import ASSETS as _ASSETS, provider_common, provider_protocol
from .config import (BUILTIN_PROVIDERS, DEFAULT_INTERPRETER, PROVIDER_SCHEMA, check_assets, check_provider,
                     check_recorded, default_state, host_config, legacy_data_dirs, strict_json)
from .host import HostError, capture_host
from .store import SPOOL, _dump

PROVIDERS = BUILTIN_PROVIDERS
# `image prepare --preset NAME`: each provider's canonical recipes by name,
# relative to the asset tree, one directory each (images/PROVIDER/PRESET/;
# images/podman/README.md#presets); `default` when none is named. A
# preset selects image contents only, never the jail's permissions.
PRESETS = {"podman": {"default": "images/podman/default/Dockerfile", "dev": "images/podman/dev/Dockerfile"},
           "qemu": {"default": "images/qemu/default/agentbox.pkr.hcl"}}
QEMU_PINS = "images/qemu/default/inputs.lock.json"
QEMU_PINS_SCHEMA = "agentbox.qemu-input-pins.v3"
# The base's and Node's signed manifests, beside the inputs (replaced at
# every prepare).
BASE_SUMS = "cloud-SHA256SUMS"
BASE_SIGNATURE = "cloud-SHA256SUMS.gpg"
NODE_SUMS = "node-SHASUMS256.txt"
NODE_SIGNATURE = "node-SHASUMS256.txt.sig"
MAX_SUMS_BYTES = 64 << 10
MAX_SIGNATURE_BYTES = 16 << 10
# The base download's cap (the pins' `max_bytes` at most this): staging's
# own (stage.MAX_BASE_BYTES).
MAX_BASE_BYTES = 2 << 30
# Node's: within staging's shared input bound (stage.MAX_INPUT_BYTES).
MAX_NODE_BYTES = 256 << 20
# A Node distribution the manifest lists: node-vMAJOR.MINOR.PATCH-linux-x64,
# stable (no suffix or leading zero; stage.node_version_ok).
NODE_PART = r"(0|[1-9][0-9]{0,4})"
NODE_FILE = re.compile(rf"node-v({NODE_PART}\.{NODE_PART}\.{NODE_PART})-linux-x64\.tar\.xz")
# gpgv's digest algorithm numbers accepted: SHA-256, SHA-384, SHA-512.
STRONG_DIGESTS = ("8", "9", "10")
GPGV_TIMEOUT = 60
SUMS_LINE = re.compile(r"([0-9a-f]{64}) [ *](\S+)")
FINGERPRINT = re.compile(r"[0-9A-F]{40}")
PODMAN_INPUTS = "podman-inputs.json"
PODMAN_INPUTS_SCHEMA = "agentbox.podman-inputs.v1"
QEMU_INPUTS = "qemu-build-inputs.json"
QEMU_INPUTS_SCHEMA = "agentbox.qemu-build-inputs.v1"
# The built-in Podman STATE of each engine store, and the old single one.
PODMAN_STATES = {"shared": "podman-shared", "private": "podman-private"}
LEGACY_PODMAN = "podman"
STATE_DIRS = (LEGACY_PODMAN, *PODMAN_STATES.values(), "qemu")
# What a Podman STATE's walk must tolerate (scopes.py uncapped).
UNREADABLE = ("resources", "work")
ENGINE_NAME = "agentbox-podman"
MAX_ENGINE_ROOT_BYTES = 64
MAX_PINS_BYTES = 64 * 1024
MAX_RESERVED_BYTES = 64 << 30
# Test seams (launch.py overrides): the asset tree and the filesystem
# types accepted for ENGINE.
ASSETS = _ASSETS
ENGINE_FILESYSTEMS = ["tmpfs"]


def hinted(code, hint):
    error = HostError(code)
    error.hint = hint
    return error


def is_builtin(name):
    return name in PROVIDERS


# -- locations --------------------------------------------------------------

def state_root(controller, environ):
    root = controller.get("state_root") or default_state(environ)
    if not provider_protocol.is_path(root):
        raise HostError("state_location_invalid")
    if any(provider_protocol.overlap(root, other) for other in [controller["data"], ASSETS]
           + legacy_data_dirs(environ)):
        raise hinted("state_root_overlaps", "the built-in state root must be apart from the data root, the "
                                            "package and the old CLI's store: set state_root in the controller "
                                            "config")
    return root


def engine_root(controller, environ):
    """(path, configured): Podman's execution-store root."""
    configured = controller.get("podman_engine_root")
    if configured is not None:
        path = configured
    else:
        xdg = environ.get("XDG_RUNTIME_DIR")
        if not xdg or not provider_protocol.is_path(xdg):
            raise hinted("podman_engine_root_unavailable",
                         "XDG_RUNTIME_DIR is unset: set podman_engine_root in the controller config to a private "
                         "directory on a tmpfs mounted without noexec")
        path = f"{xdg}/{ENGINE_NAME}"
    if len(path.encode()) > MAX_ENGINE_ROOT_BYTES:
        raise hinted("podman_engine_root_unavailable",
                     f"the Podman engine root is longer than {MAX_ENGINE_ROOT_BYTES} bytes: set podman_engine_root "
                     "in the controller config")
    return path, configured is not None


def _filesystem_types(fd):
    st = os.fstat(fd)
    device = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    types = set()
    try:
        with open("/proc/self/mountinfo", "rb") as stream:
            for line in stream.read(1 << 22).decode("utf-8", "replace").splitlines():
                fields = line.split(" ")
                if len(fields) > 6 and fields[2] == device and " - " in line:
                    types.add(line.split(" - ", 1)[1].split(" ")[0])
    except OSError:
        pass
    return types


def make_engine(path):
    """ENGINE made (0700) when absent, then checked: ours, private, on an
    accepted tmpfs without noexec."""
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    except OSError:
        raise hinted("podman_engine_root_unavailable",
                     "cannot make the Podman engine root: set podman_engine_root in the controller config to a "
                     "private directory on a tmpfs mounted without noexec") from None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise hinted("podman_engine_root_unsuitable", "the Podman engine root is not a directory") from None
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077 \
                or os.fstatvfs(fd).f_flag & os.ST_NOEXEC \
                or not _filesystem_types(fd) or not _filesystem_types(fd) <= set(ENGINE_FILESYSTEMS):
            raise hinted("podman_engine_root_unsuitable",
                         "the Podman engine root must be a private (0700) directory of yours on a tmpfs mounted "
                         "without noexec: set podman_engine_root in the controller config")
    finally:
        os.close(fd)
    return path


def ensure_dir(path, private=True):
    """A directory of ours, made (0700) with missing parents: private
    (no group/world access), else at least not writable by others."""
    try:
        os.makedirs(path, 0o700, exist_ok=True)
        st = os.lstat(path)
    except OSError:
        raise HostError("builtin_state_unavailable") from None
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() \
            or stat.S_IMODE(st.st_mode) & (0o077 if private else 0o022):
        raise hinted("builtin_state_invalid", "the built-in state directories must be directories of yours, "
                                              "the providers' private (0700)")
    return path


def refresh(controller, environ):
    """Before a command that may admit growth: a declared ENGINE scope
    (the computed one only) made again when its tmpfs lost it (a reboot);
    best effort, never a refusal here."""
    try:
        path, _ = engine_root(controller, environ)
        declared, _ = scopes.read_limits(controller["data"])
    except HostError:
        return
    if any(s["path"] == path for s in declared) and not os.path.lexists(path):
        try:
            make_engine(path)
        except HostError:
            pass


# -- the profile ---------------------------------------------------------------

def check_tree():
    for provider in PROVIDERS:
        if not os.path.isfile(f"{ASSETS}/providers/{provider}.py"):
            raise hinted("builtin_unavailable", "this agentbox has no packaged providers: install a package "
                                                "(packaging/README.md) or pass --provider-config FILE")
    try:
        check_assets(ASSETS)
    except HostError:
        raise hinted("builtin_unavailable",
                     "the built-in profiles need a packaged asset tree owned by you or root "
                     "(packaging/README.md); reinstall or pass --provider-config FILE") from None


def store_mode(provider, flag, custom=False):
    """`--store MODE` checked against its command, before anything is
    made: the built-in Podman profile's alone, `shared` or `private`."""
    if flag is None:
        return None
    if flag not in PODMAN_STATES:
        raise hinted("store_invalid", "--store shared | private")
    if custom:
        raise hinted("store_conflict", "--store selects the built-in Podman profile's STATE; a --provider-config "
                                       "STATE's store is its own inputs'")
    if provider != "podman":
        raise hinted("store_unsupported", "--store is the built-in Podman profile's: agentbox image prepare podman "
                                          "--store shared | private")
    return flag


def config(provider, controller, environ, store=None):
    """The built-in profile's provider configuration (checked); Podman's
    of `store`, else the controller config's, else shared."""
    if not is_builtin(provider):
        raise hinted("provider_unknown", "built-in profiles: podman, qemu; another provider needs "
                                         "--provider-config FILE")
    check_tree()
    root = state_root(controller, environ)
    if provider == "podman":
        return _here(provider, f"{root}/{PODMAN_STATES[store or controller['podman_store']]}", environ)
    return _here(provider, f"{root}/{provider}", environ)


def legacy_podman(controller, environ):
    """The old single Podman STATE's configuration (recovery only)."""
    check_tree()
    return _here("podman", f"{state_root(controller, environ)}/{LEGACY_PODMAN}", environ)


def mode_of(value):
    """A built-in Podman configuration's engine store, by its STATE."""
    return next(m for m, d in PODMAN_STATES.items() if os.path.basename(value["state"]) == d)


def _here(provider, state, environ):
    """`provider`'s configuration in this (checked) install: its packaged
    entry and asset tree, the host configuration's interpreter, STATE as
    given."""
    interpreter = host_config(None, environ).get("interpreter", DEFAULT_INTERPRETER)
    return check_provider({"schema": PROVIDER_SCHEMA, "provider": provider, "interpreter": interpreter,
                           "entry": f"{ASSETS}/providers/{provider}.py", "state": state, "assets": ASSETS})


def recorded(config):
    """What a tag, run or checkpoint records of a built-in configuration:
    the provider's identity and STATE, never this install's paths."""
    return {"builtin": config["provider"], "state": config["state"]}


def resolve(value):
    """A recorded provider's configuration for this invocation: a custom
    one exactly as recorded (never replaced by a built-in, whatever its
    name); a built-in one's code from the running install (_here), its
    recorded STATE kept. An install without trusted packaged providers
    refuses (`builtin_unavailable`): nothing falls back."""
    check_recorded(value)
    if "builtin" not in value:
        return value
    check_tree()
    return _here(value["builtin"], value["state"], dict(capture_host()))


def preset_recipe(provider, preset):
    """`preset`'s canonical recipe of `provider`, relative to the assets:
    `preset_unknown` for a name no provider has, `preset_unsupported` for
    one this provider lacks (`provider_unknown` beyond the built-ins)."""
    if not any(preset in names for names in PRESETS.values()):
        raise hinted("preset_unknown", "presets: " + ", ".join(sorted({n for v in PRESETS.values() for n in v})))
    if not is_builtin(provider):
        raise hinted("provider_unknown", "presets are the built-in providers' recipes: podman, qemu")
    if preset not in PRESETS[provider]:
        raise hinted("preset_unsupported", f"{provider}'s presets: " + ", ".join(sorted(PRESETS[provider])))
    return PRESETS[provider][preset]


def canonical_recipes(provider):
    """Every canonical recipe of `provider`, relative to the assets."""
    return set(PRESETS[provider].values())


def prepare(store, controller, environ, provider, warn, mode=None):
    """Everything a built-in prepare needs before the provider runs: its
    configuration (Podman's of `mode`: config()), STATE and ENGINE made,
    the store's limits bootstrapped (absent only) and covering them, the
    inputs written and verified. Returns the provider configuration."""
    value = config(provider, controller, environ, mode)
    root = state_root(controller, environ)
    ensure_dir(root, private=False)
    state = ensure_dir(value["state"])
    engine = None
    if provider == "podman":
        path, _ = engine_root(controller, environ)
        engine = make_engine(path)
    elif not os.path.lexists(scopes.limits_path(store.path)):
        # Declared at bootstrap when available, for a later Podman prepare;
        # QEMU never needs it: without one the limits just omit it.
        try:
            path, _ = engine_root(controller, environ)
            engine = make_engine(path)
        except HostError:
            engine = None
    if bootstrap_limits(store, root, engine):
        warn(f"agentbox: created {scopes.limits_path(store.path)}: a {MAX_RESERVED_BYTES >> 30} GiB admission limit "
             f"over {root}" + (f", {engine}" if engine else "") + f" and {store.path}/{SPOOL}\n")
    needed = [state] + ([engine] if provider == "podman" else [])
    check_covered(store, needed)
    if provider == "podman":
        check_uncapped(store, state)
    held = states.lease(store, state)
    try:
        if held.pending is not None:
            option = f"--store {mode_of(value)} " if provider == "podman" else ""
            raise hinted("prepare_unsettled", "settle it first: agentbox image recover "
                                              f"{provider} {option}{held.pending['operation']}")
        if provider == "podman":
            provision_podman(state, engine, mode_of(value))
        else:
            provision_qemu(store, state, warn)
    finally:
        held.release()
    return value


def check_covered(store, paths):
    declared, _ = scopes.read_limits(store.path)
    for path in paths:
        if not scopes.covered(declared, path):
            raise hinted("storage_scope_undeclared",
                         f"{scopes.limits_path(store.path)} does not declare {path}: add a storage scope for it "
                         "(an existing file is never changed)")


def _relative(outer, inner):
    if inner == outer:
        return ""
    return inner[len(outer) + 1:] if inner.startswith(outer + "/") else None


def check_uncapped(store, state):
    """STATE/resources and STATE/work left uncapped by the declared limits
    (scopes.py: a strict walk refuses what it cannot read). Each is walked
    by its innermost enclosing tree scope (a nested tree root is walked as
    itself): that scope top-level and uncapped at or above it, no tree
    scope within it (nested trees are strict by rule); real paths both
    sides, as the walk sees them. A filesystem scope walks nothing."""
    declared, _ = scopes.read_limits(store.path)
    real = os.path.realpath(state)
    trees = [(os.path.realpath(s["path"]), s) for s in declared if s["measure"] == "tree"]
    wanted = []
    for name in UNREADABLE:
        path = f"{real}/{name}"
        wanted += [f"{s['path']}: a tree scope within {path}, strict by rule; remove it"
                   for root, s in trees if _relative(path, root)]
        around = [(root, s) for root, s in trees if _relative(root, path) is not None]
        if not around:
            continue
        root, scope = max(around, key=lambda found: len(found[0]))
        rest = _relative(root, path)
        if rest == "" or len(around) > 1:
            wanted.append(f"{scope['path']}: a tree scope measuring {path} strictly (exact or nested: it cannot "
                          f"leave it uncapped); remove it and leave {name} uncapped in an enclosing tree scope")
        elif not any(scopes._under(p, rest) for p in scope.get("uncapped", [])):
            wanted.append(f'"{rest}" in the uncapped list of {scope["path"]}')
    if wanted:
        raise hinted("storage_scope_strict",
                     f"{scopes.limits_path(store.path)} measures {real}'s resources and work strictly (they hold "
                     "files you cannot read): add " + "; ".join(wanted) + " (an existing file is never changed)")


def bootstrap_limits(store, root, engine):
    """DATA/run-limits.json made only when absent: a complete private
    temp file linked to its name (another's file wins, kept as it is).
    True when this call made it."""
    name = scopes.LIMITS_FILE
    if os.path.lexists(scopes.limits_path(store.path)):
        return False
    spool = f"{store.path}/{SPOOL}"
    try:
        os.mkdir(spool, 0o700)
    except FileExistsError:
        pass
    except OSError:
        raise HostError("store_invalid") from None
    declared = [{"path": root, "measure": "tree",
                 "uncapped": [f"{p}/{d}" for p in STATE_DIRS for d in UNREADABLE]}]
    if engine is not None:
        declared.append({"path": engine, "measure": "filesystem"})
    declared.append({"path": spool, "measure": "tree"})
    data = _dump({"max_reserved_bytes": MAX_RESERVED_BYTES, "storage_scopes": declared})
    try:
        provider_common.parse_limits(data)
    except provider_common.Failure:
        raise HostError("storage_limits_invalid") from None
    temp = f".{name}.{secrets.token_hex(8)}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                 dir_fd=store.root)
    try:
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.link(temp, name, src_dir_fd=store.root, dst_dir_fd=store.root, follow_symlinks=False)
        except FileExistsError:
            return False
        os.fsync(store.root)
        return True
    finally:
        try:
            os.unlink(temp, dir_fd=store.root)
        except OSError:
            pass


# -- inputs ------------------------------------------------------------------

def _asset_json(rel, limit=MAX_PINS_BYTES):
    path = f"{ASSETS}/{rel}"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise HostError("builtin_pins_invalid") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise HostError("builtin_pins_invalid")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise HostError("builtin_pins_invalid")
    return strict_json(data, "builtin_pins_invalid")


def _open_private(name, dir_fd, make=True):
    if make:
        try:
            os.mkdir(name, 0o700, dir_fd=dir_fd)
        except FileExistsError:
            pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700:
        os.close(fd)
        raise hinted("builtin_state_invalid", "the built-in state directories must be directories of yours, "
                                              "the providers' private (0700)")
    return fd


def _inputs_dir(state):
    try:
        fd = _open_private(state, None, make=False)
        try:
            return _open_private("inputs", fd)
        finally:
            os.close(fd)
    except OSError:
        raise HostError("builtin_state_unavailable") from None


def _write_json(dir_fd, name, value):
    """`name` holds exactly `value` (atomically replaced when not)."""
    data = (json.dumps(value, indent=1, sort_keys=True) + "\n").encode()
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        try:
            same = os.read(fd, len(data) + 1) == data
        finally:
            os.close(fd)
        if same:
            return
    except FileNotFoundError:
        pass
    temp = f".{name}.{secrets.token_hex(8)}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    try:
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


def provision_podman(state, engine, store="private"):
    fd = _inputs_dir(state)
    try:
        _write_json(fd, PODMAN_INPUTS, {"schema": PODMAN_INPUTS_SCHEMA, "storage_root": engine,
                                        "build_args": {}, "store": store})
    except OSError:
        raise HostError("builtin_inputs_failed") from None
    finally:
        os.close(fd)


def _keyring_path(rel):
    if not isinstance(rel, str) or not rel or rel.startswith("/") or ".." in rel.split("/"):
        raise HostError("builtin_pins_invalid")
    return rel


def _base_spec(entry):
    """The pins' `base`: where and how the current base is resolved."""
    if not isinstance(entry, dict) or set(entry) != {"index", "file", "keyring", "signer", "max_bytes",
                                                      "provenance"} \
            or not all(isinstance(entry[k], str) for k in ("index", "file", "keyring", "signer", "provenance")) \
            or not entry["index"].startswith("https://") or not entry["index"].endswith("/") \
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}", entry["file"]) \
            or FINGERPRINT.fullmatch(entry["signer"]) is None \
            or type(entry["max_bytes"]) is not int or not 0 < entry["max_bytes"] <= MAX_BASE_BYTES:
        raise HostError("builtin_pins_invalid")
    _keyring_path(entry["keyring"])
    return entry


def _node_spec(entry):
    """The pins' `node`: the line (`major`), its signed manifest's
    directory (`index`), the release directories (`dist`), the releasers'
    primary keys (`signers`, exactly the packaged keyring's)."""
    if not isinstance(entry, dict) or set(entry) != {"major", "index", "dist", "keyring", "signers", "max_bytes",
                                                      "provenance"} \
            or type(entry["major"]) is not int or not 24 <= entry["major"] <= 999 \
            or not all(isinstance(entry[k], str) and entry[k].startswith("https://") and entry[k].endswith("/")
                       for k in ("index", "dist")) \
            or not isinstance(entry["signers"], list) or not entry["signers"] \
            or not all(isinstance(f, str) and FINGERPRINT.fullmatch(f) for f in entry["signers"]) \
            or len(set(entry["signers"])) != len(entry["signers"]) or not isinstance(entry["provenance"], str) \
            or type(entry["max_bytes"]) is not int or not 0 < entry["max_bytes"] <= MAX_NODE_BYTES:
        raise HostError("builtin_pins_invalid")
    _keyring_path(entry["keyring"])
    return entry


def qemu_pins():
    """The QEMU inputs' resolutions: (base, node)."""
    value = _asset_json(QEMU_PINS)
    if not isinstance(value, dict) or set(value) != {"schema", "base", "node"} \
            or value["schema"] != QEMU_PINS_SCHEMA:
        raise HostError("builtin_pins_invalid")
    return _base_spec(value["base"]), _node_spec(value["node"])


def provision_qemu(store, state, warn):
    """STATE/inputs: the current base and Node resolved (resolve_base,
    resolve_node), then qemu-build-inputs.json; superseded top-level files
    removed. Each fetch is admitted (its bound as extra) and bounded."""
    spec, node_spec = qemu_pins()
    fd = _inputs_dir(state)
    try:
        try:
            fetch.clean(fd)
        except OSError:
            raise HostError("builtin_state_unavailable") from None
        base = resolve_base(store, state, fd, spec, warn)
        node = resolve_node(store, state, fd, node_spec, warn)
        try:
            _write_json(fd, QEMU_INPUTS, {"schema": QEMU_INPUTS_SCHEMA, "base": base, "node": node})
        except OSError:
            raise HostError("builtin_inputs_failed") from None
        _prune(fd, {QEMU_INPUTS, BASE_SUMS, BASE_SIGNATURE, NODE_SUMS, NODE_SIGNATURE, base["file"], node["file"]})
    finally:
        os.close(fd)


def _admit(store, state, fd, extra):
    st = os.fstatvfs(fd)
    if st.f_bavail * st.f_frsize < extra:
        raise HostError("input_space_insufficient")
    scopes.admit(store, state, lambda: None, extra=extra)


def _signed_sums(state, fd, names, urls, keyring, signers, code, hint, warn):
    """A manifest and its detached signature fetched fresh (bounded) into
    `names`, the signature verified (verify_signature). Returns (the
    manifest's lines, its SHA-256, (signed, signer))."""
    sums_name, signature_name = names
    sums = fetch.fetch(fd, sums_name, [urls[0]], None, None, MAX_SUMS_BYTES, warn)
    fetch.fetch(fd, signature_name, [urls[1]], None, None, MAX_SIGNATURE_BYTES, warn)
    signed = verify_signature(f"{state}/inputs", signature_name, sums_name, keyring, signers, code, hint)
    try:
        with open(sums_name, "rb",
                  opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW, dir_fd=fd)) as stream:
            text = stream.read(MAX_SUMS_BYTES + 1).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise HostError(code) from None
    return [m for m in (SUMS_LINE.fullmatch(line) for line in text.splitlines()) if m is not None], sums, signed


def _signed_file(store, state, fd, name, url, digest, max_bytes, warn, what):
    """`name`, a verified file of the signed `digest`, reused; else fetched
    (bounded by `max_bytes`, admitted) and verified before it gets its
    name. Returns its size."""
    if not fetch.verified(fd, name, fetch.Digest("sha256:" + digest), None):
        _admit(store, state, fd, max_bytes)
        warn(f"agentbox: fetching {what} (sha256 {digest[:16]})\n")
        fetch.fetch(fd, name, [url], fetch.Digest("sha256:" + digest), None, max_bytes, warn)
    return os.stat(name, dir_fd=fd, follow_symlinks=False).st_size


def resolve_base(store, state, fd, spec, warn):
    """The current base: its signed manifest fetched fresh and verified,
    its one entry for `spec`'s file, the image reused or fetched
    (_signed_file). Returns the inputs' `base` entry with its provenance
    (`source`)."""
    lines, sums, (signed, _) = _signed_sums(
        state, fd, (BASE_SUMS, BASE_SIGNATURE), (spec["index"] + "SHA256SUMS", spec["index"] + "SHA256SUMS.gpg"),
        spec["keyring"], [spec["signer"]], "base_signature_invalid",
        f"the Ubuntu cloud image manifest's signature did not verify (signer {spec['signer']}, SHA-256 or stronger)",
        warn)
    found = [m[1] for m in lines if m[2] == spec["file"]]
    if len(found) != 1:
        raise hinted("base_unlisted", f"the signed Ubuntu manifest does not list {spec['file']} exactly once")
    digest = found[0]
    name = f"base-{digest}.img"
    url = spec["index"] + spec["file"]
    size = _signed_file(store, state, fd, name, url, digest, spec["max_bytes"], warn,
                        f"the current Ubuntu base {spec['file']}")
    return {"file": name, "bytes": size, "sha256": digest,
            "source": {"url": url, "sums_sha256": sums, "signer": spec["signer"], "signed": signed}}


def resolve_node(store, state, fd, spec, warn):
    """The current release of the pinned Node line: its signed manifest
    (latest-vMAJOR.x) fetched fresh and verified, listing exactly one
    stable linux-x64 tar.xz of that major; the file, from its own release
    directory (never the moving `latest`), reused or fetched
    (_signed_file). Returns the inputs' `node` entry with its provenance."""
    lines, sums, (signed, signer) = _signed_sums(
        state, fd, (NODE_SUMS, NODE_SIGNATURE), (spec["index"] + "SHASUMS256.txt",
                                                  spec["index"] + "SHASUMS256.txt.sig"),
        spec["keyring"], spec["signers"], "node_signature_invalid",
        "the Node release manifest's signature did not verify (a pinned Node releaser, SHA-256 or stronger)", warn)
    found = [(m[1], n) for m in lines for n in [NODE_FILE.fullmatch(m[2])] if n is not None]
    if len(found) != 1 or int(found[0][1][2]) != spec["major"]:
        raise hinted("node_unlisted", f"the signed Node manifest does not list exactly one stable "
                                      f"Node {spec['major']} linux-x64 tar.xz")
    digest, match = found[0]
    name, version = match[0], match[1]
    url = f"{spec['dist']}v{version}/{name}"
    size = _signed_file(store, state, fd, name, url, digest, spec["max_bytes"], warn, f"Node {version}")
    return {"file": name, "bytes": size, "sha256": digest, "version": version,
            "source": {"url": url, "sums_sha256": sums, "signer": signer, "signed": signed}}


def verify_signature(inputs, signature, sums, keyring, signers, code, hint):
    """gpgv (installed, found on the host PATH) checks `sums`' detached
    `signature` (beneath `inputs`) against the packaged `keyring` in an
    empty private home: every signature valid, by a primary key among
    `signers`, with a strong digest. Returns (the first signature's
    creation time in seconds, its primary key)."""
    try:
        gpgv = host.find_tool("gpgv")
    except HostError:
        raise hinted("gpgv_missing", "the QEMU inputs are verified with gpgv: install GnuPG's gpgv") from None
    keyring = f"{ASSETS}/{keyring}"
    if not os.path.isfile(keyring):
        raise HostError("builtin_pins_invalid")
    with tempfile.TemporaryDirectory(prefix="agentbox-gpgv-") as home:
        try:
            out = subprocess.run([gpgv, "--homedir", home, "--status-fd", "1", "--keyring", keyring,
                                  f"{inputs}/{signature}", f"{inputs}/{sums}"],
                                 env=host.tool_env(), stdin=subprocess.DEVNULL, capture_output=True,
                                 timeout=GPGV_TIMEOUT)
        except (OSError, subprocess.SubprocessError):
            raise HostError(code) from None
    status = out.stdout.decode("utf-8", "replace").splitlines()
    valid = [line.split() for line in status if line.startswith("[GNUPG:] VALIDSIG ")]
    refused = [line for line in status if line.split()[1:2] and line.split()[1] in (
        "BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "NO_PUBKEY")]
    if out.returncode != 0 or refused or not valid or any(
            len(v) != 12 or v[11] not in signers or v[9] not in STRONG_DIGESTS or not v[4].isdigit()
            for v in valid):
        raise hinted(code, hint)
    return int(valid[0][4]), valid[0][11]


def _prune(fd, keep):
    """Superseded top-level regular files of ours removed (an older base,
    Node or manifest); anything else is left."""
    for name in os.listdir(fd):
        if name in keep:
            continue
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid():
                os.unlink(name, dir_fd=fd)
        except OSError:
            pass
