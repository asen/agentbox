"""The rootless Podman jail provider (agentbox.provider v1; stdlib only).

  python3 -I providers/podman.py control STATE
  python3 -I providers/podman.py connect STATE RUN EXECUTION INSTANCE

Linux x86-64, a nonzero effective user. Trusted host code, selected and
started by the host inside a custody domain (common.Custody); README.md
here. The jail is one container of a measured OCI archive in a fresh
private engine store per execution: no network, no published port, no
engine socket, no host share but a mount resource's (below). Its only
channel is `connect`: raw SSH bytes relayed to `podman exec -i ... sshd -i`
with the instance's own engine profile.

The workload account is the resource's (`create.user`, fixed uid/gid
1000, HOME /home/USER): the engine generates its passwd and group entries
(`--passwd-entry`, `--group-entry`; under the read-only root the engine's
own copy of the image's files, bind-mounted read-only), never a root
setup step. The engine adds nothing where the image already has uid or
gid 1000 and never checks names, so the image must be account-free
(`image_accounts`, checked at prepare: uid and gid 1000 unused, an empty
real /home) and `create` refuses a user the image names (`user_conflict`)
before anything exists. Account sources other than the image's
/etc/passwd and /etc/group are unsupported.

Host mounts (`host_mounts`, retained storage only; mounts.rs): a resource
created with `mounts` records them and `mapping` `keep_id`; one without
keeps the default mapping (absent `mapping`). A documented weakening of the
jail: each source, a host directory, is bound at HOME/destination.

  mapping   userns                      HOME volume owner (engine)  jail 1000
  default   rootless default            1000:1000 (host subuid)     subuid
  keep_id   keep-id:uid=1000,gid=1000   0:0 (the invoking user)     the user

Every engine step of the resource (volume registration and removal, init,
destination preparation, create) takes its flags from the recorded
mapping. At create and every start (before the retained HOME is touched,
and again just before `create`): each source path resolved anew (symlinks
followed, never pinned) to an existing directory of the path grammar, on
no pseudo-filesystem, disjoint from the others and from the protected set
read at that moment (`Provider.protected`: the host's run store, the
directory of the limits file it names; every storage scope declared there;
the old CLI's default store roots by the host environment; STATE; the
assets; the storage roots), else its `mount_source_*` code;
an unreadable limits file refuses too, `prerequisite` (`resolve_mounts`).
Between the two, a fixed helper as the workload makes each destination's
missing components (0700) in the retained HOME, refusing a symlink or
non-directory there (`mount_destination_unsafe`; any other helper failure
`failed`) (`prepare_command`). Binds are explicit `ro`/`rw`, nosuid, nodev,
non-recursive and private; nothing is chowned, relabelled or grouped, and
no source is ever removed. The resource's own exclusive lock keeps its
workload away between the helper and `start`; a concurrent host change of
a source path is not excluded. A start below MOUNT_MIN_MEMORY_MIB fails
(`mounts_need_memory`) before anything is allocated (limits arrive only
with `start`).

STATE (0700, the host's choice):

  inputs/podman-inputs.json  agentbox.podman-inputs.v1: storage root, build args,
                             store (private | shared; absent: private)
  images/IMAGE/              0500; IMAGE = SHA-256 of the OCI archive
    image.oci.tar worker-metadata.json record.json   (0400)
                             record: the image's account names (`accounts`);
                             the canonical recipe's `agents` (agent_provenance)
  work/OPERATION/            one prepare's staging and build store
  bindings/INSTANCE          the instance's run, resource and execution
  resources/RESOURCE/        resource.json, lock, volumes/ (retained HOME)
    instances/INSTANCE/      instance.json, owner.lock, admission.lock
                             shared: container.id (the engine's cidfile), diag/
  shared/                    shared store only: containers.conf (the override),
                             mounts.conf (empty), hooks/ (empty)

  STORAGE_ROOT/s-<32 hex>/   one execution's engine store (tmpfs, 0700)

Records are written before the effect they describe; an interrupted effect
is found by its handle and stays blocked (`partial`, `busy`) until an
explicit stop or discard settles it. Process ids are never handles: every
engine process is in the recorded custody child `engine`, killed and
removed by that record.

Shared store (inputs `store` shared, recorded on the resource as
`engine_store` with the host's engine environment; class Shared): the
jail is one container in the user's own initialized rootless store, so
ordinary `podman ps`/`inspect` from the same user see it. Same container
flags (plus SHARED_SANDBOX), the closed container defaults as
CONTAINERS_CONF_OVERRIDE, no hooks or default mounts; retention none or
home (`explicit_retention`), mounts with home only. A retained HOME is one volume in
that store named for the resource (`shared_volume`; the name is its
identity): made by `create` (a name already taken refuses, never
claimed; owned as the recorded mapping needs, keep-id: engine 0),
checked by every start (missing: `retained_home_missing`,
never made again), kept by stop, removed by `discard` alone (`volume rm`,
never forced; already gone counts). Mounts there as in a private store,
the volume's root being HOME: keep-id the one userns flag in place of
SHARED_SANDBOX's; the protected set adds the user's store's own paths,
the engine's static and tmp dirs, its runtime and conmon and the
enumerated configuration candidates (`shared_config_paths`), with their
link chains, read at every resolution (`shared_roots`): enumerated
storage and configuration protection, not a discovery of every runtime
dependency (README.md#shared-mounts, limits); the destinations are
prepared by a transient container recorded and removed by ID like the
workload's (`prepare_shared`, `shared.prepare`, PREPARE_CIDFILE). The
keep-id copy of the image's layers the engine makes in that store is
its own, kept with the image (never removed here). Before every engine invocation, Podman's own rootless helper
must demonstrably run outside Agentbox custody (`shared_helper`; refused:
`shared_store_uninitialized`, nothing run). No engine version is checked:
any Podman whose helper is recognized is used, best effort.
`prepare` loads its measured archive into that store when the image ID is
absent (no tag, pull or replacement); `create` and `start` need that ID
there (`shared_image_missing`) and never load or pull. The container is
named `agentbox-INSTANCE`, labelled with run and instance, its create
intent recorded first and its ID (stdout, the cidfile agreeing) before it
starts. Settling kills the engine child (conmon and the container are in
it, as in a private store), then removes the container by its recorded
ID (or the cidfile's) only; settled once the engine says it is absent.
An intent without any ID is warned residue (it was never started); a
refused preflight or an unconfirmed removal keeps the instance unsettled.
Never a prune, image removal or container name lookup; the helper is
never signalled. A helper's death or replacement after a preflight is not
excluded.

Every control operation and bridge is a child subreaper (Host.subreaper):
what an engine process detaches (pause, conmon, an exec's conmon) is
orphaned to that invocation, never to the host. A settled answer, the
owner's included, and a bridge's end come only after every child of the
invocation is collected (common.settle_children); unconfirmed is
`unsettled`, and an abrupt death leaves them to the host's custody.
"""
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
import posixpath
import re
import selectors
import signal
import stat
import subprocess
import sys
import tarfile
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WORKER_DIR = os.path.join(ROOT, "images", "worker")
sys.dont_write_bytecode = True
for _path in (WORKER_DIR, HERE):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import protocol  # noqa: E402
import common  # noqa: E402
from common import (  # noqa: E402
    Custody, Dir, Failure, Interrupted, Session, Unsettled, diagnostic, fingerprint, hash_fd,
    read_prefix, run_tool, spawn, trusted_executable, trusted_path,
)

PROVIDER = "podman"
RETENTION = ("none", "home", "home_tmp")
# Enforced by the engine child's cgroup; no disk limit is enforceable.
LIMITS = ("cpus", "memory_mib", "pids")
# A selected account (engine-generated), the host's project placement and
# host mounts.
FEATURES = ("select_user", "project_layout", "host_mounts")
GUEST_UID = GUEST_GID = 1000
HOMES = "/home"
# The host store's limits file (Rust run.rs STORE_LIMITS_FILE): its
# directory is the store, protected from every mount.
LIMITS_FILE = "run-limits.json"
# The user namespace mappings of a resource (`mapping`, absent: default).
MAPPINGS = ("default", "keep_id")
# keep-id: the invoking user is the workload uid/gid.
KEEP_ID = f"--userns=keep-id:uid={GUEST_UID},gid={GUEST_GID}"
# Kernel trees no source may be on: by path (devtmpfs) and by type.
PSEUDO_ROOTS = ("/proc", "/sys", "/dev")
PSEUDO_TYPES = frozenset(("proc", "sysfs", "cgroup", "cgroup2", "devtmpfs", "devpts", "debugfs", "tracefs",
                          "securityfs", "bpf", "configfs", "pstore", "efivarfs", "fusectl", "mqueue",
                          "binfmt_misc", "nsfs", "selinuxfs", "smackfs"))
# The image's account files, at most this long each.
MAX_ACCOUNT_FILE = 64 << 10
MAX_ACCOUNTS = 4096
# The layer entries the account facts read (`account_entry`).
ACCOUNT_FACTS = ("etc", "home", "etc/passwd", "etc/group")
IMAGE_INIT = ("/usr/bin/tini", "--", "/usr/bin/sleep", "infinity")
SSHD = "/usr/sbin/sshd"
SSH_PARENT = "/etc"
SSH_DIR = "/etc/agentbox-ssh"
# Retained HOME only: the fresh tmpfs for the execution's launcher.
CONTROL_ROOT = "/run/agentbox-control"
GUEST_PROXY_PORT = 18080
VOLUME = "agentbox-workspace"
HOSTNAME = "agentbox"
# A shared store's retention: `home` only, a named volume in the user's
# store, made by `create` and removed only by `discard`. Its name, derived
# from the resource handle, is its identity (never a pin or a label).
SHARED_RETENTION = ("none", "home")
SHARED_FEATURES = ("select_user", "project_layout", "host_mounts", "explicit_retention")
SHARED_VOLUME_PREFIX = "agentbox-home-"

# Installed engine programs, from the host PATH (common.trusted_executable).
# conmon alone may then come from the engine's own helper directory, where
# some distributions install it off PATH; no other fallback.
PROGRAMS = ("podman", "conmon", "crun")
PROGRAM_FALLBACK = {"conmon": ("/usr/libexec/podman",)}

DEFAULT_CPUS = 2
DEFAULT_MEMORY_MIB = 6144
DEFAULT_PIDS = 1024
MIN_MEMORY_MIB = 1024
# A mount resource's start (keep-id: the image's layers copied once more
# into the execution's store, charged to the engine child): at 1024 MiB it
# was OOM-killed natively; 1536 MiB started and restarted (peaks ~1.2 GiB).
MOUNT_MIN_MEMORY_MIB = 1536
MIN_PIDS = 64
HOME_TMPFS_MIB = 1024
TMP_TMPFS_MIB = 512
RUN_TMPFS_MIB = 16
SHM_MIB = 64
MAX_STORAGE_ROOT_BYTES = 64
OUT_LIMIT = 4096
ADMISSION_WAIT = 5.0
DISPOSE_SECONDS = 30.0
STORE_ENTRIES = 1 << 20
RELAY_CHUNK = 1 << 16
RELAY_FLUSH = 5.0
MAX_PROVISION_FILE = 16 << 10
MAX_JSON_BLOB = 1 << 20
MAX_OUTER_MEMBERS = 64
MAX_METADATA_BYTES = 1 << 20

INPUTS = "podman-inputs.json"
INPUTS_SCHEMA = "agentbox.podman-inputs.v1"
# The engine store of the operator's inputs (`store`, absent: private),
# recorded on each resource (`engine_store`).
STORES = ("private", "shared")
# The rootless helper as recognized (PAUSE_PID, PAUSE_CMDLINE, PAUSE_COMM),
# read from upstream Podman v5.7.0 (pkg/util/utils_linux.go
# GetRootlessPauseProcessPidPath: $XDG_RUNTIME_DIR/libpod/tmp/pause.pid;
# pkg/domain/infra/abi/system_linux.go SetupRootless joins that pid before
# it would make a helper; pkg/rootless/rootless_linux.c do_pause:
# `catatonit -P`, else comm "podman pause"). Not a version gate: another
# version is used when its helper matches, else refused.
# The user's engine environment, as the user's own podman finds its store
# and database; HOME and XDG_RUNTIME_DIR required.
SHARED_ENV = ("HOME", "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "CONTAINERS_CONF",
              "CONTAINERS_STORAGE_CONF")
SHARED_REQUIRED = ("HOME", "XDG_RUNTIME_DIR")
SHARED_DIR = "shared"
PAUSE_PID = "libpod/tmp/pause.pid"
PAUSE_CMDLINE = b"catatonit\0-P\0"
PAUSE_COMM = b"podman pause\n"
MAX_PID_FILE = 32
MAX_PROC_FILE = 4096
CONTAINER_PREFIX = "agentbox-"
LABEL_RUN = "io.agentbox.run"
LABEL_INSTANCE = "io.agentbox.instance"
CIDFILE = "container.id"
# A shared mount start's destination preparation: its own transient
# container (`agentbox-INSTANCE-prepare`) and cidfile.
PREPARE_SUFFIX = "-prepare"
PREPARE_CIDFILE = "prepare.id"
# The user's store's own paths (`shared_roots`): its graph, run and volume
# roots and storage.conf, then the runtime and conmon it runs, one JSON
# array on stdout; with debug logging, stderr names the engine's effective
# static and tmp dirs (libpod's "Using static dir", "Using tmp dir").
SHARED_INFO = ("--format=[{{json .Store.GraphRoot}},{{json .Store.RunRoot}},{{json .Store.VolumePath}},"
               "{{json .Store.ConfigFile}},{{json .Host.OCIRuntime.Path}},{{json .Host.Conmon.Path}}]")
SHARED_INFO_COMMAND = ("info", "--log-level=debug", SHARED_INFO)
MAX_INFO_ERR = 64 << 10
_ENGINE_DIR = re.compile(r'time="[^"\n]*" level=debug msg="Using (static|tmp) dir (/[^"\\\n]*)"\Z')
# The engine's configuration files, rootless (upstream containers/common
# pkg/config systemConfigs: the system file, its drop-ins, the rootless
# file and drop-ins (and the uid's; `containers.rootless.d` too, its
# other spelling, and its uid's), the user's file and drop-ins;
# containers/storage types/options.go: CONTAINERS_STORAGE_CONF, else the
# user's storage.conf, else the system's). Candidates, present or not.
CONTAINERS_CONF_SYSTEM = ("/usr/share/containers/containers.conf", "/etc/containers/containers.conf")
CONTAINERS_ROOTLESS_CONF = "/etc/containers/containers.rootless.conf"
STORAGE_CONF_SYSTEM = ("/usr/share/containers/storage.conf", "/etc/containers/storage.conf")
MAX_DROP_INS = 256
MAX_LINK_HOPS = 40
DIAG = "diag"
# A shared container's flags beyond SANDBOX: the explicit default rootless
# mapping (containers.conf(5) `userns` "host") and no privilege, whatever
# the user's configuration says.
SHARED_SANDBOX = ("--userns=host", "--privileged=false")
SHARED_CODES = ("shared_store_uninitialized", "shared_image_missing")
# CONTAINERS_CONF_OVERRIDE (loaded last; `{append=false}` overrides an
# array whatever an earlier file appended): the private profile's closed
# container defaults plus everything else that adds a host resource or
# identity to a container. Engine, storage and network settings stay the
# user's, so the store, its database and `podman ps` are the user's own.
SHARED_CONF = ('[containers]\nannotations = [{append=false}]\ncgroup_conf = [{append=false}]\n'
               'cgroupns = "private"\ncgroups = "disabled"\ndefault_capabilities = [{append=false}]\n'
               'default_sysctls = [{append=false}]\ndevices = [{append=false}]\nenv = [{append=false}]\n'
               'env_host = false\nhttp_proxy = false\ninit = false\nipcns = "private"\nlog_driver = "none"\n'
               'mounts = [{append=false}]\nnetns = "none"\nno_hosts = true\npidns = "private"\n'
               'privileged = false\nread_only = true\nuserns = "host"\nutsns = "private"\n'
               'volumes = [{append=false}]\n')
SHARED_FILES = (("containers.conf", SHARED_CONF.encode()), ("mounts.conf", b""))
RESOURCE_SCHEMA = "agentbox.podman-resource.v2"
INSTANCE_SCHEMA = "agentbox.podman-instance.v1"
CACHE_SCHEMA = "agentbox.podman-cache.v2"
STAGING_FILES = ("image.oci.tar", "worker-metadata.json", "record.json")
# Admission (not quotas): free space and entries (live plus leftover
# residue) before a prepare's work dir or an execution's store is made.
PREPARE_MIN_FREE = 16 << 30
WORK_RESIDUE = 8
STORE_MIN_FREE = 2 << 30
STORE_RESIDUE = 32
CANONICAL_RECIPE = os.path.join(ROOT, "images", "podman", "default", "Dockerfile")
# The canonical recipes, one per preset (images/podman/PRESET/Dockerfile;
# images/podman/README.md#presets): stage.json's recipe path of each.
CANONICAL_RECIPES = {CANONICAL_RECIPE: "podman/default/Dockerfile",
                     os.path.join(ROOT, "images", "podman", "dev", "Dockerfile"): "podman/dev/Dockerfile"}
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYERS = {"application/vnd.oci.image.layer.v1.tar": None,
              "application/vnd.oci.image.layer.v1.tar+gzip": "gz"}
WORKER_ROOT = "opt/agentbox/worker"
WORKER_METADATA = "opt/agentbox/worker-metadata.json"
# The canonical recipe's agents (images/podman/README.md#agents): AGENT/package.json,
# AGENT/package-lock.json and the installed AGENT/node_modules/PACKAGE/
# package.json, each read bounded from the layer.
AGENTS_ROOT = "opt/agentbox-agents"
MAX_AGENT_FILE = 1 << 20
# Every name a settled or interrupted instance directory may hold.
INSTANCE_FILES = ("instance.json", ".instance.json.tmp", "owner.lock", "admission.lock", "host_ed25519",
                  "host_ed25519.pub", "provision.tar", CIDFILE, PREPARE_CIDFILE)
SECRET_FILES = ("host_ed25519", "host_ed25519.pub", "provision.tar")

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_STORE = re.compile(r"s-[0-9a-f]{32}\Z")
_PID = re.compile(rb"[1-9][0-9]{0,9}\n?\Z")
_UNIT = re.compile(r"agentbox-launch-[0-9a-f]{32}\.scope\Z")
_ARG_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_ARG_VALUE = re.compile(r"[A-Za-z0-9._:/@+=-]{1,512}\Z")
_PRIVATE = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{64,4096}"
                      r"-----END OPENSSH PRIVATE KEY-----\n\Z")


# ---------------------------------------------------------------------------
# The closed engine profiles of one private store.

class Store:
    """One engine store's closed profiles (runtime/podman/engine.rs before
    the cutover). `task`: the execution's (or a build's) engine; `dispose`:
    a fresh profile for one post-kill disposal, its own libpod database,
    locks, pause process and runtime state, sharing only `graph/`."""

    DIRS = ("graph", "run", "run/libpod", "tmp", "static", "volumes", "hooks", "network", "home",
            "home/.config", "home/.config/containers", "xdg-run", "xdg-config", "xdg-data", "xdg-cache",
            "conf", "diag")
    PROFILE_DIRS = ("run", "run/libpod", "tmp", "static", "volumes", "hooks", "network", "home", "home/.config",
                    "home/.config/containers", "xdg-run", "xdg-run/libpod", "xdg-run/libpod/tmp", "xdg-config",
                    "xdg-data", "xdg-cache", "conf")

    def __init__(self, path, programs, volumes=None, build=False, dispose=None, search=None):
        if not protocol.is_path(path) or (volumes is not None and not protocol.is_path(volumes)) \
                or (dispose is not None and not re.fullmatch(r"dispose-[0-9]{1,6}", dispose)):
            raise Failure("failed")
        self.path, self.programs, self.volumes, self.build = path, programs, volumes, build
        self.dispose, self.search = dispose, search

    def at(self, profile, sub):
        if profile == "dispose":
            return f"{self.path}/{self.dispose}/{sub}"
        return f"{self.path}/{sub}"

    def env(self, profile="task"):
        """The complete environment of every engine invocation: no host
        HOME, XDG, proxy, registry, auth or ambient configuration; the
        user bus an absent socket in the store. PATH is the host's
        (`search`, Host.search), for the engine's own lookups (newuidmap,
        its network helpers), which this process cannot pin; none when
        the host gave none."""
        at = lambda sub: self.at(profile, sub)  # noqa: E731
        path = {} if self.search is None else {"PATH": self.search}
        return {**path, "LC_ALL": "C", "HOME": at("home"), "TMPDIR": at("tmp"),
                "XDG_RUNTIME_DIR": at("xdg-run"), "XDG_CONFIG_HOME": at("xdg-config"),
                "XDG_DATA_HOME": at("xdg-data"), "XDG_CACHE_HOME": at("xdg-cache"),
                "CONTAINERS_CONF": at("conf/containers.conf"), "CONTAINERS_STORAGE_CONF": at("conf/storage.conf"),
                "CONTAINERS_REGISTRIES_CONF": at("conf/registries.conf"),
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + at("absent-bus")}

    def global_args(self, profile="task"):
        at = lambda sub: self.at(profile, sub)  # noqa: E731
        args = ["--remote=false", f"--root={self.path}/graph", f"--runroot={at('run')}", "--storage-driver=vfs",
                "--cgroup-manager=cgroupfs", "--events-backend=none", f"--tmpdir={at('run/libpod')}",
                f"--runtime={self.programs['crun']}", f"--conmon={self.programs['conmon']}",
                f"--hooks-dir={at('hooks')}", f"--network-config-dir={at('network')}", "--log-level=error"]
        if profile == "task" and self.volumes is not None:
            args.append(f"--volumepath={self.volumes}")
        return args

    def argv(self, command, profile="task"):
        return [self.programs["podman"]] + self.global_args(profile) + list(command)

    def preflight(self):
        """Nothing: a private store's helpers are its own."""

    def containers_conf(self, profile="task"):
        at = lambda sub: self.at(profile, sub)  # noqa: E731
        engine = (f'[engine]\n{"database_backend = \"sqlite\"\nlock_type = \"file\"\n" if profile == "dispose" else ""}'
                  f'cgroup_manager = "cgroupfs"\nconmon_path = ["{self.programs["conmon"]}"]\n'
                  f'detach_keys = ""\nevents_logger = "none"\nhooks_dir = ["{at("hooks")}"]\n'
                  f'image_copy_tmp_dir = "{at("tmp")}"\nruntime = "agentbox"\nstatic_dir = "{at("static")}"\n'
                  f'tmp_dir = "{at("run/libpod")}"\nvolume_path = "{at("volumes")}"\n\n'
                  f'[engine.runtimes]\nagentbox = ["{self.programs["crun"]}"]\n\n'
                  f'[network]\n{"network_backend = \"netavark\"\n" if profile == "dispose" else ""}'
                  f'network_config_dir = "{at("network")}"\n')
        if self.build and profile == "task":
            # A build's RUN steps keep the engine's default network and
            # capabilities (the recipe's own, trusted needs).
            return ('[containers]\ndevices = []\nenv = []\nenv_host = false\nhttp_proxy = false\n'
                    'volumes = []\n\n' + engine)
        return ('[containers]\ncgroups = "disabled"\ncgroupns = "private"\ndefault_capabilities = []\n'
                'devices = []\nenv = []\nenv_host = false\nhttp_proxy = false\ninit = false\n'
                'ipcns = "private"\nlog_driver = "none"\nnetns = "none"\nno_hosts = true\npidns = "private"\n'
                'read_only = true\nutsns = "private"\nvolumes = []\n\n' + engine)

    def storage_conf(self, profile="task"):
        graph = self.path + "/graph"
        return (f'[storage]\ndriver = "vfs"\ngraphroot = "{graph}"\nrunroot = "{self.at(profile, "run")}"\n'
                f'rootless_storage_path = "{graph}"\n')

    @staticmethod
    def registries_conf():
        return 'unqualified-search-registries = []\nshort-name-mode = "enforcing"\n'

    @staticmethod
    def policy():
        """Explicit, so no host policy.json applies: the archive or recipe
        is the host's selection; signatures play no role."""
        return '{"default":[{"type":"insecureAcceptAnything"}]}\n'

    def files(self, profile="task"):
        """Every configuration file of `profile`, store-relative, with its
        exact bytes. The empty mounts.conf keeps the host's default mounts
        out of every container."""
        base = "" if profile == "task" else self.dispose + "/"
        return [(base + "conf/containers.conf", self.containers_conf(profile).encode()),
                (base + "conf/storage.conf", self.storage_conf(profile).encode()),
                (base + "conf/registries.conf", self.registries_conf().encode()),
                (base + "home/.config/containers/mounts.conf", b""),
                (base + "home/.config/containers/policy.json", self.policy().encode())]

    def prepare(self, store, profile="task"):
        """Creates `profile`'s directories (0700) and configuration files
        (0600, exclusively) beneath the pinned store, never following a
        link."""
        if profile == "task":
            dirs = self.DIRS
        else:
            os.mkdir(self.dispose, 0o700, dir_fd=store.fd)
            dirs = [self.dispose + "/" + d for d in self.PROFILE_DIRS]
        for rel in dirs:
            parent, _, name = rel.rpartition("/")
            with _opened_dir(store, parent) as fd:
                os.mkdir(name, 0o700, dir_fd=fd)
        for rel, data in self.files(profile):
            parent, _, name = rel.rpartition("/")
            with _opened_dir(store, parent) as fd:
                out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                              dir_fd=fd)
                try:
                    os.write(out, data)
                    os.fsync(out)
                finally:
                    os.close(out)

    def matches(self, store, profile="task"):
        """Whether every configuration file of `profile` is exactly ours:
        regular, single-link, this user's, the generated bytes."""
        for rel, data in self.files(profile):
            parent, _, name = rel.rpartition("/")
            try:
                with _opened_dir(store, parent) as fd:
                    out = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                try:
                    st = os.fstat(out)
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid() \
                            or read_prefix(out, len(data) + 1) != data:
                        return False
                finally:
                    os.close(out)
            except OSError:
                return False
        return True


class _opened_dir:
    """A directory `rel` beneath `base` (a Dir), each component opened
    without following a link; the descriptor for a `with` block."""

    def __init__(self, base, rel):
        self.base, self.rel = base, rel

    def __enter__(self):
        fd = os.dup(self.base.fd)
        for part in (self.rel.split("/") if self.rel else ()):
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            finally:
                os.close(fd)
            fd = child
        self.fd = fd
        return fd

    def __exit__(self, *_):
        os.close(self.fd)


# ---------------------------------------------------------------------------
# The user's own rootless store (`store` shared).

class Shared:
    """The user's own rootless engine store: the user's configuration,
    storage and database (ordinary `podman ps` and `inspect` see the jail),
    with SHARED_CONF over it (CONTAINERS_CONF_OVERRIDE), no hooks and no
    default mounts (`conf`'s empty ones), and the cgroupfs manager with
    cgroups disabled, so that conmon and the container stay in the engine
    child (limits, kill) as in a private store. `recorded`: the resource's
    engine environment (`shared_env`); the helper preflight
    (`shared_helper`) reads its XDG_RUNTIME_DIR, the very value the engine
    gets. The engine's runtime and conmon are the user's configured ones."""

    def __init__(self, recorded, podman, conf, search, custody, proc="/proc"):
        self.recorded, self.podman, self.conf = dict(recorded), podman, conf
        self.search, self.custody, self.proc = search, custody, proc

    def env(self, profile="task"):
        path = {} if self.search is None else {"PATH": self.search}
        return {**path, "LC_ALL": "C", **self.recorded, "CONTAINERS_CONF_OVERRIDE": self.conf + "/containers.conf",
                "DBUS_SESSION_BUS_ADDRESS": "unix:path=" + self.conf + "/absent-bus"}

    def global_args(self, profile="task"):
        return ["--remote=false", "--cgroup-manager=cgroupfs", "--events-backend=none",
                f"--hooks-dir={self.conf}/hooks", f"--default-mounts-file={self.conf}/mounts.conf",
                "--log-level=error"]

    def argv(self, command, profile="task"):
        return [self.podman] + self.global_args(profile) + list(command)

    def preflight(self):
        shared_helper(self.recorded.get("XDG_RUNTIME_DIR"), self.custody, self.proc)


def shared_env(environ):
    """The engine environment of a shared store from the host's (empty
    values unset): SHARED_ENV's paths, HOME and XDG_RUNTIME_DIR required;
    else `shared_store_uninitialized`."""
    found = {}
    for name in SHARED_ENV:
        value = environ.get(name)
        if value:
            found[name] = value
    if not recorded_env(found):
        diagnostic("shared store: needs HOME and XDG_RUNTIME_DIR (absolute paths)")
        raise Failure("shared_store_uninitialized")
    return found


def recorded_env(value):
    return isinstance(value, dict) and set(value) <= set(SHARED_ENV) and all(k in value for k in SHARED_REQUIRED) \
        and all(protocol.is_path(v) for v in value.values())


def _within(inner, outer):
    return inner == outer or inner.startswith(outer + "/")


def _proc_read(fd, name):
    out = os.open(name, os.O_RDONLY | os.O_CLOEXEC, dir_fd=fd)
    try:
        return os.read(out, MAX_PROC_FILE + 1)
    finally:
        os.close(out)


def shared_helper(runtime_dir, custody, proc="/proc"):
    """Podman's rootless helper (its pause process) demonstrably running
    for `runtime_dir`, outside Agentbox custody: the pid file at PAUSE_PID
    (ours, regular, a pid), naming a live process of ours (/proc/PID, read
    through one directory descriptor) that is the helper (PAUSE_CMDLINE or
    PAUSE_COMM), in another user namespace than this process, and in a
    cgroup neither in nor beneath `custody`'s domain or its launch unit, nor
    beneath any `agentbox-launch-*.scope`. Anything missing, ambiguous or
    mismatched refuses `shared_store_uninitialized`, a fixed diagnostic;
    nothing is run, signalled or made. A helper's death or replacement
    after this check is not excluded."""
    def refuse(why):
        diagnostic(f"shared store: {why}")
        return Failure("shared_store_uninitialized")

    if not protocol.is_path(runtime_dir):
        raise refuse("no runtime directory")
    try:
        fd = os.open(f"{runtime_dir}/{PAUSE_PID}", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        raise refuse("no rootless helper pid file: run a rootless podman command first "
                     "(still refused: this podman's helper is not recognized)") from None
    try:
        st = os.fstat(fd)
        data = os.read(fd, MAX_PID_FILE + 1) if stat.S_ISREG(st.st_mode) else b""
    finally:
        os.close(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or _PID.match(data) is None:
        raise refuse("helper pid file unusable")
    try:
        pfd = os.open(f"{proc}/{int(data)}", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError:
        raise refuse("helper not running") from None
    try:
        if os.fstat(pfd).st_uid != os.geteuid():
            raise refuse("helper not this user's")
        if _proc_read(pfd, "cmdline") != PAUSE_CMDLINE and _proc_read(pfd, "comm") != PAUSE_COMM:
            raise refuse("pid file names no recognized helper")
        if os.readlink("ns/user", dir_fd=pfd) == os.readlink(f"{proc}/self/ns/user"):
            raise refuse("helper in this user namespace")
        lines = _proc_read(pfd, "cgroup").decode("ascii").split("\n")
        if len(lines) != 2 or lines[1] != "" or not lines[0].startswith("0::/"):
            raise refuse("helper cgroup unknown")
        rel = lines[0][3:]
        where = common.CGROUP_ROOT + rel
        if any(_within(where, outer) for outer in (custody.path, os.path.dirname(custody.path))) \
                or any(_UNIT.match(part) for part in rel.split("/")):
            raise refuse("helper inside agentbox custody")
    except (OSError, UnicodeDecodeError):
        raise refuse("helper unreadable") from None
    finally:
        os.close(pfd)


def container_name(instance):
    return CONTAINER_PREFIX + instance


def shared_flags(mapping):
    """SHARED_SANDBOX under `mapping`: exactly one userns flag, the
    explicit default mapping or keep-id (`userns_flags`, already in the
    command) in its place."""
    if mapping not in MAPPINGS:
        raise Failure("failed")
    return [w for w in SHARED_SANDBOX if mapping == "default" or not w.startswith("--userns=")]


def shared_names(run, instance, cidfile, suffix=""):
    """A shared container's name and labels (never a handle: removal is by
    the recorded ID only) and its cidfile."""
    if not protocol.is_id(run) or not protocol.is_id(instance) or not protocol.is_path(cidfile):
        raise Failure("failed")
    return [f"--name={container_name(instance)}{suffix}", f"--label={LABEL_RUN}={run}",
            f"--label={LABEL_INSTANCE}={instance}", f"--cidfile={cidfile}"]


def shared_create_command(image_id, user, run, instance, cidfile, volume=None, mapping="default", binds=()):
    """`create_command` (retention none) in the user's store: `mapping`'s
    SHARED_SANDBOX (`shared_flags`), a recognizable name and labels and
    the instance's cidfile (`shared_names`). With `volume` (retention
    `home`), that volume's root is HOME instead of the tmpfs; /tmp stays a
    tmpfs. `binds` (`bind_flags`) only with `volume`."""
    words = create_command(image_id, "none", user, mapping)
    names = shared_names(run, instance, cidfile)
    if binds and volume is None:
        raise Failure("failed")
    home = guest_home(user)
    if volume is not None:
        shared_volume_create(run, volume)
        at = next(i for i, w in enumerate(words) if w.startswith(f"--mount=type=tmpfs,destination={home},"))
        words[at] = f"--mount=type=volume,source={volume},destination={home},rw,exec,nosuid,nodev"
    at = words.index(f"--entrypoint={IMAGE_INIT[0]}")
    return words[:at] + bind_flags(home, binds) + shared_flags(mapping) + names + words[at:]


def shared_prepare_command(image_id, user, mapping, destinations, run, instance, cidfile, volume):
    """`prepare_command` as a transient container of the user's store:
    `create` (never `run --rm`: its ID is recorded and it is removed by
    that ID), `mapping`'s SHARED_SANDBOX, the HOME volume's root at HOME
    (its only mount: no host share), named `agentbox-INSTANCE-prepare`,
    labelled, its own cidfile; run by `start --attach`."""
    shared_volume_create(run, volume)
    home = guest_home(user)
    words = prepare_command(image_id, user, mapping, destinations)
    names = shared_names(run, instance, cidfile, PREPARE_SUFFIX)
    words[words.index(f"--mount=type=volume,source={VOLUME},destination={home},subpath=/home,rw,noexec,nosuid,"
                      "nodev")] = f"--mount=type=volume,source={volume},destination={home},rw,noexec,nosuid,nodev"
    at = words.index("--entrypoint=/bin/sh")
    return ["create"] + words[2:at] + shared_flags(mapping) + names + words[at:]


def shared_roots(engine_env, status, out, err, uid=None):
    """What no mount source may meet in a shared store, each path with its
    link chain (`link_chain`), read now: from its `info` (SHARED_INFO_COMMAND:
    `status`, stdout `out`, stderr `err`) the graph, run and volume roots,
    storage.conf, the static and tmp dirs (exactly one value each in the
    debug lines), the OCI runtime and conmon; from the recorded
    `engine_env` (what the engine gets) its runtime directory and every
    configuration candidate (`shared_config_paths`). A configuration file
    or program sealed by root (`root_sealed`) is left out: nothing in the
    jail can change it. Anything unclear or unreadable refuses
    (`prerequisite`), never a smaller set."""
    try:
        found = json.loads(out) if status == 0 else None
    except ValueError:
        found = None
    engine = {}
    for line in err.decode("utf-8", "replace").splitlines():
        match = _ENGINE_DIR.match(line)
        if match is not None and engine.setdefault(match.group(1), match.group(2)) != match.group(2):
            engine = None
            break
    if not isinstance(found, list) or len(found) != 6 or not all(protocol.is_path(p) for p in found) \
            or engine is None or set(engine) != {"static", "tmp"} \
            or not all(protocol.is_path(p) for p in engine.values()):
        diagnostic("shared store: its storage paths are unreadable")
        raise Failure("prerequisite")
    store = found[:3] + [engine["static"], engine["tmp"], engine_env["XDG_RUNTIME_DIR"]]
    roots = []
    try:
        sealable = found[3:] + shared_config_paths(engine_env, os.getuid() if uid is None else uid)
        for path in store:
            roots += link_chain(path)
        for path in sealable:
            roots += [p for p in link_chain(path) if not root_sealed(p)]
    except OSError:
        diagnostic("shared store: its configuration is unreadable")
        raise Failure("prerequisite") from None
    return list(dict.fromkeys(roots))


def shared_config_paths(engine_env, uid):
    """The engine's configuration candidates under `engine_env`, present or
    not: CONTAINERS_CONF, CONTAINERS_STORAGE_CONF (when set), the system,
    rootless and user containers.conf files and drop-in directories (the
    rootless `containers.rootless.conf.d` and `containers.rootless.d`, each
    with its `uid` child) with each `.conf` entry in them, storage.conf
    (user's, system's), the user's containers configuration directory.
    Read now; an unreadable or oversized drop-in directory raises OSError.
    Enumerated candidates, not Podman's whole configuration logic."""
    config = (engine_env.get("XDG_CONFIG_HOME") or engine_env["HOME"] + "/.config") + "/containers"
    paths = [engine_env[k] for k in ("CONTAINERS_CONF", "CONTAINERS_STORAGE_CONF") if k in engine_env]
    paths += [config, config + "/storage.conf", *STORAGE_CONF_SYSTEM]
    files = (*CONTAINERS_CONF_SYSTEM, CONTAINERS_ROOTLESS_CONF, config + "/containers.conf")
    paths += files
    rootless = (CONTAINERS_ROOTLESS_CONF + ".d", os.path.dirname(CONTAINERS_ROOTLESS_CONF) + "/containers.rootless.d")
    drop_ins = [f + ".d" for f in files if f != CONTAINERS_ROOTLESS_CONF] \
        + [d for base in rootless for d in (base, f"{base}/{int(uid)}")]
    for directory in drop_ins:
        paths.append(directory)
        try:
            names = os.listdir(directory)
        except (FileNotFoundError, NotADirectoryError):
            continue
        if len(names) > MAX_DROP_INS:
            raise OSError(errno.E2BIG, directory)
        paths += [f"{directory}/{n}" for n in sorted(names) if n.endswith(".conf")]
    return paths


def link_chain(path):
    """`path` lexically, every symbolic link met resolving it (its own
    location) and where it resolves (missing components kept lexically),
    each normalized: a mount meeting any one could change what the engine
    reads there. More than MAX_LINK_HOPS links, or a component that cannot
    be read, raises OSError."""
    chain = [os.path.normpath(path)]
    todo = [p for p in path.split("/") if p][::-1]
    at, hops = "/", 0
    while todo:
        part = todo.pop()
        if part == ".":
            continue
        if part == "..":
            at = os.path.dirname(at)
            continue
        step = os.path.join(at, part)
        try:
            target = os.readlink(step)
        except OSError as error:
            if error.errno not in (errno.EINVAL, errno.ENOENT, errno.ENOTDIR):
                raise
            at = step
            continue
        hops += 1
        if hops > MAX_LINK_HOPS:
            raise OSError(errno.ELOOP, path)
        chain.append(step)
        if target.startswith("/"):
            at = "/"
        todo += [p for p in target.split("/") if p][::-1]
    chain.append(at)
    return list(dict.fromkeys(chain))


def root_sealed(path):
    """Whether `path` (else its nearest existing ancestor) and every
    directory above it are root's and neither group nor world writable (a
    link: root's): no uid the jail maps can change what it names."""
    while True:
        try:
            os.lstat(path)
            break
        except (FileNotFoundError, NotADirectoryError):
            path = os.path.dirname(path)
    while True:
        st = os.lstat(path)
        if st.st_uid != 0 or (not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022):
            return False
        if path == "/":
            return True
        path = os.path.dirname(path)


def shared_volume(resource):
    """The resource's retained HOME volume name in the user's store."""
    if not protocol.is_id(resource):
        raise Failure("failed")
    return SHARED_VOLUME_PREFIX + resource


def shared_volume_create(run, volume, mapping="default"):
    """`volume create` of a shared resource's HOME: owned by the engine
    uid/gid that is the workload's under `mapping` (default 1000, keep-id
    0: the invoking user), no copy-up; labelled with its run for the
    user's own `podman volume ls` (never checked)."""
    if not protocol.is_id(run) or not isinstance(volume, str) or not volume.startswith(SHARED_VOLUME_PREFIX) \
            or not protocol.is_id(volume[len(SHARED_VOLUME_PREFIX):]) or mapping not in MAPPINGS:
        raise Failure("failed")
    owner = 0 if mapping == "keep_id" else GUEST_UID
    return ["volume", "create", "--driver=local", f"--uid={owner}", f"--gid={owner}", "--opt=nocopy",
            f"--label={LABEL_RUN}={run}", volume]


def created_id(status, out):
    """The container ID a `create` printed (exactly one line), else
    `failed`."""
    if status != 0 or len(out) != 65 or not out.endswith(b"\n") or not _HEX64.match(out[:64].decode("ascii",
                                                                                                     "replace")):
        raise Failure("failed")
    return out[:64].decode()


def read_cidfile(idir, name=CIDFILE):
    """The instance's cidfile `name`'s container ID (the engine's own
    write), or None when absent or not exactly one ID."""
    try:
        fd = idir.open_file(name)
    except OSError:
        return None
    try:
        data = os.read(fd, 80)
    finally:
        os.close(fd)
    text = data.decode("ascii", "replace")
    text = text[:-1] if text.endswith("\n") else text
    return text if _HEX64.match(text) else None


def clear_diag(idir, strict=False):
    """The instance's engine outputs (`diag/`, regular files only) removed;
    best effort unless `strict`."""
    try:
        diag = idir.sub(DIAG)
        if diag is None:
            return
        try:
            for name in diag.names(256):
                os.unlink(name, dir_fd=diag.fd)
        finally:
            diag.close()
        idir.rmdir(DIAG)
    except (OSError, Failure):
        if strict:
            raise OSError(errno.EIO, "diag")
        common.warning("instance engine outputs left")


SANDBOX = ("--pull=never", "--read-only", "--read-only-tmpfs=false", "--network=none", "--no-hosts",
           "--cgroups=disabled", "--cgroupns=private", "--ipc=private", "--pid=private", "--uts=private",
           f"--hostname={HOSTNAME}", "--cap-drop=all", "--security-opt=no-new-privileges", "--init=false",
           "--systemd=false", "--http-proxy=false", "--unsetenv-all", "--image-volume=ignore",
           "--log-driver=none", "--no-healthcheck", "--sdnotify=ignore", "--umask=0077")


def guest_home(user):
    """A workload account's HOME."""
    return f"{HOMES}/{user}"


def mapping_of(record):
    """A resource's recorded mapping: `keep_id` with mounts, else default."""
    mapping = record.get("mapping", "default")
    if mapping not in MAPPINGS:
        raise Failure("failed")
    return mapping


def userns_flags(mapping):
    """The engine flags of `mapping`: none for the default."""
    if mapping not in MAPPINGS:
        raise Failure("failed")
    return [KEEP_ID] if mapping == "keep_id" else []


def volume_create(mapping):
    """`volume create` (registration, no copy) of the resource's volume: its
    directory owned by the engine uid/gid that is the workload's under
    `mapping` (keep-id: engine 0, the invoking user)."""
    owner = 0 if mapping == "keep_id" else GUEST_UID
    return ["volume", "create", "--driver=local", f"--uid={owner}", f"--gid={owner}", "--opt=nocopy", VOLUME]


def bind_flags(home, binds):
    """`--mount` of each (resolved source, destination, access): explicit
    access, nosuid, nodev, private and non-recursive; exec kept. Paths are
    the protocol's path grammar, so no option delimiter can appear."""
    flags = []
    for source, destination, access in binds:
        target = f"{home}/{destination}"
        if access not in protocol.ACCESS or not protocol.is_path(source) or not protocol.is_path(target):
            raise Failure("failed")
        flags.append(f"--mount=type=bind,source={source},destination={target},{access},nosuid,nodev,"
                     "bind-propagation=private,bind-nonrecursive")
    return flags


def account_flags(user):
    """The engine-generated account `user`: uid/gid 1000, its HOME,
    /bin/sh; one group of its name (`image_accounts` keeps both free)."""
    return [f"--passwd-entry={user}:x:{GUEST_UID}:{GUEST_GID}:{user}:{guest_home(user)}:/bin/sh",
            f"--group-entry={user}:x:{GUEST_GID}:"]


def create_command(image_id, retention, user, mapping="default", binds=()):
    """`podman create` of exactly `image_id`: never pulled, read-only, no
    network, cgroups or capabilities, no new privileges, the fixed uid/gid,
    the account `user` generated by the engine (`account_flags`), init,
    command, environment and tmpfs; every image default (volume,
    entrypoint, user, environment, healthcheck) overridden or ignored; no
    host share (but `binds`), log or init binary. HOME is /home/USER; a retained one is
    the volume's `home` subpath (and `/tmp` its `tmp` with `home_tmp`),
    never its root; the launcher's tmpfs is CONTROL_ROOT whatever the
    retention (`started` `control`). `mapping` the resource's (`userns_flags`);
    `binds` its resolved mounts (`bind_flags`), never with retention none."""
    if not _HEX64.match(image_id) or retention not in RETENTION or not protocol.is_user(user) \
            or (binds and retention == "none"):
        raise Failure("failed")
    home = guest_home(user)
    tmpfs_tmp = f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={TMP_TMPFS_MIB}m,mode=1777"
    control = (f"--mount=type=tmpfs,destination={CONTROL_ROOT},rw,exec,nosuid,nodev,"
               f"tmpfs-size={HOME_TMPFS_MIB}m,tmpfs-mode=0700,U=true")
    if retention == "none":
        mounts = [control, f"--mount=type=tmpfs,destination={home},rw,exec,nosuid,nodev,"
                  f"tmpfs-size={HOME_TMPFS_MIB}m,tmpfs-mode=0700,U=true", tmpfs_tmp]
    else:
        mounts = [control,
                  f"--mount=type=volume,source={VOLUME},destination={home},subpath=/home,rw,exec,nosuid,nodev",
                  f"--mount=type=volume,source={VOLUME},destination=/tmp,subpath=/tmp,rw,noexec,nosuid,nodev"
                  if retention == "home_tmp" else tmpfs_tmp]
    mounts.append(f"--tmpfs=/run:rw,noexec,nosuid,nodev,size={RUN_TMPFS_MIB}m,mode=0755")
    # Writable, the container's own (`--read-only-tmpfs=false` leaves the
    # engine's /dev/shm read-only): an agent `run`'s interactive staging.
    mounts.append(f"--mount=type=tmpfs,destination=/dev/shm,rw,noexec,nosuid,nodev,"
                  f"tmpfs-size={SHM_MIB}m,tmpfs-mode=1777")
    mounts += bind_flags(home, binds)
    return (["create"] + list(SANDBOX) + userns_flags(mapping)
            + [f"--user={GUEST_UID}:{GUEST_GID}", f"--workdir={home}", f"--env=HOME={home}",
               f"--env=USER={user}", "--env=PATH=/usr/local/bin:/usr/bin:/bin", "--env=LC_ALL=C"]
            + account_flags(user) + mounts + [f"--entrypoint={IMAGE_INIT[0]}", image_id] + list(IMAGE_INIT[1:]))


def init_command(image_id, retention, user, mapping="default"):
    """The first allocation's closed initialization: the image's /bin/sh
    as the workload uid (the account `user`, `mapping`'s userns) on the
    volume's root (at the account's HOME), a fixed script making its `home`
    (and `tmp`) subpaths."""
    if not _HEX64.match(image_id) or retention not in ("home", "home_tmp") or not protocol.is_user(user):
        raise Failure("failed")
    home = guest_home(user)
    script = f"mkdir -p -m 0700 {home}/home"
    if retention == "home_tmp":
        script += f" && mkdir -p -m 1777 {home}/tmp"
    return (["run", "--rm"] + list(SANDBOX) + userns_flags(mapping)
            + [f"--user={GUEST_UID}:{GUEST_GID}", "--workdir=/", "--env=PATH=/usr/bin:/bin", "--env=LC_ALL=C"]
            + account_flags(user)
            + [f"--mount=type=volume,source={VOLUME},destination={home},rw,noexec,nosuid,nodev",
               "--entrypoint=/bin/sh", image_id, "-c", script])


# Every destination's components from HOME: a symlink or a non-directory
# refuses (exit 3, PREPARE_UNSAFE); a missing one is made 0700 by the
# workload, its failure exit 4.
PREPARE_UNSAFE = 3
PREPARE_SCRIPT = """set -euf
umask 077
home=$1
shift
for destination in "$@"; do
  at=$home
  IFS=/
  for part in $destination; do
    at=$at/$part
    if [ -L "$at" ]; then exit 3; fi
    if [ ! -e "$at" ]; then mkdir -m 0700 "$at" || exit 4; fi
    if [ -L "$at" ] || [ ! -d "$at" ]; then exit 3; fi
  done
  unset IFS
done
"""


def prepare_command(image_id, user, mapping, destinations):
    """Every start's destination preparation in the retained HOME (the
    volume's `home` subpath at the account's HOME, `mapping`'s userns, the
    workload's uid and account): `PREPARE_SCRIPT` with HOME and each
    destination (`protocol.is_mount_destination`) as its arguments, never in its
    text."""
    if not _HEX64.match(image_id) or not protocol.is_user(user) or not destinations \
            or not all(protocol.is_mount_destination(d) for d in destinations):
        raise Failure("failed")
    home = guest_home(user)
    return (["run", "--rm"] + list(SANDBOX) + userns_flags(mapping)
            + [f"--user={GUEST_UID}:{GUEST_GID}", "--workdir=/", "--env=PATH=/usr/bin:/bin", "--env=LC_ALL=C"]
            + account_flags(user)
            + [f"--mount=type=volume,source={VOLUME},destination={home},subpath=/home,rw,noexec,nosuid,nodev",
               "--entrypoint=/bin/sh", image_id, "-c", PREPARE_SCRIPT, "sh", home] + list(destinations))


def filesystem_types(fd):
    """The mountinfo types of open `fd`'s device; empty when unknown."""
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
        return set()
    return types


def _ids(path):
    """(dev, ino) of `path` and each ancestor, `/` last; empty when any is
    missing."""
    ids = []
    while True:
        try:
            st = os.stat(path)
        except OSError:
            return []
        ids.append((st.st_dev, st.st_ino))
        if path == "/":
            return ids
        path = os.path.dirname(path)


def _meets(a, b):
    """Chains `a` and `b` (`_ids`): one path is the other or its ancestor
    by identity; `/` counts only as itself."""
    return bool(a and b) and (a[0] in b[:-1] or b[0] in a[:-1] or a[0] == b[0])


def resolve_mounts(mounts, protected, types=filesystem_types):
    """[(resolved source, destination, access)] of the recorded `mounts`:
    each source path resolved now (symlinks followed) to an existing
    directory of the path grammar, on no pseudo-filesystem, disjoint from
    the others' and from every `protected` root (resolved path, and the
    bounded (dev, ino) chains). Anything else: its `mount_source_*` code,
    with a fixed diagnostic."""
    guarded = []
    for root in protected:
        try:
            real = os.path.realpath(root, strict=True)
        except OSError:
            real = root
        guarded.append((real, _ids(real)))
    binds = []
    for mount in mounts:
        try:
            real = os.path.realpath(mount["source"], strict=True)
            fd = os.open(real, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            diagnostic("mount source unavailable")
            raise Failure("mount_source_unavailable") from None
        try:
            kinds = types(fd)
        finally:
            os.close(fd)
        if not protocol.is_path(real) or any(protocol.overlap(real, r) for r in PSEUDO_ROOTS) \
                or not kinds or kinds & PSEUDO_TYPES:
            diagnostic("mount source unsupported")
            raise Failure("mount_source_unsupported")
        chain = _ids(real)
        if any(protocol.overlap(real, root) or _meets(chain, ids) for root, ids in guarded):
            diagnostic("mount source protected")
            raise Failure("mount_source_protected")
        if any(protocol.overlap(real, other) for other, _, _ in binds):
            diagnostic("mount sources overlap")
            raise Failure("mount_source_overlap")
        binds.append((real, mount["destination"], mount["access"]))
    return binds


VOLUME_REMOVE = ("volume", "rm", VOLUME)
DISPOSE = ("rmi", "--all", "--force")


def exec_command(container):
    """The bridge: the container's sshd on stdin/stdout as the workload
    user; no TTY, no detach keys, no environment."""
    if not _HEX64.match(container):
        raise Failure("failed")
    return ["exec", "-i", "--tty=false", "--detach-keys=", f"--user={GUEST_UID}:{GUEST_GID}", container, SSHD,
            "-i", "-f", SSH_DIR + "/sshd_config"]


def sshd_config(user):
    """Same-user (`user`), public key only, no PAM, agent, X11, tunnel or
    local forward; only the session's remote forward of loopback
    GUEST_PROXY_PORT; internal-sftp. A PTY only on request: `agentbox
    shell`'s interactive login; executions request none."""
    if not protocol.is_user(user):
        raise Failure("failed")
    return (f"HostKey {SSH_DIR}/ssh_host_ed25519_key\nAuthorizedKeysFile {SSH_DIR}/authorized_keys\n"
            "HostKeyAlgorithms ssh-ed25519\nPubkeyAcceptedAlgorithms ssh-ed25519\nPidFile none\nUsePAM no\n"
            f"StrictModes yes\nAllowUsers {user}\nPermitRootLogin no\nPubkeyAuthentication yes\n"
            "PasswordAuthentication no\nKbdInteractiveAuthentication no\nHostbasedAuthentication no\n"
            "GSSAPIAuthentication no\nPermitEmptyPasswords no\nPermitUserEnvironment no\nPermitUserRC no\n"
            "PermitTTY yes\nPermitTunnel no\nX11Forwarding no\nAllowAgentForwarding no\n"
            "AllowStreamLocalForwarding no\nAllowTcpForwarding remote\nGatewayPorts no\n"
            f"PermitListen 127.0.0.1:{GUEST_PROXY_PORT}\nPermitOpen none\nClientAliveInterval 5\n"
            "ClientAliveCountMax 3\nLogLevel QUIET\nSubsystem sftp internal-sftp\n")


def provisioning_tar(host_private, authorized_key, user):
    """The fixed tar `podman cp --archive=false` places in SSH_PARENT:
    `agentbox-ssh/` (root, 0755), its sshd_config (root, 0644), the guest
    host key (workload, 0600) and the host's public client key (workload,
    0400). Never a client private key."""
    if not 0 < len(host_private) <= MAX_PROVISION_FILE or not 0 < len(authorized_key) <= MAX_PROVISION_FILE:
        raise Failure("failed")
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for name, perm, owner, data in (("agentbox-ssh", 0o755, 0, None),
                                        ("agentbox-ssh/sshd_config", 0o644, 0, sshd_config(user).encode()),
                                        ("agentbox-ssh/ssh_host_ed25519_key", 0o600, GUEST_UID, host_private),
                                        ("agentbox-ssh/authorized_keys", 0o400, GUEST_UID, authorized_key)):
            info = tarfile.TarInfo(name)
            info.mode, info.uid, info.gid, info.mtime = perm, owner, owner, 0
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def limits_of(request_limits):
    """(cpus, memory_mib, pids) with defaults; the engine child's limits
    bound everything: engine, container, tmpfs and the store's pages."""
    cpus = request_limits.get("cpus", DEFAULT_CPUS)
    memory = request_limits.get("memory_mib", DEFAULT_MEMORY_MIB)
    pids = request_limits.get("pids", DEFAULT_PIDS)
    if "disk_mib" in request_limits:
        raise Failure("unsupported")
    if memory < MIN_MEMORY_MIB or pids < MIN_PIDS:
        raise Failure("failed")
    return cpus, memory, pids


def engine_limits(cpus, memory_mib, pids):
    return {"cpu.max": f"{cpus * 100000} 100000", "memory.max": str(memory_mib << 20),
            "memory.swap.max": "0", "pids.max": str(pids)}


def bare_key(text):
    parts = text.strip().split(" ")
    if len(parts) not in (2, 3):
        raise Failure("failed")
    key = parts[0] + " " + parts[1]
    try:
        protocol._ssh_key(key)
    except protocol.ProtocolError:
        raise Failure("failed") from None
    return key


# ---------------------------------------------------------------------------
# Directories reached safely from `/` (store.rs safe_dir before the cutover).

def _ancestor_ok(st, anchored):
    if not stat.S_ISDIR(st.st_mode):
        return False
    mode = stat.S_IMODE(st.st_mode)
    if anchored[0]:
        return st.st_uid == os.geteuid() and not mode & 0o077
    if st.st_uid == 0 and mode & stat.S_ISVTX:
        anchored[0] = True
        return True
    return st.st_uid in (0, os.geteuid()) and not mode & 0o022


def safe_dir(path):
    """`path` opened from `/` one component at a time without following a
    link: every ancestor root's or ours and unwritable by others, except a
    root-owned sticky anchor below which everything is ours and private;
    the directory itself ours and private. Returns a Dir."""
    if not protocol.is_path(path) or path == "/":
        raise Failure("prerequisite")
    anchored = [False]
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        if not _ancestor_ok(os.fstat(fd), anchored):
            raise Failure("prerequisite")
        parts = path[1:].split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            if not _ancestor_ok(os.fstat(fd), anchored):
                raise Failure("prerequisite")
        child = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
    except OSError:
        raise Failure("prerequisite") from None
    finally:
        os.close(fd)
    st = os.fstat(child)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        os.close(child)
        raise Failure("prerequisite")
    return Dir(child, path)


def identity(st):
    return [st.st_dev, st.st_ino]


Budget = common.Budget
clear_tree = common.clear_tree


# ---------------------------------------------------------------------------
# The measured OCI archive: index, manifest, config, one squashed layer.

def _object(value):
    if not isinstance(value, dict):
        raise Failure("failed")
    return value


def _digest_hex(value):
    if not isinstance(value, str) or not value.startswith("sha256:") or not _HEX64.match(value[7:]):
        raise Failure("failed")
    return value[7:]


class Archive:
    """`podman save --format=oci-archive` output, read through the pinned
    descriptor that was hashed: one manifest, its config and exactly one
    layer, every blob checked against its digest."""

    def __init__(self, fd, check):
        self.check = check
        self.stream = os.fdopen(os.dup(fd), "rb")
        self.stream.seek(0)
        try:
            self.tar = tarfile.open(fileobj=self.stream, mode="r:")
        except tarfile.TarError:
            self.stream.close()
            raise Failure("failed") from None
        self.members = {}
        try:
            for count, info in enumerate(self.tar):
                name = info.name[2:] if info.name.startswith("./") else info.name
                if count >= MAX_OUTER_MEMBERS:
                    raise Failure("failed")
                if info.isdir() and name.rstrip("/") in ("blobs", "blobs/sha256"):
                    continue
                if not info.isreg() or name in self.members:
                    raise Failure("failed")
                self.members[name] = info
        except tarfile.TarError:
            self.close()
            raise Failure("failed") from None

    def close(self):
        self.tar.close()
        self.stream.close()

    def member(self, name):
        info = self.members.get(name)
        if info is None:
            raise Failure("failed")
        return info

    def blob(self, digest):
        return self.member("blobs/sha256/" + _digest_hex(digest))

    def read_json(self, info, digest=None):
        if info.size > MAX_JSON_BLOB:
            raise Failure("failed")
        data = self.tar.extractfile(info).read(MAX_JSON_BLOB + 1)
        if digest is not None and hashlib.sha256(data).hexdigest() != _digest_hex(digest):
            raise Failure("failed")
        try:
            return json.loads(data)
        except ValueError:
            raise Failure("failed") from None

    def hash(self, stream):
        digest = hashlib.sha256()
        while True:
            self.check()
            data = stream.read(common.CHUNK)
            if not data:
                return digest.hexdigest()
            digest.update(data)

    def names(self):
        """The reference names the archive's index gives its manifests
        (`org.opencontainers.image.ref.name`): what a load would tag."""
        index = _object(self.read_json(self.member("index.json")))
        manifests = index.get("manifests")
        if not isinstance(manifests, list):
            raise Failure("failed")
        found = []
        for manifest in manifests:
            annotations = _object(manifest).get("annotations") or {}
            if "org.opencontainers.image.ref.name" in _object(annotations):
                found.append(annotations["org.opencontainers.image.ref.name"])
        return found

    def inspect(self):
        """{image_id, layer: {info, compression}}: the image id is the
        config blob's digest, as the engine names a loaded image."""
        if _object(self.read_json(self.member("oci-layout"))).get("imageLayoutVersion") != "1.0.0":
            raise Failure("failed")
        index = _object(self.read_json(self.member("index.json")))
        manifests = index.get("manifests")
        if index.get("schemaVersion") != 2 or not isinstance(manifests, list) or len(manifests) != 1 \
                or _object(manifests[0]).get("mediaType") != OCI_MANIFEST:
            raise Failure("failed")
        manifest = _object(self.read_json(self.blob(manifests[0].get("digest")), manifests[0]["digest"]))
        config_ref = _object(manifest.get("config"))
        layers = manifest.get("layers")
        if manifest.get("schemaVersion") != 2 or config_ref.get("mediaType") != OCI_CONFIG \
                or not isinstance(layers, list) or len(layers) != 1 \
                or _object(layers[0]).get("mediaType") not in OCI_LAYERS:
            raise Failure("failed")
        config = _object(self.read_json(self.blob(config_ref.get("digest")), config_ref["digest"]))
        rootfs = _object(config.get("rootfs"))
        if config.get("architecture") != "amd64" or config.get("os") != "linux" \
                or rootfs.get("type") != "layers" or not isinstance(rootfs.get("diff_ids"), list) \
                or len(rootfs["diff_ids"]) != 1:
            raise Failure("failed")
        layer = self.blob(layers[0].get("digest"))
        compression = OCI_LAYERS[layers[0]["mediaType"]]
        if layer.size != layers[0].get("size") \
                or self.hash(self.tar.extractfile(layer)) != _digest_hex(layers[0]["digest"]):
            raise Failure("failed")
        diff_id = _digest_hex(rootfs["diff_ids"][0])
        if compression is None:
            uncompressed = _digest_hex(layers[0]["digest"])
        else:
            with gzip.GzipFile(fileobj=self.tar.extractfile(layer)) as stream:
                try:
                    uncompressed = self.hash(stream)
                except (OSError, EOFError):
                    raise Failure("failed") from None
        if uncompressed != diff_id:
            raise Failure("failed")
        return {"image_id": _digest_hex(config_ref["digest"]), "layer": layer, "compression": compression,
                "layer_digest": _digest_hex(layers[0]["digest"]), "diff_id": diff_id}

    def baked_worker(self, layer, compression, out, agents=False):
        """Copies the layer's baked bundle (WORKER_ROOT) and its metadata
        into the new directory `out` exactly: root-owned, sealed modes,
        regular files and directories only, no whiteout anywhere. In the
        same pass, the account facts (`image_accounts`): `etc`, `home`,
        `etc/passwd` and `etc/group` read bounded, never extracted, and
        anything beneath `home`; with `agents`, the agents' files
        (`agent_files`), root's, not group or other writable, read bounded,
        each reached only through its ancestors' own entries (`opt` down),
        each once, a root-owned directory not group or other writable, and
        no other spelling of any of those paths (`./`, a trailing `/` are
        the tar conventions). Returns the metadata bytes, the bundle's
        directories, the account names and {agent file: bytes}; the caller
        validates the copy."""
        worker = _worker()
        limits = worker.LIMITS
        os.mkdir(out, 0o700)
        bundle = os.path.join(out, "worker")
        seen, dirs, metadata, total = set(), set(), None, 0
        accounts = {"etc": None, "home": None, "etc/passwd": None, "etc/group": None, "beneath": False}
        wanted, found = (agent_files() if agents else set()), {}
        ancestry, walked = {a for name in wanted for a in _ancestors(name)}, set()
        mode = "r|gz" if compression == "gz" else "r|"
        try:
            with tarfile.open(fileobj=self.tar.extractfile(layer), mode=mode) as tar:
                while True:
                    self.check()
                    info = tar.next()
                    if info is None:
                        break
                    tar.members.clear()
                    name = info.name[2:] if info.name.startswith("./") else info.name
                    name = name.rstrip("/")
                    if os.path.basename(name).startswith(".wh."):
                        raise Failure("failed")
                    if name in ACCOUNT_FACTS:
                        if accounts[name] is not None:
                            raise Failure("failed")
                        accounts[name] = account_entry(name, info, tar)
                        continue
                    if name.startswith(HOMES[1:] + "/"):
                        accounts["beneath"] = True
                        continue
                    if wanted and (name.startswith("/") or posixpath.normpath(name) != name) \
                            and _agent_path(posixpath.normpath(name.lstrip("/")), wanted, ancestry):
                        raise Failure("failed")
                    if name in ancestry:
                        if name in walked or not info.isdir() or info.uid != 0 or info.gid != 0 \
                                or info.mode & 0o022:
                            raise Failure("failed")
                        walked.add(name)
                        if name != "opt":
                            continue
                    if name in wanted:
                        if name in found or not info.isreg() or info.uid != 0 or info.gid != 0 \
                                or info.mode & 0o022 or info.size > MAX_AGENT_FILE:
                            raise Failure("failed")
                        found[name] = tar.extractfile(info).read(MAX_AGENT_FILE + 1)
                        if len(found[name]) != info.size:
                            raise Failure("failed")
                        continue
                    if name in ("opt", "opt/agentbox"):
                        if not info.isdir() or info.uid != 0 or info.mode & 0o022 or name in seen:
                            raise Failure("failed")
                        seen.add(name)
                        continue
                    if name != WORKER_METADATA and name != WORKER_ROOT and not name.startswith(WORKER_ROOT + "/"):
                        continue
                    if name in seen or info.uid != 0 or info.gid != 0 or len(seen) > 2 * limits["max_files"] + 4:
                        raise Failure("failed")
                    seen.add(name)
                    if name == WORKER_METADATA:
                        if not info.isreg() or info.mode != 0o444 or info.size > MAX_METADATA_BYTES:
                            raise Failure("failed")
                        metadata = tar.extractfile(info).read(MAX_METADATA_BYTES + 1)
                        continue
                    rel = name[len(WORKER_ROOT) + 1:]
                    if info.isdir():
                        if info.mode != worker.mode(rel, "dir"):
                            raise Failure("failed")
                        dirs.add(rel)
                        os.makedirs(os.path.join(bundle, rel) if rel else bundle, 0o700, exist_ok=True)
                    elif info.isreg():
                        total += info.size
                        if info.mode != worker.mode(rel, "file") or info.size > limits["max_file_bytes"] \
                                or total > limits["max_total_bytes"] + limits["max_manifest_bytes"]:
                            raise Failure("failed")
                        path = os.path.join(bundle, rel)
                        os.makedirs(os.path.dirname(path), 0o700, exist_ok=True)
                        source = tar.extractfile(info)
                        with open(path, "xb") as target:
                            while True:
                                data = source.read(common.CHUNK)
                                if not data:
                                    break
                                target.write(data)
                    else:
                        raise Failure("failed")
        except (tarfile.TarError, EOFError, OSError, zlib.error):
            raise Failure("failed") from None
        if metadata is None or len(metadata) > MAX_METADATA_BYTES or seen & {"opt", "opt/agentbox"} \
                != {"opt", "opt/agentbox"} or any(a not in walked for name in found for a in _ancestors(name)):
            raise Failure("failed")
        return metadata, dirs, image_accounts(accounts), found


def _ancestors(name):
    """`name`'s ancestor directories, `opt` first."""
    parts = name.split("/")
    return ["/".join(parts[:n]) for n in range(1, len(parts))]


def _agent_path(name, wanted, ancestry):
    """Whether `name` is, or lies beneath, a path the agents' files are
    reached through."""
    return name in wanted or name in ancestry or name.startswith(AGENTS_ROOT + "/")


def _agentlock():
    import agentlock
    return agentlock


def agent_files():
    """The layer names `agent_provenance` reads."""
    agentlock = _agentlock()
    return {f"{AGENTS_ROOT}/{agent}/{name}" for agent in agentlock.AGENTS
            for name in agentlock.LOCK_FILES + (f"node_modules/{agentlock.PACKAGES[agent]}/package.json",)}


def agent_provenance(files):
    """The canonical recipe's agents, from the layer's `files`
    (`agent_files`): each lock checked as the build checked it (agentlock:
    the agent's own package, registry tarballs only) and the installed
    package exactly its version. {agent: {package, version, lock_sha256}};
    anything missing or else `failed`."""
    agentlock = _agentlock()
    out = {}
    for agent in agentlock.AGENTS:
        base, package = f"{AGENTS_ROOT}/{agent}", agentlock.PACKAGES[agent]
        try:
            lock = files[f"{base}/package-lock.json"]
            (_, version), _ = agentlock.check(files[f"{base}/package.json"], lock, agentlock.REGISTRY, package)
            installed = json.loads(files[f"{base}/node_modules/{package}/package.json"])
        except (KeyError, ValueError, agentlock.Refused):
            raise Failure("failed") from None
        if not isinstance(installed, dict) or installed.get("name") != package or installed.get("version") != version:
            raise Failure("failed")
        out[agent] = {"package": package, "version": version, "lock_sha256": hashlib.sha256(lock).hexdigest()}
    return out


def account_entry(name, info, tar):
    """One account fact of the layer: `etc` and `home` root-owned
    directories, not group or other writable; `etc/passwd` and `etc/group`
    root-owned regular files, not group or other writable, at most
    MAX_ACCOUNT_FILE (their bytes). A link or anything else is
    unsupported."""
    owned = info.uid == 0 and info.gid == 0 and not info.mode & 0o022
    if name in ("etc", "home"):
        if not info.isdir() or not owned:
            raise Failure("unsupported")
        return True
    if not info.isreg() or not owned or info.size > MAX_ACCOUNT_FILE:
        raise Failure("unsupported")
    data = tar.extractfile(info).read(MAX_ACCOUNT_FILE + 1)
    if len(data) != info.size:
        raise Failure("failed")
    return data


def _account_lines(data, fields):
    """`data`'s lines, each exactly `fields` `:`-separated fields, its
    first a nonempty name and its third a decimal id; anything else (a
    `+`/`-` NIS line, a comment, a blank line) unsupported."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Failure("unsupported") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    out = []
    for line in lines:
        parts = line.split(":")
        if len(parts) != fields or not parts[0] or parts[0][0] in "+-#" \
                or not parts[2].isascii() or not parts[2].isdigit() or len(parts[2]) > 10:
            raise Failure("unsupported")
        out.append(parts)
    return out


def image_accounts(found):
    """The image's account names (users, groups and group members, sorted)
    from one layer's facts (`account_entry`). Account-free for the
    workload: `etc` and a real empty `home` present, uid 1000 in no passwd
    entry and gid 1000 in no group entry; else `unsupported`, a diagnostic
    naming the rule."""
    if not found["etc"] or not found["home"] or found["beneath"] \
            or found["etc/passwd"] is None or found["etc/group"] is None:
        diagnostic("image accounts: needs /etc/passwd, /etc/group and an empty /home")
        raise Failure("unsupported")
    names = set()
    for parts in _account_lines(found["etc/passwd"], 7):
        if int(parts[2]) == GUEST_UID:
            diagnostic("image accounts: uid 1000 is taken")
            raise Failure("unsupported")
        names.add(parts[0])
    for parts in _account_lines(found["etc/group"], 4):
        if int(parts[2]) == GUEST_GID:
            diagnostic("image accounts: gid 1000 is taken")
            raise Failure("unsupported")
        names.add(parts[0])
        names.update(member for member in parts[3].split(",") if member)
    if len(names) > MAX_ACCOUNTS or any(len(name) > 256 for name in names):
        raise Failure("unsupported")
    return sorted(names)


def account_names(value):
    """A recorded `accounts`: sorted distinct strings, as `image_accounts`
    returns."""
    return isinstance(value, list) and len(value) <= MAX_ACCOUNTS \
        and all(isinstance(name, str) and 0 < len(name) <= 256 for name in value) \
        and value == sorted(set(value))


def _worker():
    import worker
    return worker


# ---------------------------------------------------------------------------
# Host effects.

class Host:
    """Production effects: trusted installed programs, the custody domain,
    the storage root's filesystem, staging. Tests substitute their own
    subclass; there is no switch that weakens a check here."""

    def __init__(self, environ=None):
        self.environ = os.environ if environ is None else environ
        self._custody = None
        self._tools = {}

    def tool(self, name):
        """Resolved once per invocation; the same path for every use."""
        if name not in self._tools:
            self._tools[name] = trusted_executable(name, self.environ, PROGRAM_FALLBACK.get(name, ()))
        return self._tools[name]

    def search(self):
        """The engine's own PATH (common.host_search)."""
        return common.host_search(self.environ)

    def tool_env(self):
        """The whole environment of a directly run tool (common.tool_env)."""
        return common.tool_env(self.environ)

    def programs(self):
        return {name: self.tool(name) for name in PROGRAMS}

    def custody(self):
        if self._custody is None:
            self._custody = Custody.from_environment(self.environ)
        return self._custody

    def growth(self, *dirs):
        """Before a NEW allocation: each opened directory a new entry is
        made in (STATE, work, images, resources, checkpoints, instances, an
        external store root) lies in a declared storage scope by actual
        filesystem membership (common.require_scopes). Never asked for
        disposal."""
        common.require_scopes(self.environ, *dirs)

    def allocation(self, *pairs):
        """Each (`parent`, `name`) subdirectory, the existing ones checked
        before any absent one is made (common.allocation_dirs); every
        `parent` checked by the caller."""
        return common.allocation_dirs(self.environ, *pairs)

    def rootless(self):
        if not sys.platform.startswith("linux") or os.uname().machine != "x86_64" or os.geteuid() == 0:
            raise Failure("prerequisite")

    def storage_root(self, path):
        """The admitted storage root: a safe private directory (safe_dir)
        on a tmpfs mounted without noexec (the store's pages are charged to
        the engine child's memory.max; its graph executes)."""
        if len(path.encode()) > MAX_STORAGE_ROOT_BYTES:
            raise Failure("prerequisite")
        root = safe_dir(path)
        if not self.executable_tmpfs(root.fd):
            root.close()
            raise Failure("prerequisite")
        return root

    def executable_tmpfs(self, fd):
        if os.fstatvfs(fd).f_flag & os.ST_NOEXEC:
            return False
        return filesystem_types(fd) == {"tmpfs"}

    def mount_sources(self, mounts, protected):
        """The resolved binds of `mounts` (`resolve_mounts`); a test seam."""
        return resolve_mounts(mounts, protected)

    def proc(self):
        """The process table the shared helper is checked in; a test seam."""
        return "/proc"

    def sync(self):
        os.sync()

    def admitted(self):
        """A bridge holds the shared admission lock and has seen `live`;
        it spawns next. Nothing here in production (a test seam)."""

    def subreaper(self):
        """Before any effect, every control operation and bridge becomes a
        child subreaper (common.subreaper): what its engine processes detach
        (pause, conmon, an exec's conmon) stays its own descendant until it
        reaps it, never the host's."""
        common.subreaper()

    def stage(self, repo, out):
        import stage
        return stage.stage_podman(repo, out)


class Deadline:
    """A cleanup's own bounded session: no control input can interrupt it;
    only its deadline does (run_tool's `session`)."""

    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def remaining(self):
        return max(0.0, self.deadline - time.monotonic())

    def check(self):
        if time.monotonic() >= self.deadline:
            raise Interrupted("timeout")

    def wait(self, fds=(), timeout=None):
        selector = selectors.DefaultSelector()
        try:
            for fd in fds:
                selector.register(fd, selectors.EVENT_READ)
            limit = self.remaining() if timeout is None else min(timeout, self.remaining())
            events = selector.select(limit) if fds else (time.sleep(limit) or [])
        finally:
            selector.close()
        return [key.fd for key, _ in events]


class Engine:
    """One private store's engine: every call's process joins the same
    recorded custody child and stays there, with whatever it leaves
    behind (pause process, conmon, the container; orphaned to this
    subreaper), until `settle`. A call
    ends at its leader's exit (pidfd), never at a pipe's end: stdout and
    stderr are regular files in the store's diag/, read back bounded."""

    def __init__(self, session, store, child, diag, profile="task"):
        self.session, self.store, self.child, self.diag, self.profile = session, store, child, diag, profile
        self.leaders = []
        self.calls = 0

    def call(self, kind, command, stdin=None, out_limit=OUT_LIMIT, err_limit=None):
        """(exit status, stdout prefix) of one closed call; with `out_limit`
        None its stdout is not read (b""). With `err_limit`, (status,
        stdout, stderr), stderr empty when longer than that."""
        # A shared store: its helper checked before each engine process.
        self.store.preflight()
        self.calls += 1
        name = f"{self.calls:02d}-{kind}"
        out = self.diag.create(name + ".out")
        try:
            err = self.diag.create(name + ".err")
            try:
                process = spawn(self.store.argv(command, self.profile), self.store.env(self.profile), self.child,
                                stdout=out, stderr=err,
                                stdin=stdin if stdin is not None else subprocess.DEVNULL)
            finally:
                os.close(err)
        finally:
            os.close(out)
        self.leaders.append(process)
        if not process.admitted:
            # Started but not watchable: its child settles it.
            raise Failure("failed")
        while process.poll() is None:
            self.session.check()
            self.session.wait([process.pidfd], timeout=1.0)
        self.leaders.remove(process)
        process.close()
        if out_limit is None:
            return process.status, b""
        fd = self.diag.open_file(name + ".out")
        try:
            data = read_prefix(fd, out_limit + 1)
        finally:
            os.close(fd)
        if len(data) > out_limit:
            raise Failure("failed")
        if err_limit is None:
            return process.status, data
        fd = self.diag.open_file(name + ".err")
        try:
            err = read_prefix(fd, err_limit + 1)
        finally:
            os.close(fd)
        return process.status, data, err if len(err) <= err_limit else b""

    def settle(self, deadline):
        """Kills every member through the pinned child, waits for it to read
        empty, removes it, then reaps every unreaped leader: True only when
        all of that is confirmed."""
        try:
            settled = self.child.settle(deadline)
        except Exception:  # noqa: BLE001 - any doubt is unconfirmed
            settled = False
        for process in list(self.leaders):
            if process.reap(max(deadline, time.monotonic() + common.SETTLE_POLL)) is not None:
                self.leaders.remove(process)
                process.close()
            else:
                settled = False
        return settled


# ---------------------------------------------------------------------------
# The provider.

def _failed(request, error):
    return {"type": "failed", "operation": request["operation"], "op": request["type"],
            "code": error.code, "settlement": error.settlement, "durability": error.durability}


def instance_result(record, inst, clean):
    """What an ended instance did to its resource's storage: unchanged
    unless a retained volume was mounted by anything that ran."""
    generation = inst["generation"]
    if inst["retention"] == "none" or not inst.get("volume_used"):
        return {"durability": "unchanged", "storage": record["storage"], "generation": generation}
    if clean:
        return {"durability": "retained", "storage": "clean", "generation": generation + 1}
    return {"durability": "uncertain", "storage": "unclean", "generation": generation + 1}


class Provider:
    def __init__(self, state, host, session):
        self.state, self.host, self.session = state, host, session
        self._root = None
        self.request = None
        self.scratch = None
        self.tools_run = 0

    @property
    def root(self):
        if self._root is None:
            self._root = Dir.root(self.state)
        return self._root

    def handle(self, request):
        self.request = request
        kind = request["type"]
        self.session.begin(request["operation"], request["timeout_ms"])
        try:
            if kind in protocol.OPTIONAL_OPERATIONS:
                raise Failure("unsupported")
            self.host.subreaper()
            answer = getattr(self, "op_" + kind)(request)
        except Interrupted as error:
            if error.reason == "lost":
                return 0
            answer = _failed(request, Failure(error.code))
        except Failure as error:
            answer = _failed(request, error)
        except (OSError, ValueError, KeyError, TypeError) as error:
            diagnostic(f"{kind}: {type(error).__name__}")
            durability = "uncertain" if kind in protocol.LOST_UNCERTAIN else "unchanged"
            answer = _failed(request, Failure("failed", "unknown", durability))
        if answer is not None and (answer["type"] != "failed" or answer["settlement"] == "settled"):
            # A settled answer needs every child collected first (the owner
            # gates its own answers in teardown), within the operation's own
            # cleanup bound, never a fresh one. Unconfirmed: what the
            # operation recorded stays, the answer says unsettled.
            if not common.settle_children(self.session.cleanup_deadline()):
                diagnostic(f"{kind}: adopted children unconfirmed")
                answer = _failed(request, Failure("failed", "unsettled", "uncertain"))
        if answer is not None:
            self.session.send(answer)
        return 0

    # Tools and inputs.

    def tool(self, name, args, out_limit=1 << 20, ledger=None, env=None, session=None, log=None, err_sink=None):
        if ledger is None and self.scratch is not None:
            ledger = self.scratch
        self.tools_run += 1
        child = f"tool-{self.request['operation']}-{self.tools_run}"
        program = args.pop(0) if name is None else self.host.tool(name)
        env = self.host.tool_env() if env is None else env
        return run_tool(session or self.session, self.host.custody(), child, [program] + args, env,
                        out_limit=out_limit, ledger=ledger, log=log, err_sink=err_sink,
                        durability="unchanged" if type(ledger) is common.Ledger else "uncertain")

    def inputs(self):
        """The operator's inputs: {storage_root, build_args, store}, closed;
        `store` absent is private."""
        inputs = self.root.sub("inputs", modes=(0o700, 0o500))
        if inputs is None:
            raise Failure("prerequisite")
        try:
            value = inputs.read_json(INPUTS)
        except Failure:
            raise Failure("prerequisite") from None
        finally:
            inputs.close()
        if not isinstance(value, dict) or set(value) - {"store"} != {"schema", "storage_root", "build_args"} \
                or value.setdefault("store", "private") not in STORES \
                or value["schema"] != INPUTS_SCHEMA or not protocol.is_path(value["storage_root"]) \
                or not isinstance(value["build_args"], dict) or len(value["build_args"]) > 16 \
                or not all(isinstance(k, str) and _ARG_NAME.match(k) and isinstance(v, str) and _ARG_VALUE.match(v)
                           for k, v in value["build_args"].items()):
            raise Failure("prerequisite")
        return value

    # Images.

    def image(self, image, full, pin=False):
        """The cached image `image` checked: record, modes, fingerprint;
        with `full` the archive's digest and the worker metadata. Returns
        {image_id, worker, accounts, fd (pinned, with `pin`)}."""
        try:
            images = self.root.sub("images")
            entry = images.sub(image, modes=(0o500,)) if images is not None else None
        except Failure:
            raise Failure("failed") from None
        if entry is None:
            raise Failure("not_found")
        fd = -1
        try:
            record = entry.read_json("record.json")
            if record is None or record.get("schema") != CACHE_SCHEMA or record.get("image") != image \
                    or not _HEX64.match(record.get("image_id", "")) or not account_names(record.get("accounts")):
                raise Failure("failed")
            fd = entry.open_file("image.oci.tar", mode=0o400)
            if fingerprint(os.fstat(fd)) != record["fingerprint"]:
                raise Failure("failed")
            if full:
                if hash_fd(fd, self.session.check, record["bytes"]) != image:
                    raise Failure("failed")
                worker = _worker()
                try:
                    worker.check_metadata(entry.join("worker-metadata.json"), record["worker"])
                except (worker.Refused, OSError):
                    raise Failure("failed") from None
            found = {"image_id": record["image_id"], "worker": record["worker"], "accounts": record["accounts"],
                     "fd": -1}
            if pin:
                found["fd"], fd = fd, -1
            return found
        except (OSError, KeyError, TypeError):
            raise Failure("failed") from None
        finally:
            if fd >= 0:
                os.close(fd)
            entry.close()

    def protected(self, *storage_roots):
        """What no mount source may equal, lie in or contain, read now at
        every resolution (never a saved set): the host's run store (the
        directory of the limits file the host names, `common.SCOPES_ENV`),
        every storage scope it declares, the old CLI's default store roots
        (`common.legacy_store_roots` of the host environment: whichever
        store asked, the other path's store stays out of reach), STATE, the
        assets tree (the entry within it) and the engine storage roots. A
        missing or malformed limits path or file, an absent one included,
        refuses (`prerequisite`), never a smaller set."""
        limits = self.host.environ.get(common.SCOPES_ENV)
        if not protocol.is_path(limits) or os.path.basename(limits) != LIMITS_FILE:
            raise Failure("prerequisite")
        scopes = common.storage_scopes(self.host.environ, required=True)
        roots = [os.path.dirname(limits), self.state, ROOT, *storage_roots] + [s["path"] for s in scopes] \
            + common.legacy_store_roots(self.host.environ)
        return [path for path in roots if path]

    # The user's own store (`store` shared).

    def shared_conf(self, create=True):
        """STATE/shared (0700): SHARED_FILES (0600, exact bytes) and an
        empty hooks/ (0700), made when absent (`create`), then checked.
        Its path."""
        shared = self.root.sub(SHARED_DIR, create=create)
        if shared is None:
            raise Failure("failed")
        try:
            hooks = shared.sub("hooks", create=create)
            if hooks is None:
                raise Failure("failed")
            try:
                if hooks.names(1):
                    raise Failure("failed")
            finally:
                hooks.close()
            for name, data in SHARED_FILES:
                if create and not shared.exists(name):
                    temp = f".{name}.{os.urandom(8).hex()}"
                    fd = shared.create(temp)
                    try:
                        os.write(fd, data)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    try:
                        os.link(temp, name, src_dir_fd=shared.fd, dst_dir_fd=shared.fd, follow_symlinks=False)
                    except FileExistsError:
                        pass
                    finally:
                        shared.unlink(temp)
                fd = shared.open_file(name, mode=0o600)
                try:
                    if read_prefix(fd, len(data) + 1) != data:
                        raise Failure("failed")
                finally:
                    os.close(fd)
            return shared.path
        except OSError:
            raise Failure("failed") from None
        finally:
            shared.close()

    def shared_profile(self, recorded, create=True):
        if not recorded_env(recorded):
            raise Failure("failed")
        return Shared(recorded, self.host.tool("podman"), self.shared_conf(create), self.host.search(),
                      self.host.custody(), self.host.proc())

    def shared_call(self, shared, command, ledger=None, session=None, err_sink=None):
        """One engine invocation in the user's store as a tool child, its
        helper checked first; its stderr to `err_sink` when given."""
        shared.preflight()
        return self.tool(None, shared.argv(command), out_limit=OUT_LIMIT, ledger=ledger, env=shared.env(),
                         session=session, err_sink=err_sink)

    def shared_image(self, shared, image_id):
        """Whether `image_id` is in the user's store (`image exists`)."""
        status, _ = self.shared_call(shared, ["image", "exists", image_id])
        if status not in (0, 1):
            raise Failure("failed")
        return status == 0

    def share_image(self, shared, image, image_id):
        """The prepared image in the user's store by its ID: one already
        there is kept as it is; else the measured archive (which names no
        reference, so the load adds no tag and moves none) is loaded and its
        ID checked. Never a pull, tag, prune or removal."""
        if self.shared_image(shared, image_id):
            return
        entry = self.image(image, full=False, pin=True)
        try:
            parsed = Archive(entry["fd"], self.session.check)
            try:
                names = parsed.names()
            finally:
                parsed.close()
        finally:
            os.close(entry["fd"])
        if names:
            raise Failure("failed")
        archive = self.root.join(f"images/{image}/image.oci.tar")
        status, _ = self.shared_call(shared, ["load", "--quiet", f"--input={archive}"])
        if status != 0 or not self.shared_image(shared, image_id):
            diagnostic("shared store: the image did not load")
            raise Failure("failed")

    def remove_shared(self, inst, ledger, idir, until=None):
        """(done, code): an instance's containers in the user's store (a
        mount start's destination preparation, `shared.prepare`, then the
        workload's), each removed by its recorded ID only (else its
        cidfile's, the engine's own write), with bridge admission closed
        and no engine call of the instance running (an owner's graceful
        teardown: before its engine child is killed; otherwise after; the
        owner's own preparation: once its `start --attach` ended): `rm
        --force --ignore --time=0` (one removed meanwhile, by hand
        included, counts), then `container exists` must say absent, all
        within DISPOSE_SECONDS (and `until`, a monotonic bound, when
        given). One confirmed is recorded `removed` and never asked again.
        An intent without an ID: whatever podman made was never started (a
        start comes only after the ID is recorded); recorded as residue,
        warned, never looked up by name. Any refusal, failure or doubt: not
        done (`code` the shared refusal's, if any); the record stays for a
        later stop."""
        shared = inst.get("shared")
        if not shared:
            return True, None
        session = None
        prepare = shared.get("prepare")
        for slot, holder, cidfile in ((prepare, prepare, PREPARE_CIDFILE), (shared, inst, CIDFILE)):
            if not slot or slot["removed"] or not slot["intent"]:
                continue
            if holder.get("container") is None:
                found = read_cidfile(idir, cidfile)
                if found is not None:
                    holder["container"] = found
                    ledger.save()
            container = holder.get("container")
            if container is None:
                if not slot["residue"]:
                    slot["residue"] = True
                    ledger.save()
                    common.warning("shared store: a never-started container named for this instance may remain")
                continue
            if session is None:
                session = Deadline(DISPOSE_SECONDS)
                if until is not None:
                    session.deadline = min(session.deadline, until)
            try:
                profile = self.shared_profile(inst["engine_env"])
                status, _ = self.shared_call(profile, ["rm", "--force", "--ignore", "--time=0", container], ledger,
                                             session)
                if status == 0:
                    status, _ = self.shared_call(profile, ["container", "exists", container], ledger, session)
                    status = "absent" if status == 1 else status
                if status != "absent":
                    diagnostic("shared store: container removal unconfirmed")
                    return False, None
            except Failure as error:
                return False, error.code if error.code in SHARED_CODES else None
            except Interrupted:
                return False, None
            slot["removed"] = True
            ledger.save()
        return True, None

    def store_mode(self):
        """The inputs' engine store; private when they are unreadable (the
        operations needing them refuse on their own)."""
        try:
            return self.inputs()["store"]
        except Failure:
            return "private"

    def op_capabilities(self, request):
        # A shared store: a retained HOME only when asked for (explicit
        # retention); mounts with it.
        shared = self.store_mode() == "shared"
        return {"type": "described", "operation": request["operation"], "provider": PROVIDER,
                "operations": list(protocol.REQUIRED_OPERATIONS), "transport": "stdio",
                "retention": list(SHARED_RETENTION if shared else RETENTION), "limits": list(LIMITS),
                "features": list(SHARED_FEATURES if shared else FEATURES)}

    # prepare

    def op_prepare(self, request):
        custody = self.host.custody()
        self.host.rootless()
        programs = self.host.programs()
        recipe, repo = request["recipe"], request["worker"]
        try:
            trusted_path(recipe, "file")
            trusted_path(repo, "dir")
            trusted_path(repo + "/guest", "dir")
            trusted_path(repo + "/acquisitions", "dir")
        except OSError:
            raise Failure("prerequisite") from None
        # One asset tree: the worker sources are this provider's own.
        if os.path.realpath(repo) != os.path.realpath(ROOT):
            raise Failure("prerequisite")
        staged_as = next((rel for path, rel in CANONICAL_RECIPES.items()
                          if os.path.realpath(recipe) == os.path.realpath(path)), None)
        canonical = staged_as is not None
        inputs = self.inputs()
        build_args = inputs["build_args"]
        self.host.growth(self.root)
        shared = None
        if inputs["store"] == "shared":
            # Before any build: the user's store's helper demonstrably
            # running.
            shared = self.shared_profile(shared_env(self.host.environ))
            shared.preflight()
        work = self.root.sub("work", create=True)
        images = self.root.sub("images", create=True)
        try:
            self.host.growth(work, images)
        finally:
            images.close()
        common.admit_space(work, PREPARE_MIN_FREE, WORK_RESIDUE)
        common.admit_cache(self.root)
        name = request["operation"]
        if not work.mkdir(name):
            raise Failure("exists")
        workdir = work.sub(name)
        # The build's live writers (engine child, tool children) and its
        # store, in memory: a prepare has no handle to recover by. An
        # unconfirmed writer keeps work/OP and answers unsettled; the
        # host's custody domain is the guard.
        record = {"custody": custody.record(), "tools": [], "engine": None, "engine_identity": None,
                  "store": None, "loaded": False, "programs": programs}
        self.scratch = ledger = common.MemoryLedger(record, custody)
        engine = store_dir = error = None
        try:
            worker = _worker()
            try:
                staged = self.host.stage(repo, workdir.join("stage"))
            except worker.Refused:
                raise Failure("failed") from None
            except (OSError, subprocess.SubprocessError):
                raise Failure("failed") from None
            stage_digest = worker.measured(workdir.join("stage/stage.json"))[1]
            self.session.check()
            # The recipe the build reads: our private copy, measured.
            with open(recipe, "rb") as stream:
                data = stream.read((1 << 20) + 1)
            if len(data) > 1 << 20:
                raise Failure("prerequisite")
            os.mkdir(workdir.join("recipe"), 0o700)
            with open(workdir.join("recipe/Dockerfile"), "xb") as stream:
                stream.write(data)
            recipe_digest = hashlib.sha256(data).hexdigest()
            if canonical and recipe_digest != next(
                    (e["sha256"] for e in staged["recipe"] if e["path"] == staged_as), None):
                raise Failure("failed")
            store, store_dir = self.new_store(record, ledger, workdir, programs, None, scope=name, build=True)
            engine = self.new_engine(record, ledger, custody, store, store_dir, None, name="build")
            record["loaded"] = True
            ledger.save()
            iidfile = workdir.join("iid")
            command = ["build", "--squash-all", "--format=oci", f"--iidfile={iidfile}",
                       f"--file={workdir.join('recipe/Dockerfile')}"]
            command += [f"--build-arg={k}={v}" for k, v in sorted(build_args.items())]
            status, _ = engine.call("build", command + [workdir.join("stage/context")], out_limit=None)
            if status != 0:
                raise Failure("failed")
            with open(iidfile, "rb") as stream:
                iid = stream.read(80).decode("ascii", "replace").strip()
            image_id = _digest_hex(iid) if iid.startswith("sha256:") else iid
            if not _HEX64.match(image_id):
                raise Failure("failed")
            archive = workdir.join("image.oci.tar")
            status, _ = engine.call("save", ["save", "--format=oci-archive", f"--output={archive}", image_id],
                                    out_limit=None)
            if status != 0:
                raise Failure("failed")
            # The build store's own images, removed by its live engine.
            status, _ = engine.call("cleanup", list(DISPOSE), out_limit=None)
            if status == 0:
                record["store"]["disposed"] = True
                ledger.save()
        except BaseException as caught:  # noqa: BLE001 - settled below, then re-raised
            error = caught
        # Every build writer settles first; the build store is then
        # disposable (best effort).
        settled = True
        if engine is not None:
            settled = engine.settle(time.monotonic() + common.KILL_RESERVE)
            if settled:
                record["engine"] = record["engine_identity"] = None
        if store_dir is not None:
            store_dir.close()
        settled = self.settle_holder(record, custody, ledger) and settled
        if not settled:
            # A writer is unconfirmed: work/OP stays, named by this
            # operation; nothing is imported.
            workdir.close()
            raise Unsettled() from error
        try:
            if error is not None:
                raise error
            image, release, agents = self.import_image(workdir, image_id, staged, recipe, recipe_digest,
                                                       canonical, build_args, stage_digest)
            if shared is not None:
                self.share_image(shared, image, image_id)
            prepared = {"type": "prepared", "operation": name, "image": image, "worker_sha256": release}
            if agents is not None:
                prepared["agents"] = {agent: agents[agent]["version"] for agent in agents}
            return prepared
        except Interrupted as caught:
            if caught.reason == "lost":
                raise
            raise Failure(caught.code) from None
        except (Failure, OSError, ValueError, KeyError, TypeError) as caught:
            if isinstance(caught, Failure):
                raise
            raise Failure("failed") from None
        finally:
            if not common.remove_scratch(work, name, workdir.fd):
                common.warning("prepare scratch residue left")
            workdir.close()

    def write_entry(self, entry, name, data):
        out = entry.create(name, 0o400)
        try:
            os.write(out, data)
            os.fsync(out)
        finally:
            os.close(out)

    def import_image(self, workdir, image_id, staged, recipe, recipe_digest, canonical, build_args, stage_digest):
        """The saved archive is the image: hashed through one descriptor,
        parsed from it (config digest = the built id, one layer), its baked
        bundle and metadata validated from that same layer, the canonical
        recipe's agents too (`agent_provenance`), then published under the
        archive's digest (common.publish_entry: an immutable 0500/0400
        entry; an existing one is verified, never replaced). Returns
        (image, release, agents or None)."""
        worker = _worker()
        fd = workdir.open_file("image.oci.tar")
        try:
            st = os.fstat(fd)
            image = hash_fd(fd, self.session.check, st.st_size)
            parsed = Archive(fd, self.session.check)
            try:
                found = parsed.inspect()
                if found["image_id"] != image_id:
                    raise Failure("failed")
                metadata, dirs, accounts, baked = parsed.baked_worker(found["layer"], found["compression"],
                                                                      workdir.join("baked"), agents=canonical)
            finally:
                parsed.close()
            with open(workdir.join("baked/worker-metadata.json"), "xb") as stream:
                stream.write(metadata)
            try:
                release, files = worker.validate(workdir.join("baked/worker"))
                checked = worker.check_metadata(workdir.join("baked/worker-metadata.json"), release)
            except worker.Refused:
                raise Failure("failed") from None
            if dirs != worker.directories(files) or checked.get("sources", {}).get("revision") \
                    != staged["worker"]["sources"]["revision"]:
                raise Failure("failed")
            agents = agent_provenance(baked) if canonical else None
            if hash_fd(fd, self.session.check, st.st_size) != image:
                raise Failure("failed")

            def fill(entry):
                os.rename("image.oci.tar", "image.oci.tar", src_dir_fd=workdir.fd, dst_dir_fd=entry.fd)
                if identity(os.stat("image.oci.tar", dir_fd=entry.fd, follow_symlinks=False)) != identity(st):
                    raise Failure("failed")
                os.fchmod(fd, 0o400)
                os.fsync(fd)
                self.write_entry(entry, "worker-metadata.json", metadata)
                record = {
                    "schema": CACHE_SCHEMA, "image": image, "image_id": image_id, "bytes": st.st_size,
                    "fingerprint": fingerprint(os.fstat(fd)), "worker": release, "accounts": accounts,
                    "layer": {"digest": found["layer_digest"], "diff_id": found["diff_id"]},
                    "origin": {"recipe": {"path": recipe, "sha256": recipe_digest, "canonical": canonical},
                               "stage_sha256": stage_digest, "build_args": build_args}}
                if agents is not None:
                    record["agents"] = agents
                self.write_entry(entry, "record.json", (json.dumps(record, sort_keys=True, separators=(",", ":"))
                                                        + "\n").encode())

            images = self.root.sub("images", create=True)
            try:
                common.publish_entry(images, self.request["operation"], image, fill,
                                     lambda: self.image(image, full=True), STAGING_FILES,
                                     lambda unused: common.claim_unused(self.root, unused,
                                                                        (("resources", "resource.json"),)))
            finally:
                images.close()
            return image, release, agents
        finally:
            os.close(fd)

    # Resources.

    def resources(self, create=False):
        return self.root.sub("resources", create=create)

    def open_resource(self, request, lock):
        resources = self.resources()
        directory = resources.sub(request["resource"]) if resources is not None else None
        if directory is None:
            raise Failure("not_found")
        record = directory.read_json("resource.json")
        if record is not None and record.get("run") != request["run"]:
            directory.close()
            raise Failure("binding_mismatch")
        held = None
        if lock:
            held = directory.lock("lock")
            if held is None:
                directory.close()
                raise Failure("busy", "unsettled", "unchanged")
            record = directory.read_json("resource.json")
        return directory, record, held

    def settled_instance(self, directory, record):
        attached = record.get("instance")
        if not attached:
            return None
        instances = directory.sub("instances")
        idir = instances.sub(attached["instance"]) if instances is not None else None
        if idir is None:
            return None
        try:
            inst = idir.read_json("instance.json")
        finally:
            idir.close()
        return inst if inst is not None and inst.get("phase") == "settled" else None

    def roll_forward(self, directory, record, save):
        inst = self.settled_instance(directory, record)
        if inst is not None:
            result = inst["result"]
            record.update(generation=result["generation"], storage=result["storage"], instance=None)
            if save:
                directory.write_json("resource.json", record)
        return record

    def peek_store(self, request):
        """The resource's recorded engine store, read without its lock
        (private when there is no readable record: ready_resource then
        refuses as ever)."""
        try:
            directory, record, _ = self.open_resource(request, lock=False)
        except Failure:
            return "private"
        try:
            return engine_store_of(record) if record is not None else "private"
        finally:
            directory.close()

    def ready_resource(self, request):
        """A ready resource for start (growth only): bound, not partial, the
        resource directory declared before any reconciliation write, no
        live or unsettled instance, the requested generation."""
        directory, record, held = self.open_resource(request, True)
        try:
            if record is None or record["state"] in ("creating", "discarding"):
                raise Failure("partial")
            if record["state"] == "discarded":
                raise Failure("not_found")
            self.host.growth(directory)
            self.roll_forward(directory, record, save=True)
            if record.get("instance"):
                raise Failure("busy", "unsettled", "unchanged")
            if record["generation"] != request["generation"]:
                raise Failure("generation_mismatch")
        except BaseException:
            os.close(held)
            directory.close()
            raise
        return directory, record, held

    # create

    def op_create(self, request):
        self.host.custody()
        self.host.rootless()
        if request["retention"] not in RETENTION:
            raise Failure("unsupported")
        retained = request["retention"] != "none"
        # Mounts: retained storage only, the keep-id mapping, every source
        # checked now as at every start.
        mounts = request.get("mounts")
        if mounts is not None:
            if not retained:
                raise Failure("unsupported")
            if not protocol.mounts_valid(mounts):
                raise Failure("failed")
        # The engine store, recorded as the resource's own (start, stop and
        # recovery never follow a later edit of the inputs). A shared one
        # keeps `home` only, a volume in the user's store.
        inputs = self.inputs()
        engine_store = inputs["store"]
        if engine_store == "shared" and request["retention"] not in SHARED_RETENTION:
            raise Failure("unsupported")
        engine_env = shared_env(self.host.environ) if engine_store == "shared" else None
        shared_home = engine_store == "shared" and retained
        # A private retained volume's later removal needs a fresh engine
        # store: on the storage root admitted now, recorded as the
        # resource's own (cleanup never follows a later edit of the inputs).
        storage_root = inputs["storage_root"] if retained and not shared_home else None
        if mounts is not None and not shared_home:
            self.host.mount_sources(mounts, self.protected(storage_root))
        if retained and not shared_home:
            root = self.host.storage_root(storage_root)
            try:
                self.host.growth(self.root, root)
            finally:
                root.close()
        else:
            self.host.growth(self.root)
        if mounts is not None and shared_home:
            # The user's store's own paths too, read now from it (its
            # profile's files made in STATE after the growth check).
            err = common.Collect(MAX_INFO_ERR)
            status, out = self.shared_call(self.shared_profile(engine_env), list(SHARED_INFO_COMMAND),
                                           err_sink=err)
            self.host.mount_sources(mounts, self.protected() + shared_roots(engine_env, status, out,
                                                                            err.data if not err.over else b""))
        # Shared images.lock until the record names the image: an invalid
        # entry is moved aside only while no record uses it.
        uses = common.images_lock(self.root, exclusive=False)
        try:
            # The account before anything exists: never one the image names.
            user = request["user"]
            if not protocol.is_user(user):
                raise Failure("failed")
            found = self.image(request["image"], full=False)
            if user in found["accounts"]:
                raise Failure("user_conflict")
            if engine_store == "shared":
                # The prepared image already in the user's store, by ID.
                shared = self.shared_profile(engine_env)
                if not self.shared_image(shared, found["image_id"]):
                    diagnostic("shared store: the prepared image is not in it: prepare it again")
                    raise Failure("shared_image_missing")
                # A volume already under the resource's name is never
                # claimed (nor ever removed for this create).
                if shared_home and self.shared_volume_exists(shared, shared_volume(request["resource"])):
                    diagnostic("shared store: a volume of this resource's name already exists")
                    raise Failure("exists")
            resources = self.resources(create=True)
            self.host.growth(resources)
            name = request["resource"]
            if not resources.mkdir(name):
                existing = resources.sub(name)
                record = existing.read_json("resource.json") if existing is not None else None
                if record is not None and record.get("run") != request["run"]:
                    raise Failure("binding_mismatch")
                raise Failure("exists")
            directory = resources.sub(name)
            held = directory.lock("lock")
            record = {"schema": RESOURCE_SCHEMA, "run": request["run"], "resource": name,
                      "image": request["image"], "retention": request["retention"], "state": "creating",
                      "generation": 0, "storage": "clean", "instance": None,
                      "capacity": "uncapped" if retained else None,
                      # A shared HOME's name, durable with the first record.
                      "volume": {"name": shared_volume(name), "state": None} if shared_home else None,
                      "storage_root": storage_root, "user": user, "home": guest_home(user),
                      "engine_store": engine_store}
            if engine_env is not None:
                record["engine_env"] = engine_env
            if mounts is not None:
                record.update(mounts=[dict(m) for m in mounts], mapping="keep_id")
            directory.write_json("resource.json", record)
        finally:
            os.close(uses)
        try:
            self.image(request["image"], full=True)
            if shared_home:
                self.create_shared_volume(directory, record, shared, request["run"], mapping_of(record))
            elif retained:
                directory.mkdir("volumes")
                parent = os.stat("volumes", dir_fd=directory.fd, follow_symlinks=False)
                record["volume"] = {"parent": identity(parent), "state": None, "pin": None, "receipt": None}
                # No quota exists for it: the host must say so.
                diagnostic("retained volume capacity uncapped")
            record["state"] = "ready"
            directory.write_json("resource.json", record)
        except Exception as error:  # noqa: BLE001 - undone by name
            if not isinstance(error, (Failure, Interrupted)):
                error = Failure("failed")
            if shared_home and record["volume"]["state"] in ("allocating", "ready"):
                # The shared volume may exist (or does) under its name: the
                # record stays (`creating`, partial) for discard to remove
                # it. A known refusal made nothing (state null): undone.
                os.close(held)
                if isinstance(error, Interrupted) and error.reason == "lost":
                    raise error
                raise Failure("partial" if isinstance(error, Interrupted) else error.code, "unsettled",
                              "uncertain") from None
            try:
                directory.rmdir("volumes")
                for entry in ("resource.json", ".resource.json.tmp", "lock"):
                    directory.unlink(entry)
                os.close(held)
                resources.rmdir(name)
                resources.fsync()
            except OSError:
                raise Failure("partial" if isinstance(error, Interrupted) else error.code,
                              "unsettled", "uncertain") from None
            if isinstance(error, Interrupted) and error.reason == "lost":
                raise error
            raise Failure(error.code) from None
        os.close(held)
        created = {"type": "created", "operation": request["operation"], "run": request["run"],
                   "resource": name, "retention": request["retention"], "generation": 0,
                   "user": record["user"], "home": record["home"]}
        if shared_home:
            created["volume"] = record["volume"]["name"]
        return created

    def shared_volume_exists(self, shared, volume):
        """Whether the user's store has a volume named `volume`."""
        status, _ = self.shared_call(shared, ["volume", "exists", volume])
        if status not in (0, 1):
            raise Failure("failed")
        return status == 0

    def create_shared_volume(self, directory, record, shared, run, mapping):
        """A shared resource's HOME, made now (never by a start), owned as
        `mapping` needs: its intent (`allocating`) recorded first; the
        engine's refusal made nothing (back to null, undone with the
        record); an interrupted or unclear answer keeps the intent for
        discard (by name)."""
        volume = record["volume"]
        volume["state"] = "allocating"
        directory.write_json("resource.json", record)
        status, out = self.shared_call(shared, shared_volume_create(run, volume["name"], mapping))
        if status != 0:
            volume["state"] = None
            directory.write_json("resource.json", record)
            raise Failure("failed")
        if out != (volume["name"] + "\n").encode():
            raise Failure("failed")
        volume["state"] = "ready"
        # No quota exists for it: the host must say so.
        diagnostic("retained volume capacity uncapped")

    # status

    def op_status(self, request):
        answer = {"type": "reported", "operation": request["operation"], "run": request["run"],
                  "resource": request["resource"], "resource_state": "absent", "generation": 0}
        asked = "instance" in request
        if asked:
            answer.update(execution=request["execution"], instance=request["instance"], instance_state="absent")
        try:
            directory, record, _ = self.open_resource(request, lock=False)
        except Failure as error:
            if error.code == "not_found":
                return answer
            raise
        try:
            if record is None:
                answer["resource_state"] = "partial"
                return answer
            record = self.roll_forward(directory, dict(record), save=False)
            state = record["state"]
            answer["generation"] = record["generation"]
            if state in ("creating", "discarding"):
                answer["resource_state"] = "partial"
            elif state == "discarded":
                answer["resource_state"] = "absent"
            elif record.get("instance"):
                answer["resource_state"] = "busy"
            else:
                answer["resource_state"] = "ready" if record["storage"] == "clean" else "unclean"
            if asked:
                answer["instance_state"] = self.instance_state(directory, request)
            return answer
        finally:
            directory.close()

    def instance_state(self, directory, request):
        instances = directory.sub("instances")
        idir = instances.sub(request["instance"]) if instances is not None else None
        if idir is None:
            return "absent"
        try:
            inst = idir.read_json("instance.json")
            if inst is None:
                return "unsettled"
            if inst["execution"] != request["execution"]:
                raise Failure("binding_mismatch")
            if inst["phase"] == "settled":
                return "settled"
            return "live" if idir.held("owner.lock") else "unsettled"
        finally:
            idir.close()

    # Settlement by record: tool children, the engine child, the store.

    def settle_engine(self, holder, custody):
        """Kills and removes the holder's recorded engine child; True only
        when that very child is gone (or was never created)."""
        if not holder.get("engine"):
            return True
        if common.foreign(holder, custody):
            # Gone by the host's precondition: never touched from here.
            return True
        deadline = time.monotonic() + common.KILL_RESERVE
        try:
            engine = custody.existing(holder["engine"], holder.get("engine_identity"))
        except (Unsettled, OSError):
            return False
        if engine is not None:
            settled = engine.settle(deadline)
            engine.close()
            if not settled:
                return False
        holder["engine"] = holder["engine_identity"] = None
        return True

    def settle_store(self, holder, ledger):
        """The holder's store once every engine and tool writer is
        confirmed gone (the caller's precondition): disposable. A loaded
        store gets one disposal (a fresh profile, its tool child settled
        strictly) for its subordinate-owned layers; then, best effort, the
        pinned store, still under its recorded name, is walked (no link,
        no mode change) and removed. Anything else (an unconfirmed
        creation, a changed root or name, foreign or unwritable leftovers)
        is never deleted: recorded as `residue` with a fixed warning,
        blocking nothing. False only when the disposal's own child is
        unconfirmed: a live writer."""
        store = holder.get("store")
        if not store or store.get("removed") or store.get("residue"):
            return True

        def residue():
            store["residue"] = True
            ledger.save()
            common.warning("engine store residue left")
            return True

        if store.get("identity") is None:
            return residue()
        try:
            root = self.store_root(store)
        except (Failure, OSError):
            return residue()
        try:
            if identity(os.fstat(root.fd)) != store["root_identity"]:
                return residue()
            try:
                fd = os.open(store["name"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=root.fd)
            except OSError:
                return residue()
            pinned = Dir(fd, root.join(store["name"]))
            try:
                if identity(os.fstat(fd)) != store["identity"]:
                    return residue()
                if holder.get("loaded") and not store.get("disposed"):
                    if holder.get("programs") != self.host.programs():
                        return residue()
                    store["disposals"] = store.get("disposals", 0) + 1
                    ledger.save()
                    outcome = self.dispose(pinned, holder["programs"], ledger, store["disposals"])
                    if outcome == "unsettled":
                        return False
                    store["disposed"] = outcome == "disposed"
                    ledger.save()
                if not common.remove_scratch(root, store["name"], fd):
                    return residue()
                store["removed"] = True
                ledger.save()
                return True
            finally:
                pinned.close()
        finally:
            root.close()

    def dispose(self, pinned, programs, ledger, attempt):
        """One disposal attempt: a fresh profile `dispose-N` (its own
        database, locks, pause process and runtime state; only graph/
        shared) made beneath the pinned store, its files checked, then
        `rmi --all --force` as a tool child settled at its end.
        "disposed", "failed" or "unsettled" (its child unconfirmed: nothing
        may be removed). Its exit status alone never removes anything: the
        store's removal is the evidence."""
        profile = Store(pinned.path, programs, dispose=f"dispose-{attempt}", search=self.host.search())
        try:
            profile.prepare(pinned, "dispose")
        except OSError:
            return "failed"
        if not profile.matches(pinned, "dispose"):
            return "failed"
        try:
            status, _ = self.tool(None, profile.argv(DISPOSE, "dispose"), ledger=ledger, env=profile.env("dispose"),
                                  session=Deadline(DISPOSE_SECONDS), log=common.BoundedSink(None, None, 0))
        except Unsettled:
            return "unsettled"
        except (Failure, Interrupted):
            return "failed"
        return "disposed" if status == 0 else "failed"

    def settle_holder(self, holder, custody, ledger):
        """Every recorded writer of `holder` in this domain, strictly: tool
        children, the engine child. True when none is left; then the store
        is cleaned up best effort (settle_store). The record is saved."""
        tools = common.settle_debts(holder, custody)
        ledger.save()
        # Every process debt is tried even when another stays: each one
        # killed is a writer less.
        engine = self.settle_engine(holder, custody)
        ledger.save()
        # Only with no writer left is the store disposable.
        return tools and engine and self.settle_store(holder, ledger)

    # stop (standalone): the owner is gone; settle by recorded handle.

    def op_stop(self, request):
        custody = self.host.custody()
        directory, record, held = self.open_resource(request, lock=True)
        try:
            instances = directory.sub("instances")
            idir = instances.sub(request["instance"]) if instances is not None else None
            if idir is None or record is None:
                raise Failure("not_found")
            inst = idir.read_json("instance.json")
            if inst is None:
                raise Failure("not_found")
            if inst["execution"] != request["execution"]:
                raise Failure("binding_mismatch")
            if inst["generation"] != request["generation"]:
                raise Failure("generation_mismatch")
            if inst["phase"] != "settled":
                owner = idir.lock("owner.lock")
                if owner is None:
                    # The owner session still runs: the host stops it there.
                    raise Failure("busy", "unsettled", "unchanged")
                admission = None
                try:
                    ledger = common.RecordLedger(idir, "instance.json", inst, custody)
                    admission = close_admission(idir, inst)
                    if admission is None:
                        # A bridge may still be between its check and its
                        # spawn: nothing is torn down under it.
                        raise Failure("busy", "unsettled", "uncertain")
                    if not self.settle_holder(inst, custody, ledger):
                        # Unconfirmed here: nothing it may write is removed.
                        raise Failure("busy", "unsettled", "uncertain")
                    # A shared store's container, by its recorded ID only.
                    done, code = self.remove_shared(inst, ledger, idir)
                    if not done:
                        raise Failure(code or "failed", "unsettled", "uncertain")
                    remove_secrets(idir)
                    clear_diag(idir)
                    inst["result"] = instance_result(record, inst, clean=False)
                    inst["phase"] = "settled"
                    idir.write_json("instance.json", inst)
                finally:
                    if admission is not None:
                        os.close(admission)
                    os.close(owner)
            self.roll_forward(directory, record, save=True)
            result = inst["result"]
            return {"type": "stopped", "operation": request["operation"], "run": request["run"],
                    "resource": request["resource"], "execution": request["execution"],
                    "instance": request["instance"], "settlement": "settled",
                    "durability": result["durability"], "generation": result["generation"],
                    "storage": result["storage"]}
        finally:
            os.close(held)
            directory.close()

    # discard

    def op_discard(self, request):
        custody = self.host.custody()
        if "checkpoint" in request:
            raise Failure("unsupported")
        directory, record, held = self.open_resource(request, lock=True)
        try:
            done = {"type": "discarded", "operation": request["operation"], "run": request["run"],
                    "resource": request["resource"], "settlement": "settled"}
            if record is not None and record["state"] == "discarded":
                return done
            if record is not None:
                self.roll_forward(directory, record, save=True)
                if record.get("instance"):
                    raise Failure("busy", "unsettled", "unchanged")
                # Further tasks are refused before anything is deleted.
                record["state"] = "discarding"
                directory.write_json("resource.json", record)
                ledger = common.RecordLedger(directory, "resource.json", record, custody)
                if not self.settle_holder(record, custody, ledger):
                    raise Failure("busy", "unsettled", "uncertain")
            try:
                self.remove_instances(directory)
            except OSError:
                raise Failure("failed", "unsettled", "uncertain") from None
            if record is None:
                directory.unlink(".resource.json.tmp")
                directory.unlink("lock")
                os.close(held)
                held = None
                self.resources().rmdir(request["resource"])
                return done
            if record["retention"] != "none":
                if engine_store_of(record) == "shared":
                    self.remove_shared_volume(record, ledger)
                elif not self.remove_volume(directory, record, custody, ledger):
                    raise Failure("failed", "unsettled", "uncertain")
            tombstone = {key: record[key] for key in ("schema", "run", "resource", "image", "retention")}
            tombstone.update(state="discarded", generation=record["generation"], storage=record["storage"],
                             instance=None, volume=None, capacity=None)
            directory.write_json("resource.json", tombstone)
            return done
        finally:
            if held is not None:
                os.close(held)
            directory.close()

    def remove_instances(self, directory):
        """Every settled instance's directory and binding, by name; any
        other is refused (busy)."""
        instances = directory.sub("instances")
        if instances is None:
            return
        bindings = self.root.sub("bindings")
        for name in instances.names():
            idir = instances.sub(name)
            inst = idir.read_json("instance.json")
            if inst is not None and (inst.get("phase") != "settled" or inst.get("tools")):
                raise Failure("busy", "unsettled", "uncertain")
            clear_diag(idir, strict=True)
            for entry in idir.names(len(INSTANCE_FILES)):
                if entry not in INSTANCE_FILES:
                    raise Failure("failed", "unsettled", "uncertain")
                idir.unlink(entry)
            idir.close()
            instances.rmdir(name)
            if bindings is not None:
                binding = bindings.read_json(name)
                if binding is not None and binding.get("resource") == directory.path.rsplit("/", 1)[1]:
                    bindings.unlink(name)
        instances.close()
        directory.rmdir("instances")
        directory.fsync()

    def remove_shared_volume(self, record, ledger):
        """A shared resource's HOME by its recorded name, its identity:
        `volume rm` (never forced). Removed, or already absent (removed by
        hand, or never made): done. In use by any container: `busy`; a
        refusal or failure: unsettled, a later discard retries. Whatever
        holds the name now is the run's (concurrent manual changes are not
        guarded)."""
        volume = record["volume"]
        # Never intended (no descriptor, or no allocation begun): nothing.
        if volume is None or volume["state"] in (None, "removed"):
            return
        session = Deadline(DISPOSE_SECONDS)
        try:
            profile = self.shared_profile(record["engine_env"])
            status, _ = self.shared_call(profile, ["volume", "rm", volume["name"]], ledger, session)
        except Failure as error:
            raise Failure(error.code if error.code in SHARED_CODES else "failed", "unsettled",
                          "uncertain") from None
        except Interrupted:
            raise Failure("failed", "unsettled", "uncertain") from None
        if status == 2:
            diagnostic("shared store: the HOME volume is in use by a container")
            raise Failure("busy", "unsettled", "uncertain")
        if status not in (0, 1):
            diagnostic("shared store: HOME volume removal failed")
            raise Failure("failed", "unsettled", "uncertain")
        if status == 1:
            diagnostic("shared store: the HOME volume was already gone")
        volume["state"] = "removed"
        ledger.save()

    def remove_volume(self, directory, record, custody, ledger):
        """The retained volume's removal through controlled engine steps:
        the original directory held (O_PATH) before any effect, registered
        in a fresh store's database, still that directory, `volume rm`,
        then the held directory's own detachment (same identity, nlink 0)
        recorded as the receipt while it is still held, before any later
        engine or store cleanup. Only a volume durably never allocated
        needs none. A missing, replaced or unreachable directory or parent,
        an ambiguous allocation without its directory, or a crash before
        the receipt stay unconfirmed. Never a host walk, chmod or chown of
        its subordinate-owned contents. True once proven."""
        volume = record["volume"]
        if volume["state"] != "removed":
            try:
                volumes = directory.sub("volumes")
            except (Failure, OSError):
                return False
            if volumes is None:
                return False
            try:
                if identity(os.fstat(volumes.fd)) != volume["parent"]:
                    return False
                try:
                    held = os.open(VOLUME, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=volumes.fd)
                except FileNotFoundError:
                    if volume["state"] is not None or volume["pin"] is not None:
                        return False
                    # Durably never allocated: no volume create ever began.
                    volume.update(state="removed", receipt="never_allocated")
                    ledger.save()
                    held = None
                except OSError:
                    return False
                if held is not None:
                    try:
                        pin = volume_pin(os.fstat(held))
                        # Without the allocation's own published pin, the
                        # name may lead anywhere: never adopted.
                        if volume["pin"] is None or pin != volume["pin"]:
                            return False
                        self.volume_engine(record, volumes, held, pin, custody, ledger)
                    finally:
                        os.close(held)
            finally:
                volumes.close()
        settled = self.settle_holder(record, custody, ledger)
        if volume["state"] != "removed" or not settled:
            return False
        return self.drop_volumes(directory)

    def volume_engine(self, record, volumes, held, pin, custody, ledger):
        """volume create (registration, no copy) + volume rm in one fresh
        store's engine child; the receipt written while `held` is open."""
        engine = store_dir = None
        try:
            # The resource's own recorded root, whatever the inputs say now;
            # disposal, never a growth admission.
            if not record.get("storage_root"):
                return
            programs = self.host.programs()
            root = self.host.storage_root(record["storage_root"])
            try:
                store, store_dir = self.new_store(record, ledger, root, programs, volumes.path,
                                                  disposal=True)
            finally:
                root.close()
            engine = self.new_engine(record, ledger, custody, store, store_dir, None)
            status, out = engine.call("volume-create", volume_create(mapping_of(record)))
            if status != 0 or out != (VOLUME + "\n").encode() or not still_named(volumes, pin):
                return
            engine.call("volume-rm", list(VOLUME_REMOVE))
            st = os.fstat(held)
            if volume_pin(st) == pin and st.st_nlink == 0:
                before = dict(record["volume"])
                record["volume"].update(state="removed", receipt={"pin": pin, "nlink": 0})
                try:
                    ledger.save()
                except OSError:
                    record["volume"].clear()
                    record["volume"].update(before)
                    raise
        except (Failure, Interrupted, OSError):
            return
        finally:
            if engine is not None and engine.settle(time.monotonic() + common.KILL_RESERVE):
                record["engine"] = record["engine_identity"] = None
                ledger.save()
            if store_dir is not None:
                store_dir.close()

    def drop_volumes(self, directory):
        try:
            directory.rmdir("volumes")
            directory.fsync()
        except OSError:
            return False
        return True

    def new_store(self, holder, ledger, root, programs, volumes, scope=None, build=False, disposal=False):
        """A fresh store in `root` (the storage root, or with `scope` a
        prepare's own work dir), admitted there first (free space, residue
        count; settling existing stores and a `disposal` store, which only
        removes, never need one): its intent (root, its identity,
        a random name) recorded first, then created exclusively (0700),
        pinned and recorded, then its closed profile. A refused mkdir
        created nothing and clears the intent; anything after it leaves the
        store unconfirmed (kept, never guessed)."""
        if not disposal:
            common.admit_space(root, STORE_MIN_FREE, STORE_RESIDUE)
        name = "s-" + os.urandom(16).hex()
        holder["programs"] = programs
        holder["store"] = {"root": root.path, "root_identity": identity(os.fstat(root.fd)), "scope": scope,
                           "name": name, "identity": None, "removed": False, "residue": False, "disposals": 0,
                           "disposed": False}
        ledger.save()
        try:
            os.mkdir(name, 0o700, dir_fd=root.fd)
        except OSError:
            holder["store"] = None
            ledger.save()
            raise Failure("failed") from None
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root.fd)
        st = os.fstat(fd)
        store_dir = Dir(fd, root.join(name))
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o700 \
                or st.st_dev != os.fstat(root.fd).st_dev:
            store_dir.close()
            raise Failure("failed")
        holder["store"]["identity"] = identity(st)
        ledger.save()
        store = Store(store_dir.path, programs, volumes=volumes, build=build, search=self.host.search())
        try:
            store.prepare(store_dir)
        except BaseException:
            store_dir.close()
            raise
        return store, store_dir

    def store_root(self, store):
        """The recorded store's parent, reached again: a prepare's work dir
        through STATE, else the storage root by its safe walk."""
        if store.get("scope") is None:
            return safe_dir(store["root"])
        work = self.root.sub("work")
        if work is None:
            raise Failure("failed")
        try:
            root = work.sub(store["scope"])
        finally:
            work.close()
        if root is None or root.path != store["root"]:
            if root is not None:
                root.close()
            raise Failure("failed")
        return root

    def new_engine(self, holder, ledger, custody, store, store_dir, limits, name="engine"):
        """The engine child (limits written and read back before anything
        joins), recorded before it exists and by identity once it does."""
        holder["custody"] = custody.record()
        holder["engine"] = name
        holder["engine_identity"] = None
        ledger.save()
        child = custody.child(name, limits)
        holder["engine_identity"] = child.identity
        ledger.save()
        diag = store_dir.sub("diag")
        return Engine(self.session, store, child, diag)

    # start: the owner session.

    def op_start(self, request):
        custody = self.host.custody()
        self.host.rootless()
        programs = self.host.programs()
        keygen = self.host.tool("ssh-keygen")
        limits = limits_of(request["limits"])
        # The resource's own engine store (read again under its lock).
        engine_store = self.peek_store(request)
        storage_root = None
        if engine_store == "shared":
            self.host.growth(self.root)
        else:
            storage_root = self.inputs()["storage_root"]
            root = self.host.storage_root(storage_root)
            try:
                self.host.growth(self.root, root)
                common.admit_space(root, STORE_MIN_FREE, STORE_RESIDUE)
            finally:
                root.close()
        directory, record, held = self.ready_resource(request)
        try:
            if not resource_account(record) or engine_store_of(record) != engine_store:
                raise Failure("failed")
            if record["storage"] == "unclean" and not request["accept_unclean"]:
                raise Failure("unclean")
            # Mounts: the higher minimum, before anything is allocated (the
            # limits reach a provider only with `start`, never `create`).
            if record.get("mounts") and limits[1] < MOUNT_MIN_MEMORY_MIB:
                diagnostic(f"mount runs need memory_mib >= {MOUNT_MIN_MEMORY_MIB}")
                raise Failure("mounts_need_memory")
            # The resource directory was checked by ready_resource; the
            # existing bindings and instances directories both before
            # either absent one is made.
            bindings, instances = self.host.allocation((self.root, "bindings"), (directory, "instances"))
            if bindings.exists(request["instance"]) or instances.exists(request["instance"]):
                raise Failure("exists")
            bindings.write_json(request["instance"], {"run": request["run"], "resource": request["resource"],
                                                      "execution": request["execution"]})
            if not instances.mkdir(request["instance"]):
                raise Failure("exists")
            idir = instances.sub(request["instance"])
            owner_lock = idir.lock("owner.lock")
            os.close(idir.create("admission.lock"))
            inst = {"schema": INSTANCE_SCHEMA, "run": request["run"], "resource": request["resource"],
                    "execution": request["execution"], "instance": request["instance"],
                    "generation": request["generation"], "retention": record["retention"], "phase": "intent",
                    "custody": custody.record(), "engine": None, "engine_identity": None, "tools": [],
                    "programs": programs, "store": None, "volumes": None, "loaded": False, "volume_used": False,
                    "container": None, "host_key": None, "result": None, "engine_store": engine_store,
                    "diag": False, "shared": None}
            if engine_store == "shared":
                # `intent`: a create may have run; `removed`: its container
                # confirmed gone; `residue`: an unidentified one reported.
                inst.update(engine_env=record["engine_env"],
                            shared={"intent": False, "removed": False, "residue": False})
            idir.write_json("instance.json", inst)
            record["instance"] = {"execution": request["execution"], "instance": request["instance"]}
            directory.write_json("resource.json", record)
        except BaseException:
            os.close(held)
            directory.close()
            raise
        owner = Owner(self, request, directory, record, held, idir, inst, owner_lock, custody, programs, keygen,
                      limits, storage_root)
        return owner.run()


def engine_store_of(record):
    """A resource's recorded engine store (absent: private); a shared one
    with its recorded engine environment."""
    found = record.get("engine_store", "private")
    if found not in STORES or (found == "shared" and not recorded_env(record.get("engine_env"))):
        raise Failure("failed")
    return found


def resource_account(record):
    """A resource record's account: a guest login and its HOME."""
    user = record.get("user")
    return protocol.is_user(user) and record.get("home") == guest_home(user)


def volume_pin(st):
    return [st.st_dev, st.st_ino, st.st_uid, st.st_gid]


def volume_entry(volumes):
    """The volume directory's pin now, None when absent; a link or other
    entry is refused."""
    try:
        st = os.stat(VOLUME, dir_fd=volumes.fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(st.st_mode):
        raise Failure("failed")
    return volume_pin(st)


def still_named(volumes, pin):
    try:
        return volume_entry(volumes) == pin
    except (Failure, OSError):
        return False


def close_admission(idir, inst):
    """Closes bridge admission: `stopping` is recorded (no bridge passes
    its check afterwards), then the exclusive admission lock is taken, so
    no bridge admitted earlier is still between its check and its spawn.
    Returns that lock (held through teardown), or None when it cannot be
    had: then nothing may be torn down."""
    if inst["phase"] in ("engine", "live"):
        inst["phase"] = "stopping"
    idir.write_json("instance.json", inst)
    try:
        return idir.lock("admission.lock", block=True, deadline=time.monotonic() + ADMISSION_WAIT)
    except Failure:
        return None


def remove_secrets(idir):
    """The guest host key, its public half and the provisioning tar, once
    nothing reads them: best effort (a failure is a fixed warning; discard
    removes what is left with the instance)."""
    try:
        for name in SECRET_FILES:
            idir.unlink(name)
        idir.fsync()
    except OSError:
        common.warning("instance secret files left")


class Owner:
    """The start invocation as the instance's owner: sets up, launches,
    answers `started`, waits for the host's `stop` (or EOF, a signal, a
    refused frame), closes bridge admission, then settles by its exact
    handles and answers."""

    def __init__(self, provider, request, directory, record, held, idir, inst, owner_lock, custody, programs,
                 keygen, limits, storage_root):
        self.p, self.session, self.request = provider, provider.session, request
        self.directory, self.record, self.held = directory, record, held
        self.idir, self.inst, self.owner_lock = idir, inst, owner_lock
        self.custody, self.programs, self.keygen = custody, programs, keygen
        self.limits, self.storage_root = limits, storage_root
        # The resource's account, fixed at create (checked by op_start).
        self.user = record["user"]
        self.shared = inst["engine_store"] == "shared"
        self.engine = self.store = self.store_dir = None
        self.image = None
        self.archive = -1
        self.admission = None
        # A shared store's refusal that kept the instance unsettled.
        self.code = None
        self.ledger = common.RecordLedger(idir, "instance.json", inst, custody)

    def save(self):
        self.idir.write_json("instance.json", self.inst)

    def run(self):
        try:
            self.setup()
            self.launch()
            self.session.check()
            self.inst["phase"] = "live"
            self.save()
        except (Failure, Interrupted) as error:
            return self.finish(error=error)
        except Exception as error:  # noqa: BLE001 - settled by handle in finish
            diagnostic(f"start: {type(error).__name__}")
            return self.finish(error=Failure("failed"))
        os.close(self.held)
        self.held = None
        started = {"type": "started", "operation": self.request["operation"], "run": self.request["run"],
                   "resource": self.request["resource"], "execution": self.request["execution"],
                   "instance": self.request["instance"], "generation": self.request["generation"],
                   "transport": {"kind": "stdio"}, "user": self.user, "host_key": self.inst["host_key"],
                   "worker_sha256": self.image["worker"], "home": guest_home(self.user), "control": CONTROL_ROOT}
        self.session.send(started)
        self.session.await_stop()
        try:
            stop = self.wait()
        except Exception as error:  # noqa: BLE001 - nothing may be written now: settle as lost
            diagnostic(f"owner: {type(error).__name__}")
            stop = None
            self.session.refused = "owner_error"
        if stop is None:
            return self.finish(error=Interrupted("lost"))
        self.p.request = stop
        self.session.begin(stop["operation"], stop["timeout_ms"])
        return self.finish(stop=stop)

    # Setup: nothing runs before the image is measured and the keys exist.

    def setup(self):
        # A shared store runs the image already there by ID: no archive.
        self.image = self.p.image(self.record["image"], full=True, pin=not self.shared)
        self.archive = self.image["fd"]
        idir = self.idir
        key = idir.join("host_ed25519")
        try:
            status, _ = self.p.tool(None, [self.keygen, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key],
                                    ledger=self.ledger)
            if status != 0:
                raise Failure("failed")
            fd = idir.open_file("host_ed25519", mode=0o600)
            try:
                private = os.read(fd, 8192)
            finally:
                os.close(fd)
            if _PRIVATE.match(private.decode("ascii", "replace")) is None:
                raise Failure("failed")
            fd = idir.open_file("host_ed25519.pub")
            try:
                public = bare_key(os.read(fd, 1024).decode("ascii"))
            finally:
                os.close(fd)
            status, derived = self.p.tool(None, [self.keygen, "-y", "-P", "", "-f", key], out_limit=1024,
                                          ledger=self.ledger)
            if status != 0 or bare_key(derived.decode("ascii")) != public \
                    or public == self.request["authorized_key"]:
                raise Failure("failed")
            data = provisioning_tar(private, (self.request["authorized_key"] + "\n").encode(), self.user)
            del private
            out = idir.create("provision.tar", 0o600)
            try:
                os.write(out, data)
                os.fsync(out)
            finally:
                os.close(out)
            self.inst["host_key"] = public
        finally:
            # Only with no tool child outstanding: one may still write.
            if not self.inst.get("tools"):
                idir.unlink("host_ed25519")
                idir.unlink("host_ed25519.pub")

    # Launch: the limits are in place before any engine process runs.

    def launch(self):
        if self.shared:
            return self.launch_shared()
        retained = self.inst["retention"] != "none"
        volumes = self.directory.join("volumes") if retained else None
        self.inst["phase"] = "engine"
        self.inst["volumes"] = volumes
        self.save()
        root = self.p.host.storage_root(self.storage_root)
        try:
            self.store, self.store_dir = self.p.new_store(self.inst, self.ledger, root, self.programs, volumes)
        finally:
            root.close()
        self.engine = self.p.new_engine(self.inst, self.ledger, self.custody, self.store, self.store_dir,
                                        engine_limits(*self.limits))
        self.inst["loaded"] = True
        self.save()
        os.lseek(self.archive, 0, os.SEEK_SET)
        status, _ = self.engine.call("load", ["load", "--quiet"], stdin=self.archive)
        if status != 0:
            raise Failure("failed")
        image_id = self.image["image_id"]
        mapping = mapping_of(self.record)
        mounts = self.record.get("mounts") or []
        roots = (self.storage_root, self.record.get("storage_root"))
        if mounts:
            # Sources first, before the retained HOME is touched: a missing
            # or protected one refuses with the storage unchanged.
            self.p.host.mount_sources(mounts, self.p.protected(*roots))
        if retained:
            self.volume(image_id, mapping)
        binds = []
        if mounts:
            # Every start: the destinations made safe in the retained HOME,
            # then each source resolved anew, just before `create`.
            status, _ = self.engine.call("prepare", prepare_command(image_id, self.user, mapping,
                                                                    [m["destination"] for m in mounts]))
            if status != 0:
                diagnostic("mount destination refused")
                # Only the script's own refusal names the cause; any other
                # status (its mkdir, the engine's 125-127, a kill) does not.
                raise Failure("mount_destination_unsafe" if status == PREPARE_UNSAFE else "failed")
            # The full protected set read again for the second resolution.
            binds = self.p.host.mount_sources(mounts, self.p.protected(*roots))
        status, out = self.engine.call("create", create_command(image_id, self.inst["retention"], self.user,
                                                                mapping, binds))
        container = created_id(status, out)
        self.inst["container"] = container
        self.save()
        self.provision(container)

    def launch_shared(self):
        """The user's store: the engine child (limits first) runs every
        call, each after the helper preflight (Engine.call); the prepared
        image there by ID (never loaded or pulled here), the create's
        intent recorded before it, its ID (stdout, and the cidfile
        agreeing) before anything starts it. Mounts: each source resolved
        before the HOME volume is touched, the destinations prepared
        (`prepare_shared`), then resolved again just before `create`, each
        time against the full protected set read anew (`shared_protected`)."""
        self.inst["phase"] = "engine"
        self.save()
        profile = self.p.shared_profile(self.inst["engine_env"])
        if not self.idir.mkdir(DIAG):
            raise Failure("failed")
        self.inst["diag"] = True
        self.save()
        self.engine = self.p.new_engine(self.inst, self.ledger, self.custody, profile, self.idir,
                                        engine_limits(*self.limits))
        image_id = self.image["image_id"]
        status, _ = self.engine.call("image-exists", ["image", "exists", image_id])
        if status == 1:
            diagnostic("shared store: the prepared image is not in it: prepare it again")
            raise Failure("shared_image_missing")
        if status != 0:
            raise Failure("failed")
        mapping = mapping_of(self.record)
        mounts = self.record.get("mounts") or []
        if mounts:
            self.p.host.mount_sources(mounts, self.shared_protected())
        volume = None
        if self.inst["retention"] != "none":
            # The HOME volume by its name, made at create only: a missing
            # one is reported, never made again (`create` itself would).
            if self.record["volume"]["state"] != "ready":
                raise Failure("failed")
            volume = self.record["volume"]["name"]
            status, _ = self.engine.call("volume-exists", ["volume", "exists", volume])
            if status == 1:
                diagnostic("shared store: the retained HOME volume is gone")
                raise Failure("retained_home_missing")
            if status != 0:
                raise Failure("failed")
            self.inst["volume_used"] = True
        binds = []
        if mounts:
            self.prepare_shared(image_id, mapping, volume, [m["destination"] for m in mounts])
            binds = self.p.host.mount_sources(mounts, self.shared_protected())
        self.inst["shared"]["intent"] = True
        self.save()
        status, out = self.engine.call("create", shared_create_command(
            image_id, self.user, self.request["run"], self.request["instance"], self.idir.join(CIDFILE), volume,
            mapping, binds))
        container = created_id(status, out)
        self.inst["container"] = container
        self.save()
        if read_cidfile(self.idir) != container:
            raise Failure("failed")
        self.provision(container)

    def shared_protected(self):
        """The full protected set read now: the host's (Provider.protected)
        and the user's store's own paths (`shared_roots`: its `info`, after
        the helper preflight, and the recorded engine environment)."""
        roots = self.p.protected()
        status, out, err = self.engine.call("info", list(SHARED_INFO_COMMAND), err_limit=MAX_INFO_ERR)
        return roots + shared_roots(self.inst["engine_env"], status, out, err)

    def prepare_shared(self, image_id, mapping, volume, destinations):
        """Every mount start's destinations made safe in the shared HOME
        (PREPARE_SCRIPT, the private store's semantics) by a transient
        container recorded as `shared.prepare`: its intent before `create`,
        its ID (stdout, its own cidfile agreeing) before `start --attach`
        runs it, then removed by that ID (Provider.remove_shared) before
        anything else runs. Interrupted, it stays recorded for the
        settlement's removal; never `run --rm`, never found by name."""
        slot = {"intent": True, "container": None, "removed": False, "residue": False}
        self.inst["shared"]["prepare"] = slot
        self.save()
        status, out = self.engine.call("prepare-create", shared_prepare_command(
            image_id, self.user, mapping, destinations, self.request["run"], self.request["instance"],
            self.idir.join(PREPARE_CIDFILE), volume))
        slot["container"] = created_id(status, out)
        self.save()
        if read_cidfile(self.idir, PREPARE_CIDFILE) != slot["container"]:
            raise Failure("failed")
        status, _ = self.engine.call("prepare", ["start", "--attach", slot["container"]])
        done, code = self.p.remove_shared(self.inst, self.ledger, self.idir)
        if not done:
            raise Failure(code or "failed")
        if status != 0:
            diagnostic("mount destination refused")
            # Only the script's own refusal names the cause.
            raise Failure("mount_destination_unsafe" if status == PREPARE_UNSAFE else "failed")

    def provision(self, container):
        """The SSH material copied in, then the container started."""
        tar = self.idir.open_file("provision.tar", mode=0o600)
        try:
            status, _ = self.engine.call("cp", ["cp", "--archive=false", "-", f"{container}:{SSH_PARENT}"],
                                         stdin=tar)
        finally:
            os.close(tar)
        if status != 0:
            raise Failure("failed")
        self.idir.unlink("provision.tar")
        status, _ = self.engine.call("start", ["start", container])
        if status != 0:
            raise Failure("failed")

    def volume(self, image_id, mapping="default"):
        """The retained volume before the container. A first allocation
        (state null, no directory) records `allocating`, runs `volume
        create`, then at once holds the directory it made and publishes
        that pin (`allocated`) before initializing it; `ready` once
        initialized. A later start needs that very directory under its
        name. An allocation intent without its published pin is never
        adopted: unconfirmed, refused."""
        record = self.record
        volume = record["volume"]
        volumes = self.directory.sub("volumes")
        if volumes is None or identity(os.fstat(volumes.fd)) != volume["parent"]:
            raise Failure("failed")
        held = None
        try:
            found = volume_entry(volumes)
            if volume["pin"] is None:
                if volume["state"] is not None or found is not None:
                    raise Failure("failed")
                volume["state"] = "allocating"
                self.directory.write_json("resource.json", record)
            elif found != volume["pin"]:
                raise Failure("failed")
            self.inst["volume_used"] = True
            self.save()
            status, out = self.engine.call("volume-create", volume_create(mapping))
            if status != 0 or out != (VOLUME + "\n").encode():
                raise Failure("failed")
            if volume["pin"] is None:
                try:
                    held = os.open(VOLUME, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=volumes.fd)
                except OSError:
                    raise Failure("failed") from None
                volume.update(state="allocated", pin=volume_pin(os.fstat(held)))
                self.directory.write_json("resource.json", record)
            elif not still_named(volumes, volume["pin"]):
                raise Failure("failed")
            if volume["state"] == "ready":
                return
            status, _ = self.engine.call("init", init_command(image_id, self.inst["retention"], self.user, mapping))
            if status != 0 or not still_named(volumes, volume["pin"]) \
                    or (held is not None and volume_pin(os.fstat(held)) != volume["pin"]):
                raise Failure("failed")
            volume["state"] = "ready"
            self.directory.write_json("resource.json", record)
        finally:
            if held is not None:
                os.close(held)
            volumes.close()

    def wait(self):
        """Waits for the host's `stop`. Writes nothing."""
        while True:
            self.session.wait((), None)
            if self.session.lost:
                return None
            if self.session.stops:
                stop = self.session.stops.pop(0)
                start = self.request
                if stop["operation"] == start["operation"] \
                        or any(stop[k] != start[k] for k in ("run", "resource", "execution", "instance")) \
                        or stop["generation"] != start["generation"]:
                    self.session.refused = "binding_mismatch"
                    return None
                return stop

    # Settlement.

    def teardown(self, graceful):
        """(settled, clean): the container removed (gracefully only when
        asked), the engine child killed and removed with every leader
        reaped, the store disposed of and removed, every tool child gone.
        A shared store's container (Provider.remove_shared): settled only
        once it is confirmed gone. Graceful: removed first, while conmon,
        in the engine child, still lives to reap the container's init
        (killed first, that init is a zombie orphaned here, and Podman's
        stop waits on its pid until it times out); the local children are
        settled whatever its outcome, a failure left to a later stop.
        Otherwise: after the engine child."""
        removed = False
        # One bound, fixed here, for the engine's kill and every child's reap.
        deadline = self.session.cleanup_deadline()
        shared = self.inst.get("shared") or {}
        intent = shared.get("intent") or (shared.get("prepare") or {}).get("intent")
        if self.engine is not None or self.inst.get("engine") or self.inst.get("store") or intent:
            self.admission = close_admission(self.idir, self.inst)
            if self.admission is None:
                # A bridge may still be between its check and its spawn:
                # engine and store stay for a later stop.
                if self.archive >= 0:
                    os.close(self.archive)
                    self.archive = -1
                return False, False
        if graceful and not self.shared and self.engine is not None and self.inst.get("container"):
            try:
                status, _ = self.engine.call("rm", ["rm", "--force", "--time=0", self.inst["container"]])
                removed = status == 0
            except (Failure, Interrupted, OSError):
                removed = False
        early = None
        if graceful and self.shared and self.engine is not None:
            # Bounded by the stop's own deadline: KILL_RESERVE stays for
            # the kills and reaps below.
            try:
                early = self.p.remove_shared(self.inst, self.ledger, self.idir, until=deadline - common.KILL_RESERVE)
            except Exception as caught:  # noqa: BLE001 - unconfirmed; the local settlement goes on
                diagnostic(f"teardown: {type(caught).__name__}")
                early = False, None
        settled = True
        if self.engine is not None:
            settled = self.engine.settle(deadline)
            if settled:
                self.inst["engine"] = self.inst["engine_identity"] = None
                self.save()
        if self.store_dir is not None:
            self.store_dir.close()
        if self.archive >= 0:
            os.close(self.archive)
            self.archive = -1
        settled = self.p.settle_holder(self.inst, self.custody, self.ledger) and settled
        if early is not None:
            removed, self.code = early
        elif settled and self.shared:
            settled, self.code = self.p.remove_shared(self.inst, self.ledger, self.idir)
            removed = settled
        # Dead is not reaped: pause, conmon and their exit commands were
        # orphaned to this subreaper, a leader may still be unreaped.
        if settled and not common.settle_children(deadline):
            diagnostic("owner: adopted children unconfirmed")
            settled = False
        if early is not None:
            settled = settled and removed
        clean = graceful and settled and removed and self.volume_intact()
        return settled, clean

    def volume_intact(self):
        if not self.inst.get("volume_used"):
            return True
        if self.shared:
            # The user's store: the volume is its name; flushed.
            self.p.host.sync()
            return True
        volumes = self.directory.sub("volumes")
        if volumes is None:
            return False
        try:
            if not still_named(volumes, self.record["volume"]["pin"]):
                return False
            self.p.host.sync()
            return True
        finally:
            volumes.close()

    def finish(self, stop=None, error=None):
        lost = isinstance(error, Interrupted) and error.reason == "lost" or self.session.lost
        graceful = stop is not None and not lost and not self.session.cancelled
        try:
            settled, clean = self.teardown(graceful)
        except Exception as caught:  # noqa: BLE001 - nothing is certified then
            diagnostic(f"teardown: {type(caught).__name__}")
            settled, clean = False, False
        op = self.p.request
        try:
            if not settled:
                # An engine, store or tool debt is unconfirmed (or a shared
                # container's removal): the record and every file stay for a
                # later stop by this handle.
                self.save()
                if not lost:
                    self.session.send(_failed(op, Failure(self.code or "failed", "unsettled", "uncertain")))
                return None
            remove_secrets(self.idir)
            clear_diag(self.idir)
            self.inst["result"] = instance_result(self.record, self.inst, clean)
            self.inst["phase"] = "settled"
            self.save()
            if self.held is None:
                self.held = self.directory.lock("lock", block=True, deadline=time.monotonic() + common.KILL_RESERVE)
            if self.held is not None:
                record = self.directory.read_json("resource.json")
                self.p.roll_forward(self.directory, record, save=True)
            result = self.inst["result"]
            if lost:
                return None
            if stop is not None:
                self.session.send({"type": "stopped", "operation": stop["operation"], "run": stop["run"],
                                   "resource": stop["resource"], "execution": stop["execution"],
                                   "instance": stop["instance"], "settlement": "settled",
                                   "durability": result["durability"], "generation": result["generation"],
                                   "storage": result["storage"]})
            else:
                code = error.code if error is not None else "failed"
                self.session.send(_failed(op, Failure(code, "settled", result["durability"])))
            return None
        finally:
            if self.admission is not None:
                os.close(self.admission)
                self.admission = None
            if self.held is not None:
                os.close(self.held)
                self.held = None
            os.close(self.owner_lock)
            self.idir.close()
            self.directory.close()


# ---------------------------------------------------------------------------
# connect: one bridge.

class Bridge:
    """`connect STATE RUN EXECUTION INSTANCE`: raw SSH bytes for one live
    instance, its exact binding and custody domain checked. Admission is a
    shared lock the owner's stop takes exclusively: once `stopping` is
    recorded no bridge starts. The bridge process (`podman exec ... sshd
    -i` with the instance's own profile) joins the engine child, so it and
    everything it starts go with that child; the relay here holds no
    store state and ends at the leader's exit, never waiting for a pipe
    end some descendant may hold. What the leader detaches (its conmon)
    is adopted here and killed and reaped before this bridge exits
    (`end`)."""

    def __init__(self, state, run, execution, instance, host):
        self.state, self.run, self.execution, self.instance, self.host = state, run, execution, instance, host
        self.signalled = False
        self.process = None

    def main(self):
        def handler(_signum, _frame):
            self.signalled = True
        self.wake_r, self.wake_w = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(number, handler)
        signal.signal(signal.SIGPIPE, signal.SIG_IGN)
        signal.set_wakeup_fd(self.wake_w, warn_on_full_buffer=False)
        try:
            self.host.subreaper()
            to_child, from_child = self.admit()
        except (Failure, OSError, ValueError, KeyError, TypeError) as error:
            code = error.code if isinstance(error, Failure) else type(error).__name__
            diagnostic(f"connect refused: {code}")
            return 2
        try:
            self.relay(to_child, from_child)
        finally:
            self.end()
        return 0

    def admit(self):
        custody = self.host.custody()
        root = Dir.root(self.state)
        bindings = root.sub("bindings")
        binding = bindings.read_json(self.instance) if bindings is not None else None
        if binding is None:
            raise Failure("not_found")
        if binding.get("run") != self.run or binding.get("execution") != self.execution \
                or not protocol.is_id(binding.get("resource")):
            raise Failure("binding_mismatch")
        resources = root.sub("resources")
        directory = resources.sub(binding["resource"]) if resources is not None else None
        instances = directory.sub("instances") if directory is not None else None
        idir = instances.sub(self.instance) if instances is not None else None
        if idir is None:
            raise Failure("not_found")
        inst = idir.read_json("instance.json")
        if inst is None or inst.get("schema") != INSTANCE_SCHEMA or [inst.get(k) for k in (
                "run", "resource", "execution", "instance")] != [self.run, binding["resource"], self.execution,
                                                                 self.instance]:
            raise Failure("binding_mismatch")
        if inst.get("phase") != "live" or not idir.held("owner.lock"):
            raise Failure("not_found")
        if not custody.same(inst["custody"]):
            raise Failure("busy")
        programs = self.host.programs()
        if programs != inst["programs"]:
            raise Failure("prerequisite")
        if inst.get("engine_store") == "shared":
            # The owner's profile: its recorded environment, STATE/shared
            # as it must be (never made here).
            provider = Provider(self.state, self.host, None)
            try:
                store = provider.shared_profile(inst["engine_env"], create=False)
            finally:
                provider.root.close()
        else:
            store = self.private_store(inst, programs)
        if inst["engine_identity"] is None:
            raise Failure("not_found")
        engine = custody.existing(inst["engine"], inst["engine_identity"])
        if engine is None:
            raise Failure("not_found")
        try:
            lock = os.open("admission.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=idir.fd)
        except OSError:
            raise Failure("not_found") from None
        try:
            deadline = time.monotonic() + ADMISSION_WAIT
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise Failure("busy") from None
                    time.sleep(common.SETTLE_POLL)
            inst = idir.read_json("instance.json")
            if inst.get("phase") != "live" or not _HEX64.match(inst.get("container") or ""):
                raise Failure("not_found")
            self.host.admitted()
            # A shared store: its helper checked just before the spawn.
            store.preflight()
            child_in, to_child = os.pipe2(os.O_CLOEXEC)
            from_child, child_out = os.pipe2(os.O_CLOEXEC)
            try:
                self.process = spawn(store.argv(exec_command(inst["container"])), store.env(), engine,
                                     stdin=child_in, stdout=child_out, stderr=subprocess.DEVNULL)
            except Failure:
                for fd in (to_child, from_child):
                    os.close(fd)
                raise
            finally:
                os.close(child_in)
                os.close(child_out)
        finally:
            os.close(lock)
            engine.close()
        return to_child, from_child

    def private_store(self, inst, programs):
        """The instance's private store, the very one, with exactly the
        owner's engine profile."""
        recorded = inst["store"]
        root_dir = self.host.storage_root(recorded["root"])
        store = Store(root_dir.join(recorded["name"]), programs, volumes=inst["volumes"],
                      search=self.host.search())
        try:
            if identity(os.fstat(root_dir.fd)) != recorded["root_identity"]:
                raise Failure("failed")
            fd = os.open(recorded["name"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=root_dir.fd)
            pinned = Dir(fd, store.path)
            try:
                if identity(os.fstat(fd)) != recorded["identity"] or not store.matches(pinned):
                    raise Failure("failed")
            finally:
                pinned.close()
        finally:
            root_dir.close()
        return store

    def relay(self, to_child, from_child):
        """stdin -> the bridge, the bridge -> stdout, bounded buffers with
        backpressure. Ends when the leader exits (what its pipe then holds
        is flushed), when the client is gone, or on a signal (the leader is
        then killed through its pidfd)."""
        process = self.process
        for fd in (0, 1, to_child, from_child):
            os.set_blocking(fd, False)
        up = down = b""
        client_in = child_out = True
        client_out = to_open = True
        while not self.signalled:
            selector = selectors.DefaultSelector()
            if client_in and len(up) < RELAY_CHUNK:
                selector.register(0, selectors.EVENT_READ, "client_in")
            if up and to_open:
                selector.register(to_child, selectors.EVENT_WRITE, "to_child")
            if child_out and len(down) < RELAY_CHUNK:
                selector.register(from_child, selectors.EVENT_READ, "child_out")
            if down and client_out:
                selector.register(1, selectors.EVENT_WRITE, "client_out")
            if process.pidfd >= 0:
                selector.register(process.pidfd, selectors.EVENT_READ, "leader")
            selector.register(self.wake_r, selectors.EVENT_READ, "wake")
            events = selector.select(None if process.pidfd >= 0 else 0.5)
            selector.close()
            for key, _ in events:
                try:
                    if key.data == "client_in":
                        data = os.read(0, RELAY_CHUNK)
                        if data:
                            up += data
                        else:
                            client_in = False
                    elif key.data == "to_child":
                        up = up[os.write(to_child, up):]
                    elif key.data == "child_out":
                        data = os.read(from_child, RELAY_CHUNK)
                        if data:
                            down += data
                        else:
                            child_out = False
                    elif key.data == "client_out":
                        down = down[os.write(1, down):]
                    elif key.data == "wake":
                        os.read(self.wake_r, 512)
                except BlockingIOError:
                    pass
                except OSError as error:
                    if key.data == "to_child":
                        to_open, up = False, b""
                    elif key.data == "client_out" or error.errno != errno.EPIPE:
                        return
            if not client_in and not up and to_open:
                os.close(to_child)
                to_open = False
            if not child_out and not down and client_out:
                os.close(1)
                client_out = False
            if process.poll() is not None:
                self.flush(from_child, down if client_out else None)
                return

    def flush(self, from_child, down):
        """After the leader's exit: what its pipe holds now, then stdout,
        within RELAY_FLUSH; never waiting for that pipe's end."""
        if down is None:
            return
        deadline = time.monotonic() + RELAY_FLUSH
        while len(down) < 1 << 22:
            try:
                data = os.read(from_child, RELAY_CHUNK)
            except (BlockingIOError, OSError):
                break
            if not data:
                break
            down += data
        while down and time.monotonic() < deadline:
            try:
                down = down[os.write(1, down):]
            except BlockingIOError:
                selectors.DefaultSelector().select(0.05)
            except OSError:
                return

    def end(self):
        """The leader killed through its pidfd if still running, then
        reaped; then, by the same bound, every child adopted here (an
        exec's conmon, its exit command, an sshd whose conmon died) killed
        through a pidfd and reaped (common.settle_children), never awaiting
        a pipe's end. Guest processes orphan to the container's init, not
        here: they stay in the engine child for the owner. Unconfirmed: a
        diagnostic; this bridge's exit hands the rest to the host."""
        process = self.process
        if process is None:
            return
        deadline = time.monotonic() + common.KILL_RESERVE
        if process.poll() is None:
            try:
                if process.pidfd >= 0:
                    signal.pidfd_send_signal(process.pidfd, signal.SIGKILL)
                else:
                    process.popen.kill()
            except OSError:
                pass
            process.reap(deadline)
        process.close()
        if not common.settle_children(deadline, kill=True):
            diagnostic("connect: adopted children unconfirmed")


# ---------------------------------------------------------------------------
# Entry.

def main(argv, host=None, session=None):
    try:
        args = protocol.parse_argv(argv)
    except protocol.ProtocolError:
        diagnostic("invalid_argv")
        return 2
    if args[0] == "connect":
        return Bridge(*args[1:], host or Host()).main()
    session = session or Session()
    session.install_signals()
    request = session.first()
    if request is None:
        if session.refused:
            diagnostic(f"request refused: {session.refused}")
            return 2
        return 0
    return Provider(args[1], host or Host(), session).handle(request)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
