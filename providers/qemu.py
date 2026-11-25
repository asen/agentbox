"""The QEMU/KVM jail provider (agentbox.provider v1; stdlib only).

  python3 -I providers/qemu.py control STATE

Linux x86-64 with KVM only. Trusted host code, selected and started by the
host inside a custody domain (common.Custody); README.md here. The jail
gets one restricted IPv4 user-mode NIC whose only forward is host loopback
TCP to guest port 22, a fresh NoCloud seed per execution and nothing else.

STATE (0700, the host's choice) holds the immutable image cache and every
resource, instance and checkpoint, each named by its host-assigned handle:

  inputs/                    operator-supplied build inputs (read only)
    qemu-build-inputs.json   agentbox.qemu-build-inputs.v1, files beside it
  images/IMAGE/              0500; IMAGE = SHA-256 of the standalone disk
    disk.qcow2 image.json worker-metadata.json record.json   (0400)
  work/OPERATION/            one prepare's staging; removed when it ends
  resources/RESOURCE/        resource.json, lock, disk.qcow2 (retention disk)
    instances/INSTANCE/      instance.json, owner.lock, seed.iso, logs
  checkpoints/CHECKPOINT/    checkpoint.json, lock, disk.qcow2 (0400)

Records are written before the effect they describe; an interrupted effect
is found by its handle and stays blocked (`partial`, `busy`) until an
explicit stop or discard settles it. Process ids are never handles: QEMU is
found through its pidfd while the owner lives, and through its recorded
custody child (`engine`) afterwards.
"""
import base64
import hashlib
import json
import os
import re
import resource
import shlex
import socket
import stat
import subprocess
import sys
import time

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
    BoundedSink, Custody, Dir, Failure, Interrupted, Session, Unsettled, copy_hashed, diagnostic,
    drain, fingerprint, hash_fd, read_prefix, run_tool, spawn, trusted_executable, trusted_path,
)

PROVIDER = "qemu"
RETENTION = ("none", "disk")
LIMITS = ("cpus", "memory_mib", "pids", "disk_mib")
USER = "agentbox"
# The session layout `started` names (contract: home, control): the image's
# account HOME, and the per-boot /tmp (emptied at boot by the image's
# systemd-tmpfiles) for each execution's launcher, outside the retained HOME.
GUEST_HOME = "/home/agentbox"
CONTROL_ROOT = "/tmp"
HOSTNAME = "agentbox-guest"
AUTHORIZED_KEYS = "/etc/ssh/agentbox_authorized_keys"
GUEST_HOST_KEY = "/etc/ssh/ssh_host_ed25519_key"
SEED_VOLUME = "CIDATA"

# The fixed launch profile (runtime/qemu.rs before the cutover).
MACHINE = "q35,usb=off,vmport=off,dump-guest-core=off"
SANDBOX = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"
GUEST_SSH_PORT = 22
# The host locations Packer's own config and plugin discovery reads
# (~/.config/packer/plugins by default); a relative one is refused, since
# Packer runs in scratch (Host.packer_env).
PACKER_LOCATIONS = ("HOME", "XDG_CONFIG_HOME", "PACKER_CONFIG_DIR", "PACKER_PLUGIN_PATH")
MIN_QEMU = (7, 2)
TOOLS = ("qemu-system-x86_64", "qemu-img", "ssh-keygen", "xorriso")

DEFAULT_CPUS = 2
DEFAULT_MEMORY_MIB = 4096
DEFAULT_PIDS = 512
MEMORY_OVERHEAD_MIB = 512
DISK_HEADROOM = 1 << 30
MAX_VIRTUAL_SIZE = 64 << 30
GRACE_SECONDS = 60.0
CONSOLE_BYTES = 1 << 20
QEMU_LOG_BYTES = 64 << 10
PACKER_LOG_BYTES = 1 << 20
QMP_MAX_LINE = 65536
QMP_MAX_EVENTS = 64
MAX_SEED_BYTES = 4 << 20

RESOURCE_SCHEMA = "agentbox.qemu-resource.v1"
INSTANCE_SCHEMA = "agentbox.qemu-instance.v1"
CHECKPOINT_SCHEMA = "agentbox.qemu-checkpoint.v1"
CACHE_SCHEMA = "agentbox.qemu-cache.v1"
CACHE_FILES = ("disk.qcow2", "image.json", "worker-metadata.json", "record.json", ".record.json.tmp")
# Prepare admission (not a quota): free space on STATE for one build, and
# leftover work/ residue entries tolerated before a refusal.
PREPARE_MIN_FREE = 8 << 30
WORK_RESIDUE = 8
# The canonical recipe's check boot (Provider.check_boot): the finished
# disk booted once as a jail boots, before it is published.
CHECK_TOOLS = ("ssh", "ssh-keygen", "xorriso")
CHECK_ALIAS = "agentbox-prepare-check"
CHECK_READY_SECONDS = 600.0
CHECK_SCRIPT_SECONDS = 300
CHECK_POWERDOWN_SECONDS = 120.0
CHECK_OUT_BYTES = 64 << 10
MAX_CHECK_COMMAND = 96 << 10
CHECK_OK = "agentbox-check-ok"
# The canonical image's baked agents (images/qemu/default/guest-install.py).
AGENTS_ROOT = "/opt/agentbox-agents"
# The SSH client's own errors, by its fixed messages: the check's diagnostic
# names one of these, never the text.
CHECK_SSH_ERRORS = (("Host key verification failed", "ssh host key"), ("Permission denied", "ssh denied"),
                    ("Connection closed", "ssh closed"), ("Connection reset", "ssh reset"),
                    ("Connection refused", "ssh refused"), ("timed out", "ssh timeout"))
CHECK_KERNEL = "agentbox-check-kernel "
# The SSH client's fixed profile (agentbox_controller/ssh.py OPTIONS): the
# seeded host key pinned under an alias, the fresh client key only.
CHECK_SSH_OPTIONS = (
    "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "CheckHostIP=no",
    "GlobalKnownHostsFile=none", "VerifyHostKeyDNS=no", "HostKeyAlgorithms=ssh-ed25519",
    "KnownHostsCommand=none", "IdentitiesOnly=yes", "IdentityAgent=none", "AddKeysToAgent=no",
    "PKCS11Provider=none", "PubkeyAuthentication=yes", "PubkeyAcceptedAlgorithms=ssh-ed25519",
    "PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
    "HostbasedAuthentication=no", "EnableSSHKeysign=no", "GSSAPIAuthentication=no", "ForwardAgent=no",
    "ForwardX11=no", "ForwardX11Trusted=no", "ControlMaster=no", "ControlPath=none", "ControlPersist=no",
    "ProxyCommand=none", "ProxyJump=none", "PermitLocalCommand=no", "ClearAllForwardings=yes",
    "SessionType=default", "Tunnel=no", "RequestTTY=no", "EscapeChar=none", "CanonicalizeHostname=no",
    "ServerAliveInterval=5", "ServerAliveCountMax=3", "ConnectTimeout=10", "ConnectionAttempts=1",
    "LogLevel=ERROR")
CANONICAL_RECIPE = os.path.join(ROOT, "images", "qemu", "default", "agentbox.pkr.hcl")
# Every name a settled or interrupted instance directory may hold.
INSTANCE_FILES = ("instance.json", ".instance.json.tmp", "owner.lock", "seed.iso", "console.log",
                  "qemu.log", "disk.qcow2", "host_ed25519", "host_ed25519.pub", "user-data", "meta-data")
SECRET_FILES = ("host_ed25519", "host_ed25519.pub", "user-data", "meta-data", "seed.iso")


# ---------------------------------------------------------------------------
# QCOW2 headers: bounded checks before any tool or QEMU opens a disk.

class QcowError(Exception):
    pass


MAGIC = b"QFI\xfb"
V3_HEADER = 104
MAX_HEADER_BYTES = 2 << 20
MAX_EXTENSIONS = 64
MAX_BACKING_BYTES = 1023
EXT_END = 0
EXT_BACKING_FORMAT = 0xE2792ACA
EXT_FEATURE_TABLE = 0x6803F857
EXT_CRYPTO = 0x0537BE77
EXT_DATA_FILE = 0x44415441
INCOMPAT_DIRTY, INCOMPAT_CORRUPT, INCOMPAT_DATA_FILE = 1, 2, 4
COMPAT_LAZY_REFCOUNTS = 1
AUTOCLEAR_DATA_FILE_RAW = 2


def _u32(data, offset):
    return int.from_bytes(data[offset:offset + 4], "big")


def _u64(data, offset):
    return int.from_bytes(data[offset:offset + 8], "big")


def _header(prefix, file_bytes):
    """The v3 header's fields and extensions; refuses anything malformed."""
    if len(prefix) < V3_HEADER or prefix[:4] != MAGIC:
        raise QcowError("invalid")
    if _u32(prefix, 4) != 3:
        raise QcowError("unsupported")
    h = {"backing_offset": _u64(prefix, 8), "backing_size": _u32(prefix, 16),
         "cluster_bits": _u32(prefix, 20), "size": _u64(prefix, 24), "crypt": _u32(prefix, 32),
         "l1_size": _u32(prefix, 36), "l1_offset": _u64(prefix, 40), "refcount_offset": _u64(prefix, 48),
         "refcount_clusters": _u32(prefix, 56), "snapshots": _u32(prefix, 60),
         "incompatible": _u64(prefix, 72), "compatible": _u64(prefix, 80), "autoclear": _u64(prefix, 88),
         "refcount_order": _u32(prefix, 96), "header_length": _u32(prefix, 100)}
    if not 9 <= h["cluster_bits"] <= 21:
        raise QcowError("invalid")
    cluster = 1 << h["cluster_bits"]
    limit = min(len(prefix), cluster)
    length = h["header_length"]
    if length < V3_HEADER or length % 8 or length > limit:
        raise QcowError("invalid")
    h["compression"] = prefix[V3_HEADER] if length > V3_HEADER else 0
    extensions, offset = {}, length
    while True:
        if offset + 8 > limit or len(extensions) >= MAX_EXTENSIONS:
            raise QcowError("invalid")
        kind, size = _u32(prefix, offset), _u32(prefix, offset + 4)
        if kind == EXT_END:
            offset += 8
            break
        end = offset + 8 + size + (8 - size % 8) % 8
        if end > limit or kind in extensions:
            raise QcowError("invalid")
        extensions[kind] = prefix[offset + 8:offset + 8 + size]
        offset = end
    h["extensions"], h["end"] = extensions, offset
    mapped = h["l1_size"] * (cluster // 8) * cluster

    def inside(at, size):
        return at != 0 and at % cluster == 0 and at + size <= file_bytes

    if h["size"] == 0 or mapped < h["size"]:
        raise QcowError("invalid")
    if not inside(h["l1_offset"], h["l1_size"] * 8) or h["refcount_clusters"] == 0 \
            or not inside(h["refcount_offset"], h["refcount_clusters"] * cluster):
        raise QcowError("incomplete")
    return h


def check_standalone(prefix, file_bytes):
    """A supported standalone QCOW2 v3:
    no backing file, external data file, encryption, snapshots, dirty or
    corrupt bit; 16-bit refcounts; zlib; only the feature-name table.
    Returns its virtual size."""
    h = _header(prefix, file_bytes)
    ext = h["extensions"]
    if h["backing_offset"] or h["backing_size"] or EXT_BACKING_FORMAT in ext:
        raise QcowError("backing")
    if h["incompatible"] & INCOMPAT_DATA_FILE or h["autoclear"] & AUTOCLEAR_DATA_FILE_RAW \
            or EXT_DATA_FILE in ext:
        raise QcowError("external_data")
    if h["crypt"] or EXT_CRYPTO in ext:
        raise QcowError("encrypted")
    if h["incompatible"] & INCOMPAT_DIRTY:
        raise QcowError("dirty")
    if h["incompatible"] & INCOMPAT_CORRUPT:
        raise QcowError("corrupt")
    if h["incompatible"] or h["compatible"] & ~COMPAT_LAZY_REFCOUNTS or h["autoclear"] \
            or h["snapshots"] or h["refcount_order"] != 4 or h["compression"] \
            or any(kind != EXT_FEATURE_TABLE for kind in ext) or h["size"] > MAX_VIRTUAL_SIZE:
        raise QcowError("unsupported")
    return h["size"]


def check_overlay(prefix, file_bytes, base, virtual_size):
    """A private overlay (run.rs check_overlay): backed by exactly `base`
    as qcow2, no other extension, feature, data file or encryption, and the
    base's virtual size."""
    h = _header(prefix, file_bytes)
    ext = h["extensions"]
    if any(kind not in (EXT_BACKING_FORMAT, EXT_FEATURE_TABLE) for kind in ext):
        raise QcowError("invalid")
    if not h["backing_offset"] or not 0 < h["backing_size"] <= MAX_BACKING_BYTES:
        raise QcowError("backing")
    start, limit = h["backing_offset"], min(len(prefix), 1 << h["cluster_bits"])
    if start < h["end"] or start + h["backing_size"] > limit:
        raise QcowError("invalid")
    if prefix[start:start + h["backing_size"]] != base.encode() or ext.get(EXT_BACKING_FORMAT) != b"qcow2":
        raise QcowError("backing")
    if h["crypt"] or h["incompatible"] or h["compatible"] & ~COMPAT_LAZY_REFCOUNTS or h["autoclear"] \
            or h["snapshots"] or h["refcount_order"] != 4 or h["compression"] or h["size"] != virtual_size:
        raise QcowError("invalid")


def check_report_ok(report, path):
    """`qemu-img check --output=json`: no errors, corruptions or leaks."""
    return isinstance(report, dict) and report.get("filename") == path and report.get("format") == "qcow2" \
        and report.get("check-errors") == 0 \
        and all(report.get(key, 0) == 0 for key in ("corruptions", "leaks", "corruptions-fixed", "leaks-fixed"))


def info_report_ok(info, path, virtual_size, base=None):
    """`qemu-img info --output=json`: exactly a v3 qcow2 of the size, with
    no backing file (base) or backed by exactly `base` (overlay)."""
    if not isinstance(info, dict):
        return False
    spec = info.get("format-specific")
    data = spec.get("data") if isinstance(spec, dict) else None
    backing = ("backing-filename", "full-backing-filename", "backing-filename-format")
    if base is None:
        chain = all(key not in info for key in backing)
    else:
        chain = [info.get(key) for key in backing] == [base, base, "qcow2"]
    return chain and info.get("format") == "qcow2" and info.get("filename") == path \
        and info.get("virtual-size") == virtual_size and info.get("encrypted") in (None, False) \
        and info.get("dirty-flag") in (None, False) and info.get("snapshots") in (None, []) \
        and isinstance(data, dict) and spec.get("type") == "qcow2" and data.get("compat") == "1.1" \
        and data.get("corrupt") in (None, False) and data.get("extended-l2") in (None, False) \
        and data.get("bitmaps") in (None, []) and "data-file" not in data and "encrypt" not in data


def check_seed(data):
    """An ISO 9660 image whose primary volume descriptor names CIDATA."""
    pvd = data[16 * 2048:17 * 2048]
    return len(pvd) == 2048 and pvd[0] == 1 and pvd[1:6] == b"CD001" and pvd[6] == 1 \
        and pvd[40:72] == SEED_VOLUME.encode().ljust(32)


# ---------------------------------------------------------------------------
# The fixed launch profile and the per-execution seed.

def limits_of(request_limits, virtual_size):
    """Requested limits with defaults: (cpus, memory_mib, pids, disk ceiling bytes)."""
    cpus = request_limits.get("cpus", DEFAULT_CPUS)
    memory = request_limits.get("memory_mib", DEFAULT_MEMORY_MIB)
    pids = request_limits.get("pids", DEFAULT_PIDS)
    disk = request_limits["disk_mib"] << 20 if "disk_mib" in request_limits else virtual_size + DISK_HEADROOM
    return cpus, memory, pids, disk


def engine_limits(cpus, memory_mib, pids):
    """The engine child's cgroup limits; QEMU joins it before it runs."""
    return {"cpu.max": f"{cpus * 100000} 100000",
            "memory.max": str((memory_mib + MEMORY_OVERHEAD_MIB) << 20),
            "memory.swap.max": "0",
            "pids.max": str(pids)}


def _blockdev(node):
    return ["-blockdev", json.dumps(node, separators=(",", ":"))]


def qemu_argv(program, base, overlay, seed, port, qmp_fd, cpus, memory_mib):
    """The whole command: KVM, no user config or default devices, seccomp,
    no display or human monitor, the console on stdout, QMP only on the
    inherited socket `qmp_fd`. The chain is explicit: the base read-only,
    the overlay backed by that node (never by its header's name), the seed
    read-only. Paths are JSON strings and cannot add options. One
    restricted IPv4 NIC with one loopback forward to guest port 22."""
    if len({base, overlay, seed}) != 3 or not all(protocol.is_path(p) for p in (base, overlay, seed)) \
            or not 1024 <= port <= 65535:
        raise Failure("failed")
    args = [program, "-no-user-config", "-nodefaults",
            "-machine", MACHINE, "-accel", "kvm", "-cpu", "host",
            "-smp", str(cpus), "-m", f"{memory_mib}M",
            "-sandbox", SANDBOX, "-display", "none", "-monitor", "none",
            "-chardev", "stdio,id=console,signal=off", "-serial", "chardev:console",
            "-chardev", f"socket,id=qmp,fd={qmp_fd},server=off", "-mon", "chardev=qmp,mode=control"]
    args += _blockdev({"driver": "file", "node-name": "base-file", "filename": base, "read-only": True,
                       "locking": "on"})
    args += _blockdev({"driver": "qcow2", "node-name": "base", "file": "base-file", "read-only": True})
    args += _blockdev({"driver": "file", "node-name": "overlay-file", "filename": overlay, "locking": "on"})
    args += _blockdev({"driver": "qcow2", "node-name": "overlay", "file": "overlay-file", "backing": "base"})
    args += _blockdev({"driver": "file", "node-name": "seed-file", "filename": seed, "read-only": True,
                       "locking": "on"})
    args += _blockdev({"driver": "raw", "node-name": "seed", "file": "seed-file", "read-only": True})
    args += ["-device", "virtio-blk-pci,drive=overlay,bootindex=1",
             "-device", "virtio-blk-pci,drive=seed",
             "-netdev", f"user,id=net0,restrict=on,ipv4=on,ipv6=off,"
                        f"hostfwd=tcp:127.0.0.1:{port}-:{GUEST_SSH_PORT}",
             "-device", "virtio-net-pci,netdev=net0,romfile="]
    return args


def user_data(authorized_key, host_private, host_public):
    """The fixed offline NoCloud document: one locked-password user, root
    management files (authorized key, host key pair) written on every boot
    before sshd (the image's ssh.service waits for cloud-init and these
    files), nothing else configured, run or fetched."""
    config = {
        "users": [{"name": USER, "lock_passwd": True, "shell": "/bin/bash",
                   "sudo": "ALL=(ALL) NOPASSWD:ALL"}],
        "disable_root": True, "ssh_pwauth": False, "allow_public_ssh_keys": False,
        "ssh_deletekeys": True, "ssh_genkeytypes": [], "ssh_publish_hostkeys": {"enabled": False},
        "package_update": False, "package_upgrade": False, "package_reboot_if_required": False,
        "cloud_init_modules": ["seed_random", ["write_files", "always"], "set_hostname", "update_hostname",
                               "update_etc_hosts", "users_groups"],
        "write_files": [
            {"path": AUTHORIZED_KEYS, "owner": "root:root", "permissions": "0644", "append": False,
             "defer": False, "content": authorized_key + "\n"},
            {"path": GUEST_HOST_KEY, "owner": "root:root", "permissions": "0600", "append": False,
             "defer": False, "content": host_private},
            {"path": GUEST_HOST_KEY + ".pub", "owner": "root:root", "permissions": "0644", "append": False,
             "defer": False, "content": host_public + "\n"},
        ],
    }
    return b"#cloud-config\n" + json.dumps(config, indent=2).encode() + b"\n"


def meta_data(instance_id):
    return json.dumps({"instance-id": instance_id, "local-hostname": HOSTNAME}, indent=2).encode() + b"\n"


def bare_key(text):
    """'ssh-ed25519 BASE64[ comment]' -> the contract's bare key, checked."""
    parts = text.strip().split(" ")
    if len(parts) not in (2, 3):
        raise Failure("failed")
    key = parts[0] + " " + parts[1]
    try:
        protocol._ssh_key(key)
    except protocol.ProtocolError:
        raise Failure("failed") from None
    return key


_PRIVATE = re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----\n[A-Za-z0-9+/=\n]{64,4096}"
                      r"-----END OPENSSH PRIVATE KEY-----\n\Z")


# ---------------------------------------------------------------------------
# QMP: fixed commands on a private socketpair; bounded reads.

class Qmp:
    COMMANDS = ("qmp_capabilities", "system_powerdown")

    def __init__(self, sock):
        self.sock = sock
        sock.setblocking(False)
        self.buffer = b""
        self.greeted = self.closed = self.broken = False
        self.returns, self.events = [], []

    def fileno(self):
        return self.sock.fileno()

    def pump(self):
        while not self.closed:
            try:
                data = self.sock.recv(65536)
            except BlockingIOError:
                break
            except OSError:
                data = b""
            if not data:
                self.closed = True
                break
            self.buffer += data
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                self._message(line)
            if len(self.buffer) > QMP_MAX_LINE:
                self.broken, self.buffer = True, b""

    def _message(self, line):
        try:
            value = json.loads(line) if len(line) <= QMP_MAX_LINE else None
        except ValueError:
            value = None
        if not isinstance(value, dict):
            self.broken = True
        elif "QMP" in value:
            self.greeted = True
        elif "return" in value or "error" in value:
            self.returns.append("error" not in value)
        elif isinstance(value.get("event"), str) and len(self.events) < QMP_MAX_EVENTS:
            data = value.get("data") if isinstance(value.get("data"), dict) else {}
            self.events.append((value["event"], data.get("guest") is True, data.get("reason")))

    def send(self, command):
        if command not in self.COMMANDS:
            raise ValueError("qmp")
        data = json.dumps({"execute": command}).encode() + b"\n"
        try:
            self.sock.sendall(data)
        except OSError:
            self.broken = True

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------------------
# Host effects.

class Host:
    """Production effects: trusted installed tools, KVM, the custody
    domain, image staging. Tests substitute their own subclass; there is no
    switch that weakens a check here."""

    def __init__(self, environ=None):
        self.environ = os.environ if environ is None else environ
        self._custody = None
        self._tools = {}

    def tool(self, name):
        """Resolved once per invocation; the same path for every use."""
        if name not in self._tools:
            self._tools[name] = trusted_executable(name, self.environ)
        return self._tools[name]

    def tool_env(self):
        """The whole environment of a directly run tool and of QEMU
        (common.tool_env): the usable host PATH, for a wrapper's own
        interpreter, and LC_ALL=C."""
        return common.tool_env(self.environ)

    def packer_env(self):
        """The host environment Packer runs with: this invocation's own
        (the host's, tools.rs host_env) but Agentbox's AGENTBOX_* variables,
        its PATH the usable host one (common.host_search, for Packer's own
        qemu-img and QEMU lookups), so its normal config, plugin, proxy and
        credential discovery is the host's; the caller adds scratch. Packer
        runs in scratch, so a relative PACKER_LOCATIONS value (any
        PACKER_PLUGIN_PATH entry included) would mean another place:
        refused (`prerequisite`), never reinterpreted."""
        env = {name: value for name, value in self.environ.items()
               if name != "PATH" and not name.startswith("AGENTBOX_")}
        search = common.host_search(self.environ)
        if search is not None:
            env["PATH"] = search
        for name in PACKER_LOCATIONS:
            value = env.get(name, "")
            parts = value.split(":") if name == "PACKER_PLUGIN_PATH" else [value]
            if not all(part.startswith("/") for part in parts if part):
                raise Failure("prerequisite")
        return env

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

    def kvm(self):
        if not sys.platform.startswith("linux") or os.uname().machine != "x86_64":
            raise Failure("prerequisite")
        try:
            st = os.stat("/dev/kvm")
        except OSError:
            raise Failure("prerequisite") from None
        if not stat.S_ISCHR(st.st_mode) or not os.access("/dev/kvm", os.R_OK | os.W_OK):
            raise Failure("prerequisite")

    def stage(self, repo, inputs, out):
        import stage
        return stage.stage_qemu(repo, inputs, out)

    def publish(self, stage_dir, output):
        import stage
        return stage.publish(stage_dir, output)

    def free_port(self):
        """A loopback port free now; QEMU binds it itself and fails if it
        was taken meanwhile (the host's pinned host key covers the rest)."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def banner(self, port, timeout):
        """Whether the forward answers with an SSH-2.0 banner (bounded)."""
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
                conn.settimeout(timeout)
                data = b""
                while b"\n" not in data and len(data) < 256:
                    chunk = conn.recv(256 - len(data))
                    if not chunk:
                        break
                    data += chunk
                return data.startswith(b"SSH-2.0-")
        except OSError:
            return False


def _worker():
    import worker
    return worker


# ---------------------------------------------------------------------------
# The provider.

def _failed(request, error):
    return {"type": "failed", "operation": request["operation"], "op": request["type"],
            "code": error.code, "settlement": error.settlement, "durability": error.durability}


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
        if answer is not None:
            self.session.send(answer)
        return 0

    # Tools.

    def tool(self, name, args, out_limit=1 << 20, log=None, cwd=None, env=None, ledger=None, err_sink=None):
        """A tool in its own custody child, recorded in `ledger` (the
        handle's record; else this invocation's scratch ledger) before it
        exists and until it is confirmed gone."""
        if ledger is None and self.scratch is not None:
            ledger = self.scratch
        self.tools_run += 1
        child = f"tool-{self.request['operation']}-{self.tools_run}"
        env = self.host.tool_env() if env is None else env
        return run_tool(self.session, self.host.custody(), child, [self.host.tool(name)] + args, env,
                        out_limit=out_limit, log=log, cwd=cwd, ledger=ledger, err_sink=err_sink,
                        durability="unchanged" if type(ledger) is common.Ledger else "uncertain")

    def settle_debts(self, record, custody):
        return common.settle_debts(record, custody)

    # Cache publication effects (a test may fault them).

    def write_entry(self, entry, name, data):
        out = entry.create(name, 0o400)
        try:
            os.write(out, data)
            os.fsync(out)
        finally:
            os.close(out)

    def tool_json(self, args, ledger=None):
        status, out = self.tool("qemu-img", args, ledger=ledger)
        try:
            return status, json.loads(out)
        except ValueError:
            return status, None

    # Images.

    def image(self, image, full):
        """The cached image `image` checked: its record, mode, fingerprint
        and header, and with `full` its digest and worker metadata.
        Returns {path, virtual_size, worker}."""
        try:
            images = self.root.sub("images")
            entry = images.sub(image, modes=(0o500,)) if images is not None else None
        except Failure:
            raise Failure("failed") from None
        if entry is None:
            raise Failure("not_found")
        try:
            return self._image(entry, image, full)
        except (Failure, OSError, KeyError, TypeError) as error:
            if isinstance(error, Failure) and error.code != "failed":
                raise
            raise Failure("failed") from None
        finally:
            entry.close()

    def _image(self, entry, image, full):
        """The checks of `image` on its open cache entry."""
        record = entry.read_json("record.json")
        if record is None or record.get("schema") != CACHE_SCHEMA or record.get("image") != image:
            raise Failure("failed")
        fd = entry.open_file("disk.qcow2", mode=0o400)
        try:
            st = os.fstat(fd)
            if fingerprint(st) != record["fingerprint"]:
                raise Failure("failed")
            try:
                size = check_standalone(read_prefix(fd, MAX_HEADER_BYTES), st.st_size)
            except QcowError:
                raise Failure("failed") from None
            if size != record["virtual_size"]:
                raise Failure("failed")
            if full:
                if hash_fd(fd, self.session.check, st.st_size) != image:
                    raise Failure("failed")
                worker = _worker()
                try:
                    worker.check_metadata(entry.join("worker-metadata.json"), record["worker"])
                except (worker.Refused, OSError):
                    raise Failure("failed") from None
        finally:
            os.close(fd)
        return {"path": entry.join("disk.qcow2"), "virtual_size": size, "worker": record["worker"]}

    def new_overlay(self, directory, name, image, ledger):
        """A fresh overlay `name` in `directory` on `image`, checked by its
        header and by qemu-img before anything boots it."""
        path = directory.join(name)
        base, size = image["path"], image["virtual_size"]
        status, _ = self.tool("qemu-img", ["create", "-q", "-f", "qcow2", "-b", base, "-F", "qcow2", path, str(size)],
                              ledger=ledger)
        if status != 0:
            raise Failure("failed")
        fd = directory.open_file(name, os.O_RDWR)
        try:
            os.fchmod(fd, 0o600)
            created = fingerprint(os.fstat(fd))[:2]
            try:
                check_overlay(read_prefix(fd, MAX_HEADER_BYTES), os.fstat(fd).st_size, base, size)
            except QcowError:
                raise Failure("failed") from None
            status, report = self.tool_json(["check", "--output=json", "-f", "qcow2", path], ledger)
            if status != 0 or not check_report_ok(report, path):
                raise Failure("failed")
            status, info = self.tool_json(["info", "--output=json", "-f", "qcow2", path], ledger)
            if status != 0 or not info_report_ok(info, path, size, base):
                raise Failure("failed")
            if fingerprint(os.stat(name, dir_fd=directory.fd, follow_symlinks=False))[:2] != created:
                raise Failure("failed")
            os.fsync(fd)
        finally:
            os.close(fd)
        directory.fsync()

    def op_capabilities(self, request):
        return {"type": "described", "operation": request["operation"], "provider": PROVIDER,
                "operations": list(protocol.OPERATIONS), "transport": "tcp",
                "retention": list(RETENTION), "limits": list(LIMITS), "features": []}

    # prepare

    def op_prepare(self, request):
        custody = self.host.custody()
        recipe, repo = request["recipe"], request["worker"]
        try:
            trusted_path(recipe, "file")
            trusted_path(repo, "dir")
            trusted_path(repo + "/guest", "dir")
            trusted_path(repo + "/acquisitions", "dir")
        except OSError:
            raise Failure("prerequisite") from None
        # Only the canonical recipe is booted before publication (its system
        # record and contract are this tree's); a custom recipe's image is
        # published as its build left it.
        canonical = os.path.realpath(recipe) == os.path.realpath(CANONICAL_RECIPE)
        for name in ("packer", "qemu-img", "qemu-system-x86_64") + (CHECK_TOOLS if canonical else ()):
            self.host.tool(name)
        if canonical:
            self.host.kvm()
        packer_env = self.host.packer_env()
        # One asset tree: the worker sources are this provider's own.
        if os.path.realpath(repo) != os.path.realpath(ROOT):
            raise Failure("prerequisite")
        inputs = self.root.sub("inputs", modes=(0o700, 0o500))
        if inputs is None or not inputs.exists("qemu-build-inputs.json"):
            raise Failure("prerequisite")
        self.host.growth(self.root)
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
        workdir = work.join(name)
        held = work.sub(name)
        self.scratch = common.Ledger()
        try:
            stage_dir = workdir + "/stage"
            worker = _worker()
            try:
                staged = self.host.stage(repo, inputs.join("qemu-build-inputs.json"), stage_dir)
            except worker.Refused as error:
                code = "prerequisite" if str(error) in ("inputs", "input_mismatch") else "failed"
                raise Failure(code) from None
            except (OSError, subprocess.SubprocessError):
                raise Failure("failed") from None
            self.session.check()
            # Every prepare builds: no earlier image stands in for a fresh
            # base and fresh packages.
            base = self.check_base(inputs, staged, stage_dir)
            for sub in ("tmp", "cache"):
                os.mkdir(workdir + "/" + sub, 0o700)
            # Packer's own config and plugin discovery is the host's
            # (packer_env); its temporary files and cache are this scratch's.
            # TMPDIR is relative to Packer's cwd, the scratch: its plugin
            # RPC sockets live there, and an absolute path under a long
            # STATE would pass the AF_UNIX path limit.
            env = {**packer_env, "TMPDIR": "tmp", "PACKER_CACHE_DIR": workdir + "/cache",
                   "CHECKPOINT_DISABLE": "1", "PACKER_NO_COLOR": "1"}
            scratch = Dir(os.open(workdir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC), workdir)
            log = BoundedSink(scratch, "packer.log", PACKER_LOG_BYTES)
            try:
                status, _ = self.tool("packer", ["build", "-color=false",
                                                 "-var-file=" + stage_dir + "/agentbox.pkrvars.hcl", recipe],
                                      log=log, cwd=workdir, env=env)
            finally:
                log.close()
                scratch.close()
            if status != 0:
                # Fixed and bounded: its log goes with the scratch.
                diagnostic(f"packer build failed: exit {status}")
                raise Failure("failed")
            self.base_unchanged(inputs, staged, base)
            output = stage_dir + "/output"
            try:
                published = self.host.publish(stage_dir, output)
            except (worker.Refused, OSError, ValueError, KeyError):
                raise Failure("failed") from None
            if canonical:
                published = self.record_check(output, published, self.check_boot(workdir, output, published))
            image, release = self.import_image(output, published, recipe, custody)
            prepared = {"type": "prepared", "operation": name, "image": image, "worker_sha256": release}
            if canonical:
                # The versions the build resolved and installed and the
                # check boot found by their locks (stage.check_system).
                prepared["agents"] = {agent: entry["version"]
                                      for agent, entry in published["system"]["agents"].items()}
            return prepared
        except Interrupted as error:
            if error.reason == "lost":
                raise
            raise Failure(error.code) from None
        finally:
            # Disposable once no tool child is outstanding (one may still
            # write here: then it stays, named by this operation). A
            # changed or unremovable path is left with a warning.
            if not self.scratch.outstanding and not common.remove_scratch(work, name, held.fd):
                common.warning("prepare scratch residue left")
            held.close()

    def check_boot(self, workdir, output, published):
        """The finished canonical disk booted once as a jail boots, before
        anything publishes it: a fresh overlay on it in this prepare's
        scratch, the runtime's seed (its own fresh host key) for a fresh
        client key, the runtime's launch (`qemu_argv`: the restricted NIC,
        SSH only) in its own custody child (CheckBoot). Over that pinned SSH
        as the jail's user: the baked worker exactly its metadata's (sealed,
        each file's size and SHA-256), the running kernel the build's newest
        installed one, a local Git clone, a venv running pip. Then the
        guest's own orderly power-off. Returns what it verified."""
        worker = _worker()
        system = published.get("system")
        if not isinstance(system, dict):
            raise Failure("failed")
        release = published["worker"]["release"]
        try:
            metadata = worker.check_metadata(output + "/worker-metadata.json", release)
            listed = worker.listing(metadata["manifest"].encode())
        except worker.Refused:
            raise Failure("failed") from None
        intended = system["kernel"]["intended"]
        command = check_command(release, metadata["manifest"].encode(), listed, intended, system["agents"])
        disk = output + "/agentbox.qcow2"
        fd = os.open(disk, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            size = check_standalone(read_prefix(fd, MAX_HEADER_BYTES), os.fstat(fd).st_size)
        except QcowError:
            raise Failure("failed") from None
        finally:
            os.close(fd)
        os.mkdir(workdir + "/check", 0o700)
        directory = Dir(os.open(workdir + "/check", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC),
                        workdir + "/check")
        try:
            running = CheckBoot(self, directory, {"path": disk, "virtual_size": size}).run(command)
        finally:
            directory.close()
        if running != intended:
            raise Failure("failed")
        kernel = system["kernel"]
        return {"kernel": {"build": kernel["build"], "intended": intended, "running": running,
                           "upgraded": intended != kernel["build"]},
                "ssh": "host key pinned", "worker": release, "git": "clone", "venv": "pip", "agents": "locks"}

    def record_check(self, output, published, checked):
        """image.json with what the check boot verified."""
        value = dict(published, checked=checked, status="built_native_checked")
        data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        temp = output + "/.image.json.tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp, output + "/image.json")
        return value

    def check_base(self, inputs, staged, stage_dir):
        """The staged recipe's base disk before Packer or any image tool
        reads it: the inputs' own regular file (no link, one link, ours, no
        foreign write), its declared size and digest, a standalone QCOW2
        header (no backing chain, external data file or encryption), the
        exact path the Packer variables name, then qemu-img's own view.
        Returns its fingerprint."""
        entry = staged["base"]
        path = inputs.join(entry["file"])
        try:
            fd = inputs.open_file(entry["file"])
        except (Failure, OSError):
            raise Failure("prerequisite") from None
        try:
            st = os.fstat(fd)
            if stat.S_IMODE(st.st_mode) & 0o022 or st.st_size != entry["bytes"]:
                raise Failure("prerequisite")
            try:
                size = check_standalone(read_prefix(fd, MAX_HEADER_BYTES), st.st_size)
            except QcowError:
                raise Failure("prerequisite") from None
            if hash_fd(fd, self.session.check, st.st_size) != entry["sha256"]:
                raise Failure("prerequisite")
            with open(stage_dir + "/agentbox.pkrvars.hcl", "rb") as stream:
                variables = stream.read(65536).decode()
            if f"base_image = {json.dumps(path)}\n" not in variables.splitlines(keepends=True):
                raise Failure("failed")
            status, report = self.tool_json(["check", "--output=json", "-f", "qcow2", path])
            if status != 0 or not check_report_ok(report, path):
                raise Failure("prerequisite")
            status, info = self.tool_json(["info", "--output=json", "-f", "qcow2", path])
            if status != 0 or not info_report_ok(info, path, size):
                raise Failure("prerequisite")
            self.base_unchanged(inputs, staged, fingerprint(st))
            return fingerprint(st)
        finally:
            os.close(fd)

    def base_unchanged(self, inputs, staged, before):
        try:
            now = fingerprint(os.stat(staged["base"]["file"], dir_fd=inputs.fd, follow_symlinks=False))
        except OSError:
            raise Failure("failed") from None
        if now != before:
            raise Failure("failed")

    def import_image(self, output, published, recipe, custody):
        """Validates the built disk and worker metadata and publishes them
        under the disk's digest: an immutable 0500/0400 entry
        (common.publish_entry)."""
        worker = _worker()
        disk = output + "/agentbox.qcow2"
        fd = os.open(disk, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != os.geteuid():
                raise Failure("failed")
            try:
                size = check_standalone(read_prefix(fd, MAX_HEADER_BYTES), st.st_size)
            except QcowError:
                raise Failure("failed") from None
            image = hash_fd(fd, self.session.check, st.st_size)
            if published.get("disk", {}).get("sha256") != image:
                raise Failure("failed")
            status, report = self.tool_json(["check", "--output=json", "-f", "qcow2", disk])
            if status != 0 or not check_report_ok(report, disk):
                raise Failure("failed")
            status, info = self.tool_json(["info", "--output=json", "-f", "qcow2", disk])
            if status != 0 or not info_report_ok(info, disk, size):
                raise Failure("failed")
            release = published["worker"]["release"]
            try:
                worker.check_metadata(output + "/worker-metadata.json", release)
            except worker.Refused:
                raise Failure("failed") from None
            with open(recipe, "rb") as stream:
                recipe_digest = hashlib.file_digest(stream, "sha256").hexdigest()

            def fill(entry):
                os.rename(disk, "disk.qcow2", dst_dir_fd=entry.fd)
                if fingerprint(os.stat("disk.qcow2", dir_fd=entry.fd, follow_symlinks=False))[:2] \
                        != [st.st_dev, st.st_ino]:
                    raise Failure("failed")
                os.fchmod(fd, 0o400)
                os.fsync(fd)
                for name in ("image.json", "worker-metadata.json"):
                    with open(output + "/" + name, "rb") as stream:
                        data = stream.read(1 << 22)
                    self.write_entry(entry, name, data)
                entry.write_json("record.json", {
                    "schema": CACHE_SCHEMA, "image": image, "virtual_size": size, "bytes": st.st_size,
                    "fingerprint": fingerprint(os.fstat(fd)), "worker": release,
                    "origin": {"recipe": {"path": recipe, "sha256": recipe_digest},
                               "stage_sha256": published.get("stage_sha256")}}, mode=0o400)

            images = self.root.sub("images", create=True)
            try:
                common.publish_entry(images, self.request["operation"], image, fill,
                                     lambda: self.image(image, full=True), CACHE_FILES,
                                     lambda unused: common.claim_unused(self.root, unused, (
                                         ("resources", "resource.json"), ("checkpoints", "checkpoint.json"))))
            finally:
                images.close()
            return image, release
        finally:
            os.close(fd)

    # Resources.

    def resources(self, create=False):
        return self.root.sub("resources", create=create)

    def open_resource(self, request, lock):
        """(dir, record, lock fd) of the request's resource, bound to its
        run; the lock is exclusive and refused as `busy` while held."""
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
        """The attached instance's record if it settled (its result is not
        yet applied to the resource), else None."""
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
        """Applies a settled instance's result to the resource record."""
        inst = self.settled_instance(directory, record)
        if inst is not None:
            result = inst["result"]
            record.update(generation=result["generation"], storage=result["storage"], instance=None)
            if save:
                directory.write_json("resource.json", record)
        return record

    def drop_pending(self, directory, record):
        """Removes an interrupted operation's exact staging file."""
        if record.get("pending"):
            directory.unlink(record["pending"])
            record["pending"] = None
            directory.write_json("resource.json", record)

    def ready_resource(self, request, lock=True):
        """A ready resource for start/checkpoint/restore (growth only): bound,
        not partial, STATE and the resource directory declared before any
        reconciliation write, no live or unsettled instance, the requested
        generation. Stop and discard never come here."""
        directory, record, held = self.open_resource(request, lock)
        try:
            if record is None or record["state"] in ("creating", "restoring", "discarding"):
                raise Failure("partial")
            if record["state"] == "discarded":
                raise Failure("not_found")
            self.host.growth(self.root, directory)
            self.roll_forward(directory, record, save=True)
            self.drop_pending(directory, record)
            if record.get("instance"):
                raise Failure("busy", "unsettled", "unchanged")
            if record["generation"] != request["generation"]:
                raise Failure("generation_mismatch")
        except BaseException:
            if held is not None:
                os.close(held)
            directory.close()
            raise
        return directory, record, held

    # create

    def op_create(self, request):
        self.host.custody()
        self.host.tool("qemu-img")
        if request["retention"] not in RETENTION:
            raise Failure("unsupported")
        # The image's own account only (no `select_user`).
        if request["user"] != USER:
            raise Failure("unsupported")
        self.host.growth(self.root)
        # Shared images.lock until the record names the image: an invalid
        # entry is moved aside only while no record uses it.
        uses = common.images_lock(self.root, exclusive=False)
        try:
            self.image(request["image"], full=False)
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
                      "generation": 0, "storage": "clean", "instance": None, "pending": None, "restoring": None}
            directory.write_json("resource.json", record)
        finally:
            os.close(uses)
        ledger = RecordLedger(directory, "resource.json", record, self.host.custody())
        try:
            image = self.image(request["image"], full=True)
            if request["retention"] == "disk":
                self.new_overlay(directory, "staging.qcow2", image, ledger)
                directory.rename("staging.qcow2", "disk.qcow2")
                directory.fsync()
            record["state"] = "ready"
            directory.write_json("resource.json", record)
        except Exception as error:  # noqa: BLE001 - undone only without outstanding writers
            if record.get("tools"):
                # A tool may still write: the record (state creating, its
                # debt) and every file stay for discard to settle by name.
                os.close(held)
                if isinstance(error, Unsettled):
                    raise
                raise Unsettled("uncertain") from error
            if not isinstance(error, (Failure, Interrupted)):
                error = Failure("failed")
            # Everything here is known by name: undo it, else stay partial.
            try:
                for entry in ("staging.qcow2", "disk.qcow2", "resource.json", ".resource.json.tmp", "lock"):
                    directory.unlink(entry)
                os.close(held)
                resources.rmdir(name)
                resources.fsync()
            except OSError:
                raise Failure("partial" if isinstance(error, Interrupted) else error.code,
                              "unsettled", "uncertain") from None
            if isinstance(error, Interrupted):
                if error.reason == "lost":
                    raise
                raise Failure(error.code) from None
            raise Failure(error.code) from None
        os.close(held)
        return {"type": "created", "operation": request["operation"], "run": request["run"],
                "resource": name, "retention": request["retention"], "generation": 0,
                "user": USER, "home": GUEST_HOME}

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
            if state in ("creating", "restoring", "discarding"):
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
                try:
                    launched = inst["phase"] in ("engine", "live")
                    debts = self.settle_debts(inst, custody)
                    idir.write_json("instance.json", inst)
                    if not debts or not self.settle_engine(inst, custody):
                        # Unconfirmed here: nothing it may write is removed.
                        raise Failure("busy", "unsettled", "uncertain")
                    remove_instance_files(idir, inst)
                    inst["result"] = instance_result(record, inst, launched, clean=False)
                    inst["phase"] = "settled"
                    idir.write_json("instance.json", inst)
                finally:
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

    def settle_engine(self, inst, custody):
        """Kills and removes the instance's recorded engine child; True only
        when that very child is gone. Recorded with another domain, it is
        gone by the host's precondition (`common.foreign`) and left
        untouched; when the name now holds another directory or cannot be
        observed, nothing is certified (False)."""
        if inst["phase"] not in ("engine", "live"):
            return True
        if common.foreign(inst, custody):
            return True
        deadline = time.monotonic() + max(common.KILL_RESERVE, self.session.remaining() or 0)
        try:
            engine = custody.existing(inst["engine"], inst.get("engine_identity"))
        except (Unsettled, OSError):
            return False
        if engine is None:
            return True
        settled = engine.settle(deadline)
        engine.close()
        return settled

    # discard

    def op_discard(self, request):
        self.host.custody()
        if "checkpoint" in request:
            return self.discard_checkpoint(request)
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
                debts = self.settle_debts(record, self.host.custody())
                directory.write_json("resource.json", record)
                if not debts:
                    raise Failure("busy", "unsettled", "uncertain")
                record["state"] = "discarding"
                directory.write_json("resource.json", record)
            try:
                instances = directory.sub("instances")
                if instances is not None:
                    for name in instances.names():
                        idir = instances.sub(name)
                        inst = idir.read_json("instance.json")
                        if inst is not None and inst.get("tools"):
                            raise Failure("busy", "unsettled", "uncertain")
                        for entry in idir.names(len(INSTANCE_FILES)):
                            if entry not in INSTANCE_FILES:
                                raise Failure("failed", "unsettled", "uncertain")
                            idir.unlink(entry)
                        idir.close()
                        instances.rmdir(name)
                    instances.close()
                    directory.rmdir("instances")
                for entry in ("disk.qcow2", "staging.qcow2", "restore.qcow2"):
                    directory.unlink(entry)
                directory.fsync()
            except OSError:
                raise Failure("failed", "unsettled", "uncertain") from None
            if record is None:
                directory.unlink("lock")
                os.close(held)
                held = None
                self.resources().rmdir(request["resource"])
                return done
            tombstone = {key: record[key] for key in ("schema", "run", "resource", "image", "retention")}
            tombstone.update(state="discarded", generation=record["generation"], storage=record["storage"],
                             instance=None, pending=None, restoring=None)
            directory.write_json("resource.json", tombstone)
            return done
        finally:
            if held is not None:
                os.close(held)
            directory.close()

    # Checkpoints: independent objects, by handle, with source provenance.

    def checkpoints(self, create=False):
        return self.root.sub("checkpoints", create=create)

    def discard_checkpoint(self, request):
        done = {"type": "discarded", "operation": request["operation"], "run": request["run"],
                "resource": request["resource"], "settlement": "settled", "checkpoint": request["checkpoint"]}
        checkpoints = self.checkpoints()
        cdir = checkpoints.sub(request["checkpoint"], modes=(0o700, 0o500)) if checkpoints is not None else None
        if cdir is None:
            raise Failure("not_found")
        try:
            record = cdir.read_json("checkpoint.json")
            if record is not None and (record["run"], record["resource"]) != (request["run"], request["resource"]):
                raise Failure("binding_mismatch")
            if record is not None and record["state"] == "discarded":
                return done
            held = cdir.lock("lock")
            if held is None:
                raise Failure("busy", "unsettled", "unchanged")
            try:
                if record is not None:
                    record["state"] = "discarding"
                    cdir.write_json("checkpoint.json", record)
                cdir.unlink("disk.qcow2")
                cdir.unlink("copy.qcow2")
                cdir.fsync()
                if record is None:
                    cdir.unlink("lock")
                    checkpoints.rmdir(request["checkpoint"])
                    return done
                record.update(state="discarded", bytes=None, sha256=None)
                cdir.write_json("checkpoint.json", record)
            except OSError:
                raise Failure("failed", "unsettled", "uncertain") from None
            finally:
                os.close(held)
            return done
        finally:
            cdir.close()

    def op_checkpoint(self, request):
        self.host.custody()
        directory, record, held = self.ready_resource(request)
        try:
            if record["retention"] != "disk":
                raise Failure("unsupported")
            if record["storage"] == "unclean" and not request["accept_unclean"]:
                raise Failure("unclean")
            self.host.growth(self.root)
            image = self.image(record["image"], full=False)
            checkpoints = self.checkpoints(create=True)
            self.host.growth(checkpoints)
            name = request["checkpoint"]
            if not checkpoints.mkdir(name):
                raise Failure("exists")
            cdir = checkpoints.sub(name)
            lock = cdir.lock("lock")
            entry = {"schema": CHECKPOINT_SCHEMA, "checkpoint": name, "run": request["run"],
                     "resource": request["resource"], "generation": record["generation"],
                     "storage": record["storage"], "image": record["image"], "state": "copying",
                     "bytes": None, "sha256": None}
            cdir.write_json("checkpoint.json", entry)
            try:
                source = directory.open_file("disk.qcow2", mode=0o600)
                try:
                    before = fingerprint(os.fstat(source))
                    size = before[2]
                    try:
                        check_overlay(read_prefix(source, MAX_HEADER_BYTES), size, image["path"], image["virtual_size"])
                    except QcowError:
                        raise Failure("failed") from None
                    target = cdir.create("disk.qcow2", 0o600)
                    try:
                        digest = copy_hashed(source, target, size, self.session.check)
                        os.fsync(target)
                        if hash_fd(target, self.session.check, size) != digest \
                                or fingerprint(os.fstat(source)) != before \
                                or fingerprint(os.stat("disk.qcow2", dir_fd=directory.fd, follow_symlinks=False)) != before:
                            raise Failure("failed")
                        os.fchmod(target, 0o400)
                        os.fsync(target)
                    finally:
                        os.close(target)
                finally:
                    os.close(source)
                cdir.fsync()
                entry.update(state="ready", bytes=size, sha256=digest)
                cdir.write_json("checkpoint.json", entry)
            except (Failure, Interrupted, OSError) as error:
                try:
                    for item in ("disk.qcow2", "checkpoint.json", ".checkpoint.json.tmp", "lock"):
                        cdir.unlink(item)
                    checkpoints.rmdir(name)
                except OSError:
                    raise Failure("failed", "unsettled", "unchanged") from None
                if isinstance(error, Interrupted):
                    if error.reason == "lost":
                        raise
                    raise Failure(error.code) from None
                raise Failure(error.code if isinstance(error, Failure) else "failed") from None
            finally:
                os.close(lock)
                cdir.close()
            return {"type": "checkpointed", "operation": request["operation"], "run": request["run"],
                    "resource": request["resource"], "checkpoint": name,
                    "generation": record["generation"], "storage": entry["storage"]}
        finally:
            os.close(held)
            directory.close()

    def op_restore(self, request):
        self.host.custody()
        directory, record, held = self.ready_resource(request)
        try:
            if record["retention"] != "disk":
                raise Failure("unsupported")
            checkpoints = self.checkpoints()
            cdir = checkpoints.sub(request["checkpoint"], modes=(0o700,)) if checkpoints is not None else None
            if cdir is None:
                raise Failure("not_found")
            shared = cdir.lock("lock", exclusive=False)
            if shared is None:
                cdir.close()
                raise Failure("busy", "unsettled", "unchanged")
            try:
                entry = cdir.read_json("checkpoint.json")
                if entry is None or entry["state"] in ("copying", "discarding"):
                    raise Failure("partial")
                if entry["state"] != "ready":
                    raise Failure("not_found")
                if entry["image"] != record["image"]:
                    raise Failure("binding_mismatch")
                image = self.image(record["image"], full=False)
                return self.restore_copy(request, directory, record, cdir, entry, image)
            finally:
                os.close(shared)
                cdir.close()
        finally:
            os.close(held)
            directory.close()

    def restore_copy(self, request, directory, record, cdir, entry, image):
        source = cdir.open_file("disk.qcow2", mode=0o400)
        target_generation = record["generation"] + 1
        try:
            size = os.fstat(source).st_size
            if size != entry["bytes"]:
                raise Failure("failed")
            try:
                check_overlay(read_prefix(source, MAX_HEADER_BYTES), size, image["path"], image["virtual_size"])
            except QcowError:
                raise Failure("failed") from None
            if hash_fd(source, self.session.check, size) != entry["sha256"]:
                raise Failure("failed")
            record["pending"] = "restore.qcow2"
            directory.unlink("restore.qcow2")
            directory.write_json("resource.json", record)
            try:
                target = directory.create("restore.qcow2", 0o600)
                try:
                    digest = copy_hashed(source, target, size, self.session.check)
                    os.fsync(target)
                    if digest != entry["sha256"] or hash_fd(target, self.session.check, size) != digest:
                        raise Failure("failed")
                finally:
                    os.close(target)
                self.session.check()
            except (Failure, Interrupted, OSError) as error:
                directory.unlink("restore.qcow2")
                record["pending"] = None
                directory.write_json("resource.json", record)
                if isinstance(error, Interrupted):
                    if error.reason == "lost":
                        raise
                    raise Failure(error.code) from None
                raise Failure(error.code if isinstance(error, Failure) else "failed") from None
        finally:
            os.close(source)
        # Only this window is partial: the record names the replacement first.
        record.update(state="restoring", restoring={"checkpoint": request["checkpoint"],
                                                    "generation": target_generation})
        directory.write_json("resource.json", record)
        try:
            directory.rename("restore.qcow2", "disk.qcow2")
            directory.fsync()
        except OSError:
            raise Failure("failed", "unsettled", "uncertain") from None
        record.update(state="ready", generation=target_generation, storage=entry["storage"], pending=None,
                      restoring=None)
        directory.write_json("resource.json", record)
        return {"type": "restored", "operation": request["operation"], "run": request["run"],
                "resource": request["resource"], "checkpoint": request["checkpoint"],
                "generation": target_generation, "storage": entry["storage"]}

    # start: the owner session.

    def op_start(self, request):
        custody = self.host.custody()
        tools = {name: self.host.tool(name) for name in TOOLS}
        self.host.kvm()
        directory, record, held = self.ready_resource(request)
        try:
            if record["storage"] == "unclean" and not request["accept_unclean"]:
                raise Failure("unclean")
            # The resource directory (retained disk.qcow2, resource.json)
            # was checked by ready_resource; an existing instances directory
            # before anything is made in it.
            instances, = self.host.allocation((directory, "instances"))
            if not instances.mkdir(request["instance"]):
                raise Failure("exists")
            idir = instances.sub(request["instance"])
            owner_lock = idir.lock("owner.lock")
            inst = {"schema": INSTANCE_SCHEMA, "run": request["run"], "resource": request["resource"],
                    "execution": request["execution"], "instance": request["instance"],
                    "generation": request["generation"], "retention": record["retention"], "phase": "intent",
                    "custody": custody.record(), "engine": "engine", "engine_identity": None, "tools": [],
                    "port": None, "host_key": None, "result": None}
            idir.write_json("instance.json", inst)
            record["instance"] = {"execution": request["execution"], "instance": request["instance"]}
            directory.write_json("resource.json", record)
        except BaseException:
            os.close(held)
            directory.close()
            raise
        owner = Owner(self, request, directory, record, held, idir, inst, owner_lock, custody, tools)
        return owner.run()


RecordLedger = common.RecordLedger


def instance_result(record, inst, launched, clean):
    """What an ended instance did to its resource's storage."""
    generation = inst["generation"]
    if inst["retention"] == "none" or not launched:
        return {"durability": "unchanged", "storage": record["storage"], "generation": generation}
    if clean:
        return {"durability": "retained", "storage": "clean", "generation": generation + 1}
    return {"durability": "uncertain", "storage": "unclean", "generation": generation + 1}


def remove_instance_files(idir, inst):
    """Removes the instance's seed (it holds the guest host private key),
    staged key files and, without retention, its overlay."""
    for name in SECRET_FILES:
        idir.unlink(name)
    if inst["retention"] == "none":
        idir.unlink("disk.qcow2")
    idir.fsync()


def write_seed(p, directory, authorized_key, instance, ledger):
    """A fresh guest host key pair and the NoCloud seed (seed.iso) in
    `directory` for one boot authorizing `authorized_key`; returns the
    host's public key. The key files and documents stay beside it for the
    caller to remove (SECRET_FILES)."""
    key = directory.join("host_ed25519")
    status, _ = p.tool("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "agentbox-guest-host", "-f", key],
                       ledger=ledger)
    if status != 0:
        raise Failure("failed")
    fd = directory.open_file("host_ed25519", mode=0o600)
    try:
        private = os.read(fd, 8192).decode("ascii")
    finally:
        os.close(fd)
    if _PRIVATE.match(private) is None:
        raise Failure("failed")
    fd = directory.open_file("host_ed25519.pub")
    try:
        public = bare_key(os.read(fd, 1024).decode("ascii"))
    finally:
        os.close(fd)
    status, derived = p.tool("ssh-keygen", ["-y", "-P", "", "-f", key], out_limit=1024, ledger=ledger)
    if status != 0 or bare_key(derived.decode("ascii")) != public or public == authorized_key:
        raise Failure("failed")
    instance_id = f"agentbox-{instance}-{os.urandom(16).hex()}"
    for name, data in (("user-data", user_data(authorized_key, private, public)),
                       ("meta-data", meta_data(instance_id))):
        out = directory.create(name, 0o600)
        try:
            os.write(out, data)
        finally:
            os.close(out)
    del private
    seed = directory.join("seed.iso")
    status, _ = p.tool("xorriso", ["-no_rc", "-as", "mkisofs", "-output", seed, "-volid", SEED_VOLUME,
                                   "-joliet", "-rock", "-graft-points",
                                   "user-data=" + directory.join("user-data"),
                                   "meta-data=" + directory.join("meta-data")], ledger=ledger)
    if status != 0:
        raise Failure("failed")
    fd = directory.open_file("seed.iso")
    try:
        os.fchmod(fd, 0o600)
        if os.fstat(fd).st_size > MAX_SEED_BYTES or not check_seed(read_prefix(fd, 17 * 2048)):
            raise Failure("failed")
    finally:
        os.close(fd)
    return public


def check_command(release, manifest, listed, kernel, agents):
    """The check boot's one remote command (Provider.check_boot), bounded
    by `timeout`: the baked worker as the SSH bootstrap verifies a
    preinstalled payload (agentbox_controller/ssh.py: sealed, each file's
    size and SHA-256), the running kernel `kernel`, each baked agent's lock
    exactly the system record's (`agents`: root's, not writable by the
    jail's user, its SHA-256) and its command, a local Git clone and a
    venv running pip; its last line CHECK_OK, a failure's
    `agentbox-check-failed WHAT`."""
    q = shlex.quote
    lines = ["set -eu", 'fail() { echo "agentbox-check-failed $1"; exit 1; }',
             f"payload={q(_worker().INSTALL_ROOT)}",
             'sealed() { [ ! -h "$1" ] && [ "$(stat -c %u -- "$1")" = 0 ] && [ ! -w "$1" ] || fail sealed; }',
             'check() { f="$payload/$1"; [ -f "$f" ] && [ ! -h "$f" ] || fail file; sealed "$f"; '
             'size=$(wc -c < "$f") || fail file; [ $size -eq "$2" ] || fail size; '
             "printf '%s  %s\\n' \"$3\" \"$f\" | sha256sum -c --status - || fail digest; }",
             '[ -d "$payload" ] && [ ! -h "$payload" ] || fail payload', 'sealed "$payload"',
             f"check manifest.json {len(manifest)} {release}"]
    lines += [f"check {q(path)} {size} {digest}" for path, (size, digest) in sorted(listed.items())]
    for agent, entry in sorted(agents.items()):
        lock = f"{AGENTS_ROOT}/{agent}/package-lock.json"
        lines += [f'sealed {q(lock)}', f"printf '%s  %s\\n' {entry['lock_sha256']} {q(lock)} | sha256sum -c --status - "
                  "|| fail agents", f'[ -x {q("/usr/local/bin/" + agent)} ] || fail agents']
    lines += ["k=$(uname -r)", f'[ "$k" = {q(kernel)} ] || fail kernel',
              "d=$(mktemp -d)", 'git -C "$d" init -q src || fail git',
              'git -C "$d/src" -c user.name=check -c user.email=check@localhost commit -q --allow-empty -m check '
              "|| fail git",
              'git -c protocol.allow=never -c protocol.file.allow=always clone -q "file://$d/src" "$d/dst" '
              "|| fail git",
              'git -C "$d/dst" rev-parse --verify -q HEAD >/dev/null || fail git',
              'python3 -m venv "$d/venv" || fail venv', '"$d/venv/bin/python" -m pip --version >/dev/null || fail venv',
              'rm -rf "$d"', f'echo "{CHECK_KERNEL}$k"', f"echo {CHECK_OK}"]
    command = f"exec timeout {CHECK_SCRIPT_SECONDS} /bin/sh -c {q(chr(10).join(lines) + chr(10))}"
    if len(command.encode()) > MAX_CHECK_COMMAND:
        raise Failure("failed")
    return command


class CheckBoot:
    """One boot of a finished disk for its check (Provider.check_boot) in
    `directory` (the prepare's scratch): the runtime's seed and launch in
    the custody child `check-OPERATION`, named in the prepare's scratch
    ledger before it exists; settled before `run` returns or raises, else
    Unsettled (the scratch then stays)."""

    def __init__(self, p, directory, image):
        self.p, self.directory, self.image, self.session = p, directory, image, p.session
        self.name = f"check-{p.request['operation']}"
        self.engine = self.process = self.qmp = None

    def run(self, command):
        """The running kernel, once the command passed and the guest
        powered itself off."""
        p, d = self.p, self.directory
        p.new_overlay(d, "disk.qcow2", self.image, p.scratch)
        status, _ = p.tool("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", CHECK_ALIAS, "-f", d.join("client")])
        if status != 0:
            raise Failure("failed")
        fd = d.open_file("client.pub")
        try:
            authorized = bare_key(os.read(fd, 1024).decode("ascii"))
        finally:
            os.close(fd)
        try:
            host_key = write_seed(p, d, authorized, self.name, p.scratch)
        finally:
            for name in ("host_ed25519", "host_ed25519.pub", "user-data", "meta-data"):
                d.unlink(name)
        out = d.create("known_hosts", 0o600)
        try:
            os.write(out, f"{CHECK_ALIAS} {host_key}\n".encode())
        finally:
            os.close(out)
        try:
            port = self.launch()
            self.ready(port)
            running = self.check(port, command)
            self.powerdown()
        finally:
            self.settle()
        return running

    def launch(self):
        cpus, memory, pids, ceiling = limits_of({}, self.image["virtual_size"])
        self.p.scratch.add(self.name)
        try:
            self.engine = self.p.host.custody().child(self.name, engine_limits(cpus, memory, pids))
        except Unsettled:
            raise
        except Failure:
            self.p.scratch.drop(self.name)
            raise
        port = self.p.host.free_port()
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            argv = qemu_argv(self.p.host.tool("qemu-system-x86_64"), self.image["path"],
                             self.directory.join("disk.qcow2"), self.directory.join("seed.iso"), port,
                             theirs.fileno(), cpus, memory)
            self.process = spawn(argv, self.p.host.tool_env(), self.engine, pass_fds=[theirs.fileno()],
                                 rlimits=[(resource.RLIMIT_FSIZE, ceiling), (resource.RLIMIT_CORE, 0)],
                                 ignore_xfsz=True)
        finally:
            theirs.close()
        self.qmp = Qmp(ours)
        if not self.process.admitted:
            raise Failure("failed")
        return port

    def wait(self, deadline):
        self.session.check()
        if time.monotonic() > deadline:
            diagnostic("check boot failed: timeout")
            raise Failure("failed")
        fds = [self.process.pidfd] + ([] if self.qmp.closed else [self.qmp.fileno()])
        self.session.wait(fds, 0.25)
        self.qmp.pump()

    def ready(self, port):
        """QMP negotiated, then the forward answers with an SSH banner."""
        deadline = time.monotonic() + CHECK_READY_SECONDS

        def alive():
            if self.process.poll() is not None or self.qmp.closed or self.qmp.broken:
                diagnostic("check boot failed: engine")
                raise Failure("failed")
        while not self.qmp.greeted:
            self.wait(deadline)
            alive()
        self.qmp.send("qmp_capabilities")
        while not self.qmp.returns:
            self.wait(deadline)
            alive()
        if not self.qmp.returns.pop(0):
            raise Failure("failed")
        while not self.p.host.banner(port, 1.0):
            self.wait(deadline)
            alive()

    def check(self, port, command):
        d = self.directory
        argv = ["-F", "/dev/null", "-T", "-p", str(port), "-l", USER]
        for option in CHECK_SSH_OPTIONS + (f"IdentityFile={d.join('client')}",
                                           f"UserKnownHostsFile={d.join('known_hosts')}",
                                           f"HostKeyAlias={CHECK_ALIAS}"):
            argv += ["-o", option]
        errors = common.Collect(4096)
        status, out = self.p.tool("ssh", argv + ["127.0.0.1", command], out_limit=CHECK_OUT_BYTES, err_sink=errors)
        lines = out.decode("utf-8", "replace").splitlines()
        running = [line[len(CHECK_KERNEL):] for line in lines if line.startswith(CHECK_KERNEL)]
        if status != 0 or not lines or lines[-1] != CHECK_OK or len(running) != 1:
            failed = [line.split(" ", 1)[-1] for line in lines if line.startswith("agentbox-check-failed ")]
            known = [code for text, code in CHECK_SSH_ERRORS if text.encode() in errors.data]
            what = re.sub(r"[^a-z_]", "", failed[-1])[:32] if failed else (known or [f"ssh exit {status}"])[0]
            diagnostic(f"check boot failed: {what}")
            raise Failure("failed")
        return running[0]

    def powerdown(self):
        """The guest's own orderly power-off, observed: acknowledged, its
        SHUTDOWN event, QEMU's exit 0."""
        self.qmp.returns.clear()
        self.qmp.events.clear()
        self.qmp.send("system_powerdown")
        deadline = time.monotonic() + CHECK_POWERDOWN_SECONDS
        while self.process.poll() is None:
            self.wait(deadline)
        if not (self.qmp.returns[:1] == [True] and ("SHUTDOWN", True, "guest-shutdown") in self.qmp.events
                and self.process.status == 0):
            diagnostic("check boot failed: shutdown")
            raise Failure("failed")

    def settle(self):
        if self.qmp is not None:
            self.qmp.close()
        if self.engine is None:
            return
        settled = common._settled(self.engine, self.process, time.monotonic() + common.KILL_RESERVE)
        if self.process is not None:
            self.process.close()
        if not settled:
            raise Unsettled()
        self.p.scratch.drop(self.name)


class Owner:
    """The start invocation as the instance's owner: sets up, launches,
    answers `started`, waits for the host's `stop` (or EOF, a signal, a
    refused frame), then settles by its exact handles and answers."""

    def __init__(self, provider, request, directory, record, held, idir, inst, owner_lock, custody, tools):
        self.p, self.session, self.request = provider, provider.session, request
        self.directory, self.record, self.held = directory, record, held
        self.idir, self.inst, self.owner_lock = idir, inst, owner_lock
        self.custody, self.tools = custody, tools
        self.engine = self.process = self.qmp = None
        self.pipes = {}
        self.launched = self.exited = self.forced = False
        self.acked = self.shutdown = False
        self.sinks = {}
        self.overlay = None
        self.ledger = RecordLedger(idir, "instance.json", inst, custody)

    def run(self):
        try:
            self.setup()
            self.launch()
            self.ready()
            self.session.check()
            self.inst["phase"] = "live"
            self.idir.write_json("instance.json", self.inst)
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
                   "transport": {"kind": "tcp", "host": "127.0.0.1", "port": self.inst["port"]},
                   "user": USER, "host_key": self.inst["host_key"], "worker_sha256": self.image["worker"],
                   "home": GUEST_HOME, "control": CONTROL_ROOT}
        self.session.send(started)
        # No request is in flight now: a cancel is out of turn.
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

    # Setup: nothing runs before the image, disk and seed are checked.

    def setup(self):
        p, request = self.p, self.request
        self.image = p.image(self.record["image"], full=False)
        cpus, memory, pids, ceiling = limits_of(request["limits"], self.image["virtual_size"])
        self.limits = (cpus, memory, pids, ceiling)
        if self.inst["retention"] == "disk":
            self.overlay_dir = self.directory
        else:
            p.new_overlay(self.idir, "disk.qcow2", self.image, self.ledger)
            self.overlay_dir = self.idir
        fd = self.overlay_dir.open_file("disk.qcow2", mode=0o600)
        try:
            st = os.fstat(fd)
            try:
                check_overlay(read_prefix(fd, MAX_HEADER_BYTES), st.st_size, self.image["path"],
                              self.image["virtual_size"])
            except QcowError:
                raise Failure("failed") from None
            if st.st_size >= ceiling:
                raise Failure("failed")
        finally:
            os.close(fd)
        self.check_qemu()
        try:
            self.seed()
        finally:
            # Only with no tool child outstanding: one may still write
            # these until it is confirmed gone (finish, or a later stop).
            if not self.inst.get("tools"):
                for name in ("host_ed25519", "host_ed25519.pub", "user-data", "meta-data"):
                    self.idir.unlink(name)

    def check_qemu(self):
        status, out = self.p.tool("qemu-system-x86_64", ["-version"], out_limit=4096, ledger=self.ledger)
        match = re.match(rb"QEMU emulator version (\d+)\.(\d+)", out)
        if status != 0 or match is None or (int(match[1]), int(match[2])) < MIN_QEMU:
            raise Failure("prerequisite")

    def seed(self):
        """A fresh guest host key and NoCloud seed for this execution."""
        self.inst["host_key"] = write_seed(self.p, self.idir, self.request["authorized_key"],
                                           self.request["instance"], self.ledger)

    # Launch: limits are in place before QEMU runs.

    def launch(self):
        cpus, memory, pids, ceiling = self.limits
        self.inst["phase"] = "engine"
        self.idir.write_json("instance.json", self.inst)
        self.engine = self.custody.child("engine", engine_limits(cpus, memory, pids))
        self.inst["engine_identity"] = self.engine.identity
        self.idir.write_json("instance.json", self.inst)
        port = self.p.host.free_port()
        ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            argv = qemu_argv(self.tools["qemu-system-x86_64"], self.image["path"],
                             self.overlay_dir.join("disk.qcow2"), self.idir.join("seed.iso"), port,
                             theirs.fileno(), cpus, memory)
            self.sinks = {"console": BoundedSink(self.idir, "console.log", CONSOLE_BYTES),
                          "qemu": BoundedSink(self.idir, "qemu.log", QEMU_LOG_BYTES)}
            self.process = spawn(argv, self.p.host.tool_env(), self.engine, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, pass_fds=[theirs.fileno()],
                                 rlimits=[(resource.RLIMIT_FSIZE, ceiling), (resource.RLIMIT_CORE, 0)],
                                 ignore_xfsz=True)
            self.launched = True
            self.pipes = {self.process.popen.stdout.fileno(): self.sinks["console"],
                          self.process.popen.stderr.fileno(): self.sinks["qemu"]}
        finally:
            theirs.close()
        self.qmp = Qmp(ours)
        for fd in self.pipes:
            os.set_blocking(fd, False)
        if not self.process.admitted:
            # Launched but not watchable: settled through its child below.
            raise Failure("failed")
        self.inst["port"] = port
        self.idir.write_json("instance.json", self.inst)

    def fds(self):
        out = list(self.pipes)
        if self.qmp is not None and not self.qmp.closed:
            out.append(self.qmp.fileno())
        if not self.exited:
            out.append(self.process.pidfd)
        return out

    def service(self, timeout):
        """One wait: drains console/log pipes and QMP, notices QEMU's exit."""
        for fd in self.session.wait(self.fds(), timeout):
            if fd in self.pipes and not drain(fd, self.pipes[fd]):
                del self.pipes[fd]
        if self.qmp is not None:
            self.qmp.pump()
        if not self.exited and self.process.poll() is not None:
            self.exited = True

    def ready(self):
        """QMP negotiated, then the forward answers with an SSH banner."""
        while not self.qmp.greeted:
            self.session.check()
            self.service(0.5)
            if self.exited or self.qmp.closed or self.qmp.broken:
                raise Failure("failed")
        self.qmp.send("qmp_capabilities")
        while not self.qmp.returns:
            self.session.check()
            self.service(0.5)
            if self.exited or self.qmp.closed or self.qmp.broken:
                raise Failure("failed")
        if not self.qmp.returns.pop(0):
            raise Failure("failed")
        while True:
            self.session.check()
            if self.p.host.banner(self.inst["port"], 1.0):
                return
            self.service(0.25)
            if self.exited:
                raise Failure("failed")

    def wait(self):
        """Waits for the host's `stop`. Writes nothing; an unexpected
        engine exit is only noted for the stop's settlement."""
        while True:
            self.service(None)
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

    def powerdown(self, deadline):
        """Asks the guest to power off through QMP; True only on observed
        evidence: the command acknowledged, the guest's own SHUTDOWN event
        after it, and QEMU's exit without any signal from us."""
        if self.exited or self.qmp is None or self.qmp.closed or self.qmp.broken:
            return
        self.qmp.returns.clear()
        self.qmp.events.clear()
        self.qmp.send("system_powerdown")
        while not self.exited and time.monotonic() < deadline:
            self.service(min(0.5, max(0.0, deadline - time.monotonic())))
            if self.qmp.returns and not self.acked:
                self.acked = self.qmp.returns.pop(0)
            if self.session.lost or self.session.cancelled:
                return
        self.shutdown = self.acked and ("SHUTDOWN", True, "guest-shutdown") in self.qmp.events

    def teardown(self, graceful):
        """(settled, clean): the engine child gone and QEMU reaped, and
        whether the shutdown was observed as orderly."""
        if self.launched and self.process is not None and graceful:
            remaining = self.session.remaining() or 0
            self.powerdown(time.monotonic() + max(0.0, min(GRACE_SECONDS, remaining - common.KILL_RESERVE)))
        status = None
        settled = True
        if self.engine is None and self.inst["phase"] in ("engine", "live"):
            # Its creation did not complete here: settle it by its record.
            settled = self.p.settle_engine(self.inst, self.custody)
        if self.engine is not None:
            self.forced = self.process is None or self.process.poll() is None
            deadline = time.monotonic() + max(common.KILL_RESERVE, (self.session.remaining() or 0))
            settled = common._settled(self.engine, self.process, deadline)
            if self.process is not None:
                status = self.process.status
                common._finish_streams(self.process, self.pipes, settled)
        if self.qmp is not None:
            self.qmp.close()
        for sink in self.sinks.values():
            try:
                sink.close()
            except OSError:
                pass
        clean = self.launched and settled and not self.forced and self.shutdown and status == 0
        return settled, clean

    def storage_ok(self):
        """The retained overlay synced and still exactly our overlay."""
        try:
            fd = self.overlay_dir.open_file("disk.qcow2", mode=0o600)
        except (Failure, OSError):
            return False
        try:
            st = os.fstat(fd)
            check_overlay(read_prefix(fd, MAX_HEADER_BYTES), st.st_size, self.image["path"],
                          self.image["virtual_size"])
            os.fsync(fd)
            self.overlay_dir.fsync()
            return True
        except (QcowError, OSError):
            return False
        finally:
            os.close(fd)

    def finish(self, stop=None, error=None):
        lost = isinstance(error, Interrupted) and error.reason == "lost" or self.session.lost
        graceful = stop is not None and not lost and not self.session.cancelled
        settled, clean = self.teardown(graceful)
        # Every tool child of this instance must be gone as well.
        settled = self.p.settle_debts(self.inst, self.custody) and settled
        op = self.p.request
        try:
            if not settled:
                # The engine or a tool child is unconfirmed: the record and
                # every file stay for a later stop by this handle.
                self.idir.write_json("instance.json", self.inst)
                if not lost:
                    self.session.send(_failed(op, Failure("failed", "unsettled", "uncertain")))
                return None
            launched = self.launched
            if launched and self.inst["retention"] == "disk" and clean:
                clean = self.storage_ok()
            remove_instance_files(self.idir, self.inst)
            self.inst["result"] = instance_result(self.record, self.inst, launched, clean)
            self.inst["phase"] = "settled"
            self.idir.write_json("instance.json", self.inst)
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
            if self.held is not None:
                os.close(self.held)
                self.held = None
            os.close(self.owner_lock)
            self.idir.close()
            self.directory.close()


# ---------------------------------------------------------------------------
# Entry.

def main(argv, host=None, session=None):
    try:
        args = protocol.parse_argv(argv)
    except protocol.ProtocolError:
        diagnostic("invalid_argv")
        return 2
    if args[0] == "connect":
        # A tcp provider has no stdio bridge.
        diagnostic("connect unsupported")
        return 2
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
