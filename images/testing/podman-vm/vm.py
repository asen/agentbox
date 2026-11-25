"""A standalone QEMU test VM for rootless Podman under a non-1000 account
(README.md here). Test-only: not an Agentbox image, provider or jail. The VM
runs under plain QEMU/KVM, outside Agentbox policy, with ordinary guest
network (passt, --no-map-gw) and no host share; only the inner smoke
containers take the Podman provider's sandbox flags. Stdlib only.

  vm.py build [--root ROOT]                  download, verify, provision, flatten
  vm.py start ROOT                           boot ROOT's disk (QEMU in its own session)
  vm.py ssh ROOT [--admin] [CMD...]          pinned SSH as abtest (or vmadmin)
  vm.py stop ROOT                            poweroff, then TERM/KILL owned pids
  vm.py smoke ROOT --archive OCI --sha256 HEX --image-id HEX
"""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))

RELEASE = "release-20261108"
BASE_URL = f"https://cloud-images.ubuntu.com/releases/resolute/{RELEASE}/"
IMAGE = "ubuntu-26.04-server-cloudimg-amd64.img"
SUMS, SUMS_SIG = "SHA256SUMS", "SHA256SUMS.gpg"
KEYRING = "/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg"
MAX_IMAGE = 1 << 30
MAX_SMALL = 1 << 16
DOWNLOAD_SECONDS = 1800

HOSTNAME = "agentbox-podman-test"
ADMIN, ADMIN_UID = "vmadmin", 1500
USER, UID, GID = "abtest", 2001, 3001
HOME = f"/home/{USER}"
SUBIDS = (100000, 65536)
PACKAGES = ("podman", "crun", "conmon", "uidmap", "catatonit", "passt", "dbus-user-session")
# Background installers and news fetchers, masked before the explicit apt.
MASKED = ("snapd.service", "snapd.socket", "snapd.seeded.service", "unattended-upgrades.service",
          "apt-daily.timer", "apt-daily.service", "apt-daily-upgrade.timer",
          "apt-daily-upgrade.service", "motd-news.timer", "motd-news.service")
MEMORY_MIB, CPUS, DISK = 4096, 2, "20G"
HEADROOM_MIB = 1024
FINAL = "podman-test-vm.qcow2"
BOOT_SECONDS, STOP_SECONDS, KILL_SECONDS, PASST_SECONDS = 300, 120, 20, 10
PASST = "/usr/bin/passt"
PASST_COMMS = ("passt", "passt.avx2")
QEMU_COMM = "qemu-system-x86"
LOCK_SECONDS = 5.0
MAX_ARCHIVE = 1 << 30
# Our QEMU children (pid -> Popen) while this process lives, for reaping.
CHILDREN = {}


class Failed(Exception):
    pass


def log(root, message):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {message}"
    print(line, file=sys.stderr)
    with open(os.path.join(root, "logs", "driver.log"), "a") as stream:
        stream.write(line + "\n")


def private_file(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, "wb" if isinstance(data, bytes) else "w") as stream:
        stream.write(data)


def sha256_file(path):
    digest, size = hashlib.sha256(), 0
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def run(argv, **kw):
    kw.setdefault("check", True)
    return subprocess.run(argv, **kw)


# Layout.

def paths(root):
    return {
        "base": os.path.join(root, "base", IMAGE),
        "client": os.path.join(root, "keys", "client"),
        "known_hosts": os.path.join(root, "keys", "known_hosts"),
        "final": os.path.join(root, FINAL),
        "run": os.path.join(root, "run"),
        "state": os.path.join(root, "run", "vm.json"),
        "build": os.path.join(root, "build"),
        "logs": os.path.join(root, "logs"),
    }


def new_root(root=None):
    """A fresh private ROOT: given (must not exist) or ~/.cache/abpvm-*."""
    if root is None:
        cache = os.path.join(os.path.expanduser("~"), ".cache")
        root = tempfile.mkdtemp(prefix="abpvm-", dir=cache)
    else:
        root = os.path.abspath(root)
        os.mkdir(root, 0o700)
    os.chmod(root, 0o700)
    for sub in ("base", "keys", "run", "build", "logs"):
        os.mkdir(os.path.join(root, sub), 0o700)
    return root


# Download and verification.

def fetch(url, dest, limit, deadline):
    with urllib.request.urlopen(url, timeout=60) as response:
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > limit:
            raise Failed(f"{url}: {length} bytes > {limit}")
        part = dest + ".part"
        size = 0
        with open(part, "xb") as out:
            while chunk := response.read(1 << 20):
                size += len(chunk)
                if size > limit or time.monotonic() > deadline:
                    raise Failed(f"{url}: size or time bound exceeded")
                out.write(chunk)
    os.rename(part, dest)
    return size


def expected_digest(sums_text, name):
    """The one sha256 SHA256SUMS lists for `name` (`HEX *NAME` or `HEX  NAME`)."""
    found = [m.group(1) for m in re.finditer(r"^([0-9a-f]{64}) [ *](\S+)$", sums_text, re.M)
             if m.group(2) == name]
    if len(found) != 1:
        raise Failed(f"{SUMS}: {len(found)} entries for {name}")
    return found[0]


def valid_signature(status):
    """The signing fingerprint from gpgv's --status-fd output, else None."""
    good = re.search(r"^\[GNUPG:\] GOODSIG ", status, re.M)
    valid = re.search(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) ", status, re.M)
    bad = re.search(r"^\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG) ", status, re.M)
    return valid.group(1) if good and valid and not bad else None


def trusted_keyring():
    st = os.stat(KEYRING, follow_symlinks=False)
    if not os.path.isfile(KEYRING) or os.path.islink(KEYRING) or st.st_uid != 0 or st.st_mode & 0o022:
        raise Failed(f"{KEYRING}: not a root-owned, non-writable regular file")


def download_base(root):
    p = paths(root)
    base_dir = os.path.dirname(p["base"])
    trusted_keyring()
    deadline = time.monotonic() + DOWNLOAD_SECONDS
    for name in (SUMS, SUMS_SIG):
        fetch(BASE_URL + name, os.path.join(base_dir, name), MAX_SMALL, deadline)
    gnupg = os.path.join(p["build"], "gnupg")
    os.mkdir(gnupg, 0o700)
    status = run(["gpgv", "--status-fd", "1", "--keyring", KEYRING,
                  os.path.join(base_dir, SUMS_SIG), os.path.join(base_dir, SUMS)],
                 check=False, capture_output=True, text=True, env={**os.environ, "GNUPGHOME": gnupg})
    fingerprint = valid_signature(status.stdout)
    if status.returncode != 0 or fingerprint is None:
        raise Failed(f"gpgv refused {SUMS}: {status.stderr.strip()}")
    with open(os.path.join(base_dir, SUMS)) as stream:
        want = expected_digest(stream.read(), IMAGE)
    log(root, f"{SUMS} signed by {fingerprint}; {IMAGE} expected {want}")
    size = fetch(BASE_URL + IMAGE, p["base"], MAX_IMAGE, deadline)
    got, _ = sha256_file(p["base"])
    if got != want:
        raise Failed(f"{IMAGE}: sha256 {got} != {want}")
    os.chmod(p["base"], 0o444)
    info = json.loads(run(["qemu-img", "info", "--output=json", p["base"]],
                          capture_output=True, text=True).stdout)
    if info.get("format") != "qcow2" or "backing-filename" in info:
        raise Failed(f"{IMAGE}: not a standalone qcow2")
    return {"url": BASE_URL + IMAGE, "bytes": size, "sha256": got, "signer": fingerprint,
            "keyring": KEYRING, "virtual_size": info.get("virtual-size")}


# Keys and seed.

def keygen(path, comment):
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", path], stdin=subprocess.DEVNULL)
    with open(path + ".pub") as stream:
        return stream.read().strip()


def known_hosts_line(host_public):
    kind, key = host_public.split()[:2]
    return f"{HOSTNAME} {kind} {key}\n"


def user_data(client_public, host_private, host_public):
    """cloud-config as JSON (a YAML subset): vmadmin only (no default
    `ubuntu`), the host's fresh host key, no generated keys."""
    mask = "; ".join(f"systemctl mask --now {unit} >/dev/null 2>&1 || true" for unit in MASKED)
    config = {
        "hostname": HOSTNAME,
        "manage_etc_hosts": True,
        "users": [{"name": ADMIN, "uid": ADMIN_UID, "shell": "/bin/bash", "lock_passwd": True,
                   "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [client_public]}],
        "ssh_pwauth": False,
        "disable_root": True,
        "ssh_deletekeys": True,
        "ssh_genkeytypes": [],
        "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public},
        "bootcmd": [mask],
        "package_update": False,
        "package_upgrade": False,
    }
    return "#cloud-config\n" + json.dumps(config, indent=2) + "\n"


def meta_data(instance):
    return f"instance-id: {instance}\nlocal-hostname: {HOSTNAME}\n"


def make_seed(root, client_public):
    p = paths(root)
    host_key = os.path.join(p["build"], "host_ed25519")
    host_public = keygen(host_key, f"root@{HOSTNAME}")
    with open(host_key) as stream:
        host_private = stream.read()
    private_file(p["known_hosts"], known_hosts_line(host_public))
    seed = os.path.join(p["build"], "seed")
    os.mkdir(seed, 0o700)
    private_file(os.path.join(seed, "user-data"), user_data(client_public, host_private, host_public))
    private_file(os.path.join(seed, "meta-data"), meta_data("abpvm-" + os.urandom(6).hex()))
    iso = os.path.join(p["build"], "seed.iso")
    run(["xorriso", "-as", "mkisofs", "-quiet", "-o", iso, "-volid", "cidata", "-joliet", "-rock",
         os.path.join(seed, "user-data"), os.path.join(seed, "meta-data")], stdin=subprocess.DEVNULL)
    os.chmod(iso, 0o600)
    return iso, host_public


# Provisioning (root in the guest, through vmadmin's sudo).

def provision_script(client_public):
    subids = f"{USER}:{SUBIDS[0]}:{SUBIDS[1]}"
    return "\n".join([
        "set -eu",
        "export DEBIAN_FRONTEND=noninteractive",
        "cloud-init status --wait >/dev/null || true",
        'echo "cloud_init=$(cloud-init status | head -n 1)"',
        f"for unit in {' '.join(MASKED)}; do systemctl mask --now \"$unit\" >/dev/null 2>&1 || true; done",
        "if command -v pro >/dev/null; then pro config set apt_news=false || true; fi",
        "apt-get update",
        f"apt-get install -y --no-install-recommends {' '.join(PACKAGES)}",
        f"groupadd -g {GID} {USER}",
        f"useradd -u {UID} -g {GID} -m -d {HOME} -s /bin/bash -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 {USER}",
        "echo \"subuid_before=$(tr '\\n' ' ' < /etc/subuid)\"",
        "echo \"subgid_before=$(tr '\\n' ' ' < /etc/subgid)\"",
        f"printf '%s\\n' {shlex.quote(subids)} > /etc/subuid",
        f"printf '%s\\n' {shlex.quote(subids)} > /etc/subgid",
        f"install -d -m 0700 -o {UID} -g {GID} {HOME}/.ssh",
        f"printf '%s\\n' {shlex.quote(client_public)} > {HOME}/.ssh/authorized_keys",
        f"chown {UID}:{GID} {HOME}/.ssh/authorized_keys",
        f"chmod 0600 {HOME}/.ssh/authorized_keys",
        f"loginctl enable-linger {USER}",
        # No Podman API or netavark DHCP-proxy socket (the packages enable them).
        "systemctl mask --now podman.socket podman.service netavark-dhcp-proxy.socket netavark-dhcp-proxy.service",
        "systemctl --global mask podman.socket podman.service",
        "apt-get clean",
        "touch /etc/cloud/cloud-init.disabled",
        f"echo \"accounts=$(getent passwd {ADMIN} {USER} | cut -d: -f1,3,4 | tr '\\n' ' ')\"",
        "echo \"uid1000=$(getent passwd 1000 || echo none)\"",
        f"dpkg-query -W {' '.join(PACKAGES)} golang-github-containers-common netavark libsubid5 | sed 's/^/package=/' || true",
        "echo \"kernel=$(uname -r)\"",
        "",
    ])


# Processes: identity is (pid, start time, comm) as observed at start
# (passt is non-dumpable: its /proc/PID/exe is unreadable). A process that
# is gone reads None; any other /proc error propagates (never "gone").

def identity(pid):
    try:
        with open(f"/proc/{pid}/stat") as stream:
            head, tail = stream.read().rsplit(")", 1)
    except (FileNotFoundError, ProcessLookupError):
        return None
    fields = tail.split()
    return {"pid": pid, "start": int(fields[19]), "comm": head.split("(", 1)[1],
            "ppid": int(fields[1]), "state": fields[0]}


def same(recorded):
    now = identity(recorded["pid"])
    return now is not None and now["state"] != "Z" and now["start"] == recorded["start"] \
        and now["comm"] == recorded["comm"]


def signal_owned(recorded, sig):
    """`sig` to exactly the recorded process, through a pidfd opened and
    then re-checked (no pid reuse race); False when it is gone."""
    try:
        fd = os.pidfd_open(recorded["pid"])
    except ProcessLookupError:
        return False
    try:
        if not same(recorded):
            return False
        signal.pidfd_send_signal(fd, sig)
        return True
    finally:
        os.close(fd)


def wait_gone(recorded, seconds):
    deadline = time.monotonic() + seconds
    while same(recorded):
        if time.monotonic() > deadline:
            return False
        time.sleep(0.2)
    return True


def end_owned(recorded, grace):
    """Already gone, or gone within `grace`; then TERM, then KILL. Our own
    child is reaped too."""
    outcome = "exited" if wait_gone(recorded, grace) else None
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if outcome:
            break
        signal_owned(recorded, sig)
        if wait_gone(recorded, KILL_SECONDS):
            outcome = sig.name
    if outcome is None:
        raise Failed(f"pid {recorded['pid']} survived SIGKILL")
    child = CHILDREN.pop(recorded["pid"], None)
    if child is not None:
        child.wait(KILL_SECONDS)
    return outcome


@contextlib.contextmanager
def deferred_interrupt():
    """SIGINT (Ctrl-C) held until the block ends, then raised: a spawn and
    its registration complete together, so no interrupt lands between the
    fork and the handle. Main thread only (else a no-op); QEMU's exec resets
    the handler."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    pending = []
    previous = signal.signal(signal.SIGINT, lambda signum, frame: pending.append(signum))
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)
    if pending:
        raise KeyboardInterrupt


def settle_child(proc):
    """Kill and reap our unpublished child through its handle: unreaped, its
    pid cannot be reused, so the signal cannot reach another process."""
    if proc.poll() is None:
        proc.kill()
    proc.wait()
    CHILDREN.pop(proc.pid, None)
    return proc.returncode


def cmdline(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as stream:
            return stream.read().decode(errors="replace").split("\0")
    except OSError:
        return []


def scan(match):
    """Identities of live processes for which `match(identity, argv)`."""
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                proc = identity(int(entry))
                if proc and proc["state"] != "Z" and match(proc, cmdline(proc["pid"])):
                    found.append(proc)
            except (OSError, IndexError, ValueError):
                continue
    return found


def passt_for(port):
    """Live passt processes forwarding exactly our port: QEMU starts passt,
    which daemonizes (reparented, so not QEMU's child)."""
    spec = f"127.0.0.1/{port}:22"
    return scan(lambda proc, argv: proc["comm"] in PASST_COMMS and "--fd" in argv
                and any(argv[i] == "--tcp-ports" and argv[i + 1] == spec for i in range(len(argv) - 1)))


def qemu_for(console):
    """Live QEMU writing exactly `console` (a per-instance path below ROOT):
    recovers a launch whose identity was never published."""
    serial = f"file:{console}"
    return scan(lambda proc, argv: proc["comm"] == QEMU_COMM and serial in argv)


def passt_pidfile(pid):
    """The /tmp/passt-*.pid QEMU gave passt (QEMU leaves it when killed)."""
    argv = cmdline(pid)
    path = argv[argv.index("--pid") + 1] if "--pid" in argv[:-1] else None
    return path if path and re.fullmatch(r"/tmp/passt-[A-Za-z0-9]+\.pid", path) else None


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def host_nameservers(path="/run/systemd/resolve/resolv.conf"):
    """Upstream nameservers (systemd-resolved's list), so the guest needs no
    route to the host's loopback stub; none: passt's own default."""
    try:
        with open(path) as stream:
            found = re.findall(r"^nameserver\s+(\S+)\s*$", stream.read(), re.M)
    except OSError:
        return []
    return [ns for ns in found if not ns.startswith("127.") and ns != "::1"][:3]


def netdev(port, nameservers):
    """QEMU's own passt backend (QEMU starts passt on a socketpair, --fd;
    passt exits when QEMU does, even killed): no gateway->host-loopback mapping, one loopback
    TCP forward to the guest's sshd, no UDP forward. (A standalone passt's
    listening socket failed every accept here: epoll EBADF.)"""
    options = ["passt", "id=net0", f"path={PASST}", "param=--no-map-gw", f"tcp-ports=127.0.0.1/{port}:22"]
    options += [f"param=--dns={ns}" for ns in nameservers]
    return ",".join(options)


def qemu_argv(disk, netdev_spec, console, seed=None):
    """QEMU/KVM in the foreground (the driver holds its handle): one virtio
    disk (+ the build seed, read-only), the passt backend as the only NIC,
    serial to a file; no display, monitor, share, pidfile or daemonize."""
    argv = ["qemu-system-x86_64", "-name", HOSTNAME, "-nodefaults", "-machine", "q35,accel=kvm",
            "-cpu", "host", "-m", str(MEMORY_MIB), "-smp", str(CPUS), "-display", "none",
            "-monitor", "none", "-serial", f"file:{console}",
            "-drive", f"file={disk},if=virtio,format=qcow2,discard=unmap"]
    if seed is not None:
        argv += ["-drive", f"file={seed},if=virtio,format=raw,readonly=on"]
    argv += ["-netdev", netdev_spec, "-device", "virtio-net-pci,netdev=net0", "-device", "virtio-rng-pci"]
    return argv


def ssh_argv(root, port, user, command=(), tty=False):
    p = paths(root)
    argv = ["ssh", "-F", "/dev/null", "-i", p["client"], "-p", str(port),
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "ForwardAgent=no",
            "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={p['known_hosts']}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={HOSTNAME}",
            "-o", "CheckHostIP=no", "-o", "UpdateHostKeys=no", "-o", "ConnectTimeout=5",
            "-o", "LogLevel=ERROR"]
    argv += ["-t"] if tty else ["-T"]
    return argv + [f"{user}@127.0.0.1", "--"] + list(command)


def mem_available_mib():
    with open("/proc/meminfo") as stream:
        for line in stream:
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    raise Failed("no MemAvailable")


def owned_root(root):
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise Failed(f"{root}: not a private (0700) directory of ours")


@contextlib.contextmanager
def locked(root, seconds=None):
    """ROOT's lifecycle lock: flock on ROOT/lock (private, regular, single
    link, never removed, close-on-exec so no child inherits it); busy past
    `seconds` fails. Serializes build, start, stop and smoke; it proves no
    process identity."""
    owned_root(root)
    path = os.path.join(root, "lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1 \
                or st.st_mode & 0o077:
            raise Failed(f"{path}: not a private regular file")
        deadline = time.monotonic() + (LOCK_SECONDS if seconds is None else seconds)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise Failed(f"{root}: busy (another vm.py operation holds its lock)") from None
                time.sleep(0.1)
        yield
    finally:
        os.close(fd)


def load_state(root):
    try:
        with open(paths(root)["state"]) as stream:
            return json.load(stream)
    except FileNotFoundError:
        return None


def save_state(root, state):
    path = paths(root)["state"]
    tmp = path + ".tmp"
    if os.path.lexists(tmp):
        os.unlink(tmp)
    private_file(tmp, json.dumps(state, indent=1))
    os.replace(tmp, path)


def drop_state(root):
    os.unlink(paths(root)["state"])


def start(root, disk=None):
    with locked(root):
        return start_locked(root, disk or paths(root)["final"])


def stop(root):
    with locked(root):
        return stop_locked(root)


def start_locked(root, disk, seed=None):
    """Boot `disk` (lock held). State is durable before any process exists
    (instance token, unique console path) and the QEMU identity is published
    while its handle is still ours; a failure before that settles the child
    through the handle, after it through stop_locked. Returns the state."""
    p = paths(root)
    if load_state(root) is not None:
        raise Failed(f"{p['state']} exists: running, or stop first")
    available = mem_available_mib()
    if available < MEMORY_MIB + HEADROOM_MIB:
        raise Failed(f"MemAvailable {available} MiB < {MEMORY_MIB + HEADROOM_MIB}")
    token = os.urandom(4).hex()
    stamp = time.strftime("%Y%m%dT%H%M%S")
    state = {"instance": token, "phase": "launching", "disk": disk, "port": free_port(),
             "nameservers": host_nameservers(),
             "console": os.path.join(p["logs"], f"console-{stamp}-{token}.log"),
             "qemu_log": os.path.join(p["logs"], f"qemu-{stamp}-{token}.log")}
    save_state(root, state)
    proc, published = None, False
    try:
        out = os.open(state["qemu_log"], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            with deferred_interrupt():
                proc = subprocess.Popen(qemu_argv(disk, netdev(state["port"], state["nameservers"]),
                                                  state["console"], seed),
                                        stdin=subprocess.DEVNULL, stdout=out, stderr=out, close_fds=True,
                                        start_new_session=True)
                CHILDREN[proc.pid] = proc
        finally:
            os.close(out)
        qemu = identity(proc.pid)
        if qemu is None or qemu["comm"] != QEMU_COMM:
            raise Failed(f"no QEMU identity for pid {proc.pid}")
        state.update(qemu=qemu, phase="running")
        save_state(root, state)
        published = True
        deadline = time.monotonic() + 10
        state["passt"] = passt_for(state["port"])
        while not state["passt"] and time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.2)
            state["passt"] = passt_for(state["port"])
        state["passt_pidfiles"] = [passt_pidfile(child["pid"]) for child in state["passt"]]
        save_state(root, state)
        if len(state["passt"]) != 1:
            raise Failed(f"expected one passt for port {state['port']}, found {len(state['passt'])}")
        log(root, f"started qemu {qemu['pid']} passt {state['passt'][0]['pid']} instance {token} "
                  f"ssh 127.0.0.1:{state['port']} disk {disk} dns {state['nameservers'] or 'passt default'}")
        wait_ssh(root, state)
    except BaseException:
        try:
            if published:
                stop_locked(root, token, graceful=False)
            else:
                if proc is not None:
                    settle_child(proc)
                for child in qemu_for(state["console"]) + passt_for(state["port"]):
                    end_owned(child, PASST_SECONDS)
                drop_state(root)
                log(root, f"launch {token} settled before publication")
        except BaseException as error:
            log(root, f"launch {token} cleanup incomplete, state kept: {error!r}")
        raise
    return state


def wait_ssh(root, state):
    deadline = time.monotonic() + BOOT_SECONDS
    while True:
        result = run(ssh_argv(root, state["port"], ADMIN, ["true"]), check=False,
                     capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=30)
        if result.returncode == 0:
            return
        if "IDENTIFICATION HAS CHANGED" in result.stderr or "Host key verification failed" in result.stderr:
            raise Failed(f"host key mismatch: {result.stderr.strip()}")
        if not same(state["qemu"]):
            raise Failed("qemu exited during boot (see console log)")
        if time.monotonic() > deadline:
            raise Failed(f"no SSH within {BOOT_SECONDS}s: {result.stderr.strip()}")
        time.sleep(2)


def stop_locked(root, instance=None, graceful=True):
    """Settle ROOT's instance (lock held): guest poweroff (graceful), else
    TERM/KILL of exactly the recorded QEMU (or, never published, the one
    writing the instance's console), then any passt still forwarding its
    port. `instance` given: only that instance, else nothing is touched.
    State is dropped only once all of it is confirmed gone."""
    state = load_state(root)
    if state is None:
        return "not running"
    if instance is not None and state.get("instance") != instance:
        raise Failed(f"state is instance {state.get('instance')}, not {instance}: not touched")
    outcome = {}
    qemu = state.get("qemu")
    if qemu is None and state.get("console"):
        found = qemu_for(state["console"])
        if len(found) > 1:
            raise Failed(f"{len(found)} QEMUs write {state['console']}")
        qemu = found[0] if found else None
    if qemu is not None:
        if graceful and same(qemu):
            try:
                run(ssh_argv(root, state["port"], ADMIN, ["sudo", "-n", "systemctl", "poweroff"]),
                    check=False, capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
            except subprocess.TimeoutExpired:
                pass
        outcome["qemu"] = end_owned(qemu, STOP_SECONDS if graceful else 0)
    passts = {child["pid"]: child for child in state.get("passt") or ()}
    passts.update({child["pid"]: child for child in passt_for(state["port"])})
    for child in passts.values():
        outcome["passt"] = end_owned(child, PASST_SECONDS)
    for leftover in state.get("passt_pidfiles") or ():
        if leftover and os.path.lexists(leftover):
            os.unlink(leftover)
    drop_state(root)
    log(root, f"stopped {state.get('instance')} {outcome}")
    return outcome


def ssh_run(root, user, command, stdin=None, timeout=1800, logname=None):
    state = load_state(root)
    result = run(ssh_argv(root, state["port"], user, command), check=False, capture_output=True,
                 input=stdin, timeout=timeout)
    if logname:
        with open(os.path.join(paths(root)["logs"], logname), "ab") as stream:
            stream.write(result.stdout + b"\n--- stderr\n" + result.stderr)
    if result.returncode != 0:
        raise Failed(f"{user}: {shlex.join(command)} exited {result.returncode}: "
                     f"{result.stderr.decode(errors='replace')[-2000:]}")
    return result.stdout.decode()


def facts(text):
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[a-z0-9_]+", key):
            out.setdefault(key, []).append(value)
    return {key: values[0] if len(values) == 1 else values for key, values in out.items()}


def provenance():
    head = run(["git", "-C", REPO, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = run(["git", "-C", REPO, "status", "--porcelain", "--untracked-files=all", "--", HERE],
                capture_output=True, text=True).stdout.splitlines()
    return {"head": head, "driver_dirty": dirty, "driver_sha256": sha256_file(__file__)[0]}


def build(root=None):
    root = new_root(root)
    print(root)
    with locked(root):
        return build_locked(root)


def build_locked(root):
    p = paths(root)
    log(root, f"build in {root}")
    meta = {"schema": "agentbox.podman-test-vm.v1", "test_only": True, "source": provenance()}
    meta["base"] = download_base(root)
    client_public = keygen(p["client"], f"abpvm-client@{os.path.basename(root)}")
    seed, host_public = make_seed(root, client_public)
    overlay = os.path.join(p["build"], "overlay.qcow2")
    run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", p["base"], overlay, DISK])
    state = None
    try:
        state = start_locked(root, overlay, seed)
        out = ssh_run(root, ADMIN, ["sudo", "-n", "/bin/sh", "-s"], provision_script(client_public).encode(),
                      logname="provision.log")
        meta["provision"] = facts(out)
    finally:
        if state is not None:
            stop_locked(root, state["instance"])
    run(["qemu-img", "check", "-q", overlay])
    tmp = p["final"] + ".tmp"
    run(["qemu-img", "convert", "-q", "-O", "qcow2", overlay, tmp])
    os.chmod(tmp, 0o600)
    os.rename(tmp, p["final"])
    info = json.loads(run(["qemu-img", "info", "--output=json", p["final"]], capture_output=True, text=True).stdout)
    if "backing-filename" in info:
        raise Failed(f"{FINAL} has a backing file")
    for transient in (overlay, seed, os.path.join(p["build"], "host_ed25519")):
        os.unlink(transient)
    shutil.rmtree(p["build"])
    if sha256_file(p["base"])[0] != meta["base"]["sha256"]:
        raise Failed("base image changed")
    digest, size = sha256_file(p["final"])
    meta["disk"] = {"path": FINAL, "bytes": size, "sha256": digest, "virtual_size": info.get("virtual-size")}
    meta["vm"] = {"memory_mib": MEMORY_MIB, "cpus": CPUS, "hostname": HOSTNAME,
                  "admin": [ADMIN, ADMIN_UID], "user": [USER, UID, GID], "subids": list(SUBIDS),
                  "host_key": host_public, "network": "passt --no-map-gw (guest egress allowed)"}
    private_file(os.path.join(root, "metadata.json"), json.dumps(meta, indent=1) + "\n")
    log(root, f"built {p['final']} {size} B sha256 {digest}")
    return root


# Readiness smoke (abtest, a throwaway overlay on the final disk).

SMOKE = f"{HOME}/smoke"
STORE = ("--root", f"{SMOKE}/graph", "--runroot", f"{SMOKE}/run", "--storage-driver=vfs",
         "--cgroup-manager=cgroupfs", "--events-backend=none")
FACTS_SCRIPT = f"""set -eu
echo "id=$(id -u):$(id -g)"
echo "id_names=$(id -un):$(id -gn)"
echo "os=$(. /etc/os-release; echo "$PRETTY_NAME")"
echo "kernel=$(uname -r)"
echo "rootfs=$(findmnt -no FSTYPE /)"
echo "home_fs=$(stat -f -c %T {HOME})"
echo "systemd=$(systemctl --version | head -n 1)"
echo "cgroupfs=$(stat -f -c %T /sys/fs/cgroup)"
echo "user_controllers=$(cat /sys/fs/cgroup/user.slice/user-{UID}.slice/user@{UID}.service/cgroup.controllers)"
echo "user_bus=$(test -S /run/user/{UID}/bus && echo present || echo absent)"
echo "linger=$(loginctl show-user {USER} -p Linger --value)"
echo "subuid=$(tr '\\n' ' ' < /etc/subuid)"
echo "subgid=$(tr '\\n' ' ' < /etc/subgid)"
echo "newuidmap=$(stat -c %A /usr/bin/newuidmap) $(getcap /usr/bin/newuidmap 2>/dev/null)"
echo "newgidmap=$(stat -c %A /usr/bin/newgidmap) $(getcap /usr/bin/newgidmap 2>/dev/null)"
echo "apparmor_userns=$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo n/a)"
echo "podman=$(podman --version)"
echo "crun=$(crun --version | head -n 1)"
echo "conmon=$(conmon --version | head -n 1)"
echo "uid1000=$(getent passwd 1000 || echo none)"
echo "api_sockets=$(ls /run/podman /run/user/{UID}/podman 2>/dev/null | tr '\n' ' ')"
echo "podman_socket_units=$(systemctl is-enabled podman.socket 2>&1),$(systemctl --user is-enabled podman.socket 2>&1)"
echo "listening_podman=$(ss -xlH | grep -c -e podman -e nv-proxy || true)"
echo "egress=$(getent ahostsv4 archive.ubuntu.com >/dev/null && echo dns-ok || echo dns-failed)"
"""
INNER = """echo "jail_id=$(id -u):$(id -g)"
echo "jail_names=$(id -un):$(id -gn)"
echo "jail_uid_map=$(tr -s ' ' < /proc/self/uid_map | tr '\\n' ';')"
echo "jail_gid_map=$(tr -s ' ' < /proc/self/gid_map | tr '\\n' ';')"
echo "jail_nnp=$(grep NoNewPrivs /proc/self/status | tr -d '\\t ')"
echo "jail_capeff=$(grep CapEff /proc/self/status | tr -d '\\t ')"
echo "jail_net=$(tail -n +3 /proc/net/dev | cut -d: -f1 | tr -d ' ' | tr '\\n' ',')"
echo "jail_mount_owner=$(stat -c %u:%g "$HOME/ro"),$(stat -c %u:%g "$HOME/rw")"
echo "jail_ro_read=$(cat "$HOME/ro/data")"
printf 'written by jail\\n' > "$HOME/rw/new" && echo "jail_rw_write=ok"
if err=$( (printf x >> "$HOME/ro/data") 2>&1 ); then echo "jail_ro_write=UNEXPECTED"; else echo "jail_ro_write=$err"; fi
if err=$( (printf x > "$HOME/ro/new") 2>&1 ); then echo "jail_ro_create=UNEXPECTED"; else echo "jail_ro_create=$err"; fi
"""


def provider():
    sys.dont_write_bytecode = True
    sys.path.insert(0, os.path.join(REPO, "providers"))
    import podman  # noqa: E402  the production profile, never run here
    return podman


def container_argv(image_id):
    """The production `create` (retention none, keep-id, generated account)
    plus two VM-local binds through the production bind flags."""
    pod = provider()
    user = "agentbox"
    home = pod.guest_home(user)
    argv = pod.create_command(image_id, "none", user, mapping="keep_id")
    at = argv.index(f"--entrypoint={pod.IMAGE_INIT[0]}")
    binds = pod.bind_flags(home, [(f"{SMOKE}/fx/ro", "ro", "ro"), (f"{SMOKE}/fx/rw", "rw", "rw")])
    return argv[:at] + binds + argv[at:]


def smoke_script(image_id):
    p = f"podman {shlex.join(STORE)}"
    create = shlex.join(container_argv(image_id))
    return f"""set -eu
umask 077
p() {{ {p} "$@"; }}
F={SMOKE}/fx
mkdir -m 0700 $F $F/ro $F/rw
printf 'agentbox podman-vm ro fixture\\n' > $F/ro/data
echo "fixture=$(stat -c %u:%g:%a $F/ro $F/rw $F/ro/data | tr '\\n' ' ')"
ro_before=$(sha256sum < $F/ro/data)
echo "info=$(p info --format '{{{{json .}}}}' | base64 -w 0)"
p load -q -i {SMOKE}/image.oci.tar >/dev/null
echo "loaded=$(p images -q --no-trunc)"
ctr=$(p {create})
trap 'p rm -f -t 0 "$ctr" >/dev/null 2>&1 || true' EXIT
p start "$ctr" >/dev/null
p exec "$ctr" /bin/sh -c {shlex.quote(INNER)}
echo "vm_new_owner=$(stat -c %u:%g:%a $F/rw/new)"
echo "vm_ro_unchanged=$(test "$(sha256sum < $F/ro/data)" = "$ro_before" && echo yes || echo no)"
echo "vm_ro_new_absent=$(test -e $F/ro/new && echo no || echo yes)"
p rm -f -t 0 "$ctr" >/dev/null
trap - EXIT
p volume create --driver=local --uid=1000 --gid=1000 --opt=nocopy abpvm-flagcheck >/dev/null
echo "volume_uid_gid=accepted $(p unshare stat -c %u:%g "$(p volume inspect --format '{{{{.Mountpoint}}}}' abpvm-flagcheck)")"
p volume rm abpvm-flagcheck >/dev/null
echo "containers_left=$(p ps -a -q | wc -l)"
"""


def podman_info(f):
    """`podman info` JSON (base64 on the wire: its strings hold raw newlines)."""
    try:
        return json.loads(base64.b64decode(f.get("info", "")), strict=False)
    except ValueError:
        return {}


def smoke_checks(f, image_id):
    info = podman_info(f)
    host = info.get("host", {})
    erofs = "Read-only file system"
    return {
        "account": f.get("id") == f"{UID}:{GID}",
        "subids": f.get("subuid", "").strip() == f"{USER}:{SUBIDS[0]}:{SUBIDS[1]}"
        and f.get("subgid", "").strip() == f"{USER}:{SUBIDS[0]}:{SUBIDS[1]}",
        "cgroup_v2": f.get("cgroupfs") == "cgroup2fs",
        "user_bus": f.get("user_bus") == "present",
        "rootless": host.get("security", {}).get("rootless") is True,
        "runtime_crun": host.get("ociRuntime", {}).get("name") == "crun",
        "loaded_image": f.get("loaded") in (image_id, f"sha256:{image_id}"),
        "jail_1000": f.get("jail_id") == "1000:1000",
        "jail_no_network": f.get("jail_net") == "lo,",
        "jail_nnp": f.get("jail_nnp") == "NoNewPrivs:1",
        "jail_no_caps": f.get("jail_capeff") == "CapEff:0000000000000000",
        "mounts_seen_as_1000": f.get("jail_mount_owner") == "1000:1000,1000:1000",
        "rw_write": f.get("jail_rw_write") == "ok",
        "rw_owner_in_vm": f.get("vm_new_owner", "").startswith(f"{UID}:{GID}:"),
        "ro_write_erofs": erofs in f.get("jail_ro_write", "") and erofs in f.get("jail_ro_create", ""),
        "ro_unchanged": f.get("vm_ro_unchanged") == "yes" and f.get("vm_ro_new_absent") == "yes",
        "volume_uid_gid_flags": f.get("volume_uid_gid") == "accepted 1000:1000",
        # Podman 5.7's info.host.remoteSocket.exists reads true with no socket
        # or directory present: recorded, not trusted.
        "no_api_socket": f.get("api_sockets", "").strip() == "" and f.get("listening_podman") == "0"
        and f.get("podman_socket_units") == "masked,masked",
        "no_containers_left": f.get("containers_left") == "0",
    }


GUEST_ARCHIVE = f"{SMOKE}/image.oci.tar"


def read_archive(path):
    """The archive's bytes (no link, a regular file, bounded), read once:
    the bytes hashed are the bytes sent."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        st = os.fstat(stream.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_ARCHIVE:
            raise Failed(f"{path}: not a regular file of at most {MAX_ARCHIVE} bytes")
        data = stream.read(MAX_ARCHIVE + 1)
    if len(data) != st.st_size:
        raise Failed(f"{path}: changed while read")
    return data, hashlib.sha256(data).hexdigest()


def guest_digest(text):
    """The digest of exactly `sha256sum -- GUEST_ARCHIVE`'s one line, else None."""
    match = re.fullmatch(rf"([0-9a-f]{{64}})  {re.escape(GUEST_ARCHIVE)}\n", text)
    return match.group(1) if match else None


def smoke(root, archive, archive_sha256, image_id):
    if not re.fullmatch(r"[0-9a-f]{64}", image_id) or not re.fullmatch(r"[0-9a-f]{64}", archive_sha256):
        raise Failed("--sha256 and --image-id are 64 lowercase hex")
    data, got = read_archive(archive)
    if got != archive_sha256:
        raise Failed(f"archive sha256 {got} != {archive_sha256}")
    with locked(root):
        return smoke_locked(root, archive, data, got, image_id)


def upload_verified(root, data, digest):
    """Send `data` to GUEST_ARCHIVE and check the guest's digest before
    anything else runs; a mismatch removes it (never loaded)."""
    ssh_run(root, USER, ["/bin/sh", "-c", f"umask 077; mkdir {SMOKE} && cat > {GUEST_ARCHIVE}"], data, timeout=600)
    try:
        seen = guest_digest(ssh_run(root, USER, ["sha256sum", "--", GUEST_ARCHIVE]))
    except Failed:
        seen = None
    if seen != digest:
        with contextlib.suppress(Failed, subprocess.TimeoutExpired):
            ssh_run(root, USER, ["rm", "-f", "--", GUEST_ARCHIVE])
        raise Failed(f"guest archive sha256 {'unreadable' if seen is None else 'mismatch'}: not loaded")
    return seen


def smoke_locked(root, archive, data, got, image_id):
    """Readiness smoke (lock held) on a fresh overlay of the final disk. An
    occupied ROOT refuses before anything is made; only this smoke's own
    instance is stopped and its overlay removed only once that is settled."""
    p = paths(root)
    if load_state(root) is not None:
        raise Failed(f"{p['state']} exists: ROOT is in use, not touched")
    overlay = os.path.join(p["run"], f"smoke-{os.urandom(4).hex()}.qcow2")
    os.close(os.open(overlay, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600))
    final_before = sha256_file(p["final"])[0]
    result = {"archive": {"path": archive, "bytes": len(data), "sha256": got}, "image_id": image_id,
              "driver_sha256": sha256_file(__file__)[0]}
    state = None
    try:
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", p["final"], overlay])
        state = start_locked(root, overlay)
        out = f"guest_archive_sha256={upload_verified(root, data, got)}\n"
        out += ssh_run(root, USER, ["/bin/sh", "-s"], FACTS_SCRIPT.encode(), logname="smoke.log")
        out += ssh_run(root, USER, ["/bin/sh", "-s"], smoke_script(image_id).encode(), timeout=900,
                       logname="smoke.log")
    finally:
        settled = False
        try:
            if state is not None:
                result["stop"] = stop_locked(root, state["instance"])
            settled = load_state(root) is None
        except Exception as error:
            log(root, f"smoke instance not settled: {error!r}")
        if settled:
            os.unlink(overlay)
        else:
            log(root, f"kept {overlay}: its instance is not confirmed settled")
    f = facts(out)
    checks = smoke_checks(f, image_id)
    checks["guest_archive_sha256"] = f.get("guest_archive_sha256") == got
    checks["final_unchanged"] = sha256_file(p["final"])[0] == final_before
    checks["settled"] = settled and not os.path.lexists(overlay) and not passt_for(state["port"]) \
        and not qemu_for(state["console"])
    result.update({"facts": {k: v for k, v in f.items() if k != "info"}, "checks": checks,
                   "passed": all(checks.values()), "instance": state["instance"]})
    info = podman_info(f)
    result["podman_info"] = {"version": info.get("version", {}).get("Version"),
                             "remoteSocket": info.get("host", {}).get("remoteSocket"),
                             "ociRuntime": info.get("host", {}).get("ociRuntime"),
                             "idMappings": info.get("host", {}).get("idMappings"),
                             "graphDriverName": info.get("store", {}).get("graphDriverName"),
                             "cgroupVersion": info.get("host", {}).get("cgroupVersion")}
    name = f"smoke-{time.strftime('%Y%m%dT%H%M%S')}.json"
    private_file(os.path.join(p["logs"], name), json.dumps(result, indent=1) + "\n")
    log(root, f"smoke {'PASSED' if result['passed'] else 'FAILED'}: logs/{name}")
    return result


def ssh_request(admin, rest):
    """(admin, command) of `ssh ROOT [--admin] [--] [CMD...]`: argparse's
    REMAINDER keeps a --admin given after ROOT."""
    if rest[:1] == ["--admin"]:
        admin, rest = True, rest[1:]
    return admin, rest[1:] if rest[:1] == ["--"] else rest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="op", required=True)
    sub.add_parser("build").add_argument("--root")
    for op in ("start", "stop"):
        sub.add_parser(op).add_argument("root")
    sh = sub.add_parser("ssh")
    sh.add_argument("root")
    sh.add_argument("--admin", action="store_true")
    sh.add_argument("command", nargs=argparse.REMAINDER)
    sm = sub.add_parser("smoke")
    sm.add_argument("root")
    sm.add_argument("--archive", required=True)
    sm.add_argument("--sha256", required=True)
    sm.add_argument("--image-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.op == "build":
            build(args.root)
        elif args.op == "start":
            state = start(os.path.abspath(args.root))
            print(f"ssh 127.0.0.1:{state['port']}")
        elif args.op == "stop":
            print(stop(os.path.abspath(args.root)))
        elif args.op == "ssh":
            root = os.path.abspath(args.root)
            state = load_state(root)
            if state is None:
                raise Failed("not running")
            admin, command = ssh_request(args.admin, args.command)
            os.execvp("ssh", ssh_argv(root, state["port"], ADMIN if admin else USER, command,
                                      tty=not command and sys.stdin.isatty()))
        elif args.op == "smoke":
            result = smoke(os.path.abspath(args.root), os.path.abspath(args.archive), args.sha256, args.image_id)
            print(json.dumps(result["checks"], indent=1))
            return 0 if result["passed"] else 1
    except (Failed, subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as error:
        print(f"vm.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
