"""Inside the QEMU builder guest, as root: upgrades the system with stock
APT, installs the staged Node, resolves and installs the coding agents'
latest releases and assembles the worker from its staged sources
(../README.md). Run by the Packer recipe over the build's inbound SSH;
never on the host. Everything else comes from the uploaded context,
checked against its context.json first.

  sudo -n /usr/bin/python3 -I -B /var/tmp/agentbox-build/qemu/guest-install.py

  Ubuntu's archive (APT)           -> apt-get update (any error fails), dist-upgrade,
                                      install git ca-certificates python3-venv; phased
                                      updates never, no recommends; lists and cache cleared
  inputs/node-vX-linux-x64.tar.xz  -> /usr/local/bin/node, /usr/local/lib/node_modules/npm
  agents/resolve.sh (npm, online)  -> each agent's npm `latest` locked, metadata only,
                                      install scripts off; agents/agentlock.py checks
                                      the locks, held by root from then on
  REGISTRY (this script, online)   -> every locked tarball for this platform, bounded,
                                      its lock's sha512; then a fresh npm cache and
                                      `npm ci --offline` in /opt/agentbox-agents/AGENT
                                      (install scripts run, offline), `AGENT --version`;
                                      verified against the held locks, its command
                                      linked as /usr/local/bin/AGENT
  worker-src/                      -> worker.py build (with worker-counterparts/), then install
                                      at /opt/agentbox/worker, run by the image's python3
  home/                            -> /etc/skel guidance
  out/                             worker/, worker-metadata.json and image-manifest.json
                                   (the system record: kernels, packages, the sandbox's
                                   observed isolation, the agents' versions and lock
                                   digests) for the recipe's download; removed by
                                   finalize.sh

Node, npm and the agents' package code are third-party: they run only as
the sandbox's throwaway system account (Sandbox), with no supplementary
groups, capabilities or new privileges and a private /run. Package code
(install scripts, the agents' own start) runs only offline: a new network
namespace with no interface up, probed from inside before any of it runs
(fail closed). Online, only the official Node's npm runs, for the
registry's metadata with install scripts off: the build network and the
guest's resolver (a root-held copy of its file in the private /run),
nothing else of /run. Tarballs are fetched by this script itself. After
every sandboxed command the account's processes are killed; what it left
is read as data, never followed; trees it wrote are root's before any
check. The account is removed before the agents are verified and the
worker metadata recorded. Optional operator extras in the inputs (`git`,
`packages`) are a custom recipe's; this script ignores them.

The static management profile (profile/) is applied by finalize.sh, the
build's last command, so the build's own SSH session is never reconfigured.
"""
import base64
import errno
import hashlib
import http.client
import json
import os
import pwd
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

CONTEXT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The staged builder is imported, never compiled to a cache: a __pycache__
# beside it would change the context that check_context verifies.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(CONTEXT, "worker"))
sys.path.insert(0, os.path.join(CONTEXT, "agents"))

import agentlock  # noqa: E402
import worker  # noqa: E402

Refused = worker.Refused
LOCAL = "/usr/local"
NODE = "/usr/local/bin/node"
NPM = "/usr/local/bin/npm"
NPM_ROOT = "/usr/local/lib/node_modules/npm"
GIT = "/usr/bin/git"
PYTHON = "/usr/bin/python3"
MIN_GIT = (2, 53)
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C.UTF-8", "HOME": "/root",
       "DEBIAN_FRONTEND": "noninteractive", "NEEDRESTART_SUSPEND": "1", "NEEDRESTART_MODE": "l",
       "UCF_FORCE_CONFFOLD": "1"}
MASKED = ("apt-daily.timer", "apt-daily-upgrade.timer", "apt-daily.service", "apt-daily-upgrade.service",
          "unattended-upgrades.service", "pollinate.service", "motd-news.service", "motd-news.timer",
          "ua-timer.timer", "fwupd-refresh.timer")
REQUIRED_TOOLS = ("/usr/sbin/sshd", "/usr/lib/openssh/sftp-server", "/usr/bin/sudo", "/usr/bin/systemctl",
                  "/usr/bin/test", "/usr/bin/tar", "/usr/bin/python3", "/usr/bin/cloud-init")
# Stock APT, deterministic about phasing: a phased update is taken only once
# fully released (the security pocket is never phased); any update error
# (a missing or unverifiable index) fails the build.
APT = ("/usr/bin/apt-get", "-o", "APT::Update::Error-Mode=any",
       "-o", "APT::Get::Never-Include-Phased-Updates=true", "-o", "APT::Install-Recommends=false",
       "-o", "APT::Install-Suggests=false", "-o", "DPkg::Lock::Timeout=600",
       "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold")
SYSTEM_PACKAGES = ("git", "ca-certificates", "python3-venv")
APT_LISTS = "/var/lib/apt/lists"
SYSTEM_SCHEMA = "agentbox.qemu-system.v1"
# The image's Node, for npm and agents only.
NODE_MAJOR = 24
# The baked coding agents (images/agents): each an npm project, its command
# the agent's name; each agent's npm `latest`, resolved at every build from
# REGISTRY, the only origin of their metadata and tarballs.
AGENTS = agentlock.AGENTS
AGENTS_ROOT = "/opt/agentbox-agents"
REGISTRY = agentlock.REGISTRY
# Who owns the installed agents' trees (uid, gid).
OWNER = (0, 0)
# The tarball download's bounds: each file, all of them, how many.
MAX_AGENT_TARBALL = 256 << 20
MAX_AGENT_BYTES = 1 << 30
MAX_AGENT_TARBALLS = 1024
DOWNLOAD_TIMEOUT = 60
DOWNLOAD_ATTEMPTS = 3
CHUNK = 1 << 20
# Each agent's start check (`AGENT --version`), offline.
AGENT_START_SECONDS = 120
# Third-party code's sandbox (module doc): offline, a new network namespace
# too; online, the build network and the guest's resolver.
SANDBOX_USER = "agentbox-sandbox"
# What runs as root inside the namespace, before setpriv: absolute paths.
PRIVATE_RUN = "/usr/bin/mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run"
SANDBOX_PREFIX = ("/usr/bin/unshare", "--net", "--mount", "--propagation", "private", "--",
                  "/bin/sh", "-c", PRIVATE_RUN + ' && exec "$@"', "sh", "/usr/bin/setpriv")
SANDBOX_PRIVILEGES = ("--clear-groups", "--no-new-privs", "--inh-caps=-all", "--bounding-set=-all")
SANDBOX_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"}
RESOLV_CONF = "/etc/resolv.conf"
MAX_RESOLV_CONF = 64 << 10
# Probed from inside: who it runs as, its network namespace and interfaces,
# a connect to the build network's gateway (the host's loopback), its DNS
# and a public address, a name lookup, and /run.
PROBE = """import json, os, socket
out = {"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(),
       "netns": os.readlink("/proc/self/ns/net"), "interfaces": sorted(n for _, n in socket.if_nameindex()),
       "connect": {}, "run": sorted(os.listdir("/run"))}
for host, port in (("10.0.2.2", 22), ("10.0.2.3", 53), ("1.1.1.1", 443)):
    try:
        socket.create_connection((host, port), timeout=3).close()
        out["connect"][host] = 0
    except OSError as error:
        out["connect"][host] = error.errno or -1
try:
    socket.getaddrinfo("archive.ubuntu.com", 443)
    out["dns"] = "resolved"
except OSError:
    out["dns"] = "failed"
print(json.dumps(out))
"""
# Probed from inside the online variant: who it runs as, its network
# namespace (the build's), what /run holds, a lookup of the registry.
ONLINE_PROBE = """import json, os, socket, sys
run = sorted(os.path.relpath(os.path.join(d, n), "/run") for d, ds, fs in os.walk("/run") for n in ds + fs)
try:
    socket.getaddrinfo(sys.argv[1], 443)
    dns = "resolved"
except OSError:
    dns = "failed"
print(json.dumps({"uid": os.getuid(), "gid": os.getgid(), "groups": os.getgroups(),
                  "netns": os.readlink("/proc/self/ns/net"), "run": run, "dns": dns}))
"""
SANDBOX = None


def run(argv, ok=(0,), env=None, code="command", timeout=1800, **kwargs):
    """`argv`'s stdout; an exit status outside `ok` (None: any) or the
    timeout refuses `code`, its stderr's tail on ours."""
    try:
        out = subprocess.run(argv, env=env or ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout,
                             check=False, **kwargs)
    except subprocess.TimeoutExpired:
        raise Refused(code) from None
    if ok is not None and out.returncode not in ok:
        sys.stderr.write(out.stderr.decode("utf-8", "replace")[-4096:])
        raise Refused(code)
    return out.stdout.decode("utf-8", "replace")


class Sandbox:
    """Third-party code's account and namespaces (module doc). Its `root`
    (/var/tmp) is root's; beneath it `home` (HOME, TMPDIR, cwd) and
    whatever `own` hands over are the account's."""

    def __init__(self, held):
        run(["/usr/sbin/useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
             "--shell", "/usr/sbin/nologin", SANDBOX_USER])
        entry = pwd.getpwnam(SANDBOX_USER)
        self.uid, self.gid = entry.pw_uid, entry.pw_gid
        if self.uid == 0 or self.gid == 0:
            raise Refused("sandbox")
        self.root = tempfile.mkdtemp(prefix="agentbox-sandbox-", dir="/var/tmp")
        os.chmod(self.root, 0o755)
        self.home = self.private("home")
        self.resolver = resolver(held)
        self.evidence = self.check()

    def private(self, name):
        """root/`name`: a new directory of the account's alone."""
        path = os.path.join(self.root, name)
        os.mkdir(path, 0o700)
        os.lchown(path, self.uid, self.gid)
        return path

    def argv(self, argv, online=False):
        if online:
            script = PRIVATE_RUN
            if self.resolver is not None:
                real, copy = self.resolver
                script += (f" && /usr/bin/mkdir -p {shlex.quote(os.path.dirname(real))} && /usr/bin/cp "
                           f"{shlex.quote(copy)} {shlex.quote(real)} && /usr/bin/chmod 0644 {shlex.quote(real)}")
            prefix = ("/usr/bin/unshare", "--mount", "--propagation", "private", "--",
                      "/bin/sh", "-c", script + ' && exec "$@"', "sh", "/usr/bin/setpriv")
        else:
            prefix = SANDBOX_PREFIX
        return [*prefix, f"--reuid={self.uid}", f"--regid={self.gid}", *SANDBOX_PRIVILEGES, "--", *argv]

    def run(self, argv, online=False, code="command", timeout=1800):
        """`argv` in the sandbox (online: the build network); afterwards,
        whatever way it ends, none of the account's processes left."""
        try:
            return run(self.argv(argv, online), env=dict(SANDBOX_ENV, HOME=self.home, TMPDIR=self.home),
                       cwd=self.home, code=code, timeout=timeout)
        finally:
            self.stop()

    def stop(self):
        """Every process of the account killed, until none is left."""
        for _ in range(100):
            for flag in ("-u", "-U"):
                run(["/usr/bin/pkill", "-KILL", flag, str(self.uid)], ok=(0, 1))
            if not any(run(["/usr/bin/pgrep", flag, str(self.uid)], ok=(0, 1)).strip() for flag in ("-u", "-U")):
                return
            time.sleep(0.1)
        raise Refused("sandbox")

    def check(self):
        """The probe, run in the sandbox, must find it isolated; returns
        what it observed."""
        try:
            seen = json.loads(self.run([PYTHON, "-I", "-c", PROBE]))
        except ValueError:
            raise Refused("sandbox") from None
        return isolated(seen, self.uid, self.gid, os.readlink("/proc/self/ns/net"))

    def check_online(self):
        """The online variant's probe: the account, the build network, a
        resolver and nothing else of /run; recorded beside the offline
        evidence."""
        host = urllib.parse.urlsplit(REGISTRY).hostname
        try:
            seen = json.loads(self.run([PYTHON, "-I", "-c", ONLINE_PROBE, host], online=True))
        except ValueError:
            raise Refused("sandbox") from None
        expected = [] if self.resolver is None else run_entries(self.resolver[0])
        self.evidence["online"] = online(seen, self.uid, self.gid, os.readlink("/proc/self/ns/net"), expected)

    def own(self, path):
        """`path` (a directory of root's, with only root's files) handed to
        the account."""
        for name in tree(path):
            os.lchown(name, self.uid, self.gid)

    def release(self, path):
        """`path`'s tree root's, nothing writable by group or others; only
        once none of the account's processes is left (`run`). The account's
        entries change hands; anything of a third owner refuses."""
        for name in tree(path):
            st = os.lstat(name)
            if st.st_uid == self.uid:
                os.lchown(name, 0, 0)
                if not stat.S_ISLNK(st.st_mode):
                    os.chmod(name, st.st_mode & 0o7755 & ~0o6000)
            elif st.st_uid != 0:
                raise Refused("sandbox_residue")

    def close(self):
        """Its processes killed, its files gone, its account removed;
        nothing of it left in the image's trees."""
        self.stop()
        shutil.rmtree(self.root)
        run(["/usr/sbin/userdel", SANDBOX_USER])
        for top in (AGENTS_ROOT, LOCAL, "/var/tmp", "/tmp"):
            if any(os.lstat(name).st_uid == self.uid or os.lstat(name).st_gid == self.gid for name in tree(top)):
                raise Refused("sandbox_residue")


def resolver(held):
    """The guest's resolver file for the online sandbox's private /run:
    None when /etc/resolv.conf does not lead into /run (it stays visible);
    else (its real path, a root-held copy in `held`)."""
    real = os.path.realpath(RESOLV_CONF)
    if not real.startswith("/run/"):
        return None
    with open(real, "rb") as stream:
        data = stream.read(MAX_RESOLV_CONF + 1)
    if len(data) > MAX_RESOLV_CONF:
        raise Refused("sandbox")
    copy = os.path.join(held, "resolv.conf")
    fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
    return real, copy


def run_entries(real):
    """What the online sandbox's /run holds: `real`'s directories and it."""
    parts = os.path.relpath(real, "/run").split("/")
    return sorted("/".join(parts[:n]) for n in range(1, len(parts) + 1))


def tree(top):
    """`top` and everything beneath it, no link followed."""
    if not os.path.lexists(top):
        return
    yield top
    for directory, dirs, files in os.walk(top):
        for name in dirs + files:
            yield os.path.join(directory, name)


def isolated(seen, uid, gid, netns):
    """The probe's observation, accepted only as an isolated sandbox: the
    unprivileged account without supplementary groups, another network
    namespace with only `lo`, every connect unreachable, no name lookup,
    an empty /run."""
    if not isinstance(seen, dict) or seen.get("uid") != uid or seen.get("gid") != gid or seen.get("groups") != [] \
            or not isinstance(seen.get("netns"), str) or seen["netns"] == netns \
            or seen.get("interfaces") != ["lo"] or seen.get("run") != [] or seen.get("dns") != "failed" \
            or not isinstance(seen.get("connect"), dict) or len(seen["connect"]) != 3 \
            or any(code != errno.ENETUNREACH for code in seen["connect"].values()):
        raise Refused("sandbox")
    return {"isolated": True, "user": SANDBOX_USER, "interfaces": seen["interfaces"],
            "connect": {host: "ENETUNREACH" for host in sorted(seen["connect"])}, "dns": "failed", "run": "empty"}


def online(seen, uid, gid, netns, expected):
    """The online variant's observation, accepted only as: the account
    without supplementary groups, the build's network namespace, `expected`
    in /run (the resolver), a resolved registry name."""
    if not isinstance(seen, dict) or seen.get("uid") != uid or seen.get("gid") != gid or seen.get("groups") != [] \
            or seen.get("netns") != netns or seen.get("run") != expected or seen.get("dns") != "resolved":
        raise Refused("sandbox")
    return {"network": "build", "run": expected, "dns": "resolved", "scripts": "off"}


def untrusted(argv):
    """Third-party code: only ever in the sandbox."""
    if SANDBOX is None:
        raise Refused("sandbox")
    return SANDBOX.run(argv)


def check_context():
    """The context is exactly context.json's listing."""
    listing = json.loads(worker.read_small(os.path.join(CONTEXT, "context.json"), 1 << 22))["files"]
    actual = []
    for rel, kind, links, _ in worker.scan(CONTEXT):
        if rel == "context.json":
            continue
        if kind == "file" and links == 1:
            size, digest = worker.measured(os.path.join(CONTEXT, rel))
            actual.append({"path": rel, "size": size, "sha256": digest})
        elif kind != "dir":
            raise Refused("context")
    if sorted(actual, key=lambda e: e["path"]) != listing:
        raise Refused("context")
    return json.loads(worker.read_small(os.path.join(CONTEXT, "inputs.json"), 65536))


def install_node(inputs):
    """Node and its npm package from the staged distribution: regular files,
    directories and npm-internal relative links only."""
    version = inputs["node"]["version"]
    prefix = f"node-v{version}-linux-x64/"
    archive_path = os.path.join(CONTEXT, "inputs", inputs["node"]["file"])
    npm = "lib/node_modules/npm"
    with tempfile.TemporaryDirectory(prefix="agentbox-node-", dir="/var/tmp") as tmp:
        with tarfile.open(archive_path, "r:xz") as archive:
            chosen = []
            for member in archive:
                # The official archives list their own top directory first.
                if member.name == prefix[:-1] and member.isdir():
                    continue
                if not member.name.startswith(prefix):
                    raise Refused("node_archive")
                rel = member.name[len(prefix):]
                if rel != "bin/node" and rel != npm and not rel.startswith(npm + "/"):
                    continue
                if any(p in ("", ".", "..") for p in rel.split("/")):
                    raise Refused("node_archive")
                if member.issym():
                    target = os.path.normpath(os.path.join(os.path.dirname(rel), member.linkname))
                    if member.linkname.startswith("/") or not target.startswith(npm + "/"):
                        raise Refused("node_archive")
                elif not (member.isreg() or member.isdir()):
                    raise Refused("node_archive")
                chosen.append(member)
            archive.extractall(tmp, members=chosen, filter="data")
        root = os.path.join(tmp, prefix)
        if os.path.lexists(NODE) or os.path.lexists(NPM_ROOT):
            raise Refused("node_exists")
        os.makedirs(os.path.dirname(NPM_ROOT), 0o755, exist_ok=True)
        shutil.move(os.path.join(root, "bin/node"), NODE)
        shutil.move(os.path.join(root, npm), NPM_ROOT)
    os.chmod(NODE, 0o755)
    for name, script in (("npm", "npm-cli.js"), ("npx", "npx-cli.js")):
        os.symlink(f"../lib/node_modules/npm/bin/{script}", os.path.join(LOCAL, "bin", name))
    if untrusted([NODE, "--version"]).strip() != "v" + version:
        raise Refused("node_version")


def clear_lists():
    """APT's lists, the base's shipped ones included: fetched fresh."""
    for name in os.listdir(APT_LISTS):
        path = os.path.join(APT_LISTS, name)
        if name != "lock" and os.path.isfile(path) and not os.path.islink(path):
            os.unlink(path)


def upgrade_system():
    """Stock APT over the build network: fresh signed indexes (any update
    error fails), the whole upgrade, then the image's system packages.
    Returns the build boot's kernel."""
    run(["/usr/bin/cloud-init", "status", "--wait"], ok=(0, 2))
    run(["/usr/bin/systemctl", "stop", *MASKED], ok=None)
    clear_lists()
    run([*APT, "update"])
    run([*APT, "-y", "dist-upgrade"])
    run([*APT, "-y", "install", *SYSTEM_PACKAGES])
    run([*APT, "clean"])
    clear_lists()
    return os.uname().release


def kernels(build):
    """The build boot's kernel, every installed one, and the newest (the one
    the disk boots by default)."""
    installed = run(["/usr/bin/linux-version", "list"]).split()
    ordered = run(["/usr/bin/linux-version", "sort", "--reverse", *installed]).split() if installed else []
    if not installed or sorted(ordered) != sorted(installed):
        raise Refused("kernel")
    return {"build": build, "intended": ordered[0], "installed": sorted(installed)}


def packages():
    out = run(["/usr/bin/dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Architecture}\t${Version}\n"])
    return sorted([name, arch, version] for status, name, arch, version in
                  (line.split("\t") for line in out.splitlines()) if status.strip() == "ii")


def write_system(build, sandbox, agents):
    path = os.path.join(CONTEXT, "out", "image-manifest.json")
    value = {"schema": SYSTEM_SCHEMA, "kernel": kernels(build), "packages": packages(),
             "apt": {"phased_updates": "never", "recommends": False}, "sandbox": sandbox, "agents": agents}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=1, sort_keys=True)


def resolve_agents(tools):
    """Each agent's npm `latest` locked by resolve.sh (a root-held copy in
    `tools`) in the online sandbox: npm, metadata only, install scripts
    off. Then, its processes gone, the result read as data: exactly the
    agents' locks (agentlock), held from then on in memory. Returns
    {agent: {package, version, project, lock, tarballs}}."""
    SANDBOX.check_online()
    work = SANDBOX.private("resolve")
    out = os.path.join(work, "locks")
    SANDBOX.run(["/bin/sh", os.path.join(tools, "resolve.sh"), REGISTRY, out], online=True, code="agent_resolve")
    try:
        if not stat.S_ISDIR(os.lstat(out).st_mode):
            raise Refused("agent_lock")
        agentlock.check_tree(out, REGISTRY)
        locks = {}
        for agent in AGENTS:
            project = agentlock.read(os.path.join(out, agent, "package.json"), agentlock.MAX_PROJECT_BYTES)
            lock = agentlock.read(os.path.join(out, agent, "package-lock.json"), agentlock.MAX_LOCK_BYTES)
            (package, version), tarballs = agentlock.check(project, lock, REGISTRY, agentlock.PACKAGES[agent])
            locks[agent] = {"package": package, "version": version, "project": project, "lock": lock,
                            "tarballs": tarballs}
    except (OSError, agentlock.Refused):
        raise Refused("agent_lock") from None
    shutil.rmtree(work)
    return locks


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        raise Refused("agent_download")


def download_plan(locks):
    """Every locked tarball for this platform, once: {file: entry}; one
    file name for different tarballs, or more than MAX_AGENT_TARBALLS,
    refuses."""
    plan = {}
    for agent in AGENTS:
        for entry in locks[agent]["tarballs"]:
            if not entry["resolved"].startswith(REGISTRY):
                raise Refused("agent_lock")
            known = plan.setdefault(entry["file"], entry)
            if (known["resolved"], known["integrity"]) != (entry["resolved"], entry["integrity"]):
                raise Refused("agent_lock")
    if len(plan) > MAX_AGENT_TARBALLS:
        raise Refused("agent_bounds")
    return plan


def download(locks, held):
    """Each tarball of the plan from REGISTRY, by this script (root, the
    build network; no proxy, no redirect), into `held`: at most
    MAX_AGENT_TARBALL each and MAX_AGENT_BYTES together, exactly its
    lock's sha512 (else `agent_integrity`). Returns the file names."""
    plan = download_plan(locks)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    total = 0
    for name in sorted(plan):
        bound = min(MAX_AGENT_TARBALL, MAX_AGENT_BYTES - total)
        for attempt in range(DOWNLOAD_ATTEMPTS):
            try:
                size = fetch_one(opener, plan[name], os.path.join(held, name), bound)
                break
            except (OSError, http.client.HTTPException, urllib.error.URLError, ValueError):
                if os.path.lexists(os.path.join(held, name)):
                    os.unlink(os.path.join(held, name))
                if attempt + 1 == DOWNLOAD_ATTEMPTS:
                    raise Refused("agent_download") from None
                time.sleep(2)
        total += size
    return sorted(plan)


def fetch_one(opener, entry, path, bound):
    """One tarball into `path` (new), at most `bound` bytes, its sha512
    the lock's; its size."""
    expected = base64.b64decode(entry["integrity"][len("sha512-"):])
    with opener.open(urllib.request.Request(entry["resolved"], headers={"User-Agent": "agentbox"}),
                     timeout=DOWNLOAD_TIMEOUT) as response:
        if response.status != 200 or response.geturl() != entry["resolved"]:
            raise Refused("agent_download")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        hasher, size = hashlib.sha512(), 0
        with os.fdopen(fd, "wb") as stream:
            while True:
                data = response.read(min(CHUNK, bound + 1 - size))
                if not data:
                    break
                size += len(data)
                if size > bound:
                    raise Refused("agent_bounds")
                hasher.update(data)
                stream.write(data)
    if hasher.digest() != expected:
        raise Refused("agent_integrity")
    return size


def install_agents(locks, files, held):
    """Each agent from its held lock, offline and in the sandbox: the
    downloaded tarballs (root's, read only) added to a fresh npm cache,
    then `npm ci --offline` (every package's integrity the lock's, install
    scripts run) in a tree the account owns only meanwhile, root's again
    once its processes are gone; its command linked in /usr/local/bin;
    then each `AGENT --version`, offline, with the sandbox's scratch HOME."""
    if SANDBOX is None:
        raise Refused("sandbox")
    flags = ["--offline", "--no-audit", "--no-fund", "--no-update-notifier"]
    staged = os.path.join(SANDBOX.root, "tarballs")
    os.mkdir(staged, 0o755)
    for name in files:
        os.rename(os.path.join(held, name), os.path.join(staged, name))
    cache = SANDBOX.private("npm-cache")
    SANDBOX.run([NPM, "cache", "add", "--cache", cache, *flags, *(os.path.join(staged, n) for n in files)],
                code="agent_install")
    for agent in AGENTS:
        target = os.path.join(AGENTS_ROOT, agent)
        os.makedirs(target, 0o755)
        for name, key in (("package.json", "project"), ("package-lock.json", "lock")):
            fd = os.open(os.path.join(target, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, "wb") as stream:
                stream.write(locks[agent][key])
        SANDBOX.own(target)
        try:
            SANDBOX.run([NPM, "ci", "--prefix", target, "--cache", cache, "--omit=dev", *flags], code="agent_install")
        finally:
            SANDBOX.release(target)
        os.symlink(f"{target}/node_modules/.bin/{agent}", os.path.join(LOCAL, "bin", agent))
    for agent in AGENTS:
        SANDBOX.run([os.path.join(LOCAL, "bin", agent), "--version"], code="agent_start",
                    timeout=AGENT_START_SECONDS)
    shutil.rmtree(staged)
    shutil.rmtree(cache)


def owner(path):
    st = os.lstat(path)
    return st.st_uid, st.st_gid


def read_beneath(root, rel, limit):
    """`root`/`rel` read as data: every directory opened without following
    a link, the file a single-link regular one, at most `limit` bytes."""
    fd = worker.opened(root, directory=True)
    try:
        parts = rel.split("/")
        for part in parts[:-1]:
            sub = worker.opened(part, directory=True, dir_fd=fd)
            os.close(fd)
            fd = sub
        with os.fdopen(worker.opened(parts[-1], dir_fd=fd), "rb") as stream:
            data = stream.read(limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise Refused("agent")
    return data


def verify_agents(locks):
    """With the sandbox gone: each agent's tree root's and not writable by
    group or others, its package.json and lock exactly the held ones, its
    package installed at exactly the locked version, its command a link
    into its own tree. Returns the system record's `agents`."""
    out = {}
    for agent in AGENTS:
        held, target = locks[agent], os.path.join(AGENTS_ROOT, agent)
        try:
            if any(owner(name) != OWNER or (not os.path.islink(name) and os.lstat(name).st_mode & 0o022)
                   for name in tree(target)):
                raise Refused("agent")
            if read_beneath(target, "package.json", agentlock.MAX_PROJECT_BYTES) != held["project"] \
                    or read_beneath(target, "package-lock.json", agentlock.MAX_LOCK_BYTES) != held["lock"]:
                raise Refused("agent")
            installed = json.loads(read_beneath(target, f"node_modules/{held['package']}/package.json", 1 << 20))
            link = os.readlink(os.path.join(LOCAL, "bin", agent))
            real = os.path.realpath(os.path.join(LOCAL, "bin", agent))
        except (OSError, ValueError, Refused):
            raise Refused("agent") from None
        if not isinstance(installed, dict) or installed.get("name") != held["package"] \
                or installed.get("version") != held["version"] or link != f"{target}/node_modules/.bin/{agent}" \
                or not real.startswith(f"{target}/node_modules/") or not os.path.isfile(real) \
                or not os.access(real, os.X_OK):
            raise Refused("agent")
        out[agent] = {"package": held["package"], "version": held["version"],
                      "lock_sha256": hashlib.sha256(held["lock"]).hexdigest()}
    return out


def install_worker():
    out = os.path.join(CONTEXT, "out")
    worker.build(os.path.join(CONTEXT, "worker-src"), out, os.path.join(CONTEXT, "worker-counterparts"))
    os.makedirs(os.path.dirname(worker.INSTALL_ROOT), 0o755, exist_ok=True)
    return worker.install(out)


def configure():
    for name in ("AGENTS.md", "CLAUDE.md"):
        target = os.path.join("/etc/skel", name)
        shutil.copyfile(os.path.join(CONTEXT, "home", name), target)
        os.chmod(target, 0o644)
    shutil.copyfile(os.path.join(CONTEXT, "qemu", "profile", "99-agentbox-no-periodic"),
                    "/etc/apt/apt.conf.d/99-agentbox-no-periodic")
    for unit in MASKED:
        path = os.path.join("/etc/systemd/system", unit)
        if os.path.lexists(path):
            os.unlink(path)
        os.symlink("/dev/null", path)


def check_node(node=NODE):
    """Node's major version at least `NODE_MAJOR`, for npm and agents."""
    major = untrusted([node, "-p", "process.versions.node.split('.')[0]"]).strip()
    if not major.isdigit() or int(major) < NODE_MAJOR:
        raise Refused("node_version")


def check_tools():
    """The runtime's prerequisites, checked in the built guest."""
    for path in REQUIRED_TOOLS + (NODE, GIT, NPM):
        if not os.access(path, os.X_OK):
            raise Refused("missing_tool")
    run([PYTHON, "-I", "-c", "import ensurepip, sys, venv; assert sys.version_info >= (3, 12)"])
    with tempfile.TemporaryDirectory(prefix="agentbox-venv-check-", dir="/var/tmp") as tmp:
        run([PYTHON, "-I", "-m", "venv", f"{tmp}/venv"])
        run([f"{tmp}/venv/bin/python", "-I", "-m", "pip", "--version"])
    check_node()
    untrusted([NPM, "--version"])
    version = run([GIT, "--version"]).split()[2].split(".")
    if tuple(int(part) for part in version[:2]) < MIN_GIT:
        raise Refused("git_version")
    with tempfile.TemporaryDirectory(prefix="agentbox-git-check-", dir="/var/tmp") as tmp:
        run([GIT, "-C", tmp, "init", "-q", "src"])
        run([GIT, "-C", f"{tmp}/src", "-c", "user.name=check", "-c", "user.email=check@localhost",
             "commit", "-q", "--allow-empty", "-m", "check"])
        run([GIT, "-c", "protocol.allow=never", "-c", "protocol.file.allow=always", "clone", "-q",
             f"file://{tmp}/src", f"{tmp}/dst"])
        run([GIT, "-C", f"{tmp}/dst", "rev-parse", "--verify", "HEAD"])


def main(argv):
    global SANDBOX
    if argv or os.geteuid() != 0:
        raise Refused("usage")
    inputs = check_context()
    build = upgrade_system()
    # Root's alone: the resolver's copy, the downloaded tarballs. Readable
    # by the sandbox: resolve.sh's copy.
    held = tempfile.mkdtemp(prefix="agentbox-held-", dir="/var/tmp")
    tools = tempfile.mkdtemp(prefix="agentbox-tools-", dir="/var/tmp")
    try:
        os.chmod(tools, 0o755)
        shutil.copyfile(os.path.join(CONTEXT, "agents", "resolve.sh"), os.path.join(tools, "resolve.sh"))
        os.chmod(os.path.join(tools, "resolve.sh"), 0o644)
        SANDBOX = Sandbox(held)
        try:
            install_node(inputs)
            locks = resolve_agents(tools)
            install_agents(locks, download(locks, held), held)
            release = install_worker()
            configure()
            check_tools()
            evidence = SANDBOX.evidence
        finally:
            sandbox, SANDBOX = SANDBOX, None
            sandbox.close()
    finally:
        shutil.rmtree(held)
        shutil.rmtree(tools)
    agents = verify_agents(locks)
    write_system(build, evidence, agents)
    print(f"agentbox-guest-installed {release} " + " ".join(f"{a}={agents[a]['version']}" for a in AGENTS))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (Refused, OSError, subprocess.SubprocessError, tarfile.TarError, ValueError) as error:
        code = error if isinstance(error, Refused) else type(error).__name__
        print(f"agentbox-guest-install refused: {code}", file=sys.stderr)
        sys.exit(1)
