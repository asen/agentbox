"""The pinned SSH profile (the Rust host's runtime/ssh.rs, session.rs and
scp.rs) and the worker bootstrap (runtime/bootstrap.rs, docs/ssh-worker.md):
a managed image's preinstalled payload or an attached target's uploaded
bundle.

```text
session    ssh -F /dev/null -T -l USER [-p PORT] -R 127.0.0.1:18080:127.0.0.1:BROKER
               -o FIXED... -o IdentityFile -o UserKnownHostsFile -o HostKeyAlias
               DESTINATION LAUNCHER
bootstrap  the same login, no forward, remote `/bin/sh -s`, a host-generated
           script on stdin: prepare; [attached: one sftp batch of the
           bundle's listed files]; verify the payload (baked in place, or
           uploaded, then 0400) and write a fresh bin/ (agentbox-request,
           the enabled handlers' shims, a session wrapper) and the launcher
transfer   scp/sftp -q -B|-b - -F /dev/null [-P PORT] -S SSH -o FIXED...
               -o IdentityFile -o UserKnownHostsFile -o HostKeyAlias -o User
```

Managed: a fresh client key per execution (`ssh-keygen`, only its public
half sent to the provider), the provider's host key pinned under an alias
of the host's ids alone. Attached: the target's own identity (named to
ssh, never opened here) and host key, pinned the same way. `-F /dev/null`,
every other authentication, agent, X11, multiplexing, local command and
escape off. A stdio provider's route is `ProxyCommand=<connect words>` in
place of `ProxyCommand=none`, with the provider's environment (the custody
domain included) on ssh's. Every field is a validated plain value;
nothing comes from the guest.
"""
import base64
import os
import re
import stat

from .assets import provider_protocol, worker_layout
from .handlers import SESSION_WRAPPER
from .host import HostError

GUEST_PROXY_PORT = 18080
LOOPBACK = "127.0.0.1"
OPTIONS = (
    "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "CheckHostIP=no",
    "GlobalKnownHostsFile=none", "VerifyHostKeyDNS=no", "HostKeyAlgorithms=ssh-ed25519",
    "KnownHostsCommand=none", "IdentitiesOnly=yes", "IdentityAgent=none", "AddKeysToAgent=no",
    "PKCS11Provider=none", "PubkeyAuthentication=yes", "PubkeyAcceptedAlgorithms=ssh-ed25519",
    "PreferredAuthentications=publickey", "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no", "HostbasedAuthentication=no", "EnableSSHKeysign=no",
    "GSSAPIAuthentication=no", "ForwardAgent=no", "ForwardX11=no", "ForwardX11Trusted=no",
    "ControlMaster=no", "ControlPath=none", "ControlPersist=no", "ProxyCommand=none",
    "ProxyJump=none", "PermitLocalCommand=no", "ForkAfterAuthentication=no",
    "SessionType=default", "Tunnel=no", "RequestTTY=no", "EscapeChar=none",
    "CanonicalizeHostname=no", "ExitOnForwardFailure=yes", "ServerAliveInterval=5",
    "ServerAliveCountMax=3", "ConnectTimeout=10", "ConnectionAttempts=1", "LogLevel=ERROR",
)
# The transfers' fixed flags and options (runtime/scp.rs).
SCP_FLAGS = ("-q", "-B", "-s", "-F", "/dev/null")
SFTP_FLAGS = ("-q", "-b", "-", "-F", "/dev/null")
MAX_BATCH_BYTES = 4 << 20
TRANSFER_OPTIONS = (
    "BatchMode=yes", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "CheckHostIP=no",
    "GlobalKnownHostsFile=none", "VerifyHostKeyDNS=no", "HostKeyAlgorithms=ssh-ed25519",
    "KnownHostsCommand=none", "IdentitiesOnly=yes", "IdentityAgent=none", "AddKeysToAgent=no",
    "PKCS11Provider=none", "PubkeyAuthentication=yes", "PubkeyAcceptedAlgorithms=ssh-ed25519",
    "PreferredAuthentications=publickey", "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no", "HostbasedAuthentication=no", "EnableSSHKeysign=no",
    "GSSAPIAuthentication=no", "NumberOfPasswordPrompts=0", "ForwardAgent=no", "ForwardX11=no",
    "ForwardX11Trusted=no", "ClearAllForwardings=yes", "ControlMaster=no", "ControlPath=none",
    "ControlPersist=no", "ProxyCommand=none", "ProxyJump=none", "PermitLocalCommand=no",
    "ForkAfterAuthentication=no", "Tunnel=no", "RequestTTY=no", "EscapeChar=none",
    "CanonicalizeHostname=no", "ServerAliveInterval=5", "ServerAliveCountMax=3", "ConnectTimeout=5",
    "ConnectionAttempts=1", "LogLevel=ERROR",
)
IDENTITY = "id_ed25519"
PUBLIC = "id_ed25519.pub"
KNOWN_HOSTS = "known_hosts"
COMMENT = "agentbox"
# An ed25519 public key blob: the type string, then a 32-byte key.
ED25519_BLOB = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
_PLAIN = re.compile(r"/[A-Za-z0-9._/-]*")
_PROXY_WORD = re.compile(r"[A-Za-z0-9._/:=,+-]+")


def plain_path(path):
    if not isinstance(path, str) or _PLAIN.fullmatch(path) is None or not provider_protocol.is_path(path):
        raise HostError("ssh_binding_invalid")
    return path


def keygen_argv(keygen, directory):
    return [keygen, "-q", "-t", "ed25519", "-N", "", "-C", COMMENT, "-f", f"{directory}/{IDENTITY}"]


def read_public(directory):
    """`ssh-ed25519 BASE64` of the generated key: ours, bounded, exactly
    type, key and the fixed comment."""
    try:
        fd = os.open(f"{directory}/{PUBLIC}", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o022:
                raise HostError("keygen_failed")
            text = os.read(fd, 513).decode()
        finally:
            os.close(fd)
    except (OSError, UnicodeDecodeError):
        raise HostError("keygen_failed") from None
    words = text[:-1].split(" ") if text.endswith("\n") else []
    if len(words) != 3 or words[2] != COMMENT:
        raise HostError("keygen_failed")
    key = f"{words[0]} {words[1]}"
    if not is_host_key(key):
        raise HostError("keygen_failed")
    return key


def is_host_key(text):
    """`ssh-ed25519 BASE64`, canonical, of an ed25519 key blob."""
    words = text.split(" ") if isinstance(text, str) else []
    if len(words) != 2 or words[0] != "ssh-ed25519":
        return False
    try:
        blob = base64.b64decode(words[1].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        return False
    return len(blob) == 51 and blob.startswith(ED25519_BLOB) and base64.b64encode(blob).decode() == words[1]


def alias(run_id, execution_id):
    return f"agentbox-{run_id}-{execution_id}"


def pin_host_key(directory, name, host_key):
    path = f"{directory}/{KNOWN_HOSTS}"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, f"{name} {host_key}\n".encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


_DNS = re.compile(r"(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*")


def is_host(text):
    """An attached target's host: IPv4, IPv6 (unbracketed) or a lowercase
    DNS name (runtime/connection.rs `Host::parse`)."""
    import ipaddress
    if not isinstance(text, str) or not text:
        return False
    try:
        address = ipaddress.ip_address(text)
        return str(address) == text and not (address.version == 6 and address.ipv4_mapped is not None)
    except ValueError:
        return _DNS.fullmatch(text) is not None and not text.replace(".", "").isdigit()


class Connection:
    """One instance's validated bindings: endpoint or proxy route, login
    user, client identity, pinned known_hosts and alias. A managed
    endpoint is loopback; an attached one the target's host."""

    def __init__(self, user, identity, known_hosts, host_key_alias, endpoint=None, proxy=None,
                 proxy_env=None, attached=False):
        if not provider_protocol.is_user(user) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,252}",
                                                               host_key_alias) is None:
            raise HostError("ssh_binding_invalid")
        if (endpoint is None) == (proxy is None) or (attached and proxy is not None):
            raise HostError("ssh_binding_invalid")
        if endpoint is not None and (not (is_host(endpoint[0]) if attached
                                          else endpoint[0] in ("127.0.0.1", "::1"))
                                     or type(endpoint[1]) is not int or not 1 <= endpoint[1] <= 65535):
            raise HostError("ssh_binding_invalid")
        if proxy is not None and (not proxy or len(proxy) > 64 or len(" ".join(proxy)) > 4096
                                  or not all(_PROXY_WORD.fullmatch(w) for w in proxy)
                                  or not provider_protocol.is_path(proxy[0])):
            raise HostError("ssh_binding_invalid")
        if plain_path(identity) == plain_path(known_hosts):
            raise HostError("ssh_binding_invalid")
        self.user, self.identity, self.known_hosts = user, identity, known_hosts
        self.alias, self.endpoint, self.proxy = host_key_alias, endpoint, proxy
        self.proxy_env = proxy_env

    def env(self, tool_env):
        """ssh's whole environment: a host tool's to an endpoint, the
        provider's (without SHELL) plus LC_ALL=C through a proxy."""
        if self.proxy is None:
            return dict(tool_env)
        env = {k: v for k, v in self.proxy_env.items() if k != "SHELL"}
        env["LC_ALL"] = "C"
        return env

    def destination(self):
        return self.alias if self.proxy is not None else self.endpoint[0]

    def operand(self):
        """An scp/sftp remote operand's host: an IPv6 literal bracketed."""
        host = self.destination()
        return f"[{host}]" if ":" in host else host

    def argv(self, ssh, remote, forward=None):
        args = [ssh, "-F", "/dev/null", "-T", "-l", self.user]
        if self.endpoint is not None:
            args += ["-p", str(self.endpoint[1])]
        if forward is not None:
            args += ["-R", forward]
        for option in OPTIONS:
            if option == "ProxyCommand=none" and self.proxy is not None:
                option = "ProxyCommand=" + " ".join(self.proxy)
            args += ["-o", option]
        for option in (f"IdentityFile={self.identity}", f"UserKnownHostsFile={self.known_hosts}",
                       f"HostKeyAlias={self.alias}"):
            args += ["-o", option]
        return args + [self.destination()] + list(remote)

    def session(self, ssh, launcher, broker_port):
        if not 1024 <= broker_port <= 65535 or (self.endpoint is not None and self.endpoint[1] == broker_port):
            raise HostError("ssh_binding_invalid")
        forward = f"{LOOPBACK}:{GUEST_PROXY_PORT}:{LOOPBACK}:{broker_port}"
        return self.argv(ssh, [plain_path(launcher)], forward)

    def bootstrap(self, ssh):
        return self.argv(ssh, ["/bin/sh", "-s"])

    def transfer(self, program, flags, ssh):
        """`scp`/`sftp`'s profile (runtime/scp.rs `profile`): fixed flags,
        the port, the trusted ssh, every fixed option, the bound ones."""
        args = [program] + list(flags)
        if self.endpoint is not None:
            args += ["-P", str(self.endpoint[1])]
        args += ["-S", plain_path(ssh)]
        for option in TRANSFER_OPTIONS:
            if option == "ProxyCommand=none" and self.proxy is not None:
                option = "ProxyCommand=" + " ".join(self.proxy)
            args += ["-o", option]
        for option in (f"IdentityFile={self.identity}", f"UserKnownHostsFile={self.known_hosts}",
                       f"HostKeyAlias={self.alias}", f"User={self.user}"):
            args += ["-o", option]
        return args

    def scp(self, scp, ssh, source, destination):
        """One file to the remote `destination` (both plain absolute)."""
        return self.transfer(plain_path(scp), SCP_FLAGS, ssh) + [
            "--", plain_path(source), f"{self.operand()}:{plain_path(destination)}"]

    def sftp_batch(self, sftp, ssh, files):
        """The bootstrap upload (runtime/scp.rs `bootstrap_batch`): argv and
        its batch, one `@put SOURCE DESTINATION` per pair, plain paths."""
        if not files:
            raise HostError("ssh_binding_invalid")
        batch = "".join(f"@put {plain_path(a)} {plain_path(b)}\n" for a, b in files)
        if len(batch) > MAX_BATCH_BYTES:
            raise HostError("bootstrap_layout_invalid")
        return self.transfer(plain_path(sftp), SFTP_FLAGS, ssh) + ["--", self.operand()], batch


# Bootstrap (runtime/bootstrap.rs): a managed image's preinstalled payload,
# verified in place; an attached target's uploaded bundle.
LAYOUT_DIR = "agentbox-worker-v1"
PREINSTALLED = worker_layout.INSTALL_ROOT
ENTRYPOINT = "guest/src/main.py"
REQUEST = "guest/src/request_main.py"
SESSION_PROFILE = "supplied-session-v3"
# Its form with a host mount's root holding the working directory.
MOUNTED_PROFILE = "supplied-mounted-v1"
SYSTEM_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SESSION_PYTHON = ("/usr/bin/env", f"PATH={SYSTEM_PATH}", "python3")
PYTHON = ("/usr/bin/env", "python3")
FLAGS = ("-I", "-S", "-B", "-X", "utf8")
TOOLS = ("uname", "id", "stat", "mkdir", "chmod", "wc", "sha256sum", "cat")
PREPARED = "agentbox-worker-prepared v1"
READY = "agentbox-worker-ready v1"
FAILED = "agentbox-worker-failed v1"
MAX_REPLY_BYTES = 512
REASONS = ("platform", "tools", "root", "layout", "exists", "file", "size", "digest", "wrapper",
           "launcher", "payload", "sealed")


def _words(python):
    return " ".join([f"'{w}'" for w in python] + list(FLAGS))


class Layout:
    """`root` the layout's parent (a managed `started.control`, an
    attached `remote_root`), HOME `started.home` (managed) or
    `<root>/agentbox-worker-v1/home` (attached), the working directory
    beneath it (the run's project location, else `work`; `mount`: the
    host mount holding it); a fresh installation `<release>-<attempt>`
    never reused."""

    def __init__(self, control, home, release, attempt, attached=False, project=None, mount=None):
        control = plain_path(control)
        base = f"{control}/{LAYOUT_DIR}"
        home = f"{base}/home" if attached else plain_path(home)
        if len(control) > 1024 or len(home) > 1024 or control == home \
                or (not attached and (home.startswith(control + "/") or control.startswith(home + "/"))) \
                or re.fullmatch(r"[0-9a-f]{64}", release) is None \
                or re.fullmatch(r"[0-9a-f]{32}", attempt) is None:
            raise HostError("bootstrap_layout_invalid")
        self.root, self.home = control, home
        self.work = f"{home}/{project or 'work'}"
        self.mount = None if mount is None else f"{home}/{mount['destination']}"
        self.base = base
        self.releases = f"{self.base}/releases"
        self.name = f"{release}-{attempt}"
        self.install = f"{self.releases}/{self.name}"
        self.launcher = f"{self.install}/launcher"
        self.release = release


class Plan:
    """What a bootstrap writes: the payload (`None` preinstalled, else the
    uploaded bundle's {path: (size, sha256)}), the target's Python (None:
    the system one), the enabled handlers' shims [(name, jail entry)] and
    the session wrapper's jail entry, if a handler has one."""

    def __init__(self, layout, manifest=None, files=None, python=None, shims=(), session=None):
        self.layout, self.manifest, self.files = layout, manifest, files
        self.python = python
        self.shims = list(shims)
        self.session = session
        listed = files if files is not None else worker_layout.listing(manifest)
        self.listed = listed
        self.payload = PREINSTALLED if files is None else layout.install

    def directories(self):
        return sorted(d for d in worker_layout.directories(self.listed) if d)

    def session_python(self):
        return (self.python,) if self.python else SESSION_PYTHON

    def command_python(self):
        return (self.python,) if self.python else PYTHON

    def launcher_text(self):
        layout = self.layout
        return (f"#!/bin/sh\nexec {_words(self.session_python())} '{self.payload}/{ENTRYPOINT}' "
                + (f"'{SESSION_PROFILE}' '{layout.home}' '{layout.work}' '{layout.install}/bin' "
                   if layout.mount is None else
                   f"'{MOUNTED_PROFILE}' '{layout.home}' '{layout.work}' '{layout.install}/bin' '{layout.mount}' ")
                + "\"$@\"\n")

    def wrapper_texts(self):
        python = _words(self.command_python())
        texts = [("agentbox-request", f"#!/bin/sh\nexec {python} '{self.payload}/{REQUEST}' \"$@\"\n")]
        for name, entry in self.shims:
            texts.append((name, f"#!/bin/sh\nexec {python} '{self.payload}/{entry}' shim '{name}' \"$@\"\n"))
        if self.session is not None:
            texts.append((SESSION_WRAPPER,
                          f"#!/bin/sh\nexec {python} '{self.payload}/{self.session}' session \"$@\"\n"))
        return texts

    def prepare_script(self):
        layout = self.layout
        script = _preamble() + (
            "[ \"$(uname -s)\" = Linux ] && [ \"$(uname -m)\" = x86_64 ] || fail platform\n"
            f"for tool in {' '.join(TOOLS)}; do command -v \"$tool\" >/dev/null 2>&1 || fail tools; done\n"
            "uid=$(id -u)\n"
            "owned() { [ -d \"$1\" ] && [ ! -h \"$1\" ] && [ \"$(stat -c %u -- \"$1\")\" = \"$uid\" ] && "
            "[ $((0$(stat -c %a -- \"$1\") & 022)) -eq 0 ]; }\n"
            "layout() { if [ ! -e \"$1\" ] && [ ! -h \"$1\" ]; then mkdir -m 700 -- \"$1\" || fail layout; fi; "
            "owned \"$1\" || fail layout; }\n"
            f"root='{layout.root}'\n"
            "[ -d \"$root\" ] && [ ! -h \"$root\" ] || fail root\n"
            f"layout '{layout.base}'\n"
            f"layout '{layout.releases}'\n"
            f"layout '{layout.home}'\n"
            f"install='{layout.install}'\n"
            "if [ -e \"$install\" ] || [ -h \"$install\" ]; then fail exists; fi\n"
            "mkdir -m 700 -- \"$install\" || fail exists\n")
        if self.files is not None:
            for directory in self.directories():
                script += f"mkdir -m 700 -- \"$install/{directory}\" || fail layout\n"
        return script + f"printf '%s %s\\n' '{PREPARED}' '{layout.name}'\n"

    def uploads(self, bundle):
        """The uploaded payload's (local source, remote destination) pairs."""
        return [(f"{bundle}/{path}", f"{self.layout.install}/{path}") for path in sorted(self.files)]

    def verify_script(self):
        """Uploaded: each listed file's size and SHA-256 as validated here,
        then 0400. Preinstalled: the baked manifest's length and SHA-256
        (the release), each listed file's, every entry root's and not
        writable by the login user. Then a fresh bin/ and its wrappers, the
        launcher last."""
        layout = self.layout
        script = _preamble() + (
            f"install='{layout.install}'\n"
            "[ -d \"$install\" ] && [ ! -h \"$install\" ] || fail layout\n")
        if self.files is not None:
            script += (
                "check() {\n"
                "  f=\"$install/$1\"\n"
                "  [ -f \"$f\" ] && [ ! -h \"$f\" ] || fail file\n"
                "  size=$(wc -c < \"$f\") || fail file\n"
                "  [ $size -eq \"$2\" ] || fail size\n"
                "  printf '%s  %s\\n' \"$3\" \"$f\" | sha256sum -c --status - || fail digest\n"
                "  chmod \"$4\" \"$f\" || fail file\n"
                "}\n")
            for path in sorted(self.files):
                size, digest = self.files[path]
                script += f"check '{path}' {size} '{digest}' 400\n"
        else:
            script += (
                f"payload='{PREINSTALLED}'\n"
                "sealed() { [ ! -h \"$1\" ] && [ \"$(stat -c %u -- \"$1\")\" = 0 ] && [ ! -w \"$1\" ] "
                "|| fail sealed; }\n"
                "[ -d \"$payload\" ] && [ ! -h \"$payload\" ] || fail payload\n"
                "sealed \"$payload\"\n")
            for directory in self.directories():
                script += f"[ -d \"$payload/{directory}\" ] || fail payload\nsealed \"$payload/{directory}\"\n"
            script += (
                "check() {\n"
                "  f=\"$payload/$1\"\n"
                "  [ -f \"$f\" ] && [ ! -h \"$f\" ] || fail file\n"
                "  sealed \"$f\"\n"
                "  size=$(wc -c < \"$f\") || fail file\n"
                "  [ $size -eq \"$2\" ] || fail size\n"
                "  printf '%s  %s\\n' \"$3\" \"$f\" | sha256sum -c --status - || fail digest\n"
                "}\n")
            script += f"check 'manifest.json' {len(self.manifest)} '{layout.release}'\n"
            for path in sorted(self.listed):
                size, digest = self.listed[path]
                script += f"check '{path}' {size} '{digest}'\n"
        script += ("set -C\nbin=\"$install/bin\"\n"
                   "if [ -e \"$bin\" ] || [ -h \"$bin\" ]; then fail wrapper; fi\n"
                   "mkdir -m 700 -- \"$bin\" || fail wrapper\n")
        for name, text in self.wrapper_texts():
            script += (f"cat > \"$bin/{name}\" <<'AGENTBOX_WRAPPER' || fail wrapper\n{text}AGENTBOX_WRAPPER\n"
                       f"chmod 500 \"$bin/{name}\" || fail wrapper\n")
        script += (f"cat > \"$install/launcher\" <<'AGENTBOX_LAUNCHER' || fail launcher\n"
                   f"{self.launcher_text()}AGENTBOX_LAUNCHER\n"
                   "chmod 500 \"$install/launcher\" || fail launcher\n"
                   f"printf '%s %s\\n' '{READY}' '{layout.name}'\n")
        return script


def _preamble():
    return f"set -eu\numask 077\nfail() {{ printf '%s %s\\n' '{FAILED}' \"$1\"; exit 1; }}\n"


def reply_ok(stage, layout, exit_code, stdout):
    """Exit 0 with exactly the stage's one line; else the failure reason
    the guest claimed (a closed set), or None."""
    expected = f"{PREPARED if stage == 'prepare' else READY} {layout.name}\n".encode()
    if exit_code == 0 and stdout == expected:
        return True, None
    reason = None
    if len(stdout) <= MAX_REPLY_BYTES and stdout.startswith(FAILED.encode() + b" ") and stdout.endswith(b"\n"):
        word = stdout[len(FAILED) + 1:-1].decode(errors="replace")
        reason = word if word in REASONS else None
    return False, reason
