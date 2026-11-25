"""The delivery's pinned connection and its fixed `scp` argv: every field a closed
plain form, nothing from the guest. Pure; nothing here runs a process."""
import ipaddress
import re

MAX_PATH_BYTES = 4096
MAX_PROXY_BYTES = 4096
MAX_PROXY_WORDS = 64
MAX_DNS_BYTES = 253
MAX_USER_BYTES = 32
MAX_ALIAS_BYTES = 253
DELIVERY_DIR = ".agentbox-requests"
UPLOAD_SUFFIX = ".artifact"
SCP_FLAGS = ("-q", "-B", "-s", "-F", "/dev/null")
SCP_SSH_OPTIONS = (
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
SSH_ENV = (("LC_ALL", "C"),)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_PLAIN_PATH = re.compile(r"[A-Za-z0-9._/-]+")
_TOOL_PATH = re.compile(r"[A-Za-z0-9._+-]+")
_LABEL = re.compile(r"[a-z0-9-]{1,63}")
_USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}")
_ALIAS = re.compile(r"[a-z0-9][a-z0-9._-]{0,252}")
_WORD = re.compile(r"[A-Za-z0-9._/:=,+-]+")
_ENV_NAME = re.compile(r"[A-Z_]+")


class Invalid(ValueError):
    pass


def is_id(text):
    return isinstance(text, str) and _ID.fullmatch(text) is not None


def is_path(text):
    """Absolute, normalized, shell-inert path."""
    if not isinstance(text, str) or len(text) > MAX_PATH_BYTES or not text.startswith("/"):
        return False
    return all(part and part not in (".", "..") and _TOOL_PATH.fullmatch(part) is not None
               for part in text[1:].split("/"))


def normalized_path(text):
    """Absolute and normalized UTF-8 without NUL; the text itself."""
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_PATH_BYTES \
            or "\0" in text or not text.startswith("/"):
        raise Invalid("transport_path_unsupported")
    parts = text[1:].split("/")
    if not text[1:] or any(part in ("", ".", "..") for part in parts):
        raise Invalid("transport_path_unsupported")
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        raise Invalid("transport_path_unsupported") from None
    return text


def plain_path(text):
    """Absolute, normalized and limited to `[A-Za-z0-9._/-]`."""
    text = normalized_path(text)
    if _PLAIN_PATH.fullmatch(text) is None:
        raise Invalid("transport_path_unsupported")
    return text


def _v4_usable(address):
    return not (address.is_unspecified or address.is_multicast or address == ipaddress.IPv4Address("255.255.255.255"))


def parse_host(text):
    """Parse a host as ("v4"|"v6"|"dns", value)."""
    try:
        address = ipaddress.IPv4Address(text)
        if not _v4_usable(address):
            raise Invalid("transport_bindings_invalid")
        return ("v4", address)
    except ipaddress.AddressValueError:
        pass
    if ":" in text:
        try:
            address = ipaddress.IPv6Address(text)
        except ValueError:
            raise Invalid("transport_bindings_invalid") from None
        if "%" in text or "[" in text:
            raise Invalid("transport_bindings_invalid")
        mapped = address.ipv4_mapped
        usable = _v4_usable(mapped) if mapped is not None else not (address.is_unspecified or address.is_multicast)
        if not usable:
            raise Invalid("transport_bindings_invalid")
        return ("v6", address)
    labels = text.split(".")
    last = labels[-1]
    if len(text) > MAX_DNS_BYTES or not all(
            _LABEL.fullmatch(label) and not label.startswith("-") and not label.endswith("-") for label in labels) \
            or not ("a" <= last[:1] <= "z"):
        raise Invalid("transport_bindings_invalid")
    return ("dns", text)


def _host_text(host):
    kind, value = host
    if kind == "v6" and value.ipv4_mapped is not None:
        return f"::ffff:{value.ipv4_mapped}"
    return str(value)


class Connection:
    """One upload connection's validated, immutable bindings: an endpoint
    (host, port) or a provider proxy (words, env), the user, identity,
    known_hosts and alias."""

    def __init__(self, route, user, identity, known_hosts, host_key_alias):
        if not isinstance(user, str) or _USER.fullmatch(user) is None \
                or not isinstance(host_key_alias, str) or _ALIAS.fullmatch(host_key_alias) is None:
            raise Invalid("transport_bindings_invalid")
        identity, known_hosts = plain_path(identity), plain_path(known_hosts)
        if identity == known_hosts:
            raise Invalid("transport_paths_not_distinct")
        self.route, self.user = route, user
        self.identity, self.known_hosts, self.alias = identity, known_hosts, host_key_alias

    @staticmethod
    def endpoint(host, port):
        host = parse_host(host)
        if port == 0:
            raise Invalid("transport_port_invalid")
        return ("endpoint", host, port)

    @staticmethod
    def proxy(words, env):
        size = sum(len(word.encode()) + 1 for word in words)
        env_ok = all(name and _ENV_NAME.fullmatch(name) and "\0" not in value for name, value in env)
        if not words or not is_path(words[0]) or len(words) > MAX_PROXY_WORDS or size > MAX_PROXY_BYTES \
                or not all(_WORD.fullmatch(word) for word in words) or not env_ok:
            raise Invalid("transport_bindings_invalid")
        return ("proxy", list(words), list(env))

    def operand(self):
        if self.route[0] == "endpoint":
            host = self.route[1]
            return f"[{_host_text(host)}]" if host[0] == "v6" else _host_text(host)
        return self.alias

    def env(self, tool_env, host_env):
        """The complete environment of `scp` and its `ssh`."""
        if self.route[0] == "endpoint":
            return list(tool_env)
        own = list(SSH_ENV) + self.route[2]
        names = {name for name, _ in own}
        return [(name, value) for name, value in host_env if name != "SHELL" and name not in names] + own

    def scp_argv(self, scp, ssh, source, destination):
        """The literal argv: fixed flags, port, trusted ssh, every option
        with the bound ones, `--`, the source and the remote destination."""
        argv = [scp] + list(SCP_FLAGS)
        if self.route[0] == "endpoint":
            argv += ["-P", str(self.route[2])]
        argv += ["-S", plain_path(ssh)]
        options = [f"ProxyCommand={' '.join(self.route[1])}"
                   if option == "ProxyCommand=none" and self.route[0] == "proxy" else option
                   for option in SCP_SSH_OPTIONS]
        options += [f"IdentityFile={self.identity}", f"UserKnownHostsFile={self.known_hosts}",
                    f"HostKeyAlias={self.alias}", f"User={self.user}"]
        for option in options:
            argv += ["-o", option]
        return argv + ["--", normalized_path(source), f"{self.operand()}:{destination}"]


def upload_name(session, request):
    if not is_id(session) or not is_id(request):
        raise Invalid("transport_bindings_invalid")
    return f"{session}-{request}{UPLOAD_SUFFIX}"
