"""Destination syntax and the one denied dial target (contracts/network/v1).

Hosts are exact ASCII LDH DNS names or IP literals. A name whose last label
is numeric (`127.1`, `0x7f.1`, `1.2.3.4.`) is an ambiguous IPv4 form and is
refused; only canonical dotted-quad IPv4 is an IPv4 literal. In a CONNECT
authority an IPv6 literal must be bracketed; an unbracketed one is
ambiguous with the port separator and is refused, as are zone identifiers,
IPvFuture, bracketed IPv4, userinfo and percent-encoding. Errors are fixed
codes and never echo the input.
"""
import ipaddress
import re

MAX_NAME_BYTES = 253
MAX_LABEL_BYTES = 63
MAX_AUTHORITY_BYTES = MAX_NAME_BYTES + 1 + 1 + 5


class AddressError(ValueError):
    """`authority_too_long`, `authority_invalid`, `port_invalid`,
    `host_invalid`, `ip_literal_ambiguous` or `network_invalid`."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_LABEL = re.compile(r"[a-z0-9-]{1,63}")
_DIGITS = re.compile(r"[0-9]+")
_HEX = re.compile(r"[0-9A-Fa-f]*")
_IPV4 = re.compile(r"(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}")
# IPv6 literals: hex groups of 1-4 digits, at most one `::`,
# an optional dotted-quad tail; no zone, brackets or other characters.
_IPV6_CHARS = re.compile(r"[0-9A-Fa-f:.]+")


def _is_label(label):
    return (_LABEL.fullmatch(label) is not None and not label.startswith("-")
            and not label.endswith("-") and not label.startswith("xn--"))


def _is_numeric_label(label):
    if label.startswith("0x"):
        return _HEX.fullmatch(label[2:]) is not None
    return all("0" <= char <= "9" for char in label)


class DnsName:
    """A lowercase ASCII LDH name without a trailing dot; IDNA A-labels are
    refused rather than compared."""

    __slots__ = ("text",)

    def __init__(self, text):
        self.text = text

    @classmethod
    def parse(cls, text):
        if not text.isascii() or len(text) > MAX_NAME_BYTES + 1:
            raise AddressError("host_invalid")
        name = (text[:-1] if text.endswith(".") else text).lower()
        if not name or len(name) > MAX_NAME_BYTES:
            raise AddressError("host_invalid")
        labels = name.split(".")
        if not all(_is_label(label) for label in labels):
            raise AddressError("host_invalid")
        if _is_numeric_label(labels[-1]):
            raise AddressError("ip_literal_ambiguous")
        return cls(name)

    def labels(self):
        return self.text.count(".") + 1

    def resolver_query(self):
        """The absolute query: a trailing dot, so no search domain applies."""
        return self.text + "."

    def is_strictly_within(self, root):
        return (len(self.text) > len(root.text) and self.text.endswith(root.text)
                and self.text[len(self.text) - len(root.text) - 1] == ".")

    def __eq__(self, other):
        return isinstance(other, DnsName) and other.text == self.text

    def __hash__(self):
        return hash(self.text)

    def __str__(self):
        return self.text


def parse_ipv4(text):
    """A canonical dotted-quad IPv4 literal; None for anything else."""
    if _IPV4.fullmatch(text) is None:
        return None
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return None
    return address if str(address) == text else None


def parse_ipv6(text):
    """Parse an IPv6 literal, returning None on invalid syntax."""
    if _IPV6_CHARS.fullmatch(text) is None:
        return None
    # An embedded IPv4 tail must use dotted-quad form without leading zeros.
    try:
        return ipaddress.IPv6Address(text)
    except ValueError:
        return None


def ip_text(address):
    """Display an IPv4-mapped IPv6 address with its dotted quad."""
    if address.version == 6 and address.ipv4_mapped is not None:
        return f"::ffff:{address.ipv4_mapped}"
    return str(address)


def parse_ip(text):
    """Canonical IPv4 or any RFC 4291 IPv6 text without a zone."""
    address = parse_ipv4(text)
    if address is not None:
        return address
    address = parse_ipv6(text)
    if address is None:
        raise AddressError("network_invalid")
    return address


class Host:
    """A name (`name`) or an IP literal (`ip`)."""

    __slots__ = ("name", "ip")

    def __init__(self, name=None, ip=None):
        self.name, self.ip = name, ip

    @classmethod
    def parse(cls, text):
        """An unbracketed host: a name or a canonical IPv4 literal."""
        address = parse_ipv4(text)
        if address is not None:
            return cls(ip=address)
        if ":" in text:
            raise AddressError("ip_literal_ambiguous")
        return cls(name=DnsName.parse(text))

    def __eq__(self, other):
        return isinstance(other, Host) and (self.name, self.ip) == (other.name, other.ip)


class Authority:
    __slots__ = ("host", "port")

    def __init__(self, host, port):
        self.host, self.port = host, port

    def __eq__(self, other):
        return isinstance(other, Authority) and (self.host, self.port) == (other.host, other.port)


def _graphic(text):
    return all("!" <= char <= "~" for char in text)


def parse_authority(text):
    """A CONNECT authority-form target, `host:port` or `[ipv6]:port`."""
    if len(text.encode("utf-8", "surrogatepass")) > MAX_AUTHORITY_BYTES:
        raise AddressError("authority_too_long")
    if not text or not _graphic(text) or any(char in text for char in "@/?#%\\"):
        raise AddressError("authority_invalid")
    if text.startswith("["):
        inner, closing, after = text[1:].partition("]")
        if not closing or not after.startswith(":"):
            raise AddressError("authority_invalid")
        port = after[1:]
        if "[" in inner or "[" in port or "]" in port:
            raise AddressError("authority_invalid")
        address = parse_ipv6(inner)
        if address is None:
            raise AddressError("authority_invalid")
        return Authority(Host(ip=address), parse_port(port))
    if "[" in text or "]" in text:
        raise AddressError("authority_invalid")
    host, colon, port = text.rpartition(":")
    if not colon:
        raise AddressError("port_invalid")
    if ":" in host:
        raise AddressError("ip_literal_ambiguous")
    port = parse_port(port)
    return Authority(Host.parse(host), port)


def parse_port(text):
    """Decimal 1-65535 without sign or leading zero."""
    if not text or len(text) > 5 or text.startswith("0") or _DIGITS.fullmatch(text) is None:
        raise AddressError("port_invalid")
    port = int(text)
    if not 0 < port <= 65535:
        raise AddressError("port_invalid")
    return port


def authority_text(authority):
    """The canonical `host:port`, `[ipv6]:port` for an IPv6 literal."""
    host = authority.host
    if host.name is not None:
        return f"{host.name.text}:{authority.port}"
    if host.ip.version == 6:
        return f"[{ip_text(host.ip)}]:{authority.port}"
    return f"{host.ip}:{authority.port}"


def denied(address):
    """`unspecified` (`0.0.0.0`, `::`, IPv4-mapped forms included): no
    remote endpoint, never a dial target under any policy; else None.
    Loopback is the policy's to allow."""
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return "unspecified" if address.is_unspecified else None
