"""Turn whatever the operator typed into something the rest of recon can use.

The input box takes one field, because that is what an operator has: a thing
written on a scoping document. It might be `example.com`, `https://app.example.com:8443/portal`,
`1.2.3.4`, `[2001:db8::1]:8443`, or a copy-paste with a trailing space and a
smart quote around it. All of those have to resolve to the same three answers:
what host, what port, and is it a name or an address.

Pure. No DNS here - resolution is a separate step precisely so this one can be
tested exhaustively.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlsplit, urlunsplit

KIND_HOSTNAME = "hostname"
KIND_IPV4 = "ipv4"
KIND_IPV6 = "ipv6"

DEFAULT_PORTS = {"http": 80, "https": 443}

# Characters people paste around a URL without meaning to.
_WRAPPERS = "\"'`<>«»“”‘’ \t\r\n"

# A hostname label: letters, digits, hyphen; not starting or ending with one.
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

# Public suffixes we special-case only to report the registrable domain
# sensibly. This is not a full PSL - carrying one would mean shipping and
# refreshing a 15,000-line list to render one label in the UI - so the answer is
# advisory and the field says so.
_TWO_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "co.za", "org.za",
    "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "net.cn", "org.cn",
    "co.jp", "or.jp", "ne.jp", "co.in", "net.in", "org.in", "co.kr",
    "com.sg", "com.hk", "com.tw", "co.il", "com.pl", "com.ua",
})


class TargetError(ValueError):
    """The input is not something we can point recon at."""


@dataclass(frozen=True)
class Target:
    raw: str
    kind: str                       # hostname | ipv4 | ipv6
    host: str                       # hostname (lowercased) or address literal
    scheme: str                     # http | https
    port: int
    path: str = "/"
    notes: List[str] = field(default_factory=list)

    @property
    def is_ip(self) -> bool:
        return self.kind in (KIND_IPV4, KIND_IPV6)

    @property
    def authority(self) -> str:
        """host[:port], with IPv6 bracketed, omitting the default port."""
        host = f"[{self.host}]" if self.kind == KIND_IPV6 else self.host
        if self.port == DEFAULT_PORTS.get(self.scheme):
            return host
        return f"{host}:{self.port}"

    @property
    def base_url(self) -> str:
        return urlunsplit((self.scheme, self.authority, "/", "", ""))

    def url_for(self, path: str) -> str:
        return urlunsplit((self.scheme, self.authority, path or "/", "", ""))

    @property
    def registrable_domain(self) -> str:
        """Best-effort eTLD+1. Empty for an IP. Advisory - see _TWO_LABEL_SUFFIXES."""
        if self.is_ip:
            return ""
        labels = self.host.split(".")
        if len(labels) <= 2:
            return self.host
        last_two = ".".join(labels[-2:])
        if last_two in _TWO_LABEL_SUFFIXES and len(labels) >= 3:
            return ".".join(labels[-3:])
        return last_two

    def to_public(self) -> dict:
        return {
            "raw": self.raw,
            "kind": self.kind,
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "path": self.path,
            "base_url": self.base_url,
            "registrable_domain": self.registrable_domain,
            "is_ip": self.is_ip,
            "notes": list(self.notes),
        }


def parse(raw: str) -> Target:
    """Parse one operator-supplied target. Raises TargetError with a sentence
    the operator can act on, never a stack trace."""
    text = (raw or "").strip(_WRAPPERS)
    if not text:
        raise TargetError("enter a hostname, an IP address, or a URL")
    if len(text) > 2048:
        raise TargetError("that is too long to be a target")

    notes: List[str] = []

    # Credentials in a URL are a real copy-paste hazard: they would be sent to
    # the target and written into the audit log. Drop them and say so.
    if "@" in text.split("/")[0] or "://" in text and "@" in text.split("://", 1)[1].split("/")[0]:
        notes.append("credentials were removed from the URL before use")

    scheme = ""
    if "://" in text:
        scheme = text.split("://", 1)[0].lower()
        if scheme not in ("http", "https"):
            raise TargetError(f"unsupported scheme {scheme!r}: use http or https")
    else:
        # urlsplit needs a scheme to populate .hostname; assume https and
        # downgrade later only if the operator wrote a plain :80.
        text = "//" + text

    parts = urlsplit(text if scheme else text, scheme="https")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise TargetError(f"could not read a host out of {raw.strip()!r}")

    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError("the port is not a number") from exc

    kind, host = _classify(host)

    if kind == KIND_HOSTNAME:
        _validate_hostname(host)

    scheme = scheme or parts.scheme or "https"
    if port is None:
        # A bare host:80 is an http service far more often than an https one on
        # a non-standard port, and guessing wrong costs a confusing failure.
        port = DEFAULT_PORTS[scheme]
    elif port == 80 and not parts.scheme.startswith("http"):
        scheme = "http"
    if not 1 <= port <= 65535:
        raise TargetError(f"port {port} is out of range")
    if port == 80 and scheme == "https":
        scheme = "http"

    notes.extend(_advisories(kind, host))

    return Target(
        raw=(raw or "").strip(),
        kind=kind,
        host=host,
        scheme=scheme,
        port=port,
        path=parts.path or "/",
        notes=notes,
    )


def _classify(host: str) -> tuple:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return KIND_HOSTNAME, host
    return (KIND_IPV4 if addr.version == 4 else KIND_IPV6), str(addr)


def _validate_hostname(host: str) -> None:
    if host.endswith("."):
        host = host[:-1]
    if len(host) > 253:
        raise TargetError("that hostname is longer than DNS allows")
    labels = host.split(".")
    for label in labels:
        # An internationalised domain arrives already punycoded from urlsplit
        # when it can be; anything else here is genuinely not a hostname.
        if not _LABEL.match(label):
            raise TargetError(
                f"{host!r} is not a valid hostname: the part {label!r} is not allowed")
    if len(labels) == 1 and host not in ("localhost",):
        raise TargetError(
            f"{host!r} has no dot in it. Did you mean {host}.com, or an internal "
            f"name that this container cannot resolve?")


def _advisories(kind: str, host: str) -> List[str]:
    """Things worth saying before the operator presses the button. Advisory
    only: an internal engagement against 10.0.0.0/8 is a normal thing to do,
    and refusing it would be this tool deciding what the operator is allowed
    to test."""
    notes: List[str] = []
    if kind == KIND_HOSTNAME:
        if host == "localhost":
            notes.append("localhost resolves inside this container, not on your machine - "
                         "use host.docker.internal to reach the host")
        return notes
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return notes
    if getattr(addr, "is_global", True) is False and addr.version == 6 and \
            addr in ipaddress.ip_network("2001:db8::/32"):
        notes.append("2001:db8::/32 is the documentation range - nothing lives there")
    elif addr.is_loopback:
        notes.append("a loopback address points at this container, not at your machine")
    elif addr.is_private:
        notes.append("private address: reachable only if this container's network can route to it")
    elif addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        notes.append("this is a reserved address and is unlikely to answer")
    return notes


def parse_or_none(raw: str) -> Optional[Target]:
    try:
        return parse(raw)
    except TargetError:
        return None
