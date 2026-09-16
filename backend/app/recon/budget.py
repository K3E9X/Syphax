"""What pre-engagement recon is allowed to do, as data.

This module exists because of where the feature sits. Everywhere else in this
tool, an *engagement* is what authorizes touching a host: the operator attests,
the scope gate enforces, the audit log records. Recon runs BEFORE that exists -
it is how you decide whether to open an engagement at all - so it has no scope
to check against and cannot be given one.

The line drawn here is therefore not "be careful", it is a list. Recon may:

  * ask public infrastructure ABOUT the target - DNS resolvers, RDAP registries,
    Certificate Transparency logs. None of this reaches the target at all.
  * do exactly what a browser does when you type the URL: one TLS handshake and
    one GET of the root.
  * read the three files the web has collectively agreed are there to be read:
    robots.txt, sitemap.xml, .well-known/security.txt.

That is the whole list, and it is enforced by PROBE_PATHS and MAX_TARGET_REQUESTS
rather than by anyone remembering. A port scan, a directory brute force, a
vulnerability template or a subdomain wordlist belongs to an engagement, which
is the thing that carries the authorization to run it.

Keeping this as a constant means a test can assert that the set never grew, and
that the growth is what someone has to justify - not the restraint.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# Every path recon will ever request from the target. Adding to this list is a
# deliberate act with a security review attached; it is not a convenience.
PROBE_PATHS: Tuple[str, ...] = (
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
)

# One request per path, plus the TLS handshake. The cap is checked at runtime as
# well, so a future bug that loops cannot turn this view into a scanner.
MAX_TARGET_REQUESTS = len(PROBE_PATHS) + 2

# A browser gives up long before this. Recon that takes a minute is recon the
# operator has already stopped reading.
CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 8.0
TOTAL_TIMEOUT = 25.0
DNS_TIMEOUT = 5.0

# Redirects are followed - a target that answers 301 to https:// is the normal
# case and refusing to follow would make every such target look dead - but only
# a few, and never off the original registrable domain without saying so.
MAX_REDIRECTS = 3

# Bodies are read to here and no further. The root of a large single-page app is
# routinely a megabyte of inlined JavaScript, and none of it is needed to read a
# <title> or a generator tag.
MAX_BODY_BYTES = 512 * 1024

# Methods. GET and HEAD only: recon must never change anything it looks at.
ALLOWED_METHODS = frozenset({"GET", "HEAD"})

# What we ask third parties, rather than the target.
PASSIVE_SOURCES: Tuple[Tuple[str, str], ...] = (
    ("DNS", "the resolver configured for this container"),
    ("RDAP", "rdap.org, for the IP's network and the domain's registration"),
    ("Certificate Transparency", "crt.sh, for names already published in CT logs"),
)


def path_allowed(path: str) -> bool:
    return (path or "/") in PROBE_PATHS


def method_allowed(method: str) -> bool:
    return (method or "").upper() in ALLOWED_METHODS


def describe() -> Dict[str, List[str]]:
    """The same list, for the UI.

    Shown rather than buried in a docstring because an operator pointing this at
    a host they do not own should be able to see, before they press the button,
    exactly what leaves this machine.
    """
    return {
        "touches_target": [f"GET {p}" for p in PROBE_PATHS] + ["one TLS handshake"],
        "asks_third_parties": [f"{name} - {what}" for name, what in PASSIVE_SOURCES],
        "never": [
            "port scanning",
            "directory or subdomain brute force",
            "vulnerability templates",
            "authentication attempts",
            "any method other than GET or HEAD",
        ],
        "limits": [
            f"at most {MAX_TARGET_REQUESTS} requests to the target",
            f"at most {MAX_REDIRECTS} redirects followed",
            f"at most {MAX_BODY_BYTES // 1024} KB read per response",
            f"{int(TOTAL_TIMEOUT)}s overall",
        ],
    }
