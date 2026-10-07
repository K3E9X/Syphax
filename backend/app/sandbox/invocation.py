"""Work out how to invoke a public PoC: its CLI flags and the argv to pass.

Public exploits are command-line programs. They take the target as an argument
("-t 10.0.0.1 -p 22", "--url https://host/", or a bare positional) and exit
non-zero with a usage message when run bare. The sandbox was running them with
no argv at all, so every argparse-based PoC died with:

    usage: poc.py [-h] -t TARGET [-p PORT]
    poc.py: error: the following arguments are required: -t/--target

- which meant it never proved anything and the finding stayed "unverified".

We read the PoC's source for its declared options (argparse / click / optparse)
and build an argv from the finding's target. This is a heuristic over source
text, not execution: when it cannot tell, it falls back to a positional target,
and the operator can always override the argv by hand before running.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

# One option declaration: argparse's add_argument(...), click's option(...),
# optparse's add_option(...). We only need the quoted flag tokens inside.
_OPTION_CALL = re.compile(r"(?:add_argument|add_option|option)\s*\(([^)]*)\)", re.S)
_FLAG = re.compile(r"""['"](-{1,2}[A-Za-z][\w-]*)['"]""")

# Long names that mean "where to point this exploit".
_TARGET_NAMES = {"target", "host", "hostname", "url", "ip", "rhost", "domain",
                 "server", "addr", "address", "site", "victim"}
_PORT_NAMES = {"port", "rport", "dport"}
# A URL-shaped option wants the whole scheme://host/path, not a bare hostname.
_URL_NAMES = {"url", "site", "uri", "link"}


def _name_of(flag: str) -> str:
    return flag.lstrip("-").lower().replace("-", "_")


def detect_options(code: str) -> Dict[str, Optional[str]]:
    """Which flag to use for the target and for the port, if any.

    Returns {"target": "-t"|None, "port": "-p"|None, "target_is_url": bool}.
    Long flags win over short ones: "-u" alone is ambiguous, "--url" is not.
    """
    target_flag: Optional[str] = None
    port_flag: Optional[str] = None
    target_is_url = False

    for block in _OPTION_CALL.findall(code or ""):
        flags = _FLAG.findall(block)
        if not flags:
            continue
        names = {_name_of(f) for f in flags}
        if "help" in names or "-h" in flags and len(flags) == 1:
            continue
        # Prefer the long form for the actual argv token.
        longest = max(flags, key=len)
        if names & _PORT_NAMES and port_flag is None:
            port_flag = longest
            continue
        if names & _TARGET_NAMES and target_flag is None:
            target_flag = longest
            target_is_url = bool(names & _URL_NAMES)
    return {"target": target_flag, "port": port_flag, "target_is_url": target_is_url}


def split_target(target: str) -> Tuple[str, Optional[str], Optional[str]]:
    """(host, port, url) from a finding target: "1.2.3.4:22" or "https://h/p"."""
    t = (target or "").strip()
    if not t:
        return "", None, None
    if "://" in t:
        p = urlparse(t)
        host = (p.hostname or "").lower()
        port = str(p.port) if p.port else None
        return host, port, t
    # "host:port" - but keep bare IPv6 (which is full of colons) intact.
    if t.count(":") == 1:
        host, _, port = t.partition(":")
        return host.lower(), (port or None), None
    return t.lower(), None, None


def build_argv(code: str, target: str) -> List[str]:
    """The argv to run this PoC against `target`. Empty when there is nothing
    sensible to pass (the PoC takes no arguments)."""
    host, port, url = split_target(target)
    if not host:
        return []
    opts = detect_options(code or "")

    argv: List[str] = []
    value = url if (opts["target_is_url"] and url) else host
    if opts["target"]:
        argv += [opts["target"], value]
        if opts["port"] and port:
            argv += [opts["port"], port]
        return argv

    # No recognised option: if the script reads sys.argv, pass the target
    # positionally; many single-purpose PoCs are written exactly that way.
    if re.search(r"\bsys\.argv\b", code or ""):
        return [url or (f"{host}:{port}" if port else host)]
    return []
