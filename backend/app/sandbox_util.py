"""Pure parsing for the PoC sandbox (no web/network imports, unit-testable).

We turn a pasted curl command or a raw HTTP request into (method, url, headers)
so the runner can replay it through the safe, in-scope, read-only channel.
"""
from __future__ import annotations

import shlex
from typing import Dict, Optional, Tuple


def parse_curl(code: str) -> Tuple[str, Optional[str], Dict[str, str]]:
    """Return (method, url, headers) parsed from a curl command line."""
    try:
        tokens = shlex.split(code, comments=False, posix=True)
    except ValueError:
        tokens = code.split()
    method = "GET"
    url: Optional[str] = None
    headers: Dict[str, str] = {}
    i = 0
    explicit_method = False
    has_body = False
    while i < len(tokens):
        t = tokens[i]
        if t in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper(); explicit_method = True; i += 2; continue
        if t in ("-H", "--header") and i + 1 < len(tokens):
            h = tokens[i + 1]
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
            i += 2; continue
        if t in ("-d", "--data", "--data-raw", "--data-binary", "-F", "--form"):
            has_body = True; i += 2; continue
        if t.startswith("http://") or t.startswith("https://"):
            url = t
        i += 1
    if has_body and not explicit_method:
        method = "POST"
    return method, url, headers


def parse_http_raw(code: str) -> Tuple[str, Optional[str], Dict[str, str]]:
    """Return (method, url, headers) from a raw HTTP request blob."""
    lines = (code or "").replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        return "GET", None, {}
    parts = lines[0].split()
    method = parts[0].upper() if parts else "GET"
    path = parts[1] if len(parts) > 1 else "/"
    headers: Dict[str, str] = {}
    for ln in lines[1:]:
        if not ln.strip():
            break
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers[k.strip()] = v.strip()
    host = headers.get("Host") or headers.get("host")
    url = None
    if path.startswith("http"):
        url = path
    elif host:
        scheme = "https"
        url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
    return method, url, headers


def parse_poc(kind: str, code: str, target: str) -> Tuple[str, Optional[str], Dict[str, str]]:
    """Dispatch by PoC type; fall back to the explicit target URL."""
    if kind == "curl":
        m, u, h = parse_curl(code)
    elif kind == "http-raw":
        m, u, h = parse_http_raw(code)
    else:
        m, u, h = "GET", None, {}
    if not u and target:
        u = target
    return m, u, h
