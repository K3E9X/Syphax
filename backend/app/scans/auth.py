"""Map an identity's HTTP headers to per-tool CLI flags for authenticated scans.

Each wrapper takes auth differently; this is the single place that knows how.
Headers come from the engagement's primary identity (list of {name,value}).
Recon tools that don't make authenticated app requests get nothing.
"""
from __future__ import annotations

from typing import Dict, List

# Tools that accept repeated `-H "Name: value"`.
#
# schemathesis and kiterunner were missing, and schemathesis is the one that
# mattered: it is the API-contract tool, so every operation behind the login
# was being property-tested as an anonymous caller. kiterunner discovers API
# routes, which it cannot do for the authenticated half of an API.
_DASH_H = {"nuclei", "ffuf", "dalfox", "katana", "httpx",
           "schemathesis", "kiterunner"}

# NOT here on purpose: nosqli. Its CLI takes a target, a request file and a
# proxy, and nothing in it is a documented repeatable header flag. Guessing one
# does not leave the tool unauthenticated, it makes the tool exit on a usage
# error and find nothing - which is how this project lost runs to `httpx -u`
# and a dnsx missing its wordlist. It stays anonymous until someone checks
# --help on the pinned version; that is a smaller loss than a broken scan.


def auth_args(tool: str, headers: List[Dict[str, str]]) -> List[str]:
    pairs = [(h.get("name", "").strip(), h.get("value", "").strip())
             for h in headers or []]
    pairs = [(n, v) for n, v in pairs if n and v]
    if not pairs:
        return []

    if tool in _DASH_H:
        args: List[str] = []
        for n, v in pairs:
            args += ["-H", f"{n}: {v}"]
        return args

    if tool == "sqlmap":
        # sqlmap wants the session as --cookie; other headers via repeated -H.
        # Using -H for the Cookie leaves sqlmap effectively unauthenticated.
        cookie = next((v for n, v in pairs if n.lower() == "cookie"), None)
        args = []
        if cookie:
            args += ["--cookie", cookie]
        for n, v in pairs:
            if n.lower() != "cookie":
                args += ["-H", f"{n}: {v}"]
        return args

    if tool == "commix":
        # commix takes all extra headers in one --headers blob (\n separated),
        # and a Cookie via --cookie.
        cookie = next((v for n, v in pairs if n.lower() == "cookie"), None)
        others = [f"{n}: {v}" for n, v in pairs if n.lower() != "cookie"]
        args = []
        if cookie:
            args += ["--cookie", cookie]
        if others:
            args += ["--headers", "\\n".join(others)]
        return args

    if tool == "arjun":
        # arjun takes every header in ONE string, newline-separated.
        blob = "\n".join(f"{n}: {v}" for n, v in pairs)
        return ["--headers", blob]

    if tool == "wpscan":
        cookie = next((v for n, v in pairs if n.lower() == "cookie"), None)
        others = [f"{n}: {v}" for n, v in pairs if n.lower() != "cookie"]
        args = []
        if cookie:
            args += ["--cookie-string", cookie]
        for h in others:
            args += ["--headers", h]
        return args

    if tool == "whatweb":
        return [f"--header={n}: {v}" for n, v in pairs]

    # nikto and recon tools (subfinder/dnsx/naabu/gau): no authenticated
    # app-request semantics here.
    return []
