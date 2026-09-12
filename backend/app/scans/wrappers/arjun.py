"""arjun: hidden HTTP parameter discovery.

arjun adds INJECTION POINTS, not findings. That is the point: the adaptive
prober and every injection scanner can only decide things that have
parameters, and an endpoint's real parameters are frequently undocumented -
`?debug=1`, `?admin=`, `?callback=` are not in the HTML and not in the JS.
Without them those endpoints are tested as if they had no input at all, and
whatever lives behind them is reported as "not found" rather than "not
looked at".

It works by differential response analysis (body length / content / code
against a stable baseline), so a hit means the parameter actually changed the
answer. Parameters are recorded as `params` findings at info severity - they
are surface, not weakness - and the endpoint is re-emitted with them attached
so later phases have something to inject into.

Parsing: arjun's `-oJ` opens the file with mode "w+" and therefore cannot
write to a pipe (`io.UnsupportedOperation: File or stream is not seekable`).
We read its stdout instead, which prints one line per confirmed parameter
with the signal that confirmed it.
"""
from __future__ import annotations

import re
from typing import List, Sequence
from urllib.parse import urlencode, urlparse, urlunparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# ANSI colour is emitted even into a pipe.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# "[✓] parameter detected: debug, based on: body length"
_DETECTED = re.compile(r"parameter detected:\s*([^,\n]+?)\s*,\s*based on:\s*([^\n]+)",
                       re.I)
# "[+] Parameters found: debug, id"
_FOUND = re.compile(r"parameters? found:\s*([^\n]+)", re.I)

MAX_PARAMS = 40


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text or "")


def parse_params(stdout_text: str) -> List[tuple]:
    """[(param, reason), ...] from arjun's console output, in order, unique."""
    text = strip_ansi(stdout_text)
    out: List[tuple] = []
    seen = set()
    for m in _DETECTED.finditer(text):
        name, reason = m.group(1).strip(), m.group(2).strip()
        if name and name not in seen:
            seen.add(name)
            out.append((name, reason))
    # The summary line is the fallback: some arjun paths print only this one.
    for m in _FOUND.finditer(text):
        for name in m.group(1).split(","):
            name = name.strip()
            if name and name not in seen:
                seen.add(name)
                out.append((name, "reported in summary"))
    return out[:MAX_PARAMS]


def with_params(url: str, params: Sequence[str]) -> str:
    """The endpoint re-expressed with the discovered parameters attached.

    This is what makes the discovery actionable: the catalog's injection tests
    apply to endpoints that have parameters, so the point has to be visible in
    the URL for the next phase to pick it up.
    """
    parsed = urlparse(url or "")
    if not parsed.scheme or not parsed.netloc or not params:
        return url or ""
    existing = parsed.query
    added = urlencode({p: "1" for p in params})
    query = f"{existing}&{added}" if existing else added
    return urlunparse(parsed._replace(query=query))


class ArjunWrapper(BaseWrapper):
    name = "arjun"
    binary = "arjun"
    description = "Discover hidden HTTP parameters by differential analysis."
    category = "recon"
    timeout_seconds = 15 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-u", target,
            "--stable",      # calibrate against an unstable endpoint first
            "-t", "10",
            "-T", "10",
            "--rate-limit", "30",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = (stdout or b"").decode("utf-8", errors="replace")
        params = parse_params(text)
        if not params:
            return ToolResult(findings=[])

        findings: List[Finding] = []
        for name, reason in params:
            findings.append(Finding(
                severity="info",
                title=f"Hidden parameter: {name}",
                description=(f"arjun confirmed the undocumented parameter '{name}' "
                             f"changes the response ({reason}). It is an injection "
                             f"point for the injection and access-control tests."),
                target=with_params(target, [name]),
                evidence=f"{target} accepts '{name}' (signal: {reason})",
                metadata={"tool": "arjun", "vuln_class": "recon",
                          "param": name, "signal": reason,
                          "asset": with_params(target, [name]),
                          "asset_kind": "endpoint"},
            ))
        # One endpoint carrying every parameter found, so a single injection
        # task covers them all instead of one task per parameter.
        if len(params) > 1:
            names = [p for p, _ in params]
            findings.append(Finding(
                severity="info",
                title=f"{len(names)} hidden parameters on {urlparse(target).path or '/'}",
                description="Endpoint re-expressed with every parameter arjun "
                            "confirmed, as an injection surface for later phases.",
                target=with_params(target, names),
                evidence=", ".join(names),
                metadata={"tool": "arjun", "vuln_class": "recon",
                          "params": names,
                          "asset": with_params(target, names),
                          "asset_kind": "endpoint"},
            ))
        return ToolResult(findings=findings)
