"""nikto: classic web-server misconfiguration scanner.

Catches the obvious: dangerous methods, server-status, backup/old files,
outdated server banners, default files. We request JSON to stdout and parse
the vulnerabilities array.

nikto does not rate its own findings, and this wrapper used to stamp
`severity="low"` on every one of them. The consequence was not cosmetic: the
validator's heuristic branch derives its confidence from severity alone, so a
`.git` directory and an "X-Powered-By header leaks the PHP version" line both
landed at likely/0.5 - and both counted in the false-positive denominator.
`severity_for()` reads nikto's own message text and rates it; `class_for()`
gives the finding a vuln_class finer than the tool-wide "misconfiguration", so
banner noise is filed as recon and not as a weakness.
"""
from __future__ import annotations

import json
import re
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# Message patterns -> (severity, vuln_class), most severe first. nikto's msg is
# free text, so these match on the words it actually prints.
_RULES = [
    (re.compile(r"remote file (retrieval|inclusion)|rfi\b", re.I),
     ("high", "file_inclusion")),
    (re.compile(r"command execution|remote (code|shell)|eval\(|backdoor|webshell", re.I),
     ("high", "command_injection")),
    (re.compile(r"sql inject", re.I), ("high", "sql_injection")),
    (re.compile(r"directory traversal|\.\./|/etc/passwd|file (retrieval|read)", re.I),
     ("high", "path_traversal")),
    (re.compile(r"default (admin |)(account|credential|password|login)|admin:admin", re.I),
     ("high", "default_credentials")),
    (re.compile(r"\.git|\.svn|\.env\b|wp-config|\.sql\b|database dump|id_rsa|private key", re.I),
     ("high", "information_disclosure")),
    (re.compile(r"cross site scripting|\bxss\b", re.I), ("medium", "xss")),
    (re.compile(r"cross site request forgery|\bcsrf\b", re.I), ("medium", "csrf")),
    (re.compile(r"http (method |verb )?(put|delete)\b|webdav|allows? (put|delete)", re.I),
     ("medium", "dangerous_http_method")),
    (re.compile(r"\btrace\b.*(enabled|allowed)|cross site tracing", re.I),
     ("medium", "dangerous_http_method")),
    (re.compile(r"phpinfo|server-status|server-info|/actuator|\.htaccess|"
                r"\bbackup\b|\.bak\b|\.old\b|~$|swap file", re.I),
     ("medium", "information_disclosure")),
    (re.compile(r"directory indexing|index(ing|es) found|open redirect", re.I),
     ("medium", "misconfiguration")),
    (re.compile(r"appears to be outdated|is out of date|end of life|\beol\b", re.I),
     ("medium", "outdated_component")),
    (re.compile(r"clickjack|x-frame-options|content-security-policy|"
                r"strict-transport-security|x-content-type-options|cookie.*(secure|httponly)", re.I),
     ("low", "missing_security_header")),
    (re.compile(r"retrieved (x-powered-by|via|server|x-aspnet)|"
                r"header.*(leak|reveal|information)|banner|version", re.I),
     ("info", "fingerprint")),
    (re.compile(r"no cgi directories|scan terminated|allowed http methods|"
                r"robots\.txt|entries? which should be manually viewed", re.I),
     ("info", "recon")),
]

DEFAULT_SEVERITY = "low"
DEFAULT_CLASS = "misconfiguration"


def _rate(msg: str):
    for pattern, verdict in _RULES:
        if pattern.search(msg or ""):
            return verdict
    return (DEFAULT_SEVERITY, DEFAULT_CLASS)


def severity_for(msg: str) -> str:
    """Rate one nikto message. Unknown wording keeps the old 'low' default."""
    return _rate(msg)[0]


def class_for(msg: str) -> str:
    """vuln_class for one nikto message, finer than the tool-wide default."""
    return _rate(msg)[1]


class NiktoWrapper(BaseWrapper):
    name = "nikto"
    binary = "nikto"
    description = "Web server scanner: misconfig, dangerous files/methods, banners."
    category = "vuln"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-h", target,
            "-Format", "json",
            "-output", "/dev/stdout",
            "-nointeractive",
            "-ask", "no",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = stdout.decode("utf-8", errors="replace").strip()
        if not text:
            return ToolResult(findings=[])

        # nikto prints scan progress mixed with the JSON object; isolate the JSON.
        start = text.find("{")
        if start == -1:
            return ToolResult(findings=[])
        # nikto may emit multiple JSON objects; take the last complete one.
        candidates = []
        depth = 0
        buf_start = None
        for i, ch in enumerate(text):
            if ch == "{":
                if depth == 0:
                    buf_start = i
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0 and buf_start is not None:
                    candidates.append(text[buf_start : i + 1])
                    buf_start = None

        data = None
        for cand in reversed(candidates):
            try:
                data = json.loads(cand)
                break
            except json.JSONDecodeError:
                continue
        if not isinstance(data, dict):
            return ToolResult(findings=[])

        host = data.get("host") or target
        findings: List[Finding] = []
        for vuln in data.get("vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            msg = vuln.get("msg") or ""
            url = vuln.get("url") or host
            method = vuln.get("method") or "GET"
            osvdb = vuln.get("OSVDB") or vuln.get("id") or ""
            severity, vuln_class = _rate(msg)
            findings.append(
                Finding(
                    severity=severity,
                    title=f"nikto: {msg[:90]}" if msg else "nikto finding",
                    description=msg,
                    target=url,
                    evidence=f"{method} {url} (OSVDB:{osvdb})",
                    metadata={"osvdb": osvdb, "method": method, "tool": "nikto",
                              "vuln_class": vuln_class},
                )
            )
        return ToolResult(findings=findings)
