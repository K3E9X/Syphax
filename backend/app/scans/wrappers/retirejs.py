"""retire.js: rate the CLIENT-side libraries, not just the server.

A real gap in the coverage: httpx and whatweb fingerprint the server, nuclei
matches server-side CVEs, wpscan rates WordPress. Nothing looked at what the
browser actually loads. A page shipping jQuery 1.7.2, an Angular 1.x with a
known sandbox bypass or a Handlebars with a prototype-pollution CVE was
invisible - and those are exploitable through the same page the scanners were
happily reporting as clean.

retire.js matches known-vulnerable library versions against its own
vulnerability database, so a hit is a version comparison, not a guess: the
library either is or is not in the affected range. That makes it low-noise by
construction, and it carries the CVE ids the report already knows how to map.

It reads files, so it scans the JavaScript the proxy captured, materialised
into the host's artifact directory (see app/scans/artifacts.py). No JS
captured, no files, no findings.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from app.scans.artifacts import js_dir, listdir
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult, iter_json_lines

# retire.js severities are already ours.
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def norm_severity(value: Any) -> str:
    sev = str(value or "").strip().lower()
    return sev if sev in _SEVERITIES else "medium"


def cve_ids(vuln: Dict[str, Any]) -> List[str]:
    ids = vuln.get("identifiers")
    if not isinstance(ids, dict):
        return []
    out = []
    for key in ("CVE", "cve"):
        value = ids.get(key)
        if isinstance(value, list):
            out.extend(str(v) for v in value if v)
        elif value:
            out.append(str(value))
    return out


def summary_of(vuln: Dict[str, Any]) -> str:
    ids = vuln.get("identifiers")
    if isinstance(ids, dict):
        for key in ("summary", "issue", "bug"):
            if ids.get(key):
                return str(ids[key])
    return ""


def iter_results(payload: Dict[str, Any]):
    """Flatten retire.js' file -> component -> vulnerability nesting."""
    data = payload.get("data")
    if not isinstance(data, list):
        return
    for entry in data:
        if not isinstance(entry, dict):
            continue
        file = str(entry.get("file") or "")
        for result in entry.get("results") or []:
            if not isinstance(result, dict):
                continue
            component = str(result.get("component") or "library")
            version = str(result.get("version") or "?")
            for vuln in result.get("vulnerabilities") or []:
                if isinstance(vuln, dict):
                    yield file, component, version, vuln


class RetireJsWrapper(BaseWrapper):
    name = "retirejs"
    binary = "retire"
    description = "Detect known-vulnerable client-side JavaScript libraries."
    category = "vuln"
    timeout_seconds = 10 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        directory = js_dir(target)
        cmd = [
            self.binary,
            "--path", str(directory) if directory else "/tmp/js",
            "--outputformat", "json",
            "--outputpath", "/dev/stdout",
            "--js",
            "--exitwith", "0",   # a finding is not a build failure
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        seen = set()
        for payload in iter_json_lines(stdout):
            for file, component, version, vuln in iter_results(payload):
                cves = cve_ids(vuln)
                key = (component, version, tuple(cves), summary_of(vuln)[:80])
                if key in seen:
                    continue
                seen.add(key)
                summary = summary_of(vuln)
                below = str(vuln.get("below") or "")
                findings.append(Finding(
                    severity=norm_severity(vuln.get("severity")),
                    title=f"Vulnerable client library: {component} {version}",
                    description=(
                        f"The page loads {component} {version}, which is affected by a "
                        f"known vulnerability"
                        + (f" fixed in {below}" if below else "")
                        + (f": {summary}" if summary else ".")),
                    target=target,
                    evidence=(f"Library : {component} {version}\n"
                              f"File    : {file or '(captured JavaScript)'}\n"
                              + (f"Fixed in: {below}\n" if below else "")
                              + (f"CVE     : {', '.join(cves)}\n" if cves else "")
                              + (f"Issue   : {summary}" if summary else "")).strip(),
                    metadata={"tool": "retirejs", "vuln_class": "vulnerable_component",
                              "component": component, "version": version,
                              "below": below, "file": file,
                              "cve_id": cves[0] if cves else "",
                              "cve": cves},
                ))
        return ToolResult(findings=findings)
