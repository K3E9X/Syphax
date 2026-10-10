"""kiterunner (kr): API route discovery.

Content-discovery tools (ffuf) brute directory paths; they miss API endpoints
that need the right method, Content-Type and path shape. kiterunner replays
real API request templates and reports the routes a service actually answers -
the hidden/undocumented API surface that then feeds auth, BOLA and injection
testing.

We run `kr scan <target> -o json` and parse the JSONL it emits (one object per
matched route). Falls back to text-line parsing if JSON is absent. Defensive:
a bad record costs one route, never the scan.
"""
from __future__ import annotations

import os
import re
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import (UNBOUNDED, as_inventory, BaseWrapper,
                                     ToolResult, iter_json_lines)

# Assetnote routes wordlist, installed in the image. Overridable.
DEFAULT_KITE = os.environ.get("KITERUNNER_WORDLIST", "/opt/wordlists/routes-small.kite")

# A line like: "200 [  1452,   40,   6] https://host/api/v1/users  (ApiRoute: ...)"
_TEXT_LINE = re.compile(r"^\s*(\d{3})\s*\[[^\]]*\]\s+(https?://\S+)", re.IGNORECASE)


class KiterunnerWrapper(BaseWrapper):
    name = "kiterunner"
    binary = "kr"
    description = "API route discovery (replays real API request templates)."
    category = "content_discovery"
    timeout_seconds = 15 * 60

    # Without the .kite route file there are no request templates to replay,
    # so it reports no API routes - indistinguishable from a service with none.
    required_data = ((DEFAULT_KITE, "the Assetnote route database"),)

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary, "scan", target,
            "-w", DEFAULT_KITE,
            "-o", "json",
            "-x", os.environ.get("KITERUNNER_CONCURRENCY", "10"),
            "--fail-status-codes", "400,404,403,429,500,501,502,503",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        seen: set = set()

        for obj in iter_json_lines(stdout):
            url = obj.get("url") or obj.get("uri") or obj.get("target")
            if isinstance(url, dict):
                url = url.get("full") or url.get("raw") or ""
            status = obj.get("status") or obj.get("status_code") or obj.get("statusCode")
            method = (obj.get("method") or "GET").upper()
            if not url or url in seen:
                continue
            seen.add(url)
            findings.append(_route_finding(url, status, method, target))

        if findings:
            return ToolResult(findings=_as_routes(findings, target))

        # No JSON (older kr / text output): parse the status-prefixed lines.
        text = (stdout or b"").decode("utf-8", errors="replace")
        for line in text.splitlines():
            m = _TEXT_LINE.match(line)
            if not m:
                continue
            status, url = m.group(1), m.group(2)
            if url in seen:
                continue
            seen.add(url)
            findings.append(_route_finding(url, status, "GET", target))
        return ToolResult(findings=_as_routes(findings, target))


def _as_routes(findings, target):
    """An undocumented API route is a lead, not inventory - it is the surface
    for auth, BOLA and injection tests - so these keep their rows. The cap is
    higher than for a crawl for that reason, and the count is still reported
    once when it bites."""
    return as_inventory(findings, tool="kiterunner", target=target,
                        what="API route", interesting=lambda f: True,
                        max_individual=UNBOUNDED)


def _route_finding(url: str, status, method: str, target: str) -> Finding:
    return Finding(
        severity="info",
        title=f"API route: {method} {url}",
        description=f"kiterunner matched an API route (HTTP {status}).",
        target=url,
        evidence=f"{method} {url} -> {status}",
        metadata={
            "vuln_class": "api_route",
            "method": method,
            "status": status,
            "tool": "kiterunner",
            # A discovered route is the surface for the auth, BOLA and
            # injection tests; declared so the ingest aims them at it.
            "asset": url,
            "asset_kind": "endpoint",
        },
    )
