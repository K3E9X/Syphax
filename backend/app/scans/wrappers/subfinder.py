"""subfinder: passive subdomain enumeration (ProjectDiscovery)."""
from __future__ import annotations

import json
from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import iter_json_lines, BaseWrapper, ToolResult


class SubfinderWrapper(BaseWrapper):
    name = "subfinder"
    binary = "subfinder"
    description = "Passive subdomain enumeration via dozens of sources."
    category = "recon"
    timeout_seconds = 15 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        domain = _target_to_domain(target)
        cmd = [
            self.binary,
            "-d", domain,
            "-silent",
            "-json",
            "-nc",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        domain = _target_to_domain(target)
        for obj in iter_json_lines(stdout):
            host = obj.get("host") or ""
            source = obj.get("source") or ""
            if not host:
                continue
            findings.append(
                Finding(
                    severity="info",
                    title=f"Subdomain: {host}",
                    description=f"Discovered via {source or 'unknown source'}.",
                    target=host,
                    evidence=f"source={source} input={domain}",
                    metadata={"source": source, "parent_domain": domain},
                )
            )
        return ToolResult(findings=findings)


def _target_to_domain(target: str) -> str:
    """Accept either a URL or a bare domain."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/", 1)[0]
