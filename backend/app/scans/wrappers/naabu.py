"""naabu: fast port scanner (ProjectDiscovery).

Connect-scan mode (-s c) so no raw-socket capability is needed. JSON lines
on stdout, one open port each.
"""
from __future__ import annotations

from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import iter_json_lines, BaseWrapper, ToolResult


class NaabuWrapper(BaseWrapper):
    name = "naabu"
    binary = "naabu"
    description = "Fast TCP port scanner (connect mode, top ports by default)."
    category = "recon"
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        cmd = [
            self.binary,
            "-host", host,
            "-s", "c",          # connect scan (no raw sockets)
            "-json",
            "-silent",
            "-top-ports", "1000",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        for obj in iter_json_lines(stdout):
            host = obj.get("host") or obj.get("ip") or _target_to_host(target)
            port = obj.get("port")
            if port is None:
                continue
            findings.append(
                Finding(
                    severity="info",
                    title=f"Open port {port}/tcp on {host}",
                    description=f"naabu found TCP port {port} open.",
                    target=f"{host}:{port}",
                    evidence=f"host={host} port={port}",
                    metadata={"host": host, "port": port, "ip": obj.get("ip"), "tool": "naabu"},
                )
            )
        return ToolResult(findings=findings)


def _target_to_host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or target).lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()
