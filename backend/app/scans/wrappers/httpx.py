"""httpx: HTTP probe + fingerprint (ProjectDiscovery).

One JSONL object per probed URL with status, title, tech stack, server,
TLS info, etc. Perfect pipe target for subfinder output.
"""
from __future__ import annotations

import json
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import iter_json_lines, BaseWrapper, ToolResult


class HttpxWrapper(BaseWrapper):
    name = "httpx"
    binary = "httpx"
    description = "HTTP probe: status, title, tech fingerprint, server, TLS."
    category = "fingerprint"
    timeout_seconds = 15 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-u", target,
            "-silent",
            "-json",
            "-nc",
            "-tech-detect",
            "-title",
            "-server",
            "-status-code",
            "-content-length",
            "-follow-redirects",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        for obj in iter_json_lines(stdout):

            url = obj.get("url") or obj.get("input") or target
            status = obj.get("status_code")
            title = obj.get("title") or ""
            tech = obj.get("tech") or []
            server = obj.get("webserver") or obj.get("server") or ""
            scheme = obj.get("scheme") or ""
            content_type = obj.get("content_type") or ""
            content_length = obj.get("content_length")

            description_bits = []
            if status is not None:
                description_bits.append(f"HTTP {status}")
            if title:
                description_bits.append(f"title: {title}")
            if tech:
                description_bits.append("tech: " + ", ".join(str(t) for t in tech))
            if server:
                description_bits.append(f"server: {server}")

            findings.append(
                Finding(
                    severity="info",
                    title=f"Live host: {url}",
                    description=" - ".join(description_bits) if description_bits else "reachable",
                    target=url,
                    evidence=f"status={status} server={server} tech={tech}",
                    metadata={
                        "status_code": status,
                        "title": title,
                        "tech": tech,
                        "server": server,
                        "scheme": scheme,
                        "content_type": content_type,
                        "content_length": content_length,
                    },
                )
            )
        return ToolResult(findings=findings)
