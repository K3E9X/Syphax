"""katana: modern crawler / spider (ProjectDiscovery).

Runs without headless browser by default (faster, fewer deps). Each
JSONL object is a request/response pair; we emit one info-severity
Finding per discovered endpoint.
"""
from __future__ import annotations

from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import (as_inventory, iter_json_lines,
                                     BaseWrapper, ToolResult)


class KatanaWrapper(BaseWrapper):
    name = "katana"
    binary = "katana"
    description = "Crawler / spider that maps routes on classic and SPA apps."
    category = "recon"
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        cmd = [
            self.binary,
            "-u", target,
            "-silent",
            "-jsonl",
            "-nc",
            "-d", "2",       # crawl depth
            "-c", "10",      # concurrent requests
            "-timeout", "10",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        for obj in iter_json_lines(stdout):

            # Newer katana emits {"timestamp","request":{...},"response":{...}}.
            # Older/simpler outputs may flatten these. Handle both.
            request = obj.get("request") or {}
            response = obj.get("response") or {}

            endpoint = (
                request.get("endpoint")
                or request.get("url")
                or obj.get("endpoint")
                or obj.get("url")
                or ""
            )
            if not endpoint:
                continue

            method = request.get("method") or obj.get("method") or "GET"
            status = response.get("status_code") or obj.get("status_code")
            content_length = response.get("content_length") or obj.get("content_length")

            desc_bits = [f"{method} {endpoint}"]
            if status is not None:
                desc_bits.append(f"HTTP {status}")
            if content_length is not None:
                desc_bits.append(f"{content_length} bytes")

            has_params = "?" in endpoint and "=" in endpoint
            findings.append(
                Finding(
                    severity="info",
                    title=("Endpoint with parameters: " if has_params
                           else "Endpoint: ") + endpoint,
                    description=" - ".join(desc_bits),
                    target=endpoint,
                    evidence=f"method={method} status={status} size={content_length}",
                    metadata={
                        "method": method,
                        "status_code": status,
                        "content_length": content_length,
                        "source": obj.get("source"),
                        "has_params": has_params,
                        "vuln_class": "recon",
                        # Declared so the ingest turns it into a scan target.
                        "asset": endpoint,
                        "asset_kind": "endpoint",
                    },
                )
            )
        # A crawl of a real site returns thousands of URLs, and every one used
        # to be its own finding. What deserves a row is the subset carrying
        # query parameters: those are injection points, and the param-gated
        # catalog items need one to exist. The rest is surface.
        return ToolResult(findings=as_inventory(
            findings, tool="katana", target=target, what="crawled URL",
            interesting=lambda f: bool((f.metadata or {}).get("has_params"))))
