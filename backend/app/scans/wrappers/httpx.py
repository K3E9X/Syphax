"""httpx: HTTP probe + fingerprint (ProjectDiscovery).

One JSONL object per probed URL with status, title, tech stack, server,
TLS info, etc. Perfect pipe target for subfinder output.
"""
from __future__ import annotations

import shutil

from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import (as_inventory, iter_json_lines,
                                     BaseWrapper, ToolResult)


def _resolve_binary() -> str:
    """ProjectDiscovery's httpx, under whichever name survived the image build.

    `httpx` is an ambiguous name: the Python HTTP library ships a console
    script of the same name, pip installs it into the same directory as the Go
    binary, and in this image pip runs last - so /usr/local/bin/httpx was the
    Python CLI. Running it with ProjectDiscovery's flags exits non-zero and
    produces nothing, which is exactly what a run showed: nine RECON-HTTP-PROBE
    jobs, nine failures, no findings.

    pd-httpx is installed by the Dockerfile and cannot be claimed by anything
    else. The plain name stays as a fallback for an older image, and the
    identity probe below is what refuses it when it is the wrong program.
    """
    return "pd-httpx" if shutil.which("pd-httpx") else "httpx"


class HttpxWrapper(BaseWrapper):
    name = "httpx"
    binary = _resolve_binary()
    # Proven, not assumed: `which` finds a file, not the right program.
    identity_probe = (("-version",), "projectdiscovery")
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
                        "vuln_class": "recon",
                        "asset": url,
                        "asset_kind": "endpoint",
                    },
                )
            )
        # One probe per URL, and a crawl can hand it hundreds. The ones worth
        # reading are those that answered something other than a plain 200, or
        # that disclosed a server banner - the rest is "it is up".
        def _worth_a_row(f):
            meta = f.metadata or {}
            code = meta.get("status_code")
            return bool(meta.get("server")) or (code is not None and code != 200)

        return ToolResult(findings=as_inventory(
            findings, tool="httpx", target=target, what="live URL",
            interesting=_worth_a_row))
