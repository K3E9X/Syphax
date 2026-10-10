"""gau (GetAllUrls): historical URLs from Wayback / Common Crawl / OTX / URLScan.

Expands the attack surface with paths and parameters that aren't linked from
the live site anymore. Plain URLs on stdout (one per line); we de-duplicate
and cap to keep finding volume sane.
"""
from __future__ import annotations

import re
from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

# HOW MANY FINDINGS gau MAY PRODUCE, and why these numbers.
#
# gau returns a domain's historical URLs. On a real target that is thousands,
# and every one of them used to become its own `info` finding AND its own
# endpoint asset. A run on testfire.net produced 2176 findings of which 2175
# were recon, and 2162 assets - which the planner then multiplied by the
# catalog, so the run hit its TIME budget at iteration 8 having launched 62
# jobs. The Findings page was unreadable and the actual vulnerabilities were
# never reached.
#
# An archived URL is INVENTORY, not a finding. What is worth a finding is the
# small subset that carries query parameters: those are injection points, and
# every param-gated catalog item needs one to exist.
MAX_URLS = 2000             # how many lines of gau output we read at all
MAX_PARAM_FINDINGS = 60     # parameterised URLs reported individually
MAX_PLAIN_ASSETS = 40       # distinct param-less paths kept as scan targets

# Nothing to test on these: no parameters, no server-side behaviour.
_STATIC_EXT = (".css", ".js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".ico", ".woff", ".woff2", ".ttf", ".eot", ".webp", ".avif",
               ".mp4", ".webm", ".pdf", ".zip", ".gz", ".tgz")


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(_STATIC_EXT)

# Deliberately strict: a scheme, a host with a dot, and no whitespace.
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._~%-]+\.[A-Za-z0-9._~%-]+(?:[:/?#]\S*)?$")


def _looks_like_url(value: str) -> bool:
    return bool(_URL_RE.match(value))


class GauWrapper(BaseWrapper):
    name = "gau"
    binary = "gau"
    description = "Fetch known URLs from Wayback/Common Crawl/OTX for a domain."
    category = "recon"
    timeout_seconds = 15 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        # gau takes the domain as a positional arg. Include subdomains and pull
        # from every provider for the widest historical surface.
        cmd = [self.binary, host, "--threads", "5", "--subs",
               "--providers", "wayback,commoncrawl,otx,urlscan"]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        seen = set()
        with_params: List[str] = []
        plain_by_path: dict = {}
        static = 0
        total = 0

        for raw in stdout.decode("utf-8", "replace").splitlines():
            url = raw.strip()
            # gau prints one URL per line, but an error page, a JSON blob or
            # binary noise on stdout used to become "historical URL" findings -
            # and those are fed back as assets the scanners then target.
            if not url or url in seen or not _looks_like_url(url):
                continue
            seen.add(url)
            total += 1
            if total > MAX_URLS:
                break
            if _is_static(url):
                static += 1
                continue
            if "?" in url and "=" in url:
                with_params.append(url)
            else:
                # One per distinct path: the archive holds the same page under
                # dozens of timestamps and trailing variations.
                plain_by_path.setdefault(urlparse(url).path or "/", url)

        findings: List[Finding] = []

        # The parameterised URLs, individually. These are the only ones worth a
        # row of their own: a URL with a query string is an injection point,
        # and seven catalog items apply ONLY to an endpoint that has one.
        for url in with_params[:MAX_PARAM_FINDINGS]:
            findings.append(Finding(
                severity="info",
                title="Archived URL with parameters: " + url[:120],
                description="Historical URL carrying query parameters (gau). "
                            "Parameters are what the injection tests need, so "
                            "this is kept as a scan target.",
                target=url,
                evidence=url,
                metadata={"has_params": True, "tool": "gau",
                          "vuln_class": "recon",
                          "asset": url, "asset_kind": "endpoint"},
            ))

        # Everything else is inventory. ONE finding, with a sample - not two
        # thousand rows the operator has to scroll past to reach a real one.
        plain = list(plain_by_path.values())
        kept = plain[:MAX_PLAIN_ASSETS]
        if plain or static or len(with_params) > MAX_PARAM_FINDINGS:
            sample = "\n".join(kept[:40])
            findings.append(Finding(
                severity="info",
                title=f"{total} archived URL(s) for {_target_to_host(target)}",
                description=(
                    f"Historical URLs from Wayback/Common Crawl/OTX/URLScan. "
                    f"{len(with_params)} carry query parameters and are listed "
                    f"individually (up to {MAX_PARAM_FINDINGS}); "
                    f"{len(plain)} distinct param-less paths and {static} static "
                    f"files are summarised here. Inventory, not findings."),
                target=target,
                evidence=sample or "(no non-static URL)",
                metadata={"tool": "gau", "vuln_class": "recon",
                          "archived_total": total,
                          "with_params": len(with_params),
                          "distinct_paths": len(plain),
                          "static_skipped": static},
            ))

        # The param-less paths still become scan targets - just a bounded
        # number of them, and without a finding each.
        for url in kept:
            findings.append(Finding(
                severity="info",
                title="Archived path: " + url[:120],
                description="Historical path kept as a scan target (gau).",
                target=url,
                evidence=url,
                metadata={"has_params": False, "tool": "gau",
                          "vuln_class": "recon",
                          "asset": url, "asset_kind": "endpoint"},
            ))
        return ToolResult(findings=findings)


def _target_to_host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or target).lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()
