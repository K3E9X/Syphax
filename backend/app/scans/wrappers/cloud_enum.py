"""cloud_enum: enumerate public cloud storage for a keyword (brand/domain).

Covers the gap no other tool filled: AWS S3, Azure blob/containers and Google
Cloud Storage buckets are not reachable by hitting the engagement's own URL -
they live on *.s3.amazonaws.com / *.blob.core.windows.net / storage.googleapis.com
and are found by permuting the organisation's name. cloud_enum does exactly
that and reports which resources exist and which are publicly open.

We derive the keyword from the target host (its registrable label), run the
three providers, and parse cloud_enum's line-oriented output. The tool emits no
JSON, so we match on the stable markers it prints for each result class:

    OPEN  / PUBLIC ...............  world-readable or listable  -> high
    AUTHENTICATED / PROTECTED ....  exists, needs a cloud identity -> medium
    (anything else is a miss and is dropped)

Marker strings follow cloud_enum's output as of the pinned version; parse() is
defensive and never raises on unexpected text (a bad line costs one result).
"""
from __future__ import annotations

import re
from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult


class CloudEnumWrapper(BaseWrapper):
    name = "cloud_enum"
    binary = "cloud_enum"
    description = "Enumerate public AWS S3 / Azure / GCP storage for a brand keyword."
    category = "recon"
    # Permutation lists hit many endpoints; keep a generous but bounded cap.
    timeout_seconds = 20 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        keyword = _keyword(target)
        cmd = [
            self.binary,
            "-k", keyword,
            # Also try the bare host label as a second keyword (e.g. "acme" and
            # "acme-corp"): many buckets use the short brand, not the FQDN.
            "-k", _short_label(keyword),
            "-t", "12",   # thread cap: polite, bounded concurrency
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        text = (stdout or b"").decode("utf-8", errors="replace")
        findings: List[Finding] = []
        seen: set = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            upper = line.upper()
            provider = _provider(upper)
            if provider is None:
                continue
            url = _first_url(line)
            if not url:
                continue
            if url in seen:
                continue
            seen.add(url)

            public = any(m in upper for m in ("OPEN", "PUBLIC", "LISTABLE", "WORLD"))
            auth_only = any(m in upper for m in ("AUTHENTICATED", "PROTECTED", "RESTRICTED"))
            if not (public or auth_only):
                continue

            sev = "high" if public else "medium"
            state = "public (world-readable / listable)" if public else "exists, authenticated access only"
            findings.append(Finding(
                severity=sev,
                title=f"{'Public' if public else 'Private'} {provider} storage: {url}",
                description=(f"cloud_enum found a {provider} storage resource for this "
                             f"organisation - {state}."),
                target=url,
                evidence=line[:500],
                metadata={
                    "vuln_class": "exposed_bucket",
                    "provider": provider,
                    "public": public,
                    "resource": url,
                    "tool": "cloud_enum",
                },
            ))
        return ToolResult(findings=findings)


_URL_RE = re.compile(r"https?://[^\s'\"]+", re.IGNORECASE)


def _provider(upper_line: str) -> str | None:
    if "S3" in upper_line or "AMAZONAWS" in upper_line or "AWS" in upper_line:
        return "AWS S3"
    if "AZURE" in upper_line or "BLOB.CORE.WINDOWS" in upper_line or "CONTAINER" in upper_line:
        return "Azure Blob"
    if "GOOGLE" in upper_line or "GCP" in upper_line or "STORAGE.GOOGLEAPIS" in upper_line or "GSUTIL" in upper_line:
        return "Google Cloud Storage"
    return None


def _first_url(line: str) -> str:
    m = _URL_RE.search(line)
    return m.group(0).rstrip(".,);]") if m else ""


def _keyword(target: str) -> str:
    """The registrable brand label from a target URL or host."""
    host = target
    if "://" in target:
        host = urlparse(target).hostname or target
    host = (host or "").strip().lower().strip(".")
    # Drop a leading www and keep the second-level label (acme from acme.co.uk).
    parts = [p for p in host.split(".") if p]
    if parts and parts[0] == "www":
        parts = parts[1:]
    if len(parts) >= 2:
        # eTLD+1 label: the part before the public suffix. A full PSL is
        # overkill here; the second-to-last label is the brand in the vast
        # majority of cases (acme.com, acme.co.uk -> acme).
        return parts[-2] if parts[-2] not in ("co", "com", "org", "gov", "ac") else parts[-3] if len(parts) >= 3 else parts[0]
    return parts[0] if parts else host


def _short_label(keyword: str) -> str:
    # A hyphen-stripped variant, so "acme-corp" also tries "acmecorp".
    return keyword.replace("-", "").replace("_", "") or keyword
