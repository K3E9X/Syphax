"""dnsx: DNS resolution / record toolkit (ProjectDiscovery).

Resolves the target host and reports A/AAAA/CNAME records as info findings.
Useful for mapping infra and spotting CNAMEs that hint at takeover targets.
"""
from __future__ import annotations

from typing import List, Sequence
from urllib.parse import urlparse

from app.scans.models import Finding
from app.scans.wrappers.base import iter_json_lines, BaseWrapper, ToolResult


class DnsxWrapper(BaseWrapper):
    name = "dnsx"
    binary = "dnsx"
    description = "DNS toolkit: resolve A/AAAA/CNAME and other records."
    category = "recon"
    timeout_seconds = 10 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        host = _target_to_host(target)
        cmd = [
            self.binary,
            "-d", host,
            "-json",
            "-silent",
            "-a", "-aaaa", "-cname",
            "-mx", "-ns", "-txt", "-soa", "-ptr",
            "-resp",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        for obj in iter_json_lines(stdout):
            host = obj.get("host") or _target_to_host(target)
            a = obj.get("a") or []
            aaaa = obj.get("aaaa") or []
            cname = obj.get("cname") or []
            mx = obj.get("mx") or []
            ns = obj.get("ns") or []
            txt = obj.get("txt") or []
            soa = obj.get("soa") or []
            ptr = obj.get("ptr") or []

            records = []
            for label, vals in (("A", a), ("AAAA", aaaa), ("CNAME", cname),
                                ("MX", mx), ("NS", ns), ("TXT", txt),
                                ("SOA", [str(s) for s in soa]), ("PTR", ptr)):
                if vals:
                    records.append(f"{label}: " + ", ".join(str(v) for v in vals))
            if not records:
                continue

            findings.append(
                Finding(
                    severity="info",
                    title=f"DNS records for {host}",
                    description="; ".join(records),
                    target=host,
                    evidence="; ".join(records),
                    metadata={"a": a, "aaaa": aaaa, "cname": cname, "mx": mx,
                              "ns": ns, "txt": txt, "tool": "dnsx"},
                )
            )
        return ToolResult(findings=findings)


def _target_to_host(target: str) -> str:
    if "://" in target:
        return (urlparse(target).hostname or target).lower()
    return target.split("/", 1)[0].split(":", 1)[0].lower()
