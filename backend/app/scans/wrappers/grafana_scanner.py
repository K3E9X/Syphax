"""Grafana-Final-Scanner: version-aware Grafana CVE checks.

The operator asked for a second opinion on Grafana specifically, alongside
nuclei's templates. Read-only HTTP, so it runs like any other scanner, gated
only by the fingerprint - RECON/VULN items apply it when "grafana" was seen.

One deliberate choice about parsing. This is a single-maintainer tool with no
release and an output format we have not verified against a live run, which is
exactly the shape that makes a wrapper silently report nothing after the format
shifts. So the parser does not depend on guessing a JSON schema: it reads the
tool's own stdout, lifts any CVE id and severity word it can, and - crucially -
if the tool clearly DID something (it named Grafana, or printed a CVE) but
nothing mapped cleanly, it surfaces the raw output as ONE finding for review
rather than returning an empty result that reads as "clean". An unverified
parser must fail loud, not silent.
"""
from __future__ import annotations

import os
import re
from typing import List, Sequence

from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_SEV = re.compile(r"\b(critical|high|medium|low)\b", re.I)
_VERSION = re.compile(r"grafana[^\d]{0,12}(\d+\.\d+\.\d+)", re.I)

MAX_FINDINGS = 50


class GrafanaScannerWrapper(BaseWrapper):
    name = "grafana_scanner"
    binary = "grafana_scanner"
    description = "Version-aware Grafana CVE checks (a second opinion to nuclei)."
    category = "vuln"
    timeout_seconds = 8 * 60

    def _resolve_binary(self) -> List[str]:
        if os.path.isfile("/opt/grafana-scanner/scanner.py"):
            return ["python3", "/opt/grafana-scanner/scanner.py"]
        return ["grafana_scanner"]

    def is_available(self) -> bool:
        return os.path.isfile("/opt/grafana-scanner/scanner.py")

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        # stdout, not -o: -o writes report.{json,html,csv} to disk and the
        # runner parses stdout. --no-banner keeps the header out of the parse.
        cmd = self._resolve_binary() + ["-u", target, "--no-banner",
                                        "--no-ssl-verify"]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int,
              target: str) -> ToolResult:
        text = (stdout or b"").decode("utf-8", errors="replace")
        findings: List[Finding] = []
        seen = set()

        version = ""
        vm = _VERSION.search(text)
        if vm:
            version = vm.group(1)

        for line in text.splitlines():
            cve_m = _CVE.search(line)
            if not cve_m:
                continue
            cve = cve_m.group(0).upper()
            if cve in seen:
                continue
            seen.add(cve)
            sev_m = _SEV.search(line)
            severity = (sev_m.group(1).lower() if sev_m else "medium")
            findings.append(Finding(
                severity=severity,
                title=f"Grafana {cve}" + (f" (version {version})" if version else ""),
                description=(f"Grafana-Final-Scanner reported {cve} against this "
                             f"instance" + (f", fingerprinted as {version}" if version
                                            else "") + ". Confirm against the "
                             "advisory and cross-check with the nuclei result "
                             "for the same template."),
                target=target,
                evidence=line.strip()[:500],
                metadata={"tool": "grafana_scanner", "vuln_class": "cve",
                          "cve_id": cve, "status": "likely", "confidence": 0.55,
                          "grafana_version": version},
            ))
            if len(findings) >= MAX_FINDINGS:
                break

        # Fail LOUD: the tool named Grafana or a CVE but nothing mapped. Better
        # one finding that says "read this output" than a silent empty result
        # that an operator reads as a clean bill of health.
        if not findings and ("grafana" in text.lower() or _CVE.search(text)):
            findings.append(Finding(
                severity="info",
                title=f"Grafana scanner ran but its output was not parsed: {target}",
                description=("Grafana-Final-Scanner produced output that this "
                             "wrapper could not map to findings - its format may "
                             "have changed. The raw output is below; review it by "
                             "hand. This is surfaced on purpose: an unverified "
                             "parser must not turn 'I could not read it' into "
                             "'nothing found'."),
                target=target,
                evidence=text[:3000],
                metadata={"tool": "grafana_scanner", "vuln_class": "recon",
                          "status": "unconfirmed", "confidence": 0.3,
                          "needs_manual_review": True},
            ))
        return ToolResult(findings=findings)
