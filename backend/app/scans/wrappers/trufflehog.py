"""trufflehog in verified mode: a secret that is PROVEN live.

This is the highest-value/lowest-noise tool in the set, and the reason is one
flag. `js_recon.py` finds secrets with regexes and reports them as `likely`:
it matches the shape of an AWS key without knowing whether that key still
works, so a rotated credential in a stale bundle and a live production key
are the same finding. `--results=verified` makes trufflehog authenticate the
candidate against its provider and only report what answered. That is an
oracle, not a pattern - the finding is proven, not guessed.

It reads files, not URLs, so it scans the two artifact directories syphax
already fills (see app/scans/artifacts.py):

    {data_dir}/artifacts/{host}/git/   the tree git-dumper recovered
    {data_dir}/artifacts/{host}/js/    the client JavaScript the proxy captured

With neither directory populated there is nothing to scan, the command gets no
path, and the job reports zero findings rather than failing.

Verification is an outbound request to the credential's OWN provider (AWS,
GitHub, Stripe), not to the target, and it never uses the credential for
anything beyond an identity call.
"""
from __future__ import annotations

from typing import Any, Dict, List, Sequence

from app.scans.artifacts import git_dir, js_dir, listdir
from app.scans.models import Finding
from app.scans.wrappers.base import BaseWrapper, ToolResult, iter_json_lines

# Detector -> severity. A verified secret is by definition live, so these are
# all high or above; the split is about what the credential can reach.
CRITICAL_DETECTORS = {
    "aws", "awssessionkey", "gcp", "azure", "azurebatch", "privatekey",
    "stripe", "square", "paypal", "twilio", "postgres", "mysql", "mongodb",
    "redis", "jdbc", "ssh", "kubeconfig", "databricks",
}


def severity_for(detector: str, verified: bool) -> str:
    """Verified secrets are rated by blast radius; unverified stay low.

    An unverified trufflehog hit is exactly what js_recon already reports, so
    it must not be presented as stronger than that.
    """
    if not verified:
        return "low"
    return "critical" if (detector or "").strip().lower() in CRITICAL_DETECTORS else "high"


def source_location(meta: Dict[str, Any]) -> str:
    """Where the secret was found: file[:line], or a git commit when known."""
    data = (meta or {}).get("Data")
    if not isinstance(data, dict):
        return ""
    for kind in ("Filesystem", "Git", "Github", "Gitlab"):
        entry = data.get(kind)
        if not isinstance(entry, dict):
            continue
        path = entry.get("file") or entry.get("link") or entry.get("repository") or ""
        line = entry.get("line")
        commit = entry.get("commit")
        out = str(path)
        if line:
            out = f"{out}:{line}"
        if commit:
            out = f"{out} (commit {str(commit)[:10]})"
        return out
    return ""


def redact(raw: str) -> str:
    """Never write a live credential into a finding.

    The evidence has to identify the secret without reproducing it: the
    operator can find it at the reported file and line.
    """
    s = str(raw or "")
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}...{s[-4:]} ({len(s)} chars)"


class TruffleHogWrapper(BaseWrapper):
    name = "trufflehog"
    binary = "trufflehog"
    description = "Find secrets in recovered source and JS, and verify each against its provider."
    category = "vuln"
    timeout_seconds = 20 * 60

    def scan_paths(self, target: str) -> List[str]:
        """The artifact directories that actually have files in them."""
        paths = []
        for d in (git_dir(target), js_dir(target)):
            if d is not None and listdir(d, limit=1):
                paths.append(str(d))
        return paths

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        paths = self.scan_paths(target)
        cmd = [
            self.binary, "filesystem",
            *paths,
            "--json",
            # The whole point: report only what the provider confirmed is live.
            "--results=verified",
            "--no-update",
        ]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        seen = set()
        for rec in iter_json_lines(stdout):
            detector = str(rec.get("DetectorName") or rec.get("DetectorType") or "secret")
            verified = bool(rec.get("Verified"))
            raw = str(rec.get("Raw") or rec.get("RawV2") or "")
            where = source_location(rec.get("SourceMetadata") or {})
            key = (detector, raw[:40], where)
            if key in seen:
                continue
            seen.add(key)
            severity = severity_for(detector, verified)
            state = "VERIFIED LIVE" if verified else "unverified"
            findings.append(Finding(
                severity=severity,
                title=(f"Live {detector} credential in recovered files"
                       if verified else f"Possible {detector} credential"),
                description=(
                    f"trufflehog found a {detector} credential and authenticated it "
                    "against the provider: the credential is currently valid."
                    if verified else
                    f"trufflehog matched a {detector} credential pattern but could "
                    "not verify it against the provider. Treat as a lead."),
                target=target,
                evidence=(f"Detector : {detector}\nStatus   : {state}\n"
                          f"Location : {where or '(unknown)'}\n"
                          f"Secret   : {redact(raw)}"),
                metadata={"tool": "trufflehog", "vuln_class": "secret_exposure",
                          "detector": detector, "verified": verified,
                          "location": where,
                          # A verified secret is proven by the provider itself,
                          # so the validator should not re-derive a guess from
                          # severity - it is confirmed.
                          "status": "confirmed" if verified else "likely",
                          "confidence": 0.97 if verified else 0.5},
            ))
        return ToolResult(findings=findings)
