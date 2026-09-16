"""nuclei: fast template-based scanner (ProjectDiscovery).

Runs with `-jsonl` so each finding is a single JSON object per line on stdout.
"""
from __future__ import annotations

import os
from typing import List, Sequence

from app.cve_refs import exploit_refs as _exploit_refs
from app.cve_refs import first_cve, normalize_cve, refs_text as _refs_text
from app.scans.models import Finding
from app.scans.wrappers.base import iter_json_lines, BaseWrapper, ToolResult


def _first_cve(cls_cve, tags, template_id) -> str | None:
    """CVE id from the template classification, then the template id, then tags."""
    return (first_cve(cls_cve) or normalize_cve(template_id or "")
            or first_cve(tags if isinstance(tags, (list, tuple)) else (tags or "")))


class NucleiWrapper(BaseWrapper):
    name = "nuclei"
    binary = "nuclei"
    description = "Template-based vulnerability scanner (4000+ community templates)."
    category = "vuln"
    timeout_seconds = 30 * 60

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        # Out-of-band: nuclei confirms blind SSRF/XXE/RCE via interactsh. By
        # default it uses ProjectDiscovery's free public servers (oast.*); set
        # INTERACTSH_SERVER in .env to point at a self-hosted instance.
        interactsh = os.environ.get("INTERACTSH_SERVER", "").strip()
        cmd = [
            self.binary,
            "-u", target,
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-stats=false",
            "-no-color",
        ]
        # Default severity floor, unless the caller set its own (e.g. an
        # exposures scan also wants info-level).
        if "-severity" not in options and "-s" not in options:
            cmd += ["-severity", "low,medium,high,critical"]
        if interactsh and "-interactsh-server" not in options:
            cmd += ["-interactsh-server", interactsh]
        cmd.extend(options)
        return cmd

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        findings: List[Finding] = []
        for obj in iter_json_lines(stdout):

            info = obj.get("info") or {}
            severity = (info.get("severity") or "info").lower()
            template_id = obj.get("template-id") or obj.get("templateID") or ""
            matched_url = obj.get("matched-at") or obj.get("matched") or target
            tags = info.get("tags")

            # Known-CVE enrichment: a nuclei CVE template is a vetted public PoC.
            # Pull the CVE id + CVSS and attach links to deeper public exploits.
            cls = info.get("classification") or {}
            cve_id = _first_cve(cls.get("cve-id"), tags, template_id)
            cvss = cls.get("cvss-score")
            vclass = _classify(tags, template_id)
            if cve_id and vclass == "multiple":
                vclass = "cve"

            evidence = _evidence(obj)
            if cve_id:
                refs = _refs_text(cve_id)
                if refs:
                    evidence = (evidence + "\n\n" + refs).strip()

            metadata = {
                "template_id": template_id,
                "tags": tags,
                "reference": info.get("reference"),
                "classification": cls,
                "curl_command": obj.get("curl-command"),
                "vuln_class": vclass,
            }
            if cve_id:
                metadata["cve_id"] = cve_id
                metadata["cvss"] = cvss
                metadata["exploit_refs"] = _exploit_refs(cve_id)

            findings.append(
                Finding(
                    severity=severity,
                    title=(f"{cve_id}: {info.get('name')}" if cve_id else
                           (info.get("name") or template_id or "nuclei finding")),
                    description=info.get("description") or "",
                    target=matched_url,
                    evidence=evidence,
                    metadata=metadata,
                )
            )
        return ToolResult(findings=findings)


# Template tag (substring) -> vuln_class. First match wins; order matters
# (more specific before generic).
_TAG_CLASS = [
    (("sqli", "sql-injection", "error-based-sql", "blind-sql"), "sql_injection"),
    (("xss", "rxss", "dom-xss"), "xss"),
    (("ssrf",), "ssrf"),
    (("ssti",), "ssti"),
    (("xxe",), "xxe"),
    (("lfi", "fileinclusion", "file-inclusion", "traversal", "path-traversal"), "lfi"),
    (("rce", "cmdi", "command-injection", "oast-rce"), "command_injection"),
    (("redirect", "open-redirect", "openredirect"), "open_redirect"),
    (("crlf", "http-response-splitting"), "crlf_injection"),
    (("takeover", "subdomain-takeover"), "subdomain_takeover"),
    (("cors",), "cors"),
    (("default-login", "auth-bypass", "auth-bypas", "weak-cred"), "auth"),
    (("exposure", "exposures", "disclosure", "backup", "config"), "exposed_resource"),
    (("ssl", "tls"), "weak_tls"),
    (("wordpress", "wp-plugin", "joomla", "drupal"), "cms_vulnerability"),
    (("cve", "cves", "edb"), "cve"),  # fallback: known CVE with no finer class
]


def _classify(tags, template_id: str) -> str:
    bag = set()
    if isinstance(tags, str):
        bag = {t.strip().lower() for t in tags.split(",") if t.strip()}
    elif isinstance(tags, (list, tuple)):
        bag = {str(t).strip().lower() for t in tags}
    tid = (template_id or "").lower()
    for needles, vclass in _TAG_CLASS:
        if bag.intersection(needles) or any(n in tid for n in needles):
            return vclass
    return "multiple"


def _evidence(obj: dict) -> str:
    bits = []
    for key in ("matcher-name", "extracted-results", "request", "response"):
        val = obj.get(key)
        if val:
            if isinstance(val, list):
                bits.append(f"{key}: {', '.join(str(v) for v in val)}")
            else:
                bits.append(f"{key}: {str(val)[:400]}")
    return "\n".join(bits)
