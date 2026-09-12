"""Vuln-class taxonomy shared by the validator, the runner and the report.

Two things live here because three modules need them and importing them from
`validation.run` would close an import cycle (run -> validator -> run):

  * TOOL_VULN_CLASS - the class to assume when a finding does not carry its
    own `metadata["vuln_class"]`. Every registered wrapper is listed: the
    recon tools used to fall through to "unknown", which sent them down the
    validator's heuristic branch and had them reported as "likely" weaknesses.
  * SURFACE_CLASSES - classes that describe the attack surface instead of a
    weakness. A live host or a server banner cannot be "likely vulnerable".
"""
from __future__ import annotations

from typing import Any, Dict

TOOL_VULN_CLASS: Dict[str, str] = {
    # --- tools that report weaknesses ---
    "sqlmap": "sql_injection",
    "commix": "command_injection",
    "dalfox": "xss",
    "nuclei": "multiple",
    "nikto": "misconfiguration",
    "testssl": "weak_tls",
    "wpscan": "cms_vulnerability",
    "trufflehog": "secret_exposure",
    "retirejs": "vulnerable_component",
    "schemathesis": "api_contract_violation",
    "gitdumper": "source_code_disclosure",
    # --- tools that describe the surface ---
    "httpx": "fingerprint",
    "whatweb": "fingerprint",
    "wafw00f": "fingerprint",
    "nmap": "recon",
    "naabu": "recon",
    "dnsx": "recon",
    "subfinder": "recon",
    "gau": "recon",
    "katana": "recon",
    "arjun": "recon",
    "jsluice": "recon",
    "ffuf": "content_discovery",
}

SURFACE_CLASSES = {"recon", "fingerprint", "content_discovery", "unknown"}

# Classes whose findings are claims about a path existing / being readable.
# These are the ones a catch-all (soft-404) server manufactures by the hundred,
# so they are the ones the baseline check is allowed to discard.
DISCOVERY_CLASSES = {"content_discovery", "information_disclosure",
                     "source_code_disclosure", "exposed_file", "backup_file"}


def vuln_class_of(finding: Any, tool: str) -> str:
    """The finding's own class if it declared one, else the tool's default."""
    meta = getattr(finding, "metadata", None) or {}
    declared = meta.get("vuln_class")
    if declared:
        return str(declared)
    return TOOL_VULN_CLASS.get(tool, "unknown")


def is_surface(vuln_class: str) -> bool:
    return str(vuln_class or "unknown").strip().lower() in SURFACE_CLASSES
