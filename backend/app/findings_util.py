"""Pure helpers for the global findings view (no web framework imports, so they
stay unit-testable): dedup key, CVSS estimate, HackerOne-format export."""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

TRIAGE_STATUSES = {"new", "triaged", "confirmed", "reported", "false_positive"}
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.1, "info": 1.0}


def dedup(vuln_class: str, target: str) -> str:
    return hashlib.sha1(f"{vuln_class}|{target}".encode()).hexdigest()[:16]


def cvss_for(severity: str) -> float:
    """The severity band expressed on the 0-10 scale. NOT a CVSS score.

    Kept because the report and the export still want a number per severity,
    but it is the BASE of a score, not the score - see score_for.
    """
    return CVSS.get((severity or "info").lower(), 1.0)


# How much a verdict is worth multiplying the impact band by.
#
# An unproven critical and a proven one scored identically, which is backwards
# for the only thing this number is used for: deciding what to look at first.
# A medium somebody demonstrated is a better use of the next hour than a
# critical a scanner guessed at.
_STATUS_FACTOR = {
    "confirmed": 1.0,
    "likely": 0.75,
    "unconfirmed": 0.5,
    "false_positive": 0.0,
}


def score_for(finding) -> Dict[str, Any]:
    """The number shown next to a finding, and where it came from.

    Two bases, and the difference is worth showing rather than hiding:

      * "cvss" - a real score published for the CVE. nuclei carries it in its
        template classification and the wrapper already stores it in
        metadata["cvss"]; it was then thrown away, and a severity-to-constant
        lookup was displayed in its place AND LABELLED CVSS. That is a false
        claim in a document a client reads.
      * "risk" - derived here, from the impact band and how well the finding
        is established. Labelled as derived, because it is.

    `finding` may be a ValidatedFinding or any object with .severity, .status
    and .metadata.
    """
    meta = getattr(finding, "metadata", None) or {}
    severity = str(getattr(finding, "severity", "") or "info").lower()
    status = str(getattr(finding, "status", "") or "").lower()

    published = _as_score(meta.get("cvss"))
    if published is not None:
        return {"value": published, "basis": "cvss",
                "explain": f"published CVSS score for this issue ({published})"}

    base = cvss_for(severity)
    factor = _STATUS_FACTOR.get(status, 0.6)
    value = round(base * factor, 1)

    # Proof outranks the band it was found in: a finding a PoC demonstrated is
    # certain, whatever a scanner called it.
    if meta.get("proven") or status == "confirmed":
        value = max(value, round(base, 1))

    explain = (f"{severity} impact ({base}) x {status or 'unrated'} "
               f"({factor:g})")
    if meta.get("proven"):
        explain += ", raised because a PoC demonstrated it"
    return {"value": value, "basis": "risk", "explain": explain}


def _as_score(raw) -> Optional[float]:
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return round(value, 1) if 0.0 <= value <= 10.0 else None


def h1_markdown(f, mapping: Dict[str, Any], cvss: float) -> str:
    """HackerOne-style report markdown for a single validated finding."""
    L: List[str] = []
    L.append(f"# {f.title}")
    L.append("")
    L.append(f"**Severity:** {f.severity} (CVSS ~{cvss})  ")
    L.append(f"**Asset:** `{f.target}`  ")
    L.append(f"**Weakness:** {mapping['cwe']} / {mapping['wstg']} / {', '.join(mapping['attack'])}")
    L.append("")
    L.append("## Summary")
    L.append((f.metadata or {}).get("description") or f.title)
    L.append("")
    L.append("## Steps To Reproduce")
    L.append("```")
    L.append((f.poc or f.evidence or "(see evidence)").strip()[:2000])
    L.append("```")
    if f.evidence and f.evidence != f.poc:
        L.append("")
        L.append("## Evidence")
        L.append("```")
        L.append(f.evidence.strip()[:2000])
        L.append("```")
    L.append("")
    L.append("## Impact")
    L.append(f"Confirmed by syphax ({f.tool}, status: {f.status}). " + (mapping.get("remediation") or ""))
    L.append("")
    L.append("## Remediation")
    L.append(mapping.get("remediation") or "Apply standard hardening for this class.")
    return "\n".join(L)
