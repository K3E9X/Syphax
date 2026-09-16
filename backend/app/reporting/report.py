"""Client-facing report builder (spec §11 screen 4, §13.7).

Deterministic assembly of a Markdown report (and a printable HTML view) from
the engagement's validated findings, kill-chains and coverage - mapped to
OWASP WSTG / MITRE ATT&CK / CWE. No LLM needed: the report only restates
confirmed/likely evidence, so it is reproducible and never invents findings.
"""
from __future__ import annotations

import html
import time
from typing import Any, Dict, List

from app.engagements import EngagementRepository
from app.orchestrator.state import EngagementState
from app.reporting.mappings import CATEGORY_LABELS, for_class
from app.scans.storage import JobRepository
from app.validation import ChainRepository, ValidatedFindingRepository
from app.validation.classes import SURFACE_CLASSES
from app.validation.corroboration import is_oracle

_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}


async def build_report(engagement_id: str) -> Dict[str, Any]:
    engagements = EngagementRepository()
    vf_repo = ValidatedFindingRepository()
    chain_repo = ChainRepository()
    jobs_repo = JobRepository()
    state = EngagementState(engagement_id)

    e = await engagements.get(engagement_id)
    if e is None:
        raise KeyError("engagement not found")

    findings = await vf_repo.list(engagement_id)
    # Report only what we stand behind.
    reportable = [f for f in findings
                  if f.status in ("confirmed", "likely") and is_reportable(f)]
    chains = await chain_repo.list(engagement_id)
    jobs = await jobs_repo.list_by_engagement(engagement_id)
    tools_used = sorted({j.tool for j in jobs})
    hosts = await state.assets("host")
    tech = await state.technologies()
    cov = await state.coverage_summary()
    vsum = await vf_repo.summary(engagement_id)

    overall = _overall_risk(reportable)
    proof = partition_by_proof(reportable)

    # The same limits the live console reported, from the same function, so the
    # report cannot claim a thoroughness the run did not have.
    from app.scans.artifacts import js_dir, listdir
    from app.validation.limits import limits_for, unverified_classes_of
    try:
        limits = limits_for(
            allow_active_exploit=bool(getattr(e, "allow_active_exploit", False)),
            unverified_classes=unverified_classes_of(findings),
            captured_js_files=len(listdir(js_dir(e.target_url), limit=1)),
        )
    except Exception:  # noqa: BLE001 - a report must still render
        limits = []

    md = _markdown(e, reportable, chains, tools_used, hosts, tech, cov, vsum,
                   overall, limits)
    return {
        "markdown": md,
        "html": _html(md),
        "meta": {
            "overall_risk": overall,
            "reportable_findings": len(reportable),
            "proven_findings": len(proof["proven"]),
            "unverified_findings": len(proof["unverified"]),
            "verification_limits": [l.to_public() for l in limits],
            "chains": len(chains),
            "false_positive_rate_pct": false_positive_rate(vsum),
        },
    }


def false_positive_rate(vsum: Dict[str, Any]) -> float:
    """False-positive rate from the status counts.

    `ValidatedFindingRepository.summary()` returns only {status: count}; the rate
    computed in validation/run.py is not persisted. Reading a key nobody sets
    made every report claim 0%, so derive it here from what summary() does give.
    """
    confirmed = int(vsum.get("confirmed", 0) or 0)
    likely = int(vsum.get("likely", 0) or 0)
    fp = int(vsum.get("false_positive", 0) or 0)
    denom = confirmed + likely + fp
    return round((fp / denom) * 100, 1) if denom else 0.0


def _overall_risk(findings: List) -> str:
    if any(f.severity == "critical" for f in findings):
        return "Critical"
    if any(f.severity == "high" for f in findings):
        return "High"
    if any(f.severity == "medium" for f in findings):
        return "Medium"
    if findings:
        return "Low"
    return "Informational"


# Classes that describe the surface rather than a weakness. They belong in the
# recon appendix, not in section 3 next to a critical. Owned by
# app.validation.classes so the validator and the report agree on the set.
_RECON_CLASSES = SURFACE_CLASSES


def is_reportable(finding) -> bool:
    """Does this finding belong in the client-facing findings section?

    Without this, "Technology: nginx" and "Live host: ..." were listed as
    findings: the heuristic branch of the validator marks every unmapped recon
    line `likely`, and nothing downstream filtered on severity.
    """
    sev = norm_severity(getattr(finding, "severity", None))
    if sev == "info":
        return False
    return norm_severity_class(getattr(finding, "vuln_class", None)) not in _RECON_CLASSES


def is_proven(finding) -> bool:
    """Did an oracle decide this, or did a scanner pattern match it?

    A finding an oracle confirmed (an active tool oracle, a safe re-fetch that
    saw the expected content, a benign marker reflected, an adaptive probe with
    a baseline, a replayed stored proof) and a finding nothing re-checked used
    to be printed identically, side by side, in the same list. The reader had
    no way to tell "we proved this" from "a scanner said so". They are now two
    sections.
    """
    if norm_severity_class(getattr(finding, "status", None)) != "confirmed":
        return False
    return is_oracle(getattr(finding, "method", "") or "")


def partition_by_proof(findings: List) -> Dict[str, List]:
    """Split the reportable set into what we proved and what we did not."""
    proven, unverified = [], []
    for f in findings:
        (proven if is_proven(f) else unverified).append(f)
    return {"proven": proven, "unverified": unverified}


def norm_severity(value) -> str:
    """Fold an arbitrary severity onto the five known levels.

    _by_severity used to bucket an unknown severity under its own key while
    _markdown only iterated the known five, so a finding with "Critical" or
    "warning" was counted but never printed."""
    sev = str(value or "info").strip().lower()
    return sev if sev in _SEV_RANK else "info"


def norm_severity_class(value) -> str:
    return str(value or "unknown").strip().lower()


def _by_severity(findings: List) -> Dict[str, List]:
    out: Dict[str, List] = {s: [] for s in _SEV_ORDER}
    for f in findings:
        out[norm_severity(getattr(f, "severity", None))].append(f)
    return out


def _markdown(e, findings, chains, tools, hosts, tech, cov, vsum, overall,
              limits=()) -> str:
    L: List[str] = []
    ts = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    L.append("# Penetration Test Report")
    L.append("")
    L.append(f"**Target:** {e.target_url}  ")
    L.append(f"**Engagement:** {e.id}  ")
    L.append(f"**Generated:** {ts}  ")
    L.append(f"**Overall risk:** {overall}")
    L.append("")

    # 1. Executive summary
    L.append("## 1. Executive Summary")
    L.append("")
    counts = {s: len(v) for s, v in _by_severity(findings).items()}
    L.append(
        f"This assessment of `{e.target_host}` identified **{len(findings)} "
        f"validated finding(s)** (overall risk: **{overall}**): "
        + ", ".join(f"{counts[s]} {s}" for s in _SEV_ORDER if counts[s]) + "."
        if findings else
        "No findings could be validated for this engagement."
    )
    L.append("")
    proof = partition_by_proof(findings)
    L.append(
        f"**{len(proof['proven'])} finding(s) were proven** with a safe "
        f"proof-of-exploit reproduced against the target (section 3); "
        f"{len(proof['unverified'])} were reported by a scanner but could not be "
        f"independently verified (section 4). Validation discarded "
        f"{vsum.get('false_positive', 0)} false positive(s) "
        f"(FP rate {false_positive_rate(vsum)}%)."
    )
    L.append("")

    # 2. Scope & methodology
    L.append("## 2. Scope and Methodology")
    L.append("")
    L.append(f"- **In-scope hosts:** {', '.join(e.scope_hosts)}")
    L.append(f"- **Hosts assessed:** {', '.join(h.value for h in hosts) or e.target_host}")
    if tech:
        L.append(f"- **Technologies identified:** {', '.join(tech)}")
    L.append(f"- **Tools used:** {', '.join(tools) or 'n/a'}")
    # The operator's declaration about what the client authorized beyond
    # read-only proof. It belongs in the report for the same reason it is in
    # the audit log: six months later this is the line that answers "were you
    # allowed to do that?", and the absence of the line answers it too.
    try:
        from app.exploit.capabilities import summary as _capability_summary
        L.append(f"- **Authorization:** "
                 f"{_capability_summary(getattr(e, 'exploit_capabilities', []) or [])}")
    except Exception:  # noqa: BLE001 - a report must still render
        pass
    L.append(f"- **Coverage:** {cov.get('done', 0)} catalog test(s) completed.")
    L.append("- **Methodology:** OWASP WSTG, mapped to MITRE ATT&CK. Every "
             "finding is put to an oracle where one exists; findings no oracle "
             "could decide are reported separately (section 4) rather than "
             "presented as established.")
    L.append("")

    # 3./4. Findings, split by whether an oracle decided them. Printing a
    # safe-PoC confirmation and an unchecked scanner pattern in the same list
    # gave the reader no way to tell them apart.
    split = partition_by_proof(findings)
    L.append("## 3. Proven Findings")
    L.append("")
    if not split["proven"]:
        L.append("_Nothing could be proven with a safe proof-of-exploit._")
        L.append("")
    else:
        L.append(f"{len(split['proven'])} finding(s) reproduced against the target: "
                 "an active tool oracle, a safe re-fetch that returned the expected "
                 "content, a benign marker reflected back, or an adaptive probe "
                 "measured against a baseline. Each carries its proof below.")
        L.append("")
        _render_findings(L, split["proven"])

    L.append("## 4. Unverified Findings")
    L.append("")
    if not split["unverified"]:
        L.append("_Every reported finding was proven._")
        L.append("")
    else:
        L.append(f"{len(split['unverified'])} finding(s) reported by a scanner that "
                 "no oracle could decide. They are real patterns, but nothing "
                 "re-checked them against the target: treat them as leads for "
                 "manual confirmation, not as established issues.")
        L.append("")
        # Why they are unverified. Without this the section reads as "the tool
        # could not tell", when the honest answer is often "it was not allowed
        # to try" - a distinction the reader has to have to judge the report.
        if limits:
            L.append("**This assessment verified less than it could have:**")
            L.append("")
            for limit in limits:
                L.append(f"- {limit.sentence}")
            L.append("")
        _render_findings(L, split["unverified"])

    # 5. Kill-chains
    L.append("## 5. Attack Chains")
    L.append("")
    if not chains:
        L.append("_No multi-step attack chains identified._")
        L.append("")
    else:
        for c in chains:
            L.append(f"### {c['title']} ({c.get('severity', 'medium')})")
            L.append("")
            if c.get("summary"):
                L.append(c["summary"])
                L.append("")
            for i, step in enumerate(c.get("steps", []), 1):
                reason = f" — {step['reason']}" if step.get("reason") else ""
                L.append(f"{i}. **{step.get('action','')}**{reason}")
            L.append("")

    # 6. Remediation priority
    L.append("## 6. Remediation Priority")
    L.append("")
    # Proven before unproven at equal severity: a reproduced medium is more
    # actionable than a scanner's unchecked high.
    ordered = sorted(findings, key=lambda f: (_SEV_RANK.get(f.severity, 9),
                                              0 if is_proven(f) else 1,
                                              -f.confidence))
    if ordered:
        for i, f in enumerate(ordered[:15], 1):
            L.append(f"{i}. [{f.severity}] {f.title} — `{f.target}`")
    else:
        L.append("_Nothing to remediate._")
    L.append("")

    # 7. Appendix
    L.append("## 7. Appendix")
    L.append("")
    L.append(f"- Tools: {', '.join(tools) or 'n/a'}")
    L.append("- Limitations: automated assessment with human-validated findings; "
             "business-logic flaws may require additional manual testing.")
    L.append("- Validation policy: safe proof-of-exploit only (read-only / benign "
             "markers / out-of-band); no destructive actions were performed.")
    L.append("")
    return "\n".join(L)


def _render_findings(L: List[str], findings: List) -> None:
    """One findings block, grouped by severity. Used by both sections."""
    bysev = _by_severity(findings)
    for sev in _SEV_ORDER:
        group = bysev.get(sev) or []
        if not group:
            continue
        L.append(f"### {sev.capitalize()} ({len(group)})")
        L.append("")
        for f in group:
            m = for_class(f.vuln_class)
            cat = CATEGORY_LABELS.get(m.get("category", "other"), "Other")
            L.append(f"#### {f.title}")
            L.append("")
            L.append(f"- **Severity:** {f.severity}")
            L.append(f"- **Category:** {cat}")
            L.append(f"- **Status:** {f.status} (confidence {int(f.confidence*100)}%)")
            L.append(f"- **Affected:** `{f.target}`")
            L.append(f"- **Tool / method:** {f.tool} / {f.method}")
            L.append(f"- **WSTG:** {m['wstg']} · **ATT&CK:** {', '.join(m['attack'])} · **CWE:** {m['cwe']}")
            corr = (getattr(f, "metadata", None) or {}).get("corroboration") or {}
            if corr.get("note"):
                L.append(f"- **Corroboration:** {corr['note']}")
            if f.poc:
                L.append("")
                L.append("**Proof of exploit:**" if is_proven(f) else "**Evidence:**")
                L.append("")
                L.append("```")
                L.append(f.poc.strip()[:1500])
                L.append("```")
            L.append("")
            L.append(f"**Remediation:** {m['remediation']}")
            L.append("")


def _html(markdown: str) -> str:
    """Minimal self-contained HTML wrapper so the operator can 'Print to PDF'.
    We don't pull a Markdown engine into the image; the report reads fine as
    monospaced preformatted text with print-friendly CSS."""
    body = html.escape(markdown)
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Penetration Test Report</title>"
        "<style>"
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:880px;"
        "margin:40px auto;padding:0 20px;color:#111;line-height:1.5}"
        "pre{white-space:pre-wrap;word-break:break-word;font-family:ui-monospace,"
        "Menlo,Consolas,monospace;font-size:13px}"
        "@media print{body{margin:0}}"
        "</style></head><body><pre>" + body + "</pre></body></html>"
    )
