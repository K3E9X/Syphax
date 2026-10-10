"""Structured report exporters (JSON + SARIF 2.1.0). Pure + unit-testable."""
from __future__ import annotations

from typing import Any, Dict, List

from app.reporting.mappings import category_for_class, for_class

_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def findings_json(engagement, findings, chains) -> Dict[str, Any]:
    out_findings: List[Dict[str, Any]] = []
    for f in findings:
        m = for_class(f.vuln_class)
        out_findings.append({
            "id": f.id, "severity": f.severity, "title": f.title, "target": f.target,
            "vuln_class": f.vuln_class, "category": category_for_class(f.vuln_class),
            "tool": f.tool, "status": f.status, "confidence": f.confidence,
            "method": f.method, "evidence": f.evidence, "poc": f.poc,
            "cwe": m["cwe"], "wstg": m["wstg"], "attack": m["attack"],
            "owasp_api": m.get("owasp_api", ""),
            "remediation": m["remediation"],
        })
    return {
        "engagement": {"id": engagement.id, "target_url": engagement.target_url,
                       "scope_hosts": engagement.scope_hosts},
        "findings": out_findings,
        "chains": chains,
    }


def sarif(engagement, findings) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []
    for f in findings:
        m = for_class(f.vuln_class)
        rule_id = f.vuln_class or "finding"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f.title},
                "properties": {"cwe": m["cwe"], "wstg": m["wstg"],
                               "attack": m["attack"],
                               "owasp_api": m.get("owasp_api", "")},
            }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get((f.severity or "info").lower(), "note"),
            "message": {"text": f"{f.title} ({f.status}, {f.tool})"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.target}}}],
            "properties": {"severity": f.severity, "confidence": f.confidence,
                           "poc": f.poc[:1000] if f.poc else ""},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "syphax",
                "informationUri": "https://github.com/K3E9X/Syphax",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
