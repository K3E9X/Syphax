"""Diff two engagements' validated findings.

A single run answers "what is wrong today". Comparing two answers the question
an operator actually asks on a retest: what did we fix, what came back, and
what is new since last time. All the data is already in validated_findings, so
this is pure comparison - no new capture, no new scan.

Identity is the hard part. Ids are per-run, so a finding is matched on what
makes it the same issue: its class, the endpoint it lives on (path only - a
query string changes between runs) and its title.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Tuple
from urllib.parse import urlparse

# Statuses that mean "this is a live issue". A false positive or an unconfirmed
# guess is not something you fixed, and not something you regressed on.
OPEN_STATUSES = frozenset({"confirmed", "likely"})

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def finding_key(finding: Any) -> Tuple[str, str, str]:
    """Stable identity across runs: (class, endpoint path, title).

    The query string is deliberately dropped - ?id=1 vs ?id=7 is the same issue
    on the same endpoint, and keeping it would report every retest as all-new.
    """
    def g(name: str) -> str:
        value = finding.get(name) if isinstance(finding, dict) else getattr(finding, name, "")
        return str(value or "").strip()

    target = g("target")
    path = urlparse(target).path or target if target else ""
    return (g("vuln_class").lower(), path.lower().rstrip("/"), g("title").lower())


def _is_open(finding: Any) -> bool:
    status = finding.get("status") if isinstance(finding, dict) else getattr(finding, "status", "")
    return str(status or "").lower() in OPEN_STATUSES


def _sev(finding: Any) -> str:
    value = finding.get("severity") if isinstance(finding, dict) else getattr(finding, "severity", "")
    sev = str(value or "info").lower()
    return sev if sev in _SEV_RANK else "info"


def _public(finding: Any) -> Dict[str, Any]:
    if isinstance(finding, dict):
        return finding
    return finding.to_public() if hasattr(finding, "to_public") else {"title": str(finding)}


@dataclass
class Diff:
    new: List[Dict[str, Any]] = field(default_factory=list)
    fixed: List[Dict[str, Any]] = field(default_factory=list)
    unchanged: List[Dict[str, Any]] = field(default_factory=list)
    worsened: List[Dict[str, Any]] = field(default_factory=list)
    improved: List[Dict[str, Any]] = field(default_factory=list)

    def to_public(self) -> Dict[str, Any]:
        return {
            "counts": {
                "new": len(self.new), "fixed": len(self.fixed),
                "unchanged": len(self.unchanged),
                "worsened": len(self.worsened), "improved": len(self.improved),
            },
            "new": self.new, "fixed": self.fixed, "unchanged": self.unchanged,
            "worsened": self.worsened, "improved": self.improved,
            "summary": self.summary(),
        }

    def summary(self) -> str:
        if not any((self.new, self.fixed, self.unchanged, self.worsened, self.improved)):
            return "Nothing to compare: neither engagement has open findings."
        parts = [f"{len(self.new)} new", f"{len(self.fixed)} fixed",
                 f"{len(self.unchanged)} still open"]
        if self.worsened:
            parts.append(f"{len(self.worsened)} worse")
        if self.improved:
            parts.append(f"{len(self.improved)} less severe")
        return ", ".join(parts) + "."


def diff_findings(previous: Iterable[Any], current: Iterable[Any]) -> Diff:
    """Compare two sets of validated findings.

    Only open findings are compared: a finding the judge marked false_positive
    was never real, so it is neither a fix nor a regression.
    """
    before = {finding_key(f): f for f in previous if _is_open(f)}
    after = {finding_key(f): f for f in current if _is_open(f)}

    out = Diff()
    for key, finding in after.items():
        was = before.get(key)
        if was is None:
            out.new.append(_public(finding))
            continue
        now_rank, was_rank = _SEV_RANK[_sev(finding)], _SEV_RANK[_sev(was)]
        entry = dict(_public(finding))
        if now_rank < was_rank:                 # lower rank = more severe
            entry["previous_severity"] = _sev(was)
            out.worsened.append(entry)
        elif now_rank > was_rank:
            entry["previous_severity"] = _sev(was)
            out.improved.append(entry)
        else:
            out.unchanged.append(entry)

    for key, finding in before.items():
        if key not in after:
            out.fixed.append(_public(finding))

    order = lambda f: (_SEV_RANK.get(str(f.get("severity", "info")).lower(), 4),
                       str(f.get("title", "")))
    for bucket in (out.new, out.fixed, out.unchanged, out.worsened, out.improved):
        bucket.sort(key=order)
    return out
