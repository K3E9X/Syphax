"""Run validation over all of an engagement's findings (spec §7).

Pulls every finding produced during the engagement, decides a status with the
FindingValidator (safe-PoC only), and writes the deduplicated, scored set to
validated_findings. Returns a small stats dict including the false-positive
rate so we can track it against the market bar (<3-10%).
"""
from __future__ import annotations

import logging
import time
from typing import Dict

from app import events
from app.engagements import EngagementRepository
from app.scans.storage import JobRepository
from app.validation import corroboration
from app.validation.baseline import calibrate
from app.validation.classes import TOOL_VULN_CLASS, vuln_class_of
from app.validation.models import ValidatedFinding, ValidationStatus
from app.validation.safe_poc import SafePoC
from app.validation.storage import ValidatedFindingRepository, new_vf_id
from app.validation.validator import FindingValidator

logger = logging.getLogger("syphax.validation.run")

# Catalog item id -> vuln_class isn't 1:1 on findings, so we read the finding's
# own metadata/tool. This maps tools to a coarse vuln_class when the finding
# doesn't carry one.
# Re-exported from app.validation.classes, which owns the taxonomy.
_TOOL_VULN_CLASS = TOOL_VULN_CLASS


async def validate_engagement(engagement_id: str) -> Dict[str, int]:
    engagements = EngagementRepository()
    jobs_repo = JobRepository()
    vf_repo = ValidatedFindingRepository()

    engagement = await engagements.get(engagement_id)
    if engagement is None:
        return {"error": 1}

    safe = SafePoC(in_scope=engagement.host_in_scope)

    # One calibration per engagement, before any verdict: ask the target for a
    # couple of paths that cannot exist. If it answers them all with the same
    # page, every "this path exists" finding needs that page ruled out first.
    baseline = await calibrate(safe, engagement.target_url)
    if baseline.catch_all:
        logger.info("[%s] catch-all target: %s", engagement_id, baseline.reason)
        await events.emit(
            engagement_id, events.VALIDATED,
            f"catch-all target detected: {baseline.reason} - path-existence "
            "findings will be re-checked against it",
            level=events.LEVEL_INFO,
        )
    validator = FindingValidator(safe, baseline=baseline)

    jobs = await jobs_repo.list_by_engagement(engagement_id)

    # Deduplicate identical findings (same tool+title+target) before validating
    # so we don't re-prove the same thing many times.
    seen = set()
    validated = []
    for job in jobs:
        for f in job.findings:
            vuln_class = _vuln_class_of(f, job.tool)
            dedup_key = (job.tool, f.title, f.target)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            result = await validator.validate(f, job.tool, vuln_class)
            validated.append(
                ValidatedFinding(
                    id=new_vf_id(),
                    engagement_id=engagement_id,
                    source_job_id=job.id,
                    tool=job.tool,
                    vuln_class=vuln_class,
                    severity=f.severity,
                    title=f.title,
                    target=f.target,
                    status=result.status.value,
                    confidence=result.confidence,
                    method=result.method,
                    poc=result.poc,
                    evidence=f.evidence,
                    created_at=time.time(),
                    metadata=f.metadata or {},
                )
            )
            await events.emit(
                engagement_id, events.VALIDATED,
                f"{result.status.value} [{f.severity}] {f.title} ({result.method})",
                level=events.LEVEL_VERBOSE,
                status=result.status.value, severity=f.severity, tool=job.tool,
            )

    # Findings were judged one at a time above. Now arbitrate them against
    # each other: independent agreement raises confidence, an oracle that
    # disproved the same class at the same target demotes the guesses that
    # claimed it, and a lone unchecked pattern match loses ground.
    adjusted = corroboration.apply(validated)
    if adjusted:
        logger.info("[%s] corroboration adjusted %d finding(s)",
                    engagement_id, adjusted)

    await vf_repo.replace_for_engagement(engagement_id, validated)

    stats = _stats(validated)
    stats["corroborated"] = adjusted
    stats["catch_all_target"] = 1 if baseline.catch_all else 0
    logger.info("[%s] validated %d findings: %s", engagement_id, len(validated), stats)
    return stats


def _vuln_class_of(finding, tool: str) -> str:
    return vuln_class_of(finding, tool)


def _stats(validated) -> Dict[str, int]:
    out = {s.value: 0 for s in ValidationStatus}
    out["total"] = len(validated)
    for v in validated:
        out[v.status] = out.get(v.status, 0) + 1
    confirmed_or_likely = out.get("confirmed", 0) + out.get("likely", 0)
    fp = out.get("false_positive", 0)
    denom = confirmed_or_likely + fp
    out["false_positive_rate_pct"] = round((fp / denom) * 100, 1) if denom else 0
    return out
