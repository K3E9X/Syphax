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
from app.validation.storage import ValidatedFindingRepository, stable_vf_id
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
                    # Stable across re-validations: see stable_vf_id. A fresh
                    # random id here renamed every row on every re-validation
                    # and orphaned every staged PoC pointing at one.
                    id=stable_vf_id(engagement_id, job.tool, f.title, f.target),
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

    # Proof obtained by RUNNING something must survive re-validation.
    #
    # replace_for_engagement is a DELETE + INSERT: it rebuilds every row from
    # the raw job findings, which know nothing about a PoC that was executed
    # afterwards. So a finding proven by a sandbox run - its "confirmed"
    # verdict AND the PoC output attached to it - was destroyed the next time
    # anyone pressed "Re-validate" or "Retest", silently reverting to
    # "likely/unverified". Carry it across, matched on the dedup key, because
    # the row ids are reassigned here.
    await _carry_over_proof(vf_repo, engagement_id, validated)

    # Ids are stable now, so a PoC staged against a finding keeps pointing at
    # it. Rows written before that change still carry a random id, and so does
    # any finding whose title a tool reworded between runs - repoint those
    # rather than leaving a PoC attached to a row about to be deleted.
    await _repoint_staged_pocs(vf_repo, engagement_id, validated)

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


async def _carry_over_proof(vf_repo, engagement_id: str, validated: list) -> int:
    """Re-attach execution proof to the rebuilt rows, keyed by dedup.

    Only ever UPGRADES: a finding that a PoC proved stays confirmed, and the
    evidence of how goes with it. Nothing here can demote a fresh verdict.
    """
    from app.findings_util import dedup as _dedup

    try:
        previous = await vf_repo.list(engagement_id)
    except Exception:  # noqa: BLE001 - a first run has nothing to carry
        return 0

    proofs = {}
    for old in previous:
        meta = old.metadata or {}
        if meta.get("exploitation") or meta.get("repro") or meta.get("proven"):
            proofs[_dedup(old.vuln_class, old.target)] = (old, meta)

    carried = 0
    for vf in validated:
        key = _dedup(vf.vuln_class, vf.target)
        found = proofs.get(key)
        if not found:
            continue
        old, meta = found
        for field in ("exploitation", "repro", "proven", "proof_replay"):
            if meta.get(field) is not None and vf.metadata.get(field) is None:
                vf.metadata[field] = meta[field]
        # It was proven by execution: that outranks anything re-derived from a
        # scanner's output, so the verdict comes back with it.
        if str(old.status).lower() == "confirmed":
            vf.status = old.status
            vf.confidence = max(float(vf.confidence or 0), float(old.confidence or 0))
            vf.method = old.method or vf.method
        carried += 1

    if carried:
        logger.info("[%s] carried execution proof across re-validation for "
                    "%d finding(s)", engagement_id, carried)
    return carried


async def _repoint_staged_pocs(vf_repo, engagement_id: str, validated: list) -> int:
    """Follow a finding's id change with the PoCs staged against it.

    A staged PoC holds finding_id. Before stable_vf_id every re-validation
    reassigned those ids, so the reference dangled and a clean run of that PoC
    confirmed nothing - in silence. This closes the two remaining ways it can
    still dangle: a row created before the ids became stable, and a finding
    whose title a tool reworded between runs (the title is part of the
    identity, so the id legitimately changes).

    Matched on the dedup key rather than the identity, because that is the
    coarser of the two: it survives a reworded title.
    """
    from app.findings_util import dedup as _dedup
    from app.sandbox.staging import StagedPoCRepository

    try:
        previous = await vf_repo.list(engagement_id)
    except Exception:  # noqa: BLE001 - a first run has nothing to repoint
        return 0

    fresh_by_key = {_dedup(vf.vuln_class, vf.target): vf.id for vf in validated}
    mapping = {}
    for old in previous:
        new_id = fresh_by_key.get(_dedup(old.vuln_class, old.target))
        if new_id and new_id != old.id:
            mapping[old.id] = new_id
    if not mapping:
        return 0

    try:
        moved = await StagedPoCRepository().repoint_findings(engagement_id, mapping)
    except Exception:  # noqa: BLE001 - never fail validation on a repair
        logger.exception("[%s] could not repoint staged PoCs", engagement_id)
        return 0
    if moved:
        logger.info("[%s] repointed %d staged PoC(s) at their finding's new id",
                    engagement_id, moved)
    return moved
