"""LLM finding judge (intelligence layer #3): false-positive reduction.

A second opinion that reads a finding WITH its evidence (the request/response /
tool output already captured) and rules confirmed / likely / unconfirmed /
false_positive, with a reason. This is where a model adds judgment the
mechanical validator can't.

Guardrails:
  * It only ever runs on the deterministic verdict as a base; the safe-PoC
    validation already happened.
  * It may DOWNGRADE freely (skepticism is safe).
  * It may UPGRADE to "confirmed" only if it cites a quote that is actually
    present in the finding's evidence (anti-hallucination); otherwise the
    upgrade is capped at "likely".
  * No LLM configured -> no-op. One bounded pass over the high-value findings.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from app.llm import ROLE_VALIDATOR, LLMError, get_router
from app.llm.grounding import (clamp_confidence, extract_json, norm_status,
                               quote_is_grounded)
from app.validation.storage import ValidatedFindingRepository

logger = logging.getLogger("syphax.validation.llm_judge")

MAX_JUDGE = 40
_JUDGEABLE_STATUS = {"likely", "unconfirmed"}
_JUDGEABLE_SEV = {"critical", "high", "medium"}

_SYSTEM = (
    "You are a meticulous penetration-test reviewer killing false positives. "
    "Given one finding and its evidence, decide if it is a real, exploitable "
    "issue. Be skeptical: scanners over-report. Rule on the EVIDENCE ONLY. "
    "If you rule 'confirmed', you MUST copy an exact substring from the evidence "
    "into 'quote' that proves it (verified; an invented quote downgrades you to "
    "'likely'). "
    "Also propose a PROOF: a single read-only request that would settle the "
    "question on a replay, and the exact substring whose presence in the "
    "response confirms the finding. The proof must be GET or HEAD only, on the "
    "finding's own host, and must not change any state - no writes, no "
    "destructive parameters, no authentication attempts. If no such read-only "
    "check exists, return an empty proof rather than inventing one. "
    "Reply JSON only: {\"verdict\":\"confirmed|likely|unconfirmed|"
    "false_positive\",\"confidence\":0.0-1.0,\"quote\":\"<exact substring or "
    "empty>\",\"reason\":\"<short>\",\"proof\":{\"method\":\"GET|HEAD\","
    "\"url\":\"<absolute url on the finding host>\",\"expect\":\"<substring "
    "proving it>\",\"why\":\"<short>\"}}."
)

# The proof is replayed against a live target, so the policy is the narrow one:
# same host as the finding, read-only verb, and nothing that looks like a write.
PROOF_METHODS = {"GET", "HEAD"}

# Query keys that mutate state on a GET often enough to be worth refusing.
_MUTATING_HINTS = (
    "delete", "remove", "drop", "destroy", "truncate", "reset", "revoke",
    "disable", "deactivate", "shutdown", "logout", "signout", "purge",
)


async def judge_engagement(engagement_id: str) -> Dict[str, int]:
    client = get_router().get(ROLE_VALIDATOR)
    if not client.configured:
        return {"skipped": 1, "reason": "no LLM configured"}

    # The engagement's scope predicate, so a proposed proof can be replayed live
    # against the target. A read-only GET/HEAD in scope - the same thing the
    # oracles already do in this phase - is what turns the model's suggestion
    # into a mechanical confirmation.
    from app.engagements import EngagementRepository
    from app.validation.proof_replay import replay_proof
    eng = await EngagementRepository().get(engagement_id)
    in_scope = eng.host_in_scope if eng is not None else None

    repo = ValidatedFindingRepository()
    findings = await repo.list(engagement_id)
    judged = downgraded = upgraded = proposed = 0
    confirmed_by_replay = refuted_by_replay = 0
    for vf in findings:
        if judged >= MAX_JUDGE:
            break
        if vf.status not in _JUDGEABLE_STATUS or (vf.severity or "").lower() not in _JUDGEABLE_SEV:
            continue
        if not (vf.evidence or "").strip():
            continue
        try:
            raw = await client.chat(
                [{"role": "system", "content": _SYSTEM},
                 {"role": "user", "content": _user_prompt(vf)}],
                temperature=0.0, max_tokens=400,
            )
        except LLMError as exc:
            logger.warning("[%s] judge unavailable: %s", engagement_id, exc)
            break
        j = parse_judgment(raw)
        if j is None:
            continue
        judged += 1

        # A verdict tells you what the model thinks; a proof lets a human check
        # it. Stored whatever the verdict, including on a false positive, where
        # "here is the request that shows it is not there" is just as useful.
        proof = parse_proof(j.get("proof"), vf.target)
        proof_outcome = None
        if proof:
            try:
                await repo.set_metadata(vf.id, {"suggested_proof": proof})
                proposed += 1
            except Exception:  # noqa: BLE001 - a proof is a bonus, never fatal
                logger.exception("[%s] could not store proof for %s",
                                 engagement_id, vf.id)
            # Replay it live. This is the only thing that can raise a finding to
            # 'confirmed'; the model's word never does that on its own. Never
            # fatal - a target problem leaves proof_outcome None, which caps the
            # verdict at 'likely' rather than crashing the pass.
            if in_scope is not None:
                try:
                    rp = await replay_proof(proof, in_scope)
                    proof_outcome = rp.get("outcome")
                    await repo.set_metadata(vf.id, {"proof_replay": rp})
                    if proof_outcome == "held":
                        confirmed_by_replay += 1
                    elif proof_outcome == "did_not_hold":
                        refuted_by_replay += 1
                except Exception:  # noqa: BLE001 - a replay problem is not fatal
                    logger.warning("[%s] proof replay failed for %s",
                                   engagement_id, vf.id)

        status, conf = reconcile(vf.status, vf.confidence, j, vf.evidence,
                                 proof_outcome=proof_outcome)
        if status == vf.status and abs(conf - vf.confidence) < 0.01:
            continue
        if _rank(status) > _rank(vf.status):
            downgraded += 1
        elif _rank(status) < _rank(vf.status):
            upgraded += 1
        await repo.update_verdict(vf.id, status=status, confidence=conf,
                                  method=f"{vf.method} + LLM judge")
    logger.info("[%s] llm-judge: judged=%d upgraded=%d downgraded=%d proofs=%d "
                "confirmed_by_replay=%d refuted_by_replay=%d",
                engagement_id, judged, upgraded, downgraded, proposed,
                confirmed_by_replay, refuted_by_replay)
    return {"judged": judged, "upgraded": upgraded, "downgraded": downgraded,
            "proofs_proposed": proposed,
            "confirmed_by_replay": confirmed_by_replay,
            "refuted_by_replay": refuted_by_replay}


# --------------------------------------------------------------------------- #
# Pure core (unit-tested)

_RANK = {"confirmed": 0, "likely": 1, "unconfirmed": 2, "false_positive": 3}


def _rank(status: str) -> int:
    return _RANK.get(status, 1)


def _user_prompt(vf) -> str:
    return (f"Finding: {vf.title}\nClass: {vf.vuln_class}\nSeverity: {vf.severity}\n"
            f"Reported status: {vf.status}\nTarget: {vf.target}\n\nEvidence:\n"
            f"{(vf.evidence or '')[:4000]}")


def parse_judgment(raw: str) -> Optional[Dict]:
    obj = extract_json(raw)
    if not isinstance(obj, dict) or "verdict" not in obj:
        return None
    return {
        "verdict": norm_status(obj.get("verdict")),
        "confidence": clamp_confidence(obj.get("confidence"), 0.5),
        "quote": str(obj.get("quote", "")),
        "reason": str(obj.get("reason", ""))[:300],
        "proof": obj.get("proof"),
    }


def parse_proof(raw: Any, target: str) -> Optional[Dict[str, str]]:
    """Validate a proposed proof before it is ever replayed.

    A proof is a request this tool will actually send, so it is checked the way
    an operator-supplied one would be: read-only verb, same host as the finding,
    a non-trivial expectation, and no query key that reads like a write.
    Anything questionable is rejected outright - a proof that needs
    interpretation is not a proof.
    """
    if not isinstance(raw, dict):
        return None

    method = str(raw.get("method") or "").strip().upper()
    if method not in PROOF_METHODS:
        return None

    url = str(raw.get("url") or "").strip()
    if not url:
        return None
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None

    # Same host as the finding. A proof pointing elsewhere is out of scope by
    # construction, and SafePoC would reject it anyway - fail early and loudly.
    target_host = (urlparse(target).hostname or target or "").strip().lower()
    if target_host and parsed.hostname.lower() != target_host:
        return None

    haystack = f"{parsed.path} {parsed.query}".lower()
    if any(hint in haystack for hint in _MUTATING_HINTS):
        return None

    # An expectation short enough to match anything proves nothing.
    expect = str(raw.get("expect") or "").strip()
    if len(expect) < 4:
        return None

    return {
        "method": method,
        "url": url,
        "expect": expect[:200],
        "why": str(raw.get("why") or "").strip()[:200],
    }


def reconcile(base_status: str, base_conf: float, judgment: Dict,
              evidence: str, *, proof_outcome: Optional[str] = None) -> Tuple[str, float]:
    """Apply the judge to the deterministic verdict, safely.

    The rule, made absolute: the model never confirms a finding on its own. It
    proposes a read-only check; a LIVE replay of that check is the only thing
    that produces 'confirmed'. A model is fluent and confident about things that
    are not there, and a grounded quote proves only that a string appears in
    evidence the same model is reading - not that the issue is real on the
    target now.

      proof held         -> confirmed. A mechanical, read-only replay found the
                            observable the judge named. This is the one path in.
      proof refuted       -> the judge claimed confirmed and a live check
                            refutes the very observable it chose. Trust the
                            check: drop to 'unconfirmed'.
      no live confirmation-> capped at 'likely'. No proof was replayable, or the
                            target did not answer. A grounded quote keeps the
                            confidence up within 'likely'; an invented one drops
                            it. Either way the verdict is not 'confirmed'.

    Downgrades from the model are always honoured - skepticism is safe.
    """
    verdict = judgment["verdict"]
    conf = clamp_confidence(judgment["confidence"], base_conf)

    if verdict == "confirmed":
        if proof_outcome == "held":
            conf = max(conf, 0.9)
        elif proof_outcome == "did_not_hold":
            verdict, conf = "unconfirmed", min(conf, 0.4)
        else:
            verdict = "likely"
            if not quote_is_grounded(judgment.get("quote", ""), evidence):
                conf = min(conf, 0.6)

    if verdict == "false_positive":
        conf = min(conf, 0.2)
    return verdict, conf
