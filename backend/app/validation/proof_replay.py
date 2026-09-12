"""Replay a suggested proof against the target.

The LLM judge spends a call per finding producing one: a single read-only
request, plus the exact substring whose presence settles the question. Until
now that was written to metadata and never read again - a paid call producing
dead data.

This replays it. The request goes through SafePoC, so the same policy applies
as everywhere else (GET/HEAD only, in-scope only, capped body), and parse_proof
has already refused anything that mutates or points off-host. The verdict is
mechanical: the expected substring is either in the response or it is not.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from app.validation.safe_poc import PolicyError, SafePoC, ScopeError

logger = logging.getLogger("syphax.validation.proof_replay")


# --------------------------------------------------------------------------- #
# Pure core (unit-tested)

def stored_proof(metadata: Optional[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    """The proof on a finding, if it carries a usable one."""
    proof = (metadata or {}).get("suggested_proof")
    if not isinstance(proof, dict):
        return None
    if not proof.get("url") or not proof.get("expect"):
        return None
    return proof


def proof_verdict(expect: str, body: Optional[str],
                  status_code: Optional[int]) -> Dict[str, Any]:
    """Did the proof hold?

    Deliberately mechanical: the judge chose the observable, so confirming is a
    substring test, not another judgement call. No response at all is
    inconclusive, not a refutation - the target may simply have been down.
    """
    if body is None:
        return {"outcome": "inconclusive",
                "detail": "the target did not answer the proof request"}
    if expect and expect in body:
        return {"outcome": "held",
                "detail": f"expected {expect!r} is present in the response",
                "status_code": status_code}
    return {"outcome": "did_not_hold",
            "detail": f"expected {expect!r} is absent from the response",
            "status_code": status_code}


# --------------------------------------------------------------------------- #

async def replay(finding, in_scope) -> Dict[str, Any]:
    """Replay the finding's stored proof. Never raises on a target problem."""
    proof = stored_proof(finding.metadata)
    if proof is None:
        return {"outcome": "none", "detail": "this finding carries no suggested proof"}

    method = str(proof.get("method") or "GET").upper()
    url = str(proof["url"])
    expect = str(proof["expect"])

    safe = SafePoC(in_scope=in_scope)
    try:
        resp = await safe.fetch(url, method=method)
    except (ScopeError, PolicyError) as exc:
        # parse_proof vetted this when it was stored, but scope can change
        # between runs - so the live gate still has the last word.
        return {"outcome": "refused", "detail": str(exc), "proof": proof}

    verdict = proof_verdict(expect, resp.text if resp else None,
                            resp.status_code if resp else None)
    verdict["proof"] = proof
    verdict["request"] = f"{method} {url}"
    if resp is not None:
        verdict["response_excerpt"] = (resp.text or "")[:400].replace("\n", " ")
    return verdict
