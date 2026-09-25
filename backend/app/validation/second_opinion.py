"""Second-opinion backends for the shadow judge.

Each is an async callable: given a validated finding, return
{"verdict", "confidence", "reason"} or None. None means "no opinion" - the
shadow harness skips the finding rather than recording a comparison against
nothing. None of these ever touches the authoritative verdict.

Two exist today:

  llm_second_opinion   the model already configured for the validator role,
                       run at a higher temperature than the real judge so it is
                       a genuinely independent read and not the same call twice.
                       Needs no new service; it is how you test the harness
                       itself and get a baseline agreement number to compare a
                       new backend against.

  jev_second_opinion   TypeSafe AI's Jev. A verdict among four options with a
                       probability is exactly the typed, bounded choice Jev is
                       built for, and native probabilities are better calibrated
                       than a number an LLM writes into JSON. It is OFF unless
                       JEV_BASE_URL and JEV_API_KEY are set, and it fails to
                       None on anything unexpected, because it is under
                       evaluation and must not be able to disturb a run.

The Jev request shape here is written against TypeSafe's published description
of the model - a choice over a fixed option set returned with per-option
probability - and has NOT been verified against a live endpoint. Treat it as the
integration point to confirm once the API is in hand, not as known-good.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

from app.llm import ROLE_VALIDATOR, LLMError, get_router
from app.llm.grounding import clamp_confidence, extract_json, norm_status
from app.validation.llm_judge import _SYSTEM, _user_prompt

logger = logging.getLogger("syphax.validation.second_opinion")

VERDICTS = ("confirmed", "likely", "unconfirmed", "false_positive")


# --------------------------------------------------------------------------- #
# LLM baseline

async def llm_second_opinion(vf) -> Optional[Dict[str, Any]]:
    """The validator-role model, read independently of the real judge.

    Same prompt, higher temperature. If it were run at temperature 0 like the
    real judge it would mostly reproduce the same call, and an agreement number
    against yourself proves only that the harness runs. The point is a second,
    slightly different read.
    """
    client = get_router().get(ROLE_VALIDATOR)
    if not client.configured:
        return None
    try:
        raw = await client.chat(
            [{"role": "system", "content": _SYSTEM},
             {"role": "user", "content": _user_prompt(vf)}],
            temperature=0.7, max_tokens=400,
        )
    except LLMError:
        return None
    obj = extract_json(raw)
    if not isinstance(obj, dict) or "verdict" not in obj:
        return None
    return {
        "verdict": norm_status(obj.get("verdict")),
        "confidence": clamp_confidence(obj.get("confidence"), 0.5),
        "reason": str(obj.get("reason", ""))[:300],
    }


# --------------------------------------------------------------------------- #
# Jev

def jev_configured() -> bool:
    return bool(os.environ.get("JEV_BASE_URL") and os.environ.get("JEV_API_KEY"))


def build_jev_request(vf) -> Dict[str, Any]:
    """The payload sent to Jev. Pure, so the request is testable without a
    network - which matters more than usual here, because the endpoint cannot
    be reached from this environment to check it live.

    Jev returns a typed choice, so the finding is posed as one: pick the verdict
    that the evidence supports, from a fixed option set, with a probability. No
    free text is asked for - the reason comes back only if Jev attaches one.
    """
    evidence = (vf.evidence or "")[:4000]
    return {
        "model": os.environ.get("JEV_MODEL", "jev-1"),
        "input": (
            f"Penetration-test finding. Decide, from the evidence alone, which "
            f"verdict it supports.\n"
            f"Finding: {vf.title}\nClass: {vf.vuln_class}\nSeverity: {vf.severity}\n"
            f"Reported status: {vf.status}\nTarget: {vf.target}\n\n"
            f"Evidence:\n{evidence}"
        ),
        # A typed choice over the four verdicts - the shape Jev exists for.
        "choice": {"options": list(VERDICTS)},
    }


def parse_jev_response(obj: Any) -> Optional[Dict[str, Any]]:
    """Turn Jev's typed reply into the second-opinion shape. Pure.

    Written defensively against a response format that has not been confirmed:
    it reads the chosen option and its probability under the field names
    TypeSafe's docs describe, and returns None rather than guessing if neither
    is present. A shadow that misreads its backend is worse than one that stays
    quiet.
    """
    if not isinstance(obj, dict):
        return None

    # The chosen option, under any of the names the docs use for it. It must be
    # one of the four verdicts EXACTLY - norm_status() coerces an unknown token
    # to "likely", so relying on it here would turn a garbled reply into a
    # confident "likely" and report disagreement that never happened.
    choice = obj.get("choice") or obj.get("value") or obj.get("output")
    verdict = str(choice or "").strip().lower()
    if verdict not in VERDICTS:
        return None

    # The probability of the chosen option. Jev returns per-option
    # probabilities; the confidence is the one for the option it picked.
    confidence = 0.5
    probs = obj.get("probabilities") or obj.get("scores")
    if isinstance(probs, dict) and choice in probs:
        confidence = clamp_confidence(probs[choice], 0.5)
    elif "confidence" in obj:
        confidence = clamp_confidence(obj.get("confidence"), 0.5)

    return {"verdict": verdict, "confidence": confidence,
            "reason": str(obj.get("reason", ""))[:300]}


async def jev_second_opinion(vf) -> Optional[Dict[str, Any]]:
    """Ask Jev. Off unless configured, and None on anything unexpected."""
    if not jev_configured():
        return None

    import httpx  # noqa: PLC0415

    base = os.environ["JEV_BASE_URL"].rstrip("/")
    key = os.environ["JEV_API_KEY"]
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=5.0)) as client:
            resp = await client.post(
                f"{base}/v1/decide",
                headers={"Authorization": f"Bearer {key}",
                         "Content-Type": "application/json"},
                json=build_jev_request(vf),
            )
        if resp.status_code != 200:
            logger.warning("jev answered %s", resp.status_code)
            return None
        return parse_jev_response(resp.json())
    except Exception as exc:  # noqa: BLE001 - a shadow backend must never raise into the run
        logger.warning("jev request failed: %s", exc)
        return None


# --------------------------------------------------------------------------- #

BACKENDS = {"llm": llm_second_opinion, "jev": jev_second_opinion}


def resolve(name: str):
    """(callable, backend_label) for a configured backend name, or (None, why)."""
    key = (name or "").strip().lower()
    if key not in BACKENDS:
        return None, f"unknown shadow backend {name!r} (choose: {', '.join(BACKENDS)})"
    if key == "jev" and not jev_configured():
        return None, "jev shadow requested but JEV_BASE_URL / JEV_API_KEY are unset"
    return BACKENDS[key], key
