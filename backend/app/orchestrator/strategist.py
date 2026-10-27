"""The strategist: turns what is on the blackboard into what to do next.

The planner decides which catalog item runs against which asset, and it does
that well from the methodology alone. What it could not do is REACT: a run
would find an admin credential, a forgotten /api/v2 answering without auth, a
parameter a tool had already confirmed injectable - and then keep planning in
the same catalog-and-severity order it would have used if it had found none of
those things. Everything discovered mid-run was recorded and then ignored.

This module closes that loop. It reads the leads the analysers and exploiters
posted to the blackboard and returns ADVICE: which assets the board says are
live, which vulnerability classes those leads unlock, and which identity the
run has acquired. The planner applies it as a within-phase reordering, exactly
like cross-engagement memory does - advisory, never a new task, never a gate.

Two properties are deliberate:

  * It works with no LLM at all. The chain map below is explicit, auditable
    pentest knowledge - a credential unlocks what sits behind the gate, an
    injectable parameter unlocks sqlmap - so the advice is the same every time
    for the same board. The optional model pass only REORDERS classes the
    deterministic map already proposed; it cannot invent a class, a tool or a
    target.

  * Advice is derived from leads, and a lead is data an analyser wrote. Nothing
    here can widen scope or skip a capability gate: the advice is a sort order
    handed to a planner whose candidates were already filtered by both.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from app import events
from app.llm import ROLE_PLANNER, get_router
from app.orchestrator import blackboard as bb
from app.orchestrator.blackboard import Blackboard
from app.orchestrator.state import EngagementState

logger = logging.getLogger("syphax.orchestrator.strategist")

# How many model-assisted advisories one run may spend. The deterministic
# chain map is the fallback and is already a sensible order, so this buys
# judgement on the rounds where the board is rich, not a call per iteration.
MAX_LLM_ADVICE = 10

# What each kind of lead unlocks, as catalog vuln_class names.
#
# This is the kill chain written down. Every name on the right MUST be a class
# that exists in the catalog - a typo here is silent, it just advises a class
# nothing matches, so there is a test that checks every one of them against
# CATALOG. Ordered within each list: most worth trying first.
LEAD_CHAIN: Dict[str, List[str]] = {
    # An identity the run did not start with. What it buys is the surface
    # behind the gate: the authenticated API contract, and the auth logic
    # itself (session handling, privilege boundaries).
    bb.CREDENTIAL: ["auth", "api_contract_violation", "multiple"],
    bb.SESSION: ["auth", "api_contract_violation", "multiple"],
    # A key or token in a bundle. The code that leaked it usually leaked more,
    # and a repository or source map is the next thing to look for.
    bb.SECRET: ["secret_exposure", "source_code_disclosure", "exposed_resource"],
    # Already executing somewhere. Nothing else is worth more than finishing
    # that, so RCE-class work goes first.
    bb.PRIVILEGE: ["rce", "command_injection"],
    # Answered with no credential. The contract tests are what turn "it
    # responds" into "it responds with data it should not hand out".
    bb.UNAUTH_ENDPOINT: ["api_contract_violation", "multiple", "exposed_resource"],
    # A parameter a tool already reached. This is the highest-yield lead on the
    # board: the injection classes exist precisely for it.
    bb.INJECTABLE: ["sql_injection", "xss", "command_injection", "nosql_injection",
                    "ssti", "lfi"],
    # An enumerable identifier. The schema-driven tests are what exercise it.
    bb.OBJECT_ID: ["api_contract_violation", "multiple"],
    bb.API_SCHEMA: ["api_contract_violation"],
    # A fingerprinted CVE: confirm it, then try to prove it.
    bb.CVE: ["cve", "rce", "multiple"],
}


# How much each kind of lead is worth chasing, lower first.
#
# Without this the order came from the board's own sort (confidence, then
# insertion), so between two equally confident leads it was an accident. That
# put a freshly earned session - a wide new surface, but not yet a finding -
# ahead of an injection point a tool had already CONFIRMED, and the
# exploitation budget went to speculative contract tests instead of running
# sqlmap on a proven hole.
#
# Chasing an identity's classes later costs nothing, because acting on the
# identity is a separate step: adopt_identity authenticates the run whatever
# the chase order says.
KIND_PRIORITY: Dict[str, int] = {
    bb.INJECTABLE: 0,       # a tool already reached it: the shortest path to proof
    bb.PRIVILEGE: 1,        # already executing somewhere - finish that
    bb.CVE: 2,              # a published weakness with a known exploit
    bb.SESSION: 3,          # a usable identity: new surface, not yet a finding
    bb.CREDENTIAL: 4,
    bb.OBJECT_ID: 5,
    bb.UNAUTH_ENDPOINT: 6,
    bb.SECRET: 7,
    bb.API_SCHEMA: 8,
    bb.HOST: 9,
}


@dataclass
class Advice:
    """What the board suggests doing next. Consumed by the planner as a sort."""
    chase_classes: List[str] = field(default_factory=list)
    hot_assets: Set[str] = field(default_factory=set)
    identity: Optional[Dict[str, Any]] = None
    # Leads nothing has been run against yet. Zero means the board is fully
    # worked through, which is a real and reportable state: it says the run
    # has acted on everything it knows, rather than that it found nothing.
    untouched: int = 0
    rationale: str = ""

    @property
    def is_empty(self) -> bool:
        return not self.chase_classes and not self.hot_assets

    def to_public(self) -> Dict[str, Any]:
        return {
            "chase_classes": list(self.chase_classes),
            "hot_assets": sorted(self.hot_assets),
            "has_identity": self.identity is not None,
            "untouched": self.untouched,
            "rationale": self.rationale,
        }


class Strategist:
    """Reads one engagement's board, advises its planner."""

    def __init__(self, state: EngagementState,
                 board: Optional[Blackboard] = None) -> None:
        self.state = state
        self.board = board or Blackboard(state.engagement_id)
        self._llm_calls = 0
        self._said_identity = False

    async def advise(self, *, use_llm: bool = True) -> Advice:
        """Current advice. Never raises: no board, no leads or a dead model all
        degrade to empty advice, and empty advice leaves the planner's
        deterministic order exactly as it was."""
        try:
            leads = await self.board.leads()
        except Exception:  # noqa: BLE001 - advice is optional, the run is not
            logger.debug("[%s] no board to advise from", self.state.engagement_id)
            return Advice()
        if not leads:
            return Advice()

        advice = self._from_leads(leads)
        if use_llm and advice.chase_classes:
            advice = await self._llm_reorder(advice, leads)
        await self._announce(advice, leads)
        return advice

    # -- the deterministic core -------------------------------------------

    def _from_leads(self, leads: List[bb.Lead]) -> Advice:
        """Fold the board into advice. Pure, so it is directly testable."""
        # A lead something has already been run against goes last, whatever
        # its kind. This is the fix for the failure OWASP GenAI's "LLM Exploit
        # Generation Phase 2" found in every agentic framework it tested: an
        # agent cracked one user's password and then looped on other users'
        # hashes while ignoring a password-reset route it had already found,
        # "because it never ranked the value of its findings". Ranking is only
        # half of it - without recording what has been TRIED, the same top
        # lead wins every round and the rest of the board waits forever.
        #
        # Consumed does not mean finished or worthless: the fact stays on the
        # board, in the report, and in `hot_assets` below. It stops being the
        # first thing reached for.
        ranked = sorted(leads, key=lambda l: (bool(l.consumed_by),
                                              KIND_PRIORITY.get(l.kind, 99),
                                              -l.confidence, l.id))
        chase: List[str] = []
        for lead in ranked:
            for cls in LEAD_CHAIN.get(lead.kind, ()):
                if cls not in chase:
                    chase.append(cls)

        # An asset the board names is an asset something already reached. That
        # is evidence, where asset_interest is only a guess from the URL - so
        # the planner lets it outrank the heuristic.
        hot = {lead.value for lead in leads
               if lead.kind in (bb.UNAUTH_ENDPOINT, bb.INJECTABLE, bb.OBJECT_ID)
               and lead.value}
        # A lead whose value is not itself a URL can still carry one.
        for lead in leads:
            url = lead.data.get("login_url") or lead.data.get("url")
            if url:
                hot.add(str(url))

        identity = self._best_identity(leads)
        fresh = [l for l in leads if not l.consumed_by]
        return Advice(chase_classes=chase, hot_assets=hot, identity=identity,
                      untouched=len(fresh),
                      rationale=self._rationale(leads, chase, fresh))

    def _best_identity(self, leads: List[bb.Lead]) -> Optional[Dict[str, Any]]:
        """The strongest identity the run holds, for the grey-box scanners.

        A session beats a credential (it is already valid, nothing to replay),
        and a credential beats a bare secret. Returns the lead's data, which is
        where the usable material lives - the board's `value` is redacted for
        display and is not meant to be used."""
        order = {bb.SESSION: 0, bb.CREDENTIAL: 1, bb.PRIVILEGE: 2, bb.SECRET: 3}
        found = [l for l in leads if l.kind in order]
        if not found:
            return None
        found.sort(key=lambda l: (order[l.kind], -l.confidence))
        best = found[0]
        return {"kind": best.kind, "lead_id": best.id, "source": best.source,
                "confidence": best.confidence, **best.data}

    def _rationale(self, leads: List[bb.Lead], chase: List[str],
                   fresh: Optional[List[bb.Lead]] = None) -> str:
        counts: Dict[str, int] = {}
        for lead in leads:
            counts[lead.kind] = counts.get(lead.kind, 0) + 1
        board = ", ".join(f"{n} {kind}" for kind, n in sorted(counts.items()))
        if not chase:
            return f"The board holds {board}; nothing on it maps to a test yet."
        tail = ""
        if fresh is not None:
            tail = (f" {len(fresh)} of {len(leads)} not yet acted on."
                    if fresh else
                    " Everything on it has been acted on at least once.")
        return (f"The board holds {board}; chasing "
                f"{', '.join(chase[:4])} first.{tail}")

    # -- the optional model pass ------------------------------------------

    async def _llm_reorder(self, advice: Advice,
                           leads: List[bb.Lead]) -> Advice:
        """Let the model reorder the classes the chain map proposed.

        Strictly constrained, for the same reason the planner's pass is: it may
        return a subset of `chase_classes` in a different order and nothing
        else. Anything it invents is dropped, and any class it omits is
        appended in the deterministic order - so the model can change what is
        tried FIRST, never what is reachable at all."""
        if self._llm_calls >= MAX_LLM_ADVICE:
            return advice
        client = get_router().get(ROLE_PLANNER)
        if not client.configured:
            return advice
        self._llm_calls += 1

        # The board as the model may see it: to_public() redacts the identity
        # values, so a credential reaches the prompt as proof an account exists
        # and never as the password itself.
        payload = {
            "board": [l.to_public() for l in leads[:40]],
            "candidate_classes": advice.chase_classes,
            "technologies": await self._tech(),
        }
        system = (
            "You are the exploitation strategist of a web-app pentest. The "
            "board lists facts this run has established. Decide which "
            "vulnerability classes to chase FIRST to build the strongest kill "
            "chain from them. Use ONLY the class names in candidate_classes; "
            "never invent a class, a tool or a target. Prefer a class that "
            "chains from an existing lead over one that starts over. Reply "
            "JSON only: {\"ordered_classes\":[...],\"rationale\":\"one short "
            "sentence\"}."
        )
        try:
            reply = await client.chat(
                [{"role": "system", "content": system},
                 {"role": "user", "content": json.dumps(payload)}],
                temperature=0.1, max_tokens=400)
        except Exception as exc:  # noqa: BLE001 - advice is optional
            logger.debug("[%s] strategist LLM unavailable: %s",
                         self.state.engagement_id, exc)
            return advice

        ordered, rationale = _parse_advice(reply)
        allowed = set(advice.chase_classes)
        kept = [c for c in ordered if c in allowed]
        if not kept:
            return advice
        # Everything the model left out still follows, in the order the chain
        # map put it. The model reprioritises; it never shortens the run.
        tail = [c for c in advice.chase_classes if c not in kept]
        advice.chase_classes = kept + tail
        if rationale:
            advice.rationale = rationale
        return advice

    async def _tech(self) -> List[str]:
        try:
            return await self.state.technologies()
        except Exception:  # noqa: BLE001
            return []

    # -- telling the operator ---------------------------------------------

    async def _announce(self, advice: Advice, leads: List[bb.Lead]) -> None:
        """Say the chain step on the live console, once per identity gained.

        The per-iteration advice is not worth a line each time - it barely
        changes - but the moment the run acquires an identity is the single
        most important thing that happens in a black-box engagement, so that
        one is said out loud."""
        if advice.identity is None or self._said_identity:
            return
        self._said_identity = True
        try:
            kind = advice.identity.get("kind", "identity")
            who = advice.identity.get("username") or advice.identity.get("source") or kind
            await events.emit(
                self.state.engagement_id, events.THOUGHT,
                f"The run now holds a {kind} ({who}). Testing continues as an "
                f"authenticated user: {advice.rationale}",
                level=events.LEVEL_INFO)
        except Exception:  # noqa: BLE001
            logger.debug("could not announce the identity")


def _parse_advice(reply: str):
    """Pull (ordered_classes, rationale) out of a model reply. Tolerant: a
    fenced block, leading prose or a bare list all parse, and anything else
    yields nothing rather than raising."""
    text = (reply or "").strip()
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            cleaned = part.strip()
            if cleaned.startswith("json"):
                cleaned = cleaned[4:].strip()
            if cleaned.startswith("{") or cleaned.startswith("["):
                text = cleaned
                break
    start = min((i for i in (text.find("{"), text.find("[")) if i >= 0),
                default=-1)
    if start < 0:
        return [], ""
    try:
        parsed = json.loads(text[start:])
    except json.JSONDecodeError:
        # A truncated reply is common at a low max_tokens; take the class
        # names we can still read rather than throwing the call away.
        try:
            parsed = json.loads(text[start:].rsplit(",", 1)[0] + "]}")
        except json.JSONDecodeError:
            return [], ""
    if isinstance(parsed, list):
        return [str(c).strip().lower() for c in parsed if isinstance(c, str)], ""
    if not isinstance(parsed, dict):
        return [], ""
    raw = parsed.get("ordered_classes") or parsed.get("classes") or []
    if not isinstance(raw, list):
        return [], ""
    return ([str(c).strip().lower() for c in raw if isinstance(c, str)],
            str(parsed.get("rationale") or "").strip()[:200])
