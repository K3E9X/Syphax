"""Adopting an identity the run earned: the black-box -> grey-box switch.

syphax already knows how to test as a logged-in user. `engagement.primary_auth`
holds the headers of a primary identity and scans/runner.py injects them into
every tool it launches; `engagement.secondary_auth` holds a SECOND identity,
and analysis/logic.py uses it to prove cross-user access properly instead of
reporting "an object is exposed by id, access control not verified".

Both were operator-supplied only. In a black-box engagement the operator
supplies nothing, so both stayed empty for the whole run - and that is a large
part of why a black-box run found so little. auth-brute would prove a default
credential worked, the console would say so, and then every single tool and
analyser that followed would still run as an anonymous visitor. The run
re-discovered the front door and never walked through it.

This module walks through it. When the blackboard holds a USABLE session (one
with a header a later request can actually send), it is written to the
engagement as an identity, and from that point:

  * every tool launched afterwards is authenticated - runner.py re-reads the
    engagement per job, so nothing else had to change;
  * if the operator already supplied a primary identity, the earned one
    becomes the SECOND identity, which is what upgrades IDOR from "likely" to
    a confirmed cross-user read.

Three rules, all deliberate:

  * An operator-supplied identity is never overwritten. Theirs is a decision;
    ours is an inference.
  * Only a lead marked `usable` is adopted. A verified secret proves a live
    key exists without handing us the key, and adopting that would send an
    empty header and silently un-authenticate the run.
  * Adopting is audited and announced. It changes what every later request
    does, so it is not allowed to be invisible.
"""
from __future__ import annotations

import logging
from typing import Dict, List, Optional

from app import events
from app.audit import audit
from app.engagements import EngagementRepository
from app.orchestrator import blackboard as bb
from app.orchestrator.blackboard import Blackboard

logger = logging.getLogger("syphax.orchestrator.identity")


def usable_headers(lead: bb.Lead) -> List[Dict[str, str]]:
    """The header list a usable identity lead implies, or [] if it has none.

    Pure, so the rule that decides whether an identity is real is testable
    without a database.
    """
    data = lead.data or {}
    if not data.get("usable"):
        return []
    name = str(data.get("header_name") or "").strip()
    value = str(data.get("header_value") or "").strip()
    if not name or not value:
        return []
    return [{"name": name, "value": value}]


async def adopt_identity(engagement_id: str) -> Optional[str]:
    """Write the best usable identity from the board onto the engagement.

    Returns the slot it filled ("primary_auth" / "secondary_auth"), or None if
    there was nothing usable to adopt or both slots are already taken. Never
    raises: a run that cannot adopt an identity is the run we had before.
    """
    try:
        board = Blackboard(engagement_id)
        leads = await board.leads()
    except Exception:  # noqa: BLE001
        logger.debug("[%s] no board to adopt from", engagement_id)
        return None

    # A session first: it is already valid, where a credential would have to be
    # replayed. Best confidence wins within a kind.
    candidates = [l for l in leads if l.kind == bb.SESSION]
    candidates.sort(key=lambda l: -l.confidence)
    pick = next(((l, h) for l in candidates if (h := usable_headers(l))), None)
    if pick is None:
        return None
    lead, headers = pick

    try:
        repo = EngagementRepository()
        eng = await repo.get(engagement_id)
        if eng is None:
            return None

        if not eng.primary_auth:
            slot = "primary_auth"
            eng.primary_auth = headers
        elif not eng.secondary_auth and headers != eng.primary_auth:
            # The operator gave us one identity; we earned a different one.
            # Two identities is exactly what a rigorous access-control test
            # needs, so this is the more valuable of the two outcomes.
            slot = "secondary_auth"
            eng.secondary_auth = headers
        else:
            return None

        await repo.update(eng)
        await board.mark_consumed(lead.id, f"identity:{slot}")
    except Exception:  # noqa: BLE001 - never fail a run over this
        logger.exception("[%s] could not adopt an identity", engagement_id)
        return None

    await _announce(engagement_id, slot, lead)
    return slot


async def _announce(engagement_id: str, slot: str, lead: bb.Lead) -> None:
    """Audit + console. The header value is never printed - the point is that
    the run HAS an identity, not what it is."""
    who = (lead.data or {}).get("username") or lead.source or "an account"
    if slot == "primary_auth":
        message = (
            f"Testing as {who} from here on. The session this run earned is "
            "now the primary identity, so every scan that follows runs "
            "authenticated instead of anonymously.")
    else:
        message = (
            f"A second identity ({who}) is now in place. Access-control tests "
            "can prove cross-user reads directly rather than reporting them "
            "as unverified.")
    try:
        await events.emit(engagement_id, events.THOUGHT, message,
                          level=events.LEVEL_INFO, slot=slot)
    except Exception:  # noqa: BLE001
        logger.debug("could not announce the adopted identity")
    try:
        await audit("identity_adopted", engagement_id=engagement_id, slot=slot,
                    source=lead.source, lead_id=lead.id)
    except Exception:  # noqa: BLE001
        logger.debug("could not audit the adopted identity")
