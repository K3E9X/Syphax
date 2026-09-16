"""GET /api/recon/scope and POST /api/recon.

Recon runs before an engagement exists, so there is no scope gate to pass and
none can be applied. Two things stand in its place:

  * app/recon/budget.py bounds what can leave this machine, as a constant.
  * every run is written to the audit log with the operator's name on it.

That second one matters more than it looks. The audit log is the record of what
this installation did to which host, and a lookup that no engagement covers is
precisely the kind of thing that has to be in it.
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.audit import audit
from app.recon import budget, run
from app.recon.target import TargetError, parse

router = APIRouter(prefix="/api/recon", tags=["recon"])
logger = logging.getLogger("syphax.api.recon")


class ReconRequest(BaseModel):
    target: str
    # crt.sh is the slowest source by a wide margin and the one most likely to
    # be rate-limiting. Skippable so a second look at the same target is fast.
    include_ct: bool = True


@router.get("/scope")
async def scope() -> Dict[str, Any]:
    """Exactly what a recon run does, and does not do.

    Served to the UI and shown next to the button. An operator pointing this at
    a host they do not own should be able to read what leaves this machine
    before they press it, not afterwards.
    """
    return budget.describe()


@router.post("")
async def recon(body: ReconRequest, request: Request) -> Dict[str, Any]:
    try:
        target = parse(body.target)
    except TargetError as exc:
        # The message is written for a human; pass it through rather than
        # replacing it with "invalid input".
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    user = getattr(request.state, "user", None)
    await audit("recon.run", target=target.host, url=target.base_url,
                by=(user or {}).get("username", "api-key"))

    try:
        return await run(body.target, include_ct=body.include_ct)
    except TargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("recon failed for %s", target.host)
        raise HTTPException(
            status_code=500,
            detail=f"recon failed: {exc.__class__.__name__}. The container log has "
                   f"the detail.") from exc
