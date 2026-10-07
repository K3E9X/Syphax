"""GET/PUT /api/settings. Provider keys are write-only and never echoed back."""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter
from pydantic import BaseModel

from app import settings_store
from app.audit import audit

router = APIRouter(tags=["settings"])


@router.get("/api/settings")
async def get_settings() -> Dict[str, Any]:
    return await settings_store.get_public()


class SettingsPatch(BaseModel):
    model_router: Dict[str, Any] | None = None
    provider_keys: Dict[str, str] | None = None   # raw to set, '' keep, '__unset__' clear
    integration_keys: Dict[str, str] | None = None  # GitHub/Shodan/Censys/VT, same rules
    scope: Dict[str, Any] | None = None
    safety: Dict[str, Any] | None = None
    integrations: Dict[str, Any] | None = None
    oob_server: str | None = None
    budget: Dict[str, Any] | None = None


@router.put("/api/settings")
async def put_settings(body: SettingsPatch) -> Dict[str, Any]:
    patch = {k: v for k, v in body.model_dump().items() if v is not None}
    result = await settings_store.get_public()
    result = await settings_store.save(patch)
    # Audit the change, but never log raw provider keys.
    await audit("settings.updated", changed=sorted(patch.keys()))
    return result
