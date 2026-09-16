"""Operator settings: persisted server-side, secrets encrypted at rest.

A single-row `settings` table holds the non-secret config (model router, scope,
safety toggles, integrations, OOB server) as JSON, plus a Fernet-encrypted blob
of provider API keys. Keys are NEVER returned to the UI - the API exposes only
`set` / `unset` per provider.

The Fernet key comes from env SYPHAX_SECRET_KEY (urlsafe-b64, 32 bytes); if it
is unset we generate one and persist it to {data_dir}/.settings.key (0600) so
restarts can still decrypt.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from typing import Any, Dict, Optional

from app import db
from app.config import settings as app_settings
from app.llm.providers import provider_for_base_url as _provider_for_base_url
from app.llm.providers import provider_ids as _provider_ids

logger = logging.getLogger("syphax.settings")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS settings (
    id      TEXT PRIMARY KEY,
    data    TEXT NOT NULL,
    secrets TEXT
);
"""
db.register_schema(SCHEMA_SQL)

_ROW_ID = "global"
# One entry per provider a key can be stored under. Sourced from the catalog so
# adding a provider is a one-line change there rather than a change here that
# someone forgets to make.
PROVIDERS = _provider_ids()

DEFAULTS: Dict[str, Any] = {
    "model_router": {
        "planner": {"base_url": "", "model": ""},
        "executor": {"base_url": "", "model": ""},
        "validator": {"base_url": "", "model": ""},
    },
    "scope": {"rate": 10, "concurrency": 4, "egress": []},
    "safety": {"safe_mode": True, "require_approval": False,
               "auto_validate": True, "oob_enabled": True},
    "integrations": {"slack": "", "discord": "", "jira": "", "webhook": ""},
    "oob_server": "",
    # LLM spend guardrail. 0 disables the alert. Only meaningful once
    # LLM_PRICING is set, otherwise every model is billed at 0 and the
    # threshold can never be reached.
    "budget": {"monthly_usd": 0, "per_engagement_usd": 0},
}

# At-rest encryption. Prefer cryptography/Fernet (used in the container image);
# if its native bindings are unavailable, fall back to a keyed stdlib AEAD
# (SHA-256 keystream + HMAC tag) so the store still encrypts everywhere.
_key_cache: Optional[bytes] = None
_fernet_cache = None
_fernet_ok: Optional[bool] = None


# True when the at-rest key could not be persisted anywhere durable: stored
# secrets will NOT survive a restart. Surfaced via get_public() so the UI warns.
KEY_IS_EPHEMERAL = False


def _key_candidates():
    from pathlib import Path
    yield app_settings.data_dir / ".settings.key"
    yield Path.home() / ".syphax" / ".settings.key"
    # Pre-rename location. Read-only fallback so an existing install keeps
    # decrypting its stored provider keys after the All-Hack -> Syphax rename.
    yield Path.home() / ".allhack" / ".settings.key"


def _secret_material() -> str:
    global KEY_IS_EPHEMERAL
    # ALLHACK_SECRET_KEY is the pre-rename name. Honoured so an existing
    # deployment does not silently generate a new key and lose the ability to
    # decrypt the provider keys already in the database.
    key = (os.environ.get("SYPHAX_SECRET_KEY", "")
           or os.environ.get("ALLHACK_SECRET_KEY", "")).strip()
    if key:
        return key

    candidates = list(_key_candidates())
    for p in candidates:
        try:
            if p.exists():
                return p.read_text().strip()
        except OSError:
            continue

    # None on disk: mint one and persist it to the first writable location.
    new = base64.urlsafe_b64encode(os.urandom(32)).decode()
    for p in candidates:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(new)
            os.chmod(p, 0o600)
            logger.info("generated at-rest settings key at %s", p)
            return new
        except OSError:
            continue

    # Could not persist anywhere: the key is ephemeral and secrets saved now are
    # lost on restart. Fail LOUD (operator must set SYPHAX_SECRET_KEY).
    KEY_IS_EPHEMERAL = True
    logger.critical(
        "CRITICAL: could not persist an at-rest encryption key (tried %s). "
        "Stored provider keys will NOT survive a restart. Set the SYPHAX_SECRET_KEY "
        "environment variable to a fixed value to fix this permanently.",
        ", ".join(str(p) for p in candidates),
    )
    return new


def _fernet():
    """Return a working Fernet, or None if the native bindings can't load."""
    global _fernet_cache, _fernet_ok
    if _fernet_ok is False:
        return None
    if _fernet_cache is not None:
        return _fernet_cache
    try:
        from cryptography.fernet import Fernet  # noqa: PLC0415
        mat = _secret_material()
        # Fernet needs a urlsafe-b64 32-byte key; derive one deterministically.
        fkey = base64.urlsafe_b64encode(hashlib.sha256(mat.encode()).digest())
        f = Fernet(fkey)
        f.decrypt(f.encrypt(b"selftest"))  # prove the bindings actually work
        _fernet_cache, _fernet_ok = f, True
        return f
    except BaseException:  # noqa: BLE001 - pyo3 panic is a BaseException
        _fernet_ok = False
        logger.warning("cryptography unavailable; using stdlib at-rest cipher")
        return None


def _xor_key() -> bytes:
    global _key_cache
    if _key_cache is None:
        _key_cache = hashlib.sha256(("syphax:" + _secret_material()).encode()).digest()
    return _key_cache


def _keystream(nonce: bytes, n: int, key: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def encrypt(plain: str) -> str:
    f = _fernet()
    if f is not None:
        return "f1:" + f.encrypt(plain.encode()).decode()
    key = _xor_key()
    data = plain.encode()
    nonce = os.urandom(16)
    ct = bytes(a ^ b for a, b in zip(data, _keystream(nonce, len(data), key)))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return "x1:" + base64.urlsafe_b64encode(nonce + tag + ct).decode()


def decrypt(token: str) -> str:
    try:
        if token.startswith("f1:"):
            f = _fernet()
            return f.decrypt(token[3:].encode()).decode() if f else ""
        if token.startswith("x1:"):
            raw = base64.urlsafe_b64decode(token[3:].encode())
            nonce, tag, ct = raw[:16], raw[16:48], raw[48:]
            key = _xor_key()
            if not hmac.compare_digest(tag, hmac.new(key, nonce + ct, hashlib.sha256).digest()):
                return ""
            return bytes(a ^ b for a, b in zip(ct, _keystream(nonce, len(ct), key))).decode()
        return ""
    except Exception:  # noqa: BLE001
        return ""


def _merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(base)
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


async def _read_row() -> Dict[str, Any]:
    async with db.acquire() as conn:
        row = await conn.fetchrow("SELECT data, secrets FROM settings WHERE id=$1", _ROW_ID)
    data = _merge(DEFAULTS, json.loads(row["data"]) if row and row["data"] else {})
    secrets: Dict[str, str] = {}
    if row and row["secrets"]:
        raw = decrypt(row["secrets"])
        if raw:
            try:
                secrets = json.loads(raw)
            except json.JSONDecodeError:
                secrets = {}
    return {"data": data, "secrets": secrets}


async def get_public() -> Dict[str, Any]:
    """Settings as returned to the UI: secrets reduced to set/unset."""
    row = await _read_row()
    data = dict(row["data"])
    data["provider_keys"] = {
        p: ("set" if row["secrets"].get(p) else "unset") for p in PROVIDERS
    }
    data["llm"] = readiness_for(data, row["secrets"]).to_public()
    # Touch the key path once so KEY_IS_EPHEMERAL is computed, then warn the UI.
    _xor_key()
    if KEY_IS_EPHEMERAL:
        data["key_warning"] = ("No durable encryption key: stored provider keys "
                               "will be lost on restart. Set SYPHAX_SECRET_KEY.")
    return data




def readiness_for(data: Dict[str, Any], secrets: Dict[str, str]):
    """Whether the saved model router actually resolves to three working roles.

    Computed from the SAVED settings rather than from the live router, so the
    answer is the same before and after a restart - the router is rebuilt
    lazily and would report "not configured" for a role nobody has called yet.
    """
    from app.llm import readiness as _readiness
    mr = data.get("model_router") or {}
    configs = {}
    for role in ("planner", "executor", "validator"):
        cfg = mr.get(role) or {}
        base_url = cfg.get("base_url") or ""
        configs[role] = {
            "base_url": base_url,
            "model": cfg.get("model") or "",
            "api_key": secrets.get(provider_for_base_url(base_url), "") if base_url else "",
        }
    return _readiness.evaluate(
        configs,
        fallback_key=(secrets.get("openrouter", "") or app_settings.openrouter_api_key),
        fallback_base_url=app_settings.openrouter_base_url,
        fallback_model=app_settings.openrouter_model,
    )


async def llm_readiness():
    """Readiness computed from what is persisted, for callers that only have a
    database connection - the run gate and the /api/llm/readiness endpoint."""
    row = await _read_row()
    return readiness_for(row["data"], row["secrets"])


async def save(patch: Dict[str, Any]) -> Dict[str, Any]:
    """Merge non-secret settings; apply provider-key updates.

    `patch['provider_keys']` may map provider -> raw key to SET, '' to leave
    unchanged, or the literal '__unset__' to clear. Raw keys are never stored
    in the public `data` blob.
    """
    row = await _read_row()
    secrets = dict(row["secrets"])
    pk = (patch or {}).pop("provider_keys", None)
    if isinstance(pk, dict):
        for p in PROVIDERS:
            if p not in pk:
                continue
            val = pk[p]
            if val == "__unset__":
                secrets.pop(p, None)
            elif isinstance(val, str) and val.strip():
                secrets[p] = val.strip()
            # empty / non-string -> leave unchanged

    data = _merge(row["data"], {k: v for k, v in (patch or {}).items()})

    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO settings (id, data, secrets) VALUES ($1,$2,$3) "
            "ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data, secrets=EXCLUDED.secrets",
            _ROW_ID, json.dumps(data),
            encrypt(json.dumps(secrets)) if secrets else None,
        )
    await apply_to_router(data, secrets)
    return await get_public()


def provider_for_base_url(base_url: str) -> str:
    """Which stored key a role pointed at this URL should use.

    Delegates to the catalog. The previous version returned "openrouter" for
    anything it did not recognise, which meant an operator who pointed a role at
    DeepSeek had their OpenRouter key sent to DeepSeek's server - a credential
    leak dressed up as a default.
    """
    return _provider_for_base_url(base_url)


async def apply_to_router(data: Dict[str, Any], secrets: Dict[str, str]) -> None:
    """Push the saved model router + keys into the live LLM router, and the OOB
    server into the environment the nuclei wrapper reads."""
    try:
        from app.llm import get_router
        router = get_router()
        mr = data.get("model_router") or {}
        for role in ("planner", "executor", "validator"):
            cfg = mr.get(role) or {}
            base_url = cfg.get("base_url") or ""
            model = cfg.get("model") or ""
            key = secrets.get(provider_for_base_url(base_url), "") if base_url else ""
            router.reconfigure(role, base_url=base_url, api_key=key, model=model)
    except Exception:  # noqa: BLE001
        logger.exception("failed to apply model router from settings")
    oob = (data.get("oob_server") or "").strip()
    if oob:
        os.environ["INTERACTSH_SERVER"] = oob


async def apply_saved_on_startup() -> None:
    """Re-apply persisted settings to the router at process start."""
    try:
        row = await _read_row()
        await apply_to_router(row["data"], row["secrets"])
    except Exception:  # noqa: BLE001
        logger.debug("no saved settings to apply on startup")
