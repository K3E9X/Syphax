"""Sign-in, setup, and account management.

The gate itself is middleware (app/main.py wiring app/auth/policy.py); this
module is only the endpoints that gate lets through, plus the ones an operator
uses to manage their own account.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from app.audit import audit
from app.auth import passwords, policy, storage, throttle, tokens
from app.config import settings

router = APIRouter(tags=["auth"])


def _source_ip(request: Request) -> str:
    """The caller's address as best we can tell.

    X-Forwarded-For is attacker-controlled on a directly-exposed backend, so
    this is fine for a throttle key and for showing the operator their own
    sessions - and is NOT a security control anywhere else.
    """
    fwd = request.headers.get("x-real-ip") or request.headers.get("x-forwarded-for") or ""
    if fwd:
        return fwd.split(",")[0].strip()[:64]
    return (getattr(request.client, "host", "") or "")[:64]


def _is_secure(request: Request) -> bool:
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
    return proto == "https"


def _set_cookie(response: Response, request: Request, token: str) -> None:
    response.set_cookie(value=token, **tokens.cookie_attributes(secure=_is_secure(request)))


def _clear_cookie(response: Response, request: Request) -> None:
    attrs = tokens.cookie_attributes(secure=_is_secure(request))
    response.delete_cookie(key=attrs["key"], path=attrs["path"],
                           samesite=attrs["samesite"], httponly=attrs["httponly"],
                           secure=attrs["secure"])


def _current(request: Request) -> Optional[Dict[str, Any]]:
    return getattr(request.state, "user", None)


def _require(request: Request) -> Dict[str, Any]:
    user = _current(request)
    if user is None:
        # Reachable when a machine calls with an API key: it is authenticated,
        # but it is not a person, so it has no account to act on.
        raise HTTPException(status_code=403,
                            detail="this endpoint needs a signed-in operator, "
                                   "not an API key")
    return user


def _require_admin(request: Request) -> Dict[str, Any]:
    user = _require(request)
    if user.get("role") != storage.ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="admin role required")
    return user


# ---- status: the only thing the login page can call -------------------------

class Credentials(BaseModel):
    username: str
    password: str


@router.get("/api/auth/status")
async def auth_status(request: Request) -> Dict[str, Any]:
    """What the UI needs to decide which screen to render. Deliberately says
    nothing an anonymous caller could not learn by trying to sign in."""
    try:
        configured = await storage.has_users()
    except Exception:  # noqa: BLE001 - a database that is still starting
        raise HTTPException(status_code=503,
                            detail="database unavailable; the backend is still starting")
    user = _current(request)
    return {
        "auth_required": True,
        "setup_required": not configured,
        "authenticated": user is not None,
        "user": user,
    }


@router.post("/api/auth/setup")
async def setup(body: Credentials, request: Request, response: Response) -> Dict[str, Any]:
    """Create the first account. The gate closes this route permanently as soon
    as one account exists, so it cannot be used to add a second."""
    if await storage.has_users():
        raise HTTPException(status_code=409, detail="setup has already been completed")
    try:
        user = await storage.create_user(body.username, body.password,
                                         role=storage.ROLE_ADMIN)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token = await storage.start_session(
        user["id"], user_agent=request.headers.get("user-agent", ""),
        source_ip=_source_ip(request))
    _set_cookie(response, request, token)
    await audit("auth.setup", username=user["username"])
    return {"user": user}


@router.post("/api/auth/login")
async def login(body: Credentials, request: Request, response: Response) -> Dict[str, Any]:
    source = _source_ip(request)
    wait = throttle.check(body.username, source)
    if wait > 0:
        raise HTTPException(status_code=429,
                            detail=f"too many failed attempts; try again in {wait}s",
                            headers={"Retry-After": str(wait)})

    user = await storage.verify_credentials(body.username, body.password)
    if user is None:
        owed = throttle.record_failure(body.username, source)
        await audit("auth.login_failed",
                    username=passwords.normalise_username(body.username), source=source)
        # One message for both "no such user" and "wrong password". Anything
        # more specific is a username oracle.
        raise HTTPException(
            status_code=401, detail="invalid username or password",
            headers={"Retry-After": str(owed)} if owed else None)

    throttle.record_success(body.username, source)
    token = await storage.start_session(
        user["id"], user_agent=request.headers.get("user-agent", ""), source_ip=source)
    _set_cookie(response, request, token)
    await audit("auth.login", username=user["username"], source=source)
    return {"user": user}


@router.post("/api/auth/logout")
async def logout(request: Request, response: Response) -> Dict[str, Any]:
    token = request.cookies.get(tokens.COOKIE_NAME, "")
    await storage.end_session(token)
    _clear_cookie(response, request)
    user = _current(request)
    if user:
        await audit("auth.logout", username=user.get("username"))
    return {"ok": True}


@router.get("/api/auth/me")
async def me(request: Request) -> Dict[str, Any]:
    return {"user": _require(request)}


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


@router.post("/api/auth/password")
async def change_password(body: PasswordChange, request: Request,
                          response: Response) -> Dict[str, Any]:
    user = _require(request)
    if await storage.verify_credentials(user["username"], body.current_password) is None:
        raise HTTPException(status_code=401, detail="current password is incorrect")
    try:
        await storage.set_password(user["id"], body.new_password,
                                   username=user["username"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Every other session for this account dies with the old password. That is
    # the point of changing it.
    await storage.end_all_sessions(user["id"])
    token = await storage.start_session(
        user["id"], user_agent=request.headers.get("user-agent", ""),
        source_ip=_source_ip(request))
    _set_cookie(response, request, token)
    await audit("auth.password_changed", username=user["username"])
    return {"ok": True, "other_sessions_ended": True}


@router.post("/api/auth/sessions/revoke")
async def revoke_sessions(request: Request, response: Response) -> Dict[str, Any]:
    """Sign out everywhere, including here."""
    user = _require(request)
    ended = await storage.end_all_sessions(user["id"])
    _clear_cookie(response, request)
    await audit("auth.sessions_revoked", username=user["username"], count=ended)
    return {"ended": ended}


# ---- accounts (admin) -------------------------------------------------------

class NewUser(BaseModel):
    username: str
    password: str
    role: str = storage.ROLE_OPERATOR


@router.get("/api/auth/users")
async def list_users(request: Request) -> Dict[str, List[Dict[str, Any]]]:
    _require_admin(request)
    return {"items": await storage.list_users()}


@router.post("/api/auth/users")
async def add_user(body: NewUser, request: Request) -> Dict[str, Any]:
    admin = _require_admin(request)
    try:
        user = await storage.create_user(body.username, body.password, role=body.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await audit("auth.user_created", username=user["username"],
                role=user["role"], by=admin["username"])
    return {"user": user}


@router.delete("/api/auth/users/{user_id}")
async def remove_user(user_id: str, request: Request) -> Dict[str, Any]:
    admin = _require_admin(request)
    if user_id == admin["id"]:
        raise HTTPException(status_code=400,
                            detail="you cannot delete the account you are signed in as")
    target = await storage.get_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="no such account")
    try:
        await storage.delete_user(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await audit("auth.user_deleted", username=target["username"], by=admin["username"])
    return {"ok": True}


# ---- what the machine credential is, for the Settings page ------------------

@router.get("/api/auth/api-key")
async def api_key_state(request: Request) -> Dict[str, Any]:
    """Whether a machine credential is configured. Never the value: it comes
    from the environment, and the operator already has it there."""
    _require(request)
    return {
        "configured": bool(settings.api_key),
        "header": policy.HEADER,
        "hint": "set SYPHAX_API_KEY in .env and restart to change it",
    }


@router.get("/api/auth/sessions")
async def my_sessions(request: Request) -> Dict[str, Any]:
    """The operator's own live sessions, so an unexpected one is visible."""
    user = _require(request)
    from app import db
    async with db.acquire() as conn:
        rows = await conn.fetch(
            "SELECT created_at, expires_at, last_seen_at, user_agent, source_ip "
            "FROM user_sessions WHERE user_id=$1 ORDER BY last_seen_at DESC",
            user["id"])
    now = time.time()
    return {"items": [{**dict(r), "expires_in": max(0, int(r["expires_at"] - now))}
                      for r in rows]}
