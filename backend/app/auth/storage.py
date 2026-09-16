"""Accounts and sessions in Postgres.

Everything that can be decided without the database lives in the sibling modules;
this one is the I/O. It is deliberately thin, because the parts worth testing are
over there.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from typing import Any, Dict, List, Optional

from app import db
from app.auth import passwords, tokens

logger = logging.getLogger("syphax.auth")

ROLE_ADMIN = "admin"
ROLE_OPERATOR = "operator"
ROLES = (ROLE_ADMIN, ROLE_OPERATOR)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    DOUBLE PRECISION NOT NULL,
    last_login_at DOUBLE PRECISION,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS user_sessions (
    token_hash   TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   DOUBLE PRECISION NOT NULL,
    expires_at   DOUBLE PRECISION NOT NULL,
    last_seen_at DOUBLE PRECISION NOT NULL,
    user_agent   TEXT,
    source_ip    TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at);
"""
db.register_schema(SCHEMA_SQL)


def _public(row) -> Dict[str, Any]:
    """A user as the API returns it. The password hash is not in here, and the
    only way it ever could be is if someone adds it to this one function."""
    return {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "created_at": row["created_at"],
        "last_login_at": row["last_login_at"],
        "disabled": bool(row["disabled"]),
    }


# ---- accounts ---------------------------------------------------------------

async def count_users() -> int:
    async with db.acquire() as conn:
        return int(await conn.fetchval("SELECT COUNT(*) FROM users") or 0)


async def has_users() -> bool:
    return await count_users() > 0


async def get_by_username(username: str) -> Optional[Dict[str, Any]]:
    u = passwords.normalise_username(username)
    async with db.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM users WHERE username=$1", u)
    return dict(row) if row else None


async def get_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    async with db.acquire() as conn:
        row = await conn.fetchrow("SELECT * FROM users WHERE id=$1", user_id)
    return _public(row) if row else None


async def list_users() -> List[Dict[str, Any]]:
    async with db.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM users ORDER BY created_at")
    return [_public(r) for r in rows]


async def create_user(username: str, password: str, *,
                      role: str = ROLE_ADMIN) -> Dict[str, Any]:
    """Create an account. Raises ValueError with every reason it was refused."""
    problems = (passwords.username_problems(username)
                + passwords.password_problems(password, username=username))
    if problems:
        raise ValueError("; ".join(problems))
    if role not in ROLES:
        raise ValueError(f"unknown role: {role}")

    u = passwords.normalise_username(username)
    user_id = uuid.uuid4().hex
    async with db.acquire() as conn:
        existing = await conn.fetchval("SELECT 1 FROM users WHERE username=$1", u)
        if existing:
            raise ValueError(f"the username {u!r} is already taken")
        await conn.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) "
            "VALUES ($1,$2,$3,$4,$5)",
            user_id, u, passwords.hash_password(password), role, time.time(),
        )
    return {"id": user_id, "username": u, "role": role,
            "created_at": time.time(), "last_login_at": None, "disabled": False}


async def set_password(user_id: str, password: str, *,
                       username: str = "") -> None:
    problems = passwords.password_problems(password, username=username)
    if problems:
        raise ValueError("; ".join(problems))
    async with db.acquire() as conn:
        await conn.execute("UPDATE users SET password_hash=$1 WHERE id=$2",
                           passwords.hash_password(password), user_id)


async def delete_user(user_id: str) -> bool:
    """Refuses to remove the last account: an install with no way in is not a
    more secure install, it is a reinstall."""
    async with db.acquire() as conn:
        total = int(await conn.fetchval("SELECT COUNT(*) FROM users") or 0)
        if total <= 1:
            raise ValueError("cannot delete the only account")
        deleted = await conn.execute("DELETE FROM users WHERE id=$1", user_id)
    return deleted.endswith("1")


# ---- signing in -------------------------------------------------------------

async def verify_credentials(username: str, password: str) -> Optional[Dict[str, Any]]:
    """Return the user on a correct password, None otherwise.

    The failure path deliberately still pays for one hash. Without it, "unknown
    username" returns in microseconds and "wrong password" takes 100ms, which
    tells an attacker which usernames exist.
    """
    row = await get_by_username(username)
    if row is None:
        passwords.verify_password(password, passwords.hash_password("decoy"))
        return None
    if row.get("disabled"):
        return None
    if not passwords.verify_password(password, row["password_hash"]):
        return None

    if passwords.needs_rehash(row["password_hash"]):
        try:
            async with db.acquire() as conn:
                await conn.execute("UPDATE users SET password_hash=$1 WHERE id=$2",
                                   passwords.hash_password(password), row["id"])
        except Exception:  # noqa: BLE001 - a failed upgrade must not fail login
            logger.warning("could not upgrade password hash for %s", row["id"])

    async with db.acquire() as conn:
        await conn.execute("UPDATE users SET last_login_at=$1 WHERE id=$2",
                           time.time(), row["id"])
    return _public(row)


# ---- sessions ---------------------------------------------------------------

async def start_session(user_id: str, *, user_agent: str = "", source_ip: str = "",
                        ttl: float = tokens.DEFAULT_TTL_SECONDS) -> str:
    """Create a session and return the token. The token is returned exactly
    once; only its fingerprint is stored."""
    token = tokens.new_token()
    now = time.time()
    async with db.acquire() as conn:
        await conn.execute(
            "INSERT INTO user_sessions "
            "(token_hash, user_id, created_at, expires_at, last_seen_at, user_agent, source_ip) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7)",
            tokens.fingerprint(token), user_id, now,
            tokens.expiry_from(now, ttl), now,
            (user_agent or "")[:300], (source_ip or "")[:64],
        )
    return token


async def resolve_session(token: str) -> Optional[Dict[str, Any]]:
    """The user this token belongs to, or None. Expired rows are deleted on
    sight rather than left to a cleanup job that may never run."""
    if not token:
        return None
    fp = tokens.fingerprint(token)
    async with db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT s.expires_at, u.* FROM user_sessions s "
            "JOIN users u ON u.id = s.user_id WHERE s.token_hash=$1", fp)
        if row is None:
            return None
        if tokens.is_expired(row["expires_at"]) or row["disabled"]:
            await conn.execute("DELETE FROM user_sessions WHERE token_hash=$1", fp)
            return None

        now = time.time()
        if tokens.should_refresh(row["expires_at"], now):
            await conn.execute(
                "UPDATE user_sessions SET expires_at=$1, last_seen_at=$2 "
                "WHERE token_hash=$3", tokens.expiry_from(now), now, fp)
    return _public(row)


async def end_session(token: str) -> None:
    if not token:
        return
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM user_sessions WHERE token_hash=$1",
                           tokens.fingerprint(token))


async def end_all_sessions(user_id: str) -> int:
    async with db.acquire() as conn:
        result = await conn.execute("DELETE FROM user_sessions WHERE user_id=$1",
                                    user_id)
    try:
        return int(result.rsplit(" ", 1)[-1])
    except ValueError:
        return 0


async def purge_expired() -> int:
    async with db.acquire() as conn:
        result = await conn.execute("DELETE FROM user_sessions WHERE expires_at <= $1",
                                    time.time())
    try:
        return int(result.rsplit(" ", 1)[-1])
    except ValueError:
        return 0


# ---- unattended provisioning ------------------------------------------------

async def bootstrap_from_env() -> Optional[str]:
    """Seed the first account from SYPHAX_ADMIN_USER / SYPHAX_ADMIN_PASSWORD.

    Exists so a VM can be provisioned by a script without a human opening the
    setup page. It runs ONLY when there is no account at all, so it can never
    reset or overwrite an existing operator's password - which is the failure
    mode that would turn a convenience into a way in.
    """
    username = (os.environ.get("SYPHAX_ADMIN_USER") or "").strip()
    password = os.environ.get("SYPHAX_ADMIN_PASSWORD") or ""
    if not username or not password:
        return None
    if await has_users():
        return None
    try:
        user = await create_user(username, password, role=ROLE_ADMIN)
    except ValueError as exc:
        logger.error("SYPHAX_ADMIN_USER/PASSWORD rejected: %s", exc)
        return None
    logger.info("bootstrapped operator account %r from the environment", user["username"])
    return user["id"]
