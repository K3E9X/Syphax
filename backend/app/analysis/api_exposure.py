"""What the API hands back: secrets, credentials and personal data.

Nothing inspected API response BODIES. trufflehog and jsluice look at source
and JavaScript; js_recon mines bundles. But the endpoint that returns the user
list with a password hash, an internal token or three hundred email addresses
was never read - which is why a run could finish with "no secret found" while
the API was handing them out.

Two questions, both answered read-only on captured responses:

  * excessive data exposure - the response carries fields no client needs
    (password/hash, token, secret, private key, internal flags);
  * personal data - emails, phone numbers, IBANs, card numbers (Luhn-checked
    so a random digit string is not a "credit card"), French NIR.

Volume matters: one email in a profile response is the product working; two
hundred in a list endpoint is a bulk disclosure, and the severity follows.

Stored as a synthetic job (tool="api_exposure").
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app import db
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.api_exposure")

MAX_FLOWS = 600
MAX_BODY = 300_000
BULK_THRESHOLD = 20          # this many PII values = a bulk disclosure

# Field names a response should never carry to a client.
_SECRET_FIELDS = {
    "password", "passwd", "pwd", "password_hash", "passwordhash", "hashed_password",
    "secret", "client_secret", "api_key", "apikey", "api_secret", "access_key",
    "private_key", "privatekey", "secret_key", "token_secret", "session_secret",
    "refresh_token", "access_token", "id_token", "auth_token", "jwt_secret",
    "aws_secret_access_key", "connection_string", "dsn", "db_password",
}
# Fields that are personal data.
_PII_FIELDS = {
    "email", "e_mail", "mail", "phone", "telephone", "mobile", "msisdn",
    "ssn", "social_security", "nir", "iban", "bic", "credit_card", "card_number",
    "pan", "cvv", "date_of_birth", "dob", "birthdate", "birth_date",
    "address", "street", "postal_code", "zipcode", "national_id", "passport",
    "tax_id", "salary", "first_name", "last_name", "full_name",
}

_RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b")
_RE_IBAN = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_RE_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_RE_NIR = re.compile(r"\b[12]\d{2}(?:0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b")
_RE_PHONE_FR = re.compile(r"\b(?:\+33|0)[1-9](?:[ .-]?\d{2}){4}\b")


def luhn_ok(digits: str) -> bool:
    """A card number passes the Luhn check. Keeps random digit runs out."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def collect_field_names(obj: Any, out: Set[str], depth: int = 0) -> None:
    """Every key in a nested JSON document, lowercased."""
    if depth > 8:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k).strip().lower())
            collect_field_names(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:200]:
            collect_field_names(v, out, depth + 1)


def secret_fields_in(names: Set[str]) -> List[str]:
    return sorted(n for n in names if n in _SECRET_FIELDS)


def pii_fields_in(names: Set[str]) -> List[str]:
    return sorted(n for n in names if n in _PII_FIELDS)


def pii_values(body: str) -> Dict[str, int]:
    """Count the personal data actually present in the body, by kind."""
    counts: Dict[str, int] = {}
    emails = set(_RE_EMAIL.findall(body))
    # Asset filenames and example addresses are not a disclosure.
    emails = {e for e in emails
              if not e.lower().endswith((".png", ".jpg", ".svg", ".webp"))
              and "example.com" not in e.lower()}
    if emails:
        counts["email"] = len(emails)
    ibans = {i for i in _RE_IBAN.findall(body)}
    if ibans:
        counts["iban"] = len(ibans)
    cards = {c for c in _RE_CARD.findall(body) if luhn_ok(c)}
    if cards:
        counts["card_number"] = len(cards)
    nirs = set(_RE_NIR.findall(body))
    if nirs:
        counts["french_nir"] = len(nirs)
    phones = set(_RE_PHONE_FR.findall(body))
    if phones:
        counts["phone"] = len(phones)
    return counts


def severity_for_pii(counts: Dict[str, int]) -> str:
    """Cards/IBAN/NIR are sensitive at any volume; contact data scales."""
    if any(k in counts for k in ("card_number", "iban", "french_nir")):
        return "high"
    total = sum(counts.values())
    if total >= BULK_THRESHOLD:
        return "medium"
    return "low"


async def analyze_api_exposure(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                'SELECT url, host, status_code, response_body, response_content_type '
                'FROM flows WHERE response_body IS NOT NULL '
                'ORDER BY "timestamp" DESC LIMIT $1', MAX_FLOWS)
    except Exception:  # noqa: BLE001
        return {"skipped": 1}

    findings: List[Finding] = []
    seen: Set[Tuple[str, str, str]] = set()

    for r in rows:
        host = (r["host"] or "").lower()
        ctype = (r["response_content_type"] or "").lower()
        if not host or not eng.host_in_scope(host) or "json" not in ctype:
            continue
        status = r["status_code"]
        if status is not None and not 200 <= status < 300:
            continue
        body = _text(r["response_body"])
        if not body.strip():
            continue
        url = r["url"] or ""
        path = urlparse(url).path or "/"

        try:
            doc = json.loads(body)
        except (TypeError, ValueError):
            doc = None

        names: Set[str] = set()
        if doc is not None:
            collect_field_names(doc, names)

        secrets = secret_fields_in(names)
        if secrets:
            _add(findings, seen, host, path, "secret_fields",
                 "high", f"API returns secret fields on {path}",
                 "The response carries fields a client never needs - a credential "
                 "or key is being serialised straight out of the data model.",
                 "fields: " + ", ".join(secrets), url,
                 "excessive_data_exposure", fields=secrets)

        counts = pii_values(body)
        if counts:
            detail = ", ".join(f"{k}x{v}" for k, v in sorted(counts.items()))
            _add(findings, seen, host, path, "pii_values",
                 severity_for_pii(counts),
                 f"Personal data in the API response on {path}",
                 "The endpoint returns personal data. Check the caller is entitled "
                 "to all of it: a list endpoint handing out contact details in bulk "
                 "is a disclosure even when each record is legitimate on its own.",
                 detail, url, "pii_exposure", counts=counts,
                 pii_fields=pii_fields_in(names))

    if findings:
        await save_analysis_job(engagement_id, "api_exposure", findings,
                                target=eng.target_host or eng.target_url)
    return {"findings": len(findings)}


def _add(findings: List[Finding], seen: Set[Tuple[str, str, str]], host: str,
         path: str, kind: str, sev: str, title: str, desc: str, evidence: str,
         url: str, vclass: str, **meta: Any) -> None:
    key = (host, path, kind)
    if key in seen:
        return
    seen.add(key)
    findings.append(Finding(
        severity=sev, title=title, description=desc, target=url,
        evidence=evidence[:600],
        metadata={"vuln_class": vclass, "host": host, "path": path,
                  "tool": "api_exposure", **meta}))


def _text(body: Any) -> str:
    if not body:
        return ""
    if isinstance(body, memoryview):
        body = body.tobytes()
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:MAX_BODY]).decode("utf-8", errors="replace")
    return str(body)[:MAX_BODY]
