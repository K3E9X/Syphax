"""Authorization verification (spec §8).

Two automatic methods prove the operator controls the target:

  * DNS TXT  - a TXT record `syphax-verify=<token>` on the target host.
  * WELL_KNOWN - a file at https://host/.well-known/syphax-<token>.txt
    whose body is exactly the token.

A MANUAL method exists for signed-authorization uploads but is approved
out-of-band (not implemented here).

Both checks are deliberately strict and side-effect free. No scan, no tool,
nothing touches the target before one of these passes.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.engagements.models import Engagement, VerificationMethod

logger = logging.getLogger("syphax.engagements.verifier")


@dataclass

class VerificationResult:
    ok: bool
    method: Optional[VerificationMethod]
    detail: str


# --------------------------------------------------------------------------- #
# Comparison logic, extracted and pure.
#
# This is what decides whether an engagement is authorised against a host, so
# it must not be loose: a comparison that accepts a near-miss authorises
# scanning something the operator does not control. Kept separate from the
# resolver/HTTP plumbing so it can be tested exhaustively.

def expected_txt_value(token: str) -> str:
    """The exact TXT value an owner has to publish."""
    return f"syphax-verify={token}"


def txt_record_value(rdata: Any) -> str:
    """Read one TXT answer as a string.

    dnspython gives the chunks in .strings (bytes); a long record arrives split
    and must be joined before comparing. The str() fallback covers stubs and
    other rdata shapes, and carries surrounding quotes we have to strip.
    """
    chunks = getattr(rdata, "strings", None)
    if chunks:
        try:
            return b"".join(chunks).decode("utf-8", "replace")
        except (TypeError, AttributeError):
            pass
    return str(rdata or "").strip().strip('"')


def txt_matches(rdata: Any, token: str) -> bool:
    """Does this TXT answer prove ownership? Exact match after trimming."""
    if not token:
        return False
    return txt_record_value(rdata).strip() == expected_txt_value(token)


def well_known_matches(body: Optional[str], token: str) -> bool:
    """Does the .well-known file prove ownership?

    Trailing whitespace and a newline are fine - editors add them. Anything
    else, including the token merely appearing inside a larger page, is not a
    proof: an error page that echoes the URL would otherwise authorise us.
    """
    if not token:
        return False
    return (body or "").strip() == token


class AuthorizationVerifier:
    def __init__(self, http_timeout: float = 10.0, dns_timeout: float = 5.0) -> None:
        self.http_timeout = http_timeout
        self.dns_timeout = dns_timeout

    async def verify(self, engagement: Engagement) -> VerificationResult:
        """Try DNS first (cheap, no connection to the target app), then the
        .well-known file. Returns on the first success."""
        token = engagement.verification_token
        host = engagement.target_host

        dns = await self._verify_dns(host, token)
        if dns.ok:
            return dns

        well_known = await self._verify_well_known(host, token)
        if well_known.ok:
            return well_known

        return VerificationResult(
            ok=False,
            method=None,
            detail=(
                f"Neither DNS TXT (syphax-verify={token} on {host}) nor "
                f"https://{host}/.well-known/syphax-{token}.txt could be confirmed. "
                f"DNS: {dns.detail} | well-known: {well_known.detail}"
            ),
        )

    async def _verify_dns(self, host: str, token: str) -> VerificationResult:
        try:
            import dns.asyncresolver  # dnspython

            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = self.dns_timeout
            answers = await resolver.resolve(host, "TXT")
            for rdata in answers:
                if txt_matches(rdata, token):
                    return VerificationResult(True, VerificationMethod.DNS_TXT, "TXT record matched")
            return VerificationResult(False, None, "no matching TXT record")
        except ModuleNotFoundError:
            return VerificationResult(False, None, "dnspython not installed")
        except Exception as exc:  # noqa: BLE001 - resolver raises many types
            return VerificationResult(False, None, f"DNS lookup failed: {type(exc).__name__}")

    async def _verify_well_known(self, host: str, token: str) -> VerificationResult:
        url = f"https://{host}/.well-known/syphax-{token}.txt"
        try:
            async with httpx.AsyncClient(
                timeout=self.http_timeout, follow_redirects=False, verify=True
            ) as client:
                resp = await client.get(url)
            if resp.status_code != 200:
                return VerificationResult(False, None, f"HTTP {resp.status_code}")
            if well_known_matches(resp.text, token):
                return VerificationResult(
                    True, VerificationMethod.WELL_KNOWN, "well-known file matched"
                )
            return VerificationResult(False, None, "file content did not match token")
        except Exception as exc:  # noqa: BLE001
            return VerificationResult(False, None, f"fetch failed: {type(exc).__name__}")


_verifier: Optional[AuthorizationVerifier] = None


def get_verifier() -> AuthorizationVerifier:
    global _verifier
    if _verifier is None:
        _verifier = AuthorizationVerifier()
    return _verifier
