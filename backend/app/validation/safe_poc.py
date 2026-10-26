"""Safe proof-of-exploit HTTP helper (spec §7 safety layer).

Hard policy, enforced here so no validator can bypass it:
  * GET / HEAD only - never a state-changing method.
  * single request per call, short timeout, capped body read.
  * the target host MUST be inside the engagement scope allow-list
    (prevents SSRF-pivot / hitting third parties).
  * benign markers only; we never send destructive payloads.

This is the only place validators are allowed to touch the target.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("syphax.validation.safe_poc")

MAX_BODY_BYTES = 256 * 1024
TIMEOUT = 10.0
ALLOWED_METHODS = {"GET", "HEAD"}


@dataclass
class SafeResponse:
    status_code: int
    headers: dict
    text: str
    url: str


@dataclass(frozen=True)
class Identity:
    """The HTTP identity a request is made AS.

    syphax could always test as a logged-in user: scans/runner injects
    `engagement.primary_auth` into every tool it launches. The analysers could
    not - SafePoC and ProbeClient took `in_scope` and nothing else, so each one
    had to remember to pass headers per call, and none of the ten did. The
    result was a split brain: an operator who filled in the credentials got an
    authenticated nuclei and an ANONYMOUS mass-assignment, api-sequences,
    rate-limit and access-control pass - exactly the checks a credential is
    worth having for.

    Empty is a real state (black box, nothing supplied) and behaves as it
    always did.
    """
    headers: Tuple[Tuple[str, str], ...] = ()
    label: str = ""

    @classmethod
    def from_auth(cls, auth: Optional[Iterable[dict]],
                  label: str = "") -> "Identity":
        pairs = []
        for entry in auth or []:
            name = str((entry or {}).get("name") or "").strip()
            value = str((entry or {}).get("value") or "").strip()
            if name and value:
                pairs.append((name, value))
        return cls(headers=tuple(pairs), label=label)

    @property
    def present(self) -> bool:
        return bool(self.headers)

    def merge(self, extra: Optional[dict]) -> Optional[dict]:
        """This identity's headers plus the caller's, caller wins on a clash.

        The caller's own headers do NOT replace the identity - that is the
        whole point. mass_assignment and api_sequences pass
        {"Content-Type": "application/json"} and were therefore probing
        anonymously; they are authenticated now without either of them
        changing.
        """
        merged = {name: value for name, value in self.headers}
        merged.update({k: v for k, v in (extra or {}).items()})
        return merged or None


def identity_for(engagement, *, secondary: bool = False) -> Identity:
    """The engagement's primary identity, or its second one.

    `secondary` is the other account: what proves a cross-user read rather
    than just reaching the endpoint.
    """
    auth = getattr(engagement, "secondary_auth" if secondary
                   else "primary_auth", None)
    return Identity.from_auth(auth, label=("second identity" if secondary
                                           else "primary identity"))


class ScopeError(RuntimeError):
    pass


class PolicyError(RuntimeError):
    pass


class SafePoC:
    """`in_scope` is a predicate (host) -> bool, supplied by the engagement.

    `identity` is sent on every request unless the caller asks for
    `anonymous=True`. Authenticated by default is deliberate: the scanners that
    produced these findings ran authenticated, so re-checking them anonymously
    compared two different things - an authenticated-only path would answer
    401/404 to the validator and be filed as a false positive.
    """

    def __init__(self, in_scope: Callable[[str], bool],
                 identity: Optional[Identity] = None) -> None:
        self._in_scope = in_scope
        self.identity = identity or Identity()

    def _check(self, method: str, url: str) -> None:
        if method.upper() not in ALLOWED_METHODS:
            raise PolicyError(f"method {method} not allowed by safe-PoC policy")
        host = urlparse(url).hostname or ""
        if not host or not self._in_scope(host):
            raise ScopeError(f"host '{host}' is out of engagement scope")

    async def fetch(
        self, url: str, *, method: str = "GET", headers: Optional[dict] = None,
        anonymous: bool = False
    ) -> Optional[SafeResponse]:
        """One request. The identity rides along unless `anonymous` is set.

        `anonymous=True` is how a cross-identity comparison asks for the
        unauthenticated side of it (access_control and logic replay a captured
        request with no credential to see whether it still answers). It is a
        named argument rather than an empty headers dict because "send
        nothing" and "send only these" are different intentions and were
        indistinguishable.
        """
        self._check(method, url)
        headers = headers if anonymous else self.identity.merge(headers)
        try:
            async with httpx.AsyncClient(
                timeout=TIMEOUT, follow_redirects=False, verify=False
            ) as client:
                resp = await client.request(method, url, headers=headers or None)
                body = b""
                if method.upper() == "GET":
                    # Read at most MAX_BODY_BYTES.
                    body = resp.content[:MAX_BODY_BYTES]
                return SafeResponse(
                    status_code=resp.status_code,
                    headers={k.lower(): v for k, v in resp.headers.items()},
                    text=body.decode("utf-8", errors="replace"),
                    url=str(resp.url),
                )
        except (ScopeError, PolicyError):
            raise
        except Exception as exc:  # noqa: BLE001
            logger.debug("safe-PoC fetch failed for %s: %s", url, exc)
            return None
