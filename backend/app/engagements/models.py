"""Engagement domain model.

An *engagement* is the unit of authorized testing: a verified target + its
scope + the budget the operator allots. Nothing scans until the engagement
reaches the AUTHORIZED state via a proof of ownership (spec §8).
"""
from __future__ import annotations

import enum
import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


class EngagementStatus(str, enum.Enum):
    # Created, target recorded, awaiting an authorization proof.
    PENDING_AUTHORIZATION = "pending_authorization"
    # Ownership verified; scans may run.
    AUTHORIZED = "authorized"
    # Operator stopped it / it finished.
    CLOSED = "closed"
    # Verification explicitly failed or was revoked.
    REVOKED = "revoked"


class VerificationMethod(str, enum.Enum):
    ATTESTATION = "attestation"   # operator attested they own/may test the target
    DNS_TXT = "dns_txt"            # TXT record syphax-verify=<token> on the apex
    WELL_KNOWN = "well_known"      # GET https://host/.well-known/syphax-<token>.txt
    MANUAL = "manual"             # operator uploaded signed written authorization


def _new_token() -> str:
    # URL/DNS-safe, short enough to paste, long enough to be unforgeable.
    return secrets.token_hex(16)


def new_engagement_id() -> str:
    return f"eng_{int(time.time() * 1000)}_{secrets.token_hex(3)}"


@dataclass
class Engagement:
    id: str
    target_url: str
    target_host: str
    scope_hosts: List[str]            # allow-list of hostnames in scope
    status: EngagementStatus
    verification_token: str
    created_at: float
    title: str = ""
    notes: str = ""
    verification_method: Optional[VerificationMethod] = None
    verified_at: Optional[float] = None
    closed_at: Optional[float] = None
    # Budget guardrails (enforced by the orchestrator later).
    budget_requests: Optional[int] = None
    budget_seconds: Optional[int] = None
    # Operator attestation (the legal checkbox) - timestamp when accepted.
    attested_at: Optional[float] = None
    # Pause before the exploitation phase and wait for human approval.
    require_exploit_approval: bool = False
    # Active exploitation: after a tool confirms an injection, PROVE impact by
    # running a benign, read-only command (RCE/SQLi). Off by default and
    # double-gated with the exploitation approval. Never destructive.
    allow_active_exploit: bool = False
    # Sub-flag: also allow OS command execution *through SQLi* (sqlmap --os-cmd).
    allow_sql_os_cmd: bool = False
    # Sub-flag: prove a DATA BREACH by dumping a small, bounded sample (<=3 rows)
    # of likely-sensitive tables via a confirmed SQLi. Off by default.
    allow_data_proof: bool = False
    # Grey-box: HTTP headers of a SECOND identity (e.g. Cookie / Authorization),
    # used to prove IDOR/BOLA by replaying a captured request as another user.
    # List of {"name": ..., "value": ...}. Never returned to the client.
    secondary_auth: List[Dict[str, str]] = field(default_factory=list)
    # Authenticated scanning: HTTP headers of the PRIMARY identity, injected
    # into every active scanner so it tests behind the login. Never returned.
    primary_auth: List[Dict[str, str]] = field(default_factory=list)
    # How the tools present themselves on the wire for THIS engagement. Empty
    # means "use the environment" (USER_AGENT_MODE), which is what every
    # existing engagement has. See app/scans/identity.py for the choices; it is
    # about tool fingerprinting and about matching what the client expects to
    # see, not about evading anything - the source IP and the request rate are
    # in their logs either way.
    user_agent_mode: str = ""
    user_agent: str = ""

    @property
    def grey_box(self) -> bool:
        return bool(self.secondary_auth)

    @property
    def authenticated(self) -> bool:
        return bool(self.primary_auth)

    # ----- factory -----
    @classmethod
    def create(
        cls,
        target_url: str,
        *,
        title: str = "",
        notes: str = "",
        scope_hosts: Optional[List[str]] = None,
        budget_requests: Optional[int] = None,
        budget_seconds: Optional[int] = None,
        attested: bool = False,
        require_exploit_approval: bool = False,
        allow_active_exploit: bool = False,
        allow_sql_os_cmd: bool = False,
        allow_data_proof: bool = False,
        user_agent_mode: str = "",
        user_agent: str = "",
        secondary_auth: Optional[List[Dict[str, str]]] = None,
        primary_auth: Optional[List[Dict[str, str]]] = None,
    ) -> "Engagement":
        host = _host_of(target_url)
        scope = scope_hosts or [host]
        # Always include the primary host in scope.
        if host not in scope:
            scope = [host] + scope
        # This tool targets domains the operator owns. The legal attestation is
        # the authorization: when attested, the engagement is authorized
        # immediately (verification_method = "attestation"). The DNS /
        # .well-known proof flow still exists (verifier + /verify endpoint) for
        # cases where you want third-party-style proof, but it is not required.
        now = time.time()
        return cls(
            id=new_engagement_id(),
            target_url=target_url,
            target_host=host,
            scope_hosts=scope,
            status=EngagementStatus.AUTHORIZED if attested else EngagementStatus.PENDING_AUTHORIZATION,
            verification_token=_new_token(),
            verification_method=VerificationMethod.ATTESTATION if attested else None,
            verified_at=now if attested else None,
            created_at=now,
            title=title or host,
            notes=notes,
            budget_requests=budget_requests,
            budget_seconds=budget_seconds,
            attested_at=now if attested else None,
            require_exploit_approval=require_exploit_approval,
            allow_active_exploit=allow_active_exploit,
            allow_sql_os_cmd=allow_sql_os_cmd,
            allow_data_proof=allow_data_proof,
            user_agent_mode=(user_agent_mode or "").strip().lower(),
            user_agent=(user_agent or "").strip(),
            secondary_auth=list(secondary_auth or []),
            primary_auth=list(primary_auth or []),
        )

    # ----- scope check -----
    def host_in_scope(self, host: str) -> bool:
        host = (host or "").lower().strip()
        for allowed in self.scope_hosts:
            allowed = allowed.lower().strip()
            if host == allowed:
                return True
            # allow subdomains of an in-scope apex when the entry starts with '.'
            if allowed.startswith(".") and host.endswith(allowed):
                return True
        return False

    def url_in_scope(self, url: str) -> bool:
        return self.host_in_scope(_host_of(url))

    # ----- serialization -----
    def to_public(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["verification_method"] = (
            self.verification_method.value if self.verification_method else None
        )
        # The token itself is needed by the UI to render the challenge, but
        # never leak it once authorized.
        if self.status != EngagementStatus.PENDING_AUTHORIZATION:
            d["verification_token"] = None
        # Never leak credentials; expose only flags.
        d.pop("secondary_auth", None)
        d.pop("primary_auth", None)
        d["grey_box"] = self.grey_box
        d["authenticated"] = self.authenticated
        return d

    def challenge(self) -> Dict[str, Any]:
        """How the operator proves ownership. Shown in the UI."""
        token = self.verification_token
        return {
            "token": token,
            "methods": {
                "dns_txt": {
                    "record_name": self.target_host,
                    "record_type": "TXT",
                    "record_value": f"syphax-verify={token}",
                    "instructions": (
                        f"Add a TXT record on {self.target_host} with value "
                        f"'syphax-verify={token}', then verify."
                    ),
                },
                "well_known": {
                    "url": f"https://{self.target_host}/.well-known/syphax-{token}.txt",
                    "file_content": token,
                    "instructions": (
                        f"Serve a file at "
                        f"https://{self.target_host}/.well-known/syphax-{token}.txt "
                        f"containing exactly '{token}', then verify."
                    ),
                },
            },
        }


def _host_of(url: str) -> str:
    if "://" in url:
        return (urlparse(url).hostname or url).lower()
    return url.split("/", 1)[0].lower()


def scope_to_json(scope: List[str]) -> str:
    return json.dumps(scope)


def scope_from_json(raw: Optional[str]) -> List[str]:
    if not raw:
        return []
    try:
        v = json.loads(raw)
        return [str(x) for x in v] if isinstance(v, list) else []
    except json.JSONDecodeError:
        return []
