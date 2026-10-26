"""The shared exploitation blackboard: where agents post what they find.

This is the coordination backbone the agentic rework is built on, and it is a
deliberate copy of the one useful idea behind the multi-agent exploit swarms
(OpenAI's Black Hat 2026 agents posted vulns and exploits to a shared message
board; xOffense/PentestAgent coordinate recon/scan/exploit agents the same
way): instead of each analyser finding something and dropping it on the floor,
it POSTS a chainable FACT here, and every later step - the strategist, the
exploiters, the chain builder - READS them. The kill chain then emerges from
what is on the board rather than being scripted in advance.

It is also what bridges BLACK BOX and GREY BOX. A credential found with no
prior access (default creds, a secret in a JS bundle, a leaked token) lands
here as a `credential`/`secret`/`session` lead, and from that point the run has
an identity it did not start with - the later scanners can use it exactly as if
the operator had supplied it. A black-box find becomes a grey-box capability,
automatically, because both halves read the same board.

Durable (Postgres) and engagement-scoped, so it survives a restart and is the
one place to answer "what does this run know that it could act on". A lead is
data an analyser wrote, never an instruction: a consumer decides what to do
with it, under the same scope and capability gates as everything else.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from app import db

logger = logging.getLogger("syphax.blackboard")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS leads (
    id               BIGSERIAL PRIMARY KEY,
    engagement_id    TEXT NOT NULL,
    kind             TEXT NOT NULL,
    value            TEXT NOT NULL,
    data_json        TEXT,
    source           TEXT,
    confidence       DOUBLE PRECISION NOT NULL DEFAULT 0.5,
    consumed_by_json TEXT,
    created_at       DOUBLE PRECISION NOT NULL,
    UNIQUE (engagement_id, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_leads_engagement ON leads(engagement_id, kind);
"""

db.register_schema(SCHEMA_SQL)


# ---------------------------------------------------------------------------
# Well-known lead kinds. A producer may post any string, but these are the
# chainable facts the strategist and the exploiters key off, so they are named
# in one place. Roughly ordered by how much they unlock.

CREDENTIAL = "credential"        # a username:password that was accepted
SECRET = "secret"                # an API key / token found in code or traffic
SESSION = "session"              # a cookie / bearer / JWT obtained at runtime
PRIVILEGE = "privilege"          # an elevated context reached (uid=0, admin)
UNAUTH_ENDPOINT = "unauth_endpoint"  # reachable with no credential
INJECTABLE = "injectable"        # a parameter confirmed/suspected injectable
OBJECT_ID = "object_id"          # an enumerable identifier (IDOR surface)
API_SCHEMA = "api_schema"        # a schema (published or synthesised)
CVE = "cve"                      # a fingerprinted CVE with a known exploit
HOST = "host"                    # a newly reached host / subdomain

# The kinds that grant the run access it did not start with - the black-box ->
# grey-box bridge. The strategist weights these highest.
IDENTITY_KINDS = frozenset({CREDENTIAL, SECRET, SESSION, PRIVILEGE})


@dataclass
class Lead:
    """One chainable fact on the board."""
    id: int
    engagement_id: str
    kind: str
    value: str
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = ""
    confidence: float = 0.5
    consumed_by: List[str] = field(default_factory=list)
    created_at: float = 0.0

    @property
    def grants_identity(self) -> bool:
        return self.kind in IDENTITY_KINDS

    def to_public(self) -> Dict[str, Any]:
        # The value of an identity lead is redacted for the UI: the board
        # proves the run HAS a credential, it does not reprint it.
        shown = self.value
        if self.grants_identity and self.value:
            shown = _redact(self.value)
        return {
            "id": self.id, "kind": self.kind, "value": shown,
            "source": self.source, "confidence": round(self.confidence, 2),
            "grants_identity": self.grants_identity,
            "consumed_by": self.consumed_by, "created_at": self.created_at,
        }


def _redact(value: str) -> str:
    """Keep a credential recognisable without reprinting it."""
    text = str(value or "")
    if ":" in text:          # user:pass -> user:****
        user, _, _pw = text.partition(":")
        return f"{user}:****"
    if len(text) <= 6:
        return "****"
    return text[:3] + "…" + text[-2:]


class Blackboard:
    """Post/read the shared board for one engagement. All I/O; the reasoning
    about what the leads MEAN lives in the strategist, not here."""

    def __init__(self, engagement_id: str) -> None:
        self.engagement_id = engagement_id

    async def post(self, kind: str, value: str, *, data: Optional[Dict[str, Any]] = None,
                   source: str = "", confidence: float = 0.5) -> bool:
        """Add a lead. Deduplicated on (kind, value): a fact two tools find is
        one lead, and re-posting it only lifts its confidence. Returns True if
        the lead is new (so a caller can act on it exactly once). Never raises
        - the board is an enhancement, a failed post must not fail a scan."""
        value = (value or "").strip()
        if not kind or not value:
            return False
        confidence = max(0.0, min(1.0, float(confidence)))
        now = time.time()
        payload = json.dumps(data or {}, default=str)
        try:
            async with db.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    INSERT INTO leads (engagement_id, kind, value, data_json,
                                       source, confidence, consumed_by_json,
                                       created_at)
                    VALUES ($1,$2,$3,$4,$5,$6,'[]',$7)
                    ON CONFLICT (engagement_id, kind, value) DO UPDATE
                        SET confidence = GREATEST(leads.confidence,
                                                  EXCLUDED.confidence),
                            data_json = EXCLUDED.data_json
                    RETURNING (xmax = 0) AS inserted
                    """,
                    self.engagement_id, kind, value, payload, source,
                    confidence, now,
                )
        except Exception:  # noqa: BLE001 - the board never fails its producer
            logger.exception("[%s] could not post %s lead", self.engagement_id, kind)
            return False
        new = bool(row and row["inserted"])
        if new:
            await self._announce(kind, value, source)
        return new

    async def leads(self, kind: Optional[str] = None) -> List[Lead]:
        """Every lead for this engagement, newest first, optionally one kind."""
        try:
            async with db.acquire() as conn:
                if kind:
                    rows = await conn.fetch(
                        "SELECT * FROM leads WHERE engagement_id=$1 AND kind=$2 "
                        "ORDER BY confidence DESC, id DESC",
                        self.engagement_id, kind)
                else:
                    rows = await conn.fetch(
                        "SELECT * FROM leads WHERE engagement_id=$1 "
                        "ORDER BY confidence DESC, id DESC",
                        self.engagement_id)
        except Exception:  # noqa: BLE001
            logger.exception("[%s] could not read leads", self.engagement_id)
            return []
        return [_row_to_lead(r) for r in rows]

    async def identities(self) -> List[Lead]:
        """Credentials, secrets, sessions, privileges - what the run can now
        act AS that it could not when it started. The grey-box bridge."""
        return [lead for lead in await self.leads() if lead.grants_identity]

    async def mark_consumed(self, lead_id: int, by: str) -> None:
        """Record that an agent acted on a lead, so the strategist does not
        keep proposing the same step. Never raises."""
        try:
            async with db.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT consumed_by_json FROM leads WHERE id=$1 "
                    "AND engagement_id=$2", lead_id, self.engagement_id)
                if row is None:
                    return
                try:
                    consumed = json.loads(row["consumed_by_json"] or "[]")
                except json.JSONDecodeError:
                    consumed = []
                if by in consumed:
                    return
                consumed.append(by)
                await conn.execute(
                    "UPDATE leads SET consumed_by_json=$1 WHERE id=$2",
                    json.dumps(consumed), lead_id)
        except Exception:  # noqa: BLE001
            logger.debug("could not mark lead %s consumed", lead_id)

    async def _announce(self, kind: str, value: str, source: str) -> None:
        """Put a new lead on the live console - the 'message board' the
        operator (and later the strategist) watches fill. Identity values are
        redacted."""
        try:
            from app import events
            shown = _redact(value) if kind in IDENTITY_KINDS else value
            await events.emit(
                self.engagement_id, events.THOUGHT,
                f"Lead on the board: {kind} = {shown}"
                + (f" (via {source})" if source else ""),
                level=events.LEVEL_VERBOSE, kind=kind, source=source)
        except Exception:  # noqa: BLE001 - announcing never fails a post
            logger.debug("could not announce lead")


def _row_to_lead(r) -> Lead:
    try:
        data = json.loads(r["data_json"]) if r["data_json"] else {}
    except (json.JSONDecodeError, TypeError):
        data = {}
    try:
        consumed = json.loads(r["consumed_by_json"]) if r["consumed_by_json"] else []
    except (json.JSONDecodeError, TypeError):
        consumed = []
    return Lead(
        id=r["id"], engagement_id=r["engagement_id"], kind=r["kind"],
        value=r["value"], data=data if isinstance(data, dict) else {},
        source=r["source"] or "", confidence=float(r["confidence"]),
        consumed_by=consumed if isinstance(consumed, list) else [],
        created_at=float(r["created_at"]),
    )


# ---------------------------------------------------------------------------
# Deriving leads from findings.
#
# Every analyser stores through save_analysis_job and every tool finding goes
# through Executor._ingest_finding, so those two are the only places a lead
# needs to be derived - which is why the mapping lives here, once, instead of
# being hand-wired into twenty analysers that would each drift.
#
# What this mapping may post is deliberately limited to NON-IDENTITY leads.
# A credential, session or privilege lead claims the run can now act AS
# someone, the strategist says so on the console, and the grey-box scanners
# believe it - so that claim is never derived from a vuln_class string. It is
# posted only where the code genuinely holds the material (auth_brute, which
# had a password accepted). A mechanical mapping that guessed at identity
# would manufacture exactly the false `confirmed` this whole design exists to
# avoid.

# The target of this finding is a reachable injection point.
_INJECTION_CLASSES = frozenset({
    "sql_injection", "nosql_injection", "command_injection", "ssti", "lfi",
    "xxe", "ssrf", "crlf_injection", "open_redirect", "xss",
})
# The target answered with something it should not have, and no credential was
# used to get it.
_UNAUTH_CLASSES = frozenset({"exposed_resource", "exposed_bucket", "auth"})
# A component with a known, published weakness - the shortest route to proof.
_CVE_CLASSES = frozenset({"cve", "cms_vulnerability", "vulnerable_component",
                          # A nuclei rce template always names its CVE or its
                          # template id, so an RCE hit is a published weakness
                          # rather than a parameter to inject into.
                          "rce"})

# Tools whose output IS a confirmation. sqlmap prints an injection point only
# once it has one; dalfox reports type "V" for verified; commix and nosqli are
# the same. None of them emits a maybe, so a finding from one of them does not
# need a confidence field to be worth chasing - and it does not HAVE one at
# this stage, which is the bug this fixes.
_CONFIRMING_TOOLS = frozenset({"sqlmap", "dalfox", "commix", "nosqli"})

# A matched template is deterministic, so a nuclei hit carries its severity as
# its weight. info/low stays below the floor: that is inventory.
_SEVERITY_CONFIDENCE = {"critical": 0.85, "high": 0.8, "medium": 0.65,
                        "low": 0.4, "info": 0.2}

# Below this, a finding is a guess, and a guess must not steer the plan: the
# strategist would spend the exploitation budget chasing noise. `confirmed`
# always passes, whatever its stated confidence.
_MIN_CONFIDENCE = 0.6


def lead_confidence(finding, tool: str = "") -> float:
    """How much this finding is worth chasing, 0..1. Pure.

    A RAW tool finding carries no confidence: `status` and `confidence` are
    assigned later, by validation. Reading only the metadata therefore scored
    every sqlmap, dalfox and nuclei finding at 0.0 - below the floor - so the
    board got nothing at all from the tool half of the run, which is most of
    it. The strategist then had no advice to give on a run where the scanners
    had confirmed real injections.
    """
    meta = getattr(finding, "metadata", None) or {}
    explicit = meta.get("confidence")
    if explicit is not None:
        try:
            return max(0.0, min(1.0, float(explicit)))
        except (TypeError, ValueError):
            pass
    if tool in _CONFIRMING_TOOLS:
        return 0.9
    severity = str(getattr(finding, "severity", "") or "info").lower()
    return _SEVERITY_CONFIDENCE.get(severity, 0.2)


def lead_for_finding(finding, tool: str = "") -> Optional[tuple]:
    """(kind, value, data) for a finding, or None if it chains to nothing.

    `tool` is what produced it. It matters because a raw tool finding has no
    vuln_class either - the class comes from the tool name, exactly as
    validation derives it (classes.vuln_class_of). Without it sqlmap's output
    had class None and chained to nothing.

    Pure, so the mapping is testable without a database.
    """
    meta = getattr(finding, "metadata", None) or {}
    try:
        from app.validation.classes import vuln_class_of
        vuln_class = str(vuln_class_of(finding, tool) or "").lower()
    except Exception:  # noqa: BLE001
        vuln_class = str(meta.get("vuln_class") or "").lower()
    if vuln_class in ("", "unknown"):
        return None
    status = str(meta.get("status") or "").lower()
    confidence = lead_confidence(finding, tool)
    if status != "confirmed" and confidence < _MIN_CONFIDENCE:
        return None

    target = str(getattr(finding, "target", "") or "").strip()

    # A named CVE first, whatever the class: it is one fact about a component,
    # not one per endpoint it was seen on.
    cve = str(meta.get("cve") or meta.get("cve_id") or "").strip()
    if cve and vuln_class in _CVE_CLASSES | _INJECTION_CLASSES:
        return (CVE, cve, {"vuln_class": vuln_class, "target": target})

    if vuln_class in _INJECTION_CLASSES and target:
        return (INJECTABLE, target,
                {"vuln_class": vuln_class, "param": meta.get("parameter"),
                 "tool": tool})
    if vuln_class in _UNAUTH_CLASSES and target:
        return (UNAUTH_ENDPOINT, target, {"vuln_class": vuln_class})
    if vuln_class in _CVE_CLASSES:
        value = str(meta.get("template_id") or "").strip() or str(
            getattr(finding, "title", "")).strip()
        if value:
            return (CVE, value, {"vuln_class": vuln_class, "target": target})
    if vuln_class == "secret_exposure" and meta.get("verified"):
        # A secret the provider itself authenticated. The run knows a live key
        # of this type exists here; it does NOT hold the key - the wrapper
        # redacts it and keeps no copy - so `usable` says so plainly rather
        # than letting a consumer assume it can authenticate with this.
        detector = str(meta.get("detector") or "secret")
        where = str(meta.get("location") or target or "")
        return (SECRET, f"{detector}@{where}",
                {"detector": detector, "location": where, "usable": False,
                 "verified": True})
    return None


async def post_from_finding(engagement_id: str, finding, *,
                            source: str = "") -> Optional[str]:
    """Derive a lead from a finding and post it. Returns the kind posted, or
    None. Never raises - this runs inside every ingest path."""
    try:
        derived = lead_for_finding(finding, source)
    except Exception:  # noqa: BLE001
        logger.debug("could not derive a lead from a finding")
        return None
    if derived is None:
        return None
    kind, value, data = derived
    meta = getattr(finding, "metadata", None) or {}
    confidence = lead_confidence(finding, source)
    posted = await Blackboard(engagement_id).post(
        kind, value, data=data, source=source or str(meta.get("tool") or ""),
        confidence=confidence)
    return kind if posted else None
