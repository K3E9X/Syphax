"""Stage a third-party PoC for review.

The missing link between github_poc_search(), which hands you a repository URL,
and run_poc(), which executes something. Staging fetches the code, inspects it,
stores it against the finding, and stops. Nothing here runs anything.

The state machine is the feature:

    staged ──approve──> approved ──run──> executed
       │
       └──reject──> rejected

`staged` is a dead end until a human moves it. Not a default-allow with a
cancel button, not a timeout that proceeds - a person reads the code and says
yes, or it never runs. That gate exists because the inspection upstream can
only report what it recognises; the reviewer is the part that catches what it
does not.

Fetching is read-only, from GitHub, over the API. Files are size-capped and
extension-restricted, because "fetch whatever the repo contains" is how you end
up staging a 200MB binary or a shell script that was never meant to be read as
one.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app import db

logger = logging.getLogger("syphax.sandbox.staging")

STATUS_STAGED = "staged"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_EXECUTED = "executed"

# Only these can move to these.
TRANSITIONS = {
    STATUS_STAGED: {STATUS_APPROVED, STATUS_REJECTED},
    STATUS_APPROVED: {STATUS_EXECUTED, STATUS_REJECTED},
    STATUS_REJECTED: set(),
    STATUS_EXECUTED: set(),
}

MAX_FILE_BYTES = 256 * 1024
MAX_FILES = 5

# Extension -> language the runner understands. Anything else is not staged:
# a compiled binary or a notebook is not something a reviewer can read line by
# line, which is the only reason staging exists.
LANGUAGES = {".py": "python", ".sh": "bash", ".bash": "bash", ".js": "javascript"}

# Filenames that are usually THE exploit rather than a helper.
_PREFERRED = ("exploit", "poc", "cve-", "main", "run")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS staged_pocs (
    id             TEXT PRIMARY KEY,
    engagement_id  TEXT NOT NULL,
    finding_id     TEXT,
    repo           TEXT NOT NULL,
    path           TEXT NOT NULL,
    language       TEXT NOT NULL,
    code           TEXT NOT NULL,
    inspection     TEXT,
    status         TEXT NOT NULL,
    decided_by     TEXT,
    decided_at     DOUBLE PRECISION,
    created_at     DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staged_pocs_engagement ON staged_pocs(engagement_id);
"""
db.register_schema(SCHEMA_SQL)


@dataclass
class StagedPoC:
    id: str
    engagement_id: str
    repo: str
    path: str
    language: str
    code: str
    status: str
    created_at: float
    finding_id: Optional[str] = None
    inspection: Dict[str, Any] = field(default_factory=dict)
    decided_by: Optional[str] = None
    decided_at: Optional[float] = None

    def to_public(self, *, include_code: bool = True) -> Dict[str, Any]:
        out = {
            "id": self.id,
            "engagement_id": self.engagement_id,
            "finding_id": self.finding_id,
            "repo": self.repo,
            "path": self.path,
            "language": self.language,
            "status": self.status,
            "inspection": self.inspection,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
            "created_at": self.created_at,
        }
        if include_code:
            out["code"] = self.code
        return out


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested)

def parse_repo_url(url: str) -> Optional[Tuple[str, str]]:
    """`https://github.com/owner/name` -> ("owner", "name").

    GitHub only, and only a repository. A gist, a raw file on some other host
    or a shortened link is refused: staging must fetch from the same place the
    operator was shown, or the review was of something else.
    """
    if not url:
        return None
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return None
    if (parsed.hostname or "").lower() not in ("github.com", "www.github.com"):
        return None
    parts = [p for p in (parsed.path or "").split("/") if p]
    if len(parts) < 2:
        return None
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    if not owner or not name:
        return None
    return owner, name


def language_for(path: str) -> Optional[str]:
    for ext, lang in LANGUAGES.items():
        if path.lower().endswith(ext):
            return lang
    return None


def rank_candidates(entries: List[Dict[str, Any]], *, limit: int = MAX_FILES
                    ) -> List[Dict[str, Any]]:
    """Pick the files worth staging from a repository listing.

    A PoC repo is usually one exploit plus README noise. Runnable extensions
    only, oversized files dropped, and names that read like the exploit first
    so the reviewer sees it before a helper module.
    """
    scored: List[Tuple[float, Dict[str, Any]]] = []
    for e in entries or []:
        if not isinstance(e, dict) or e.get("type") != "file":
            continue
        path = str(e.get("path") or e.get("name") or "")
        lang = language_for(path)
        if not lang:
            continue
        try:
            size = int(e.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        if size > MAX_FILE_BYTES:
            logger.debug("skipping oversized candidate %s (%d bytes)", path, size)
            continue

        name = path.rsplit("/", 1)[-1].lower()
        score = 0.0
        if any(name.startswith(p) for p in _PREFERRED):
            score += 10
        if "/" not in path:      # top level, not buried in tests/ or utils/
            score += 5
        score -= path.count("/")
        scored.append((score, {"path": path, "language": lang, "size": size}))

    scored.sort(key=lambda t: t[0], reverse=True)
    return [c for _, c in scored[:limit]]


def can_transition(current: str, target: str) -> bool:
    return target in TRANSITIONS.get(current, set())


# --------------------------------------------------------------------------- #
# Fetching

async def fetch_repo_files(owner: str, name: str, *, token: Optional[str] = None
                           ) -> List[Dict[str, Any]]:
    """List the candidate PoC files in a repository. [] on any failure."""
    import httpx

    token = token or os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://api.github.com/repos/{owner}/{name}/contents/"
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            logger.info("repo listing %s/%s returned %s", owner, name, resp.status_code)
            return []
        entries = resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("repo listing failed for %s/%s: %s", owner, name, exc)
        return []

    return rank_candidates(entries if isinstance(entries, list) else [])


async def fetch_file(owner: str, name: str, path: str, *,
                     token: Optional[str] = None) -> Optional[str]:
    """Fetch one file's contents, size-capped. None on any failure."""
    import httpx

    token = token or os.environ.get("GITHUB_TOKEN", "").strip()
    headers = {"Accept": "application/vnd.github.raw+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return None
        content = resp.content[:MAX_FILE_BYTES]
    except Exception as exc:  # noqa: BLE001
        logger.warning("file fetch failed for %s/%s/%s: %s", owner, name, path, exc)
        return None

    return content.decode("utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# Storage

class StagedPoCRepository:
    async def create(self, poc: StagedPoC) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO staged_pocs (id, engagement_id, finding_id, repo, path,
                    language, code, inspection, status, decided_by, decided_at, created_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                """,
                poc.id, poc.engagement_id, poc.finding_id, poc.repo, poc.path,
                poc.language, poc.code, json.dumps(poc.inspection), poc.status,
                poc.decided_by, poc.decided_at, poc.created_at,
            )

    async def get(self, poc_id: str) -> Optional[StagedPoC]:
        async with db.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM staged_pocs WHERE id=$1", poc_id)
        return _row_to_poc(row) if row else None

    async def list(self, engagement_id: str) -> List[StagedPoC]:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM staged_pocs WHERE engagement_id=$1 ORDER BY created_at DESC",
                engagement_id)
        return [_row_to_poc(r) for r in rows]

    async def set_status(self, poc_id: str, status: str, *,
                         decided_by: Optional[str] = None) -> None:
        async with db.acquire() as conn:
            await conn.execute(
                "UPDATE staged_pocs SET status=$1, decided_by=$2, decided_at=$3 WHERE id=$4",
                status, decided_by, time.time(), poc_id)

    async def attach_run_result(self, poc_id: str, result: Dict[str, Any]) -> None:
        """Persist a sandbox run's output onto the PoC's inspection blob.

        Without this the run output (the stdout that IS the proof of access)
        lived only in the browser of whoever clicked Run, and an auto-run had
        nowhere to show it at all. Stored under inspection["run_result"] so the
        review panel shows it whenever the PoC is reopened, for both paths.
        """
        async with db.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT inspection FROM staged_pocs WHERE id=$1", poc_id)
            if row is None:
                return
            try:
                inspection = json.loads(row["inspection"] or "{}")
            except (TypeError, ValueError):
                inspection = {}
            inspection["run_result"] = {**result, "ran_at": time.time()}
            await conn.execute(
                "UPDATE staged_pocs SET inspection=$1 WHERE id=$2",
                json.dumps(inspection), poc_id)


def _row_to_poc(row) -> StagedPoC:
    try:
        inspection = json.loads(row["inspection"] or "{}")
    except (TypeError, ValueError):
        inspection = {}
    return StagedPoC(
        id=row["id"], engagement_id=row["engagement_id"],
        finding_id=row["finding_id"], repo=row["repo"], path=row["path"],
        language=row["language"], code=row["code"], inspection=inspection,
        status=row["status"], decided_by=row["decided_by"],
        decided_at=row["decided_at"], created_at=row["created_at"],
    )


def new_poc_id() -> str:
    return f"poc_{secrets.token_hex(8)}"
