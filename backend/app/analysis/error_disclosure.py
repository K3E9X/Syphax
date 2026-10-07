"""Verbose errors: stack traces, SQL errors and internal paths in responses.

The OWASP Error Handling family had no check. A stack trace is not cosmetic: it
names the framework and version, the absolute path of the source tree and often
the query that failed - which is both a CVE lookup and the oracle an injection
test needs. A database error in particular means unsanitised input reached the
driver.

Read-only: it re-reads response bodies the proxy already captured and sends
nothing. One finding per (host, kind) - the same traceback on fifty pages is
one weakness.

Stored as a synthetic job (tool="error_disclosure").
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Tuple

from app import db
from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.error_disclosure")

MAX_FLOWS = 800
MAX_BODY = 200_000          # bodies are already truncated upstream
_SNIPPET = 300

# (kind, severity, label, pattern). Database errors rank highest: they mean raw
# input reached the driver, which is the injection oracle itself.
_SIGNATURES: List[Tuple[str, str, str, re.Pattern]] = [
    ("sql_error", "high", "SQL error",
     re.compile(r"(You have an error in your SQL syntax|SQLSTATE\[|"
                r"Unclosed quotation mark after the character string|"
                r"ORA-\d{5}|PG::\w+Error|psycopg2\.\w+Error|"
                r"SQLiteException|MySqlException|PostgresException)", re.I)),
    ("stack_trace", "medium", "Python traceback",
     re.compile(r"Traceback \(most recent call last\)")),
    ("stack_trace", "medium", "Java stack trace",
     re.compile(r"(Exception in thread \"|\bat (?:com|org|java)\.[\w.$]+\([\w$]+\.java:\d+\))")),
    ("stack_trace", "medium", ".NET stack trace",
     re.compile(r"(Server Error in '.*' Application|System\.[\w.]+Exception|"
                r"at System\.[\w.]+\(.*\) in )")),
    ("stack_trace", "medium", "PHP error",
     re.compile(r"(Fatal error</b>:|PHP (?:Fatal|Warning|Notice|Parse error)|"
                r"<b>Warning</b>:.{0,80}on line <b>\d+)", re.I)),
    ("stack_trace", "medium", "Node.js stack trace",
     re.compile(r"(at Object\.<anonymous> \(|\bat .{0,80}node_modules[/\\])")),
    ("stack_trace", "medium", "Ruby stack trace",
     re.compile(r"(ActionController::|ActiveRecord::\w+|[\w/]+\.rb:\d+:in `)")),
    ("debug_page", "medium", "Framework debug page",
     re.compile(r"(Werkzeug Debugger|Whoops, looks like something went wrong|"
                r"DEBUG\s*=\s*True|Django Version:|Symfony Exception|"
                r"Rails\.application|__debugger__)", re.I)),
    ("path_disclosure", "low", "Internal filesystem path",
     re.compile(r"((?:/var/www|/usr/local/|/home/[\w.-]+/|/opt/[\w.-]+/|"
                r"[A-Za-z]:\\\\(?:inetpub|wwwroot|Users|xampp))[\w./\\-]{3,})")),
]


async def analyze_error_disclosure(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    try:
        async with db.acquire() as conn:
            rows = await conn.fetch(
                'SELECT url, host, status_code, response_body, response_content_type '
                'FROM flows WHERE response_body IS NOT NULL '
                'ORDER BY "timestamp" DESC LIMIT $1', MAX_FLOWS)
    except Exception:  # noqa: BLE001 - no proxy data is a normal state
        logger.debug("error_disclosure: could not read flows")
        return {"skipped": 1}

    hits: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for r in rows:
        host = (r["host"] or "").lower()
        if not host or not eng.host_in_scope(host):
            continue
        ctype = (r["response_content_type"] or "").lower()
        # Binary payloads carry no error pages; skip them cheaply.
        if ctype.startswith(("image/", "video/", "audio/", "font/")):
            continue
        body = _text(r["response_body"])
        if not body:
            continue
        for kind, sev, label, pattern in _SIGNATURES:
            m = pattern.search(body)
            if not m:
                continue
            key = (host, kind, label)
            if key in hits:
                continue
            hits[key] = {"url": r["url"], "status": r["status_code"],
                         "snippet": _around(body, m.start()), "sev": sev}

    findings = [
        Finding(
            severity=data["sev"],
            title=f"{label} exposed on {host}",
            description=(
                "The server returned an internal error verbatim. It reveals the "
                "component and version, often the source path, and - for a "
                "database error - that unsanitised input reached the driver, "
                "which is exactly the oracle an injection test needs."
                if kind == "sql_error" else
                "The server returned an internal error verbatim, revealing the "
                "component, its version and internal paths."),
            target=data["url"],
            evidence=data["snippet"],
            metadata={"vuln_class": "information_disclosure", "kind": kind,
                      "signature": label, "host": host,
                      "status": data["status"], "tool": "error_disclosure"},
        )
        for (host, kind, label), data in hits.items()
    ]

    if findings:
        await save_analysis_job(engagement_id, "error_disclosure", findings,
                                target=eng.target_host or eng.target_url)
    return {"findings": len(findings)}


def _text(body: Any) -> str:
    if not body:
        return ""
    if isinstance(body, memoryview):
        body = body.tobytes()
    if isinstance(body, (bytes, bytearray)):
        return bytes(body[:MAX_BODY]).decode("utf-8", errors="replace")
    return str(body)[:MAX_BODY]


def _around(body: str, pos: int) -> str:
    start = max(0, pos - 80)
    return body[start:start + _SNIPPET].strip()
