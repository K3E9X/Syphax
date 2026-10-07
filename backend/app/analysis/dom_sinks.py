"""DOM-based XSS sinks and postMessage handlers in the shipped JavaScript.

The client-side family was covered only for CORS and open redirect. Two of the
most common real bugs in a modern SPA were invisible:

  * a DOM sink fed from the URL - innerHTML / document.write / eval reached by
    location.hash, location.search, document.referrer or window.name. No server
    payload is involved, so no server-side fuzzer sees it;
  * a window.message listener with no origin check - any page that can get a
    handle on the window posts into the application, which is a direct path
    into whatever the handler does with the data.

Read-only: it reads the JavaScript already cached on disk for retire.js and
jsluice. Sends nothing.

This reports REACHABLE-LOOKING patterns, not proven exploitation: a sink near a
source is a lead for a human or for dalfox's DOM mode, and the finding says so.

Stored as a synthetic job (tool="dom_sinks").
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from app.analysis._store import save_analysis_job
from app.engagements import EngagementRepository
from app.scans.artifacts import js_dir, listdir
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.dom_sinks")

MAX_FILES = 150
MAX_BYTES = 2_000_000
MAX_FINDINGS = 60
# How close a source and a sink must be to be worth reporting together.
_WINDOW = 200

# Attacker-controlled inputs available to client code.
_SOURCES = re.compile(
    r"(location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer)"
    r"|window\.name|location\[|document\.location)", re.I)

# Where a string becomes markup or code.
_SINKS: Tuple[Tuple[str, str], ...] = (
    ("innerHTML", r"\.innerHTML\s*="),
    ("outerHTML", r"\.outerHTML\s*="),
    ("insertAdjacentHTML", r"\.insertAdjacentHTML\s*\("),
    ("document.write", r"document\.write(?:ln)?\s*\("),
    ("eval", r"\beval\s*\("),
    ("Function constructor", r"\bnew\s+Function\s*\("),
    ("jQuery .html()", r"\$\([^)]*\)\s*\.html\s*\("),
    ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML"),
)
_SINK_RE = [(name, re.compile(pat, re.I)) for name, pat in _SINKS]

# postMessage.
_LISTENER = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"]\s*,", re.I)
_ORIGIN_CHECK = re.compile(r"\.origin\b", re.I)
_POST_WILDCARD = re.compile(r"\.postMessage\s*\([^;]{0,400}?,\s*['\"]\*['\"]", re.I | re.S)


def find_sink_hits(code: str) -> List[Dict[str, Any]]:
    """Sinks that have an attacker-controlled source within _WINDOW chars."""
    out: List[Dict[str, Any]] = []
    sources = [m.start() for m in _SOURCES.finditer(code)]
    if not sources:
        return out
    for name, rx in _SINK_RE:
        for m in rx.finditer(code):
            near = [s for s in sources if abs(s - m.start()) <= _WINDOW]
            if not near:
                continue
            out.append({"sink": name, "pos": m.start(),
                        "snippet": _around(code, m.start())})
            break       # one hit per sink kind per file is enough
    return out


def listener_without_origin_check(code: str) -> Optional[str]:
    """A message listener whose body never looks at the sender's origin."""
    m = _LISTENER.search(code)
    if not m:
        return None
    body = code[m.start():m.start() + 1500]
    if _ORIGIN_CHECK.search(body):
        return None
    return _around(code, m.start())


def wildcard_post_message(code: str) -> Optional[str]:
    m = _POST_WILDCARD.search(code)
    return _around(code, m.start()) if m else None


def _around(code: str, pos: int, width: int = 160) -> str:
    start = max(0, pos - width // 3)
    return " ".join(code[start:start + width].split())


async def analyze_dom_sinks(engagement_id: str) -> Dict[str, int]:
    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    paths = listdir(js_dir(eng.target_url), suffixes=(".js", ".mjs", ".ts", ".html"),
                    limit=MAX_FILES)
    if not paths:
        return {"skipped": 1, "reason": "no cached JavaScript"}

    findings: List[Finding] = []
    seen: set = set()
    for path in paths:
        try:
            code = path.read_text(encoding="utf-8", errors="replace")[:MAX_BYTES]
        except Exception:  # noqa: BLE001 - an unreadable artifact is not fatal
            continue
        name = path.name

        for hit in find_sink_hits(code):
            key = ("sink", hit["sink"])
            if key in seen or len(findings) >= MAX_FINDINGS:
                continue
            seen.add(key)
            findings.append(Finding(
                severity="medium",
                title=f"DOM XSS sink {hit['sink']} fed from the URL ({name})",
                description=(
                    f"{hit['sink']} is written to within a few lines of an "
                    "attacker-controlled source (location/document.referrer/"
                    "window.name). No server-side payload is involved, so a "
                    "request fuzzer never sees this. Confirm by hand or with "
                    "dalfox's DOM mode - this is a lead, not a proof."),
                target=eng.target_url,
                evidence=hit["snippet"][:400],
                metadata={"vuln_class": "xss", "kind": "dom_xss",
                          "sink": hit["sink"], "file": name,
                          "status": "unconfirmed", "confidence": 0.4,
                          "tool": "dom_sinks"},
            ))

        snippet = listener_without_origin_check(code)
        if snippet and ("listener", name) not in seen:
            seen.add(("listener", name))
            findings.append(Finding(
                severity="high",
                title=f"window.message listener without an origin check ({name})",
                description=(
                    "The handler never inspects event.origin, so any page that "
                    "can obtain a handle on this window - an iframe it embeds, a "
                    "popup it opened, or a page that framed it - can post data "
                    "straight into it."),
                target=eng.target_url, evidence=snippet[:400],
                metadata={"vuln_class": "xss", "kind": "postmessage_no_origin",
                          "file": name, "status": "unconfirmed",
                          "confidence": 0.5, "tool": "dom_sinks"},
            ))

        wild = wildcard_post_message(code)
        if wild and ("wildcard", name) not in seen:
            seen.add(("wildcard", name))
            findings.append(Finding(
                severity="low",
                title=f"postMessage sent to any origin (*) ({name})",
                description=(
                    "The message is published with '*' as the target origin, so "
                    "whatever it carries is readable by whichever document "
                    "currently occupies that frame."),
                target=eng.target_url, evidence=wild[:400],
                metadata={"vuln_class": "information_disclosure",
                          "kind": "postmessage_wildcard", "file": name,
                          "status": "unconfirmed", "confidence": 0.4,
                          "tool": "dom_sinks"},
            ))

    if findings:
        await save_analysis_job(engagement_id, "dom_sinks", findings,
                                target=eng.target_url)
    return {"files": len(paths), "findings": len(findings)}
