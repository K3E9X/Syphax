"""Which `info` findings have earned a row in the report.

A run on a real target produces hundreds of them: every archived URL, every
crawled page, every probed host. Most are inventory - they tell the pipeline
where to aim, and they tell the operator nothing. A few are leads and must
survive.

The operator put it exactly right: pages that answer 404 or an error do not
need reporting, except the ones that deserve it.

NOTHING HERE MAKES A REQUEST. The discovering tool already asked the server and
wrote the answer down - katana records `status_code`, ffuf records `status`,
httpx records `status_code`. Re-asking would cost a thousand requests to learn
what is already on the finding.

Pure, so the rules are readable and testable on their own.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

# Classes that are inventory: they describe where the application is, not what
# is wrong with it. Only these are ever dropped - a weakness is never silenced
# for answering 404, because an injection finding's status code means nothing.
INVENTORY_CLASSES = {"recon", "fingerprint", "content_discovery", "unknown"}

# What a dead page answers. 401 and 403 are NOT here: "this exists and is
# guarded" is one of the more interesting things a scan can find.
_DEAD = {404, 410, 500, 502, 503, 504}

# Metadata that makes an inventory row a lead, whatever the page answered.
_LEADS = (
    ("params", "it carries parameters - an injection point"),
    ("param", "a hidden parameter was confirmed on it"),
    ("has_params", "it carries parameters - an injection point"),
    ("cname", "a CNAME points elsewhere - the shape of a subdomain takeover"),
    ("secret", "a credential shape was matched in it"),
    ("tech", "it disclosed the technology stack"),
    ("server", "it disclosed a server banner"),
    ("cve_id", "a CVE is attached to it"),
)


def _status_of(meta: Dict[str, Any]) -> Optional[int]:
    for key in ("status_code", "status", "http_status"):
        raw = meta.get(key)
        if raw is None:
            continue
        try:
            return int(raw)
        except (TypeError, ValueError):
            continue
    return None


def is_noise(severity: str, vuln_class: str,
             metadata: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
    """(drop it?, why). Only ever drops inventory that answered a dead page."""
    meta = metadata or {}
    if str(severity or "info").lower() != "info":
        return False, ""
    if str(vuln_class or "").lower() not in INVENTORY_CLASSES:
        return False, ""

    for key, why in _LEADS:
        value = meta.get(key)
        if value:
            return False, why

    status = _status_of(meta)
    if status is None:
        # Nobody recorded an answer, so nobody can say it is dead. An archived
        # URL nothing has fetched sits here, and is kept.
        return False, ""
    if status in _DEAD:
        return True, (f"the page answers HTTP {status}: it is not there. "
                      f"Recorded by the tool that found it, not re-checked - "
                      f"the answer was already on the finding.")
    return False, ""
