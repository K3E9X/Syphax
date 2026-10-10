"""Paths the target publishes about itself.

robots.txt and sitemap.xml are fetched already - by pre-recon, and by any
crawl - and nothing read them. That is a waste of the single richest PASSIVE
source of endpoints there is:

  * robots.txt is a list of the paths the owner does not want indexed, which
    on most sites means the admin panel, the internal tooling, the staging
    area and the export endpoints. The owner wrote it; no guessing involved.
  * sitemap.xml is the site's own index of its URLs.

Pure, and bounded: a sitemap can list a hundred thousand URLs and a parser
that returns all of them would reproduce the flood this codebase has just
spent a day removing.
"""
from __future__ import annotations

import re
from typing import List
from urllib.parse import urlparse

MAX_PATHS = 200

# "Disallow: /admin" / "Allow: /public" - the directive is what matters, the
# user-agent section it sits in does not.
_RULE = re.compile(r"^\s*(?:dis)?allow\s*:\s*(\S+)", re.I | re.M)
# "Sitemap: https://x/sitemap.xml" - another file worth reading.
_SITEMAP = re.compile(r"^\s*sitemap\s*:\s*(\S+)", re.I | re.M)
# <loc>https://x/page</loc>
_LOC = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)

# A wildcard is a pattern, not a path, and feeding "/*.php$" to a scanner
# produces a request for a file called "*.php$".
_PATTERN = ("*", "$")


def _clean(value: str) -> str:
    value = (value or "").strip()
    if not value or any(ch in value for ch in _PATTERN):
        return ""
    if "://" in value:
        value = urlparse(value).path or "/"
    if not value.startswith("/"):
        return ""
    # "/admin/" and "/admin" are one path; normalise_target does the rest.
    return value.rstrip("/") or "/"


def paths_from(filename: str, body: str) -> List[str]:
    """Paths declared in robots.txt or sitemap.xml. [] for anything else."""
    name = (filename or "").lower()
    text = body or ""
    found: List[str] = []

    if "robots" in name:
        for raw in _RULE.findall(text):
            cleaned = _clean(raw)
            if cleaned:
                found.append(cleaned)
    elif "sitemap" in name or "<urlset" in text[:400].lower():
        for raw in _LOC.findall(text):
            cleaned = _clean(raw)
            if cleaned:
                found.append(cleaned)

    seen = set()
    out = []
    for path in found:
        if path in seen or path == "/":
            continue
        seen.add(path)
        out.append(path)
        if len(out) >= MAX_PATHS:
            break
    return out


def sitemaps_from(body: str) -> List[str]:
    """Sitemap URLs a robots.txt points at."""
    return [u.strip() for u in _SITEMAP.findall(body or "") if u.strip()][:10]
