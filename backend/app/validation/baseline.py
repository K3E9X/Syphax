"""Catch-all (soft-404) calibration.

A server that answers every request with 200 and a friendly page manufactures
findings by the hundred: every path a content-discovery tool tries "exists",
every backup file nikto guesses is "present". Nothing in the validator knew
about this - `ffuf -ac` auto-calibrates its own scan, but that knowledge never
left the ffuf process, so a nikto or nuclei path finding on the same host was
still reported.

The fix is one cheap measurement per engagement: request a couple of paths
that cannot exist, remember the shape of the answer (status, title, body
length), and discard later path-existence findings whose answer has that same
shape.

Everything except `calibrate()` is pure so the decision logic is testable
without a network.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import List, Optional, Sequence
from urllib.parse import urljoin, urlparse

# Statuses a catch-all answers with. A 404/410 means the server distinguishes
# missing paths, which is exactly the case we do NOT need to correct for.
# 401/403 for everything is also a catch-all (a blanket auth gateway), and a
# 3xx for everything is the "redirect to /login" variant.
CATCH_ALL_STATUSES = set(range(200, 400)) | {401, 403, 429}

# Relative body-length wobble tolerated between two answers of the same shape.
LENGTH_TOLERANCE = 0.08
# Absolute floor, so two tiny bodies are not judged different over a few bytes.
LENGTH_FLOOR = 64
# A catch-all often echoes the requested path back into the page, so allow the
# body to differ by a few copies of the path-length difference.
PATH_ECHO_COPIES = 3

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


@dataclass(frozen=True)
class Shape:
    """The fingerprint of one HTTP answer, at the resolution we can compare."""
    status: int
    length: int
    title: str = ""
    path_len: int = 0

    def to_public(self) -> dict:
        return {"status": self.status, "length": self.length, "title": self.title}


@dataclass(frozen=True)
class Baseline:
    """What the target says about paths that do not exist."""
    catch_all: bool
    shape: Optional[Shape]
    samples: int
    reason: str

    def to_public(self) -> dict:
        return {
            "catch_all": self.catch_all,
            "samples": self.samples,
            "reason": self.reason,
            "shape": self.shape.to_public() if self.shape else None,
        }


NO_BASELINE = Baseline(catch_all=False, shape=None, samples=0,
                       reason="not calibrated")


def title_of(body: str) -> str:
    m = _TITLE.search(body or "")
    if not m:
        return ""
    return " ".join(m.group(1).split()).strip().lower()[:120]


def shape_of(status: int, body: str, *, path: str = "") -> Shape:
    return Shape(status=int(status), length=len(body or ""),
                 title=title_of(body), path_len=len(path or ""))


def similar(a: Shape, b: Shape, *, tolerance: float = LENGTH_TOLERANCE) -> bool:
    """Do two answers look like the same generated page?

    Same status and same <title> are required. Body length may differ by the
    tolerance, by the floor, or by a few copies of the difference in path
    length - a catch-all that prints "no page at /xyz" grows with the path.
    """
    if a.status != b.status or a.title != b.title:
        return False
    slack = max(tolerance * max(a.length, b.length), LENGTH_FLOOR)
    slack += PATH_ECHO_COPIES * abs(a.path_len - b.path_len)
    return abs(a.length - b.length) <= slack


def derive(shapes: Sequence[Shape]) -> Baseline:
    """Turn calibration samples into a verdict.

    Needs at least two answers: one path could be a genuine page (the random
    token is unlikely but a single sample cannot tell a catch-all from a real
    hit). All samples must look alike, otherwise the server is generating
    per-path content and no single shape describes "missing".
    """
    usable = [s for s in shapes if s is not None]
    if len(usable) < 2:
        return Baseline(False, None, len(usable),
                        "too few samples to decide")
    first = usable[0]
    if first.status not in CATCH_ALL_STATUSES:
        return Baseline(False, first, len(usable),
                        f"missing paths answer HTTP {first.status}; server "
                        "distinguishes them")
    if not all(similar(first, s) for s in usable[1:]):
        return Baseline(False, None, len(usable),
                        "answers to missing paths differ; no single shape")
    return Baseline(True, first, len(usable),
                    f"every missing path answers HTTP {first.status} with the "
                    f"same page ({first.length} bytes)")


def probe_paths(count: int = 3) -> List[str]:
    """Paths that cannot legitimately exist, in a few different shapes.

    Different extensions on purpose: some servers 404 unknown extensions and
    catch-all only the extensionless routes.
    """
    suffixes = ["", ".html", "/", ".php", ".json"]
    return [f"/{secrets.token_hex(12)}{suffixes[i % len(suffixes)]}"
            for i in range(max(1, count))]


def probe_urls(base_url: str, count: int = 3) -> List[str]:
    """Absolute probe URLs rooted at the target's origin."""
    parsed = urlparse(base_url or "")
    if not parsed.scheme or not parsed.netloc:
        return []
    root = f"{parsed.scheme}://{parsed.netloc}/"
    return [urljoin(root, p.lstrip("/")) for p in probe_paths(count)]


def matches(baseline: Baseline, status: int, body: str, *, path: str = "") -> bool:
    """Is this answer indistinguishable from the target's missing-path page?"""
    if not baseline.catch_all or baseline.shape is None:
        return False
    return similar(baseline.shape, shape_of(status, body, path=path))


async def calibrate(safe_poc, base_url: str, *, count: int = 3) -> Baseline:
    """Measure the target's answer to paths that do not exist.

    Uses SafePoC, so this is a GET on the in-scope origin and nothing else.
    Any failure degrades to NO_BASELINE: an uncalibrated baseline discards
    nothing, which is the safe direction.
    """
    urls = probe_urls(base_url, count)
    if not urls:
        return NO_BASELINE
    shapes: List[Shape] = []
    for url in urls:
        try:
            resp = await safe_poc.fetch(url, method="GET")
        except Exception:  # noqa: BLE001 - scope errors, timeouts, DNS
            continue
        if resp is None:
            continue
        shapes.append(shape_of(resp.status_code, resp.text or "",
                               path=urlparse(url).path))
    return derive(shapes)
