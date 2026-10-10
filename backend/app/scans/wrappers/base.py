"""Shared interface for CLI tool wrappers.

Each wrapper knows how to:
  1. build a command from (target, options),
  2. declare if its binary is installed,
  3. parse its own output into a list of normalized `Finding`s.

The actual subprocess execution happens in `app.scans.runner` so the wrappers
stay pure and unit-testable (no asyncio, no DB).
"""
from __future__ import annotations

import json

import shutil
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

from app.scans.models import Finding


@dataclass
class ToolResult:
    """Return type of `parse`."""
    findings: List[Finding]


@dataclass
class Readiness:
    """Whether a tool can actually find anything, and why not."""
    tool: str
    installed: bool
    ready: bool
    reason: str

    def to_dict(self) -> dict:
        return {"tool": self.tool, "installed": self.installed,
                "ready": self.ready, "reason": self.reason}


# How many findings one job may contribute, by wrapper category.
#
# Discovery tools report one item per thing they find, and on a real target
# that is thousands: gau turned an archive into 2175 findings and 2162 assets,
# the Findings page became unreadable, and the planner - which builds a task
# per (catalog item x asset) - spent the run's whole TIME budget on them. gau
# was fixed in its own parser, but katana, ffuf, httpx, subfinder, dnsx and
# kiterunner all have the same shape and no cap at all, so the limit belongs
# here, at the one place every wrapper's output passes through.
FINDING_CAP = {
    "recon": 120,
    "fingerprint": 120,
    "content_discovery": 150,
}
DEFAULT_FINDING_CAP = 400

# Severities that are NEVER dropped, however many there are. A flood of
# criticals is a signal, not noise, and losing one to a display limit would be
# far worse than the flood this guards against.
_NEVER_DROP = ("critical", "high")
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def cap_findings(findings: List[Finding], *, tool: str = "",
                 category: str = "", limit: Optional[int] = None) -> List[Finding]:
    """Bound one job's findings, keeping the most severe and saying what was cut.

    Pure, so the rule is testable on its own. Nothing is lost quietly: the
    remainder is summarised in one finding carrying the counts.
    """
    if limit is None:
        limit = FINDING_CAP.get(category, DEFAULT_FINDING_CAP)
    if len(findings) <= limit:
        return findings

    kept: List[Finding] = []
    rest: List[Finding] = []
    for finding in findings:
        if str(getattr(finding, "severity", "") or "").lower() in _NEVER_DROP:
            kept.append(finding)
        else:
            rest.append(finding)

    rest.sort(key=lambda f: _SEV_RANK.get(
        str(getattr(f, "severity", "") or "info").lower(), 9))
    room = max(0, limit - len(kept))
    dropped = rest[room:]
    kept.extend(rest[:room])
    if not dropped:
        return kept

    by_severity: Dict[str, int] = {}
    for finding in dropped:
        sev = str(getattr(finding, "severity", "") or "info").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1
    breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(
        by_severity.items(), key=lambda kv: _SEV_RANK.get(kv[0], 9)))
    sample = "\n".join(str(getattr(f, "title", ""))[:120] for f in dropped[:20])

    kept.append(Finding(
        severity="info",
        title=f"{len(dropped)} further {tool or 'tool'} result(s) not listed "
              f"individually",
        description=(
            f"This job produced {len(findings)} results; the {limit} most "
            f"severe are listed. The remainder ({breakdown}) are summarised "
            f"here. Nothing critical or high is ever cut - only lower "
            f"severities, and only past the cap."),
        target=str(getattr(findings[0], "target", "") or ""),
        evidence=sample or "(no titles)",
        metadata={"tool": tool, "vuln_class": "recon", "capped": True,
                  "total": len(findings), "listed": limit,
                  "dropped": len(dropped), "dropped_by_severity": by_severity},
    ))
    return kept


def _missing_data(path: str) -> str:
    """"" when the data is usable, else why it is not."""
    import os

    try:
        if not os.path.exists(path):
            return "missing"
        if os.path.isdir(path):
            # An empty directory is the nuclei-templates failure mode.
            for _root, _dirs, files in os.walk(path):
                if files:
                    return ""
            return "empty"
        return "" if os.path.getsize(path) > 0 else "empty"
    except OSError as exc:  # noqa: BLE001 - unreadable counts as unusable
        return f"unreadable ({exc.__class__.__name__})"


class BaseWrapper:
    name: str = ""
    binary: str = ""
    description: str = ""
    # Coarse grouping for the UI and the methodology engine. One of:
    # recon | fingerprint | content_discovery | vuln | injection | xss |
    # tls | cms | waf
    category: str = "vuln"

    # Hard cap on runtime (seconds). Subclasses can override.
    timeout_seconds: int = 30 * 60

    # Data files the tool cannot work without: templates, wordlists, a route
    # database. Declared per wrapper as (path, what it is). A missing one is
    # NOT an absent tool - the binary runs, scans nothing and exits 0, which
    # the pipeline records as "scanned, found nothing".
    required_data: Sequence = ()

    def is_available(self) -> bool:
        return shutil.which(self.binary) is not None

    def readiness(self) -> "Readiness":
        """Is this tool actually able to find anything?

        `is_available` only answers "is the binary on PATH", and for several
        tools that is not the same question at all:

          * nuclei with an empty templates directory scans for nothing. It
            exits 0 and prints nothing, so a target full of known CVEs comes
            back clean. The image runs `nuclei -update-templates || true` at
            build time, so a rate-limited or offline build produces exactly
            this - and the build succeeds.
          * ffuf without its wordlist fuzzes an empty list.
          * kiterunner without its .kite route file replays no routes.

        Every one of those looks identical to a clean target from the outside.
        This is what the preflight reports so it cannot be invisible.
        """
        if not self.is_available():
            return Readiness(self.name, False, False,
                             f"{self.binary} is not installed in this image")
        for path, what in self.required_data:
            missing = _missing_data(path)
            if missing:
                return Readiness(
                    self.name, True, False,
                    f"{what} is {missing} ({path}), so {self.binary} would run "
                    f"and find nothing")
        return Readiness(self.name, True, True, "")

    def build_command(self, target: str, options: Sequence[str]) -> List[str]:
        """Return the argv to run. Must include the binary as argv[0]."""
        raise NotImplementedError

    def parse(self, stdout: bytes, stderr: bytes, exit_code: int, target: str) -> ToolResult:
        raise NotImplementedError

def iter_json_lines(stdout: bytes):
    """Yield each JSONL record from a tool's stdout as a dict.

    Everything that is not a usable record is skipped rather than raising, one
    line at a time, so a single corrupt line costs one record and not the whole
    scan. Three real failure modes this centralises:

      * bytes handed straight to json.loads: it sniffs the encoding, and binary
        output made it guess UTF-16 and raise UnicodeDecodeError;
      * a top-level list/string/number, whose .get() raised AttributeError;
      * blank lines and progress noise.
    """
    text = (stdout or b"").decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] not in "{[":
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(obj, dict):
            yield obj
