"""Why a finding stayed unverified.

"0 confirmed" is the single most confusing thing this tool can print. The
operator reads it as "the scanner is broken", when usually it means something
far more mundane: an oracle exists but a switch they never set kept it from
running, or the input an oracle needs was never captured.

Nothing said so. `run_cve_checks` returned `{"skipped": 1, "reason":
"allow_active_exploit is off"}` into a dict nobody rendered; the file-reading
tools scanned an empty directory and reported nothing, which is
indistinguishable from finding nothing. So the run looked identical whether it
had been thorough or hobbled.

These are pure: the loop emits them to the live console, the report prints them
next to the unverified findings, and both say the same thing because both call
the same function.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Sequence


@dataclass(frozen=True)
class Limit:
    """One reason verification was narrower than it could have been."""
    key: str
    what: str      # what could not be decided
    why: str       # the setting or missing input responsible
    fix: str       # what the operator would change

    @property
    def sentence(self) -> str:
        return f"{self.what} {self.why} {self.fix}".strip()

    def to_public(self) -> Dict[str, str]:
        return {"key": self.key, "what": self.what, "why": self.why,
                "fix": self.fix, "sentence": self.sentence}


# Classes an active check could settle but a passive pass cannot.
ACTIVE_ONLY_CLASSES = frozenset({
    "cve", "multiple", "sql_injection", "command_injection", "xss",
    "ssrf", "ssti", "file_inclusion", "path_traversal", "rce",
    "nosql_injection", "xxe", "crlf_injection", "redirect",
})

# Classes whose evidence comes from files the proxy capture materialises.
CAPTURE_FED_CLASSES = frozenset({
    "vulnerable_component", "secret_exposure", "source_code_disclosure",
})


def limits_for(
    *,
    allow_active_exploit: bool,
    unverified_classes: Sequence[str] = (),
    captured_js_files: int = 0,
    stop_reason: str = "",
    tools_unavailable: Sequence[str] = (),
) -> List[Limit]:
    """Every reason this run verified less than it could have.

    Only reports a limit that actually bit: a gate that blocked nothing because
    no finding needed it is noise, and noise here trains the operator to skip
    the whole panel.
    """
    classes = {str(c or "").lower() for c in unverified_classes}
    out: List[Limit] = []

    if not allow_active_exploit and (classes & ACTIVE_ONLY_CLASSES):
        out.append(Limit(
            key="active_exploit_off",
            what="Known-CVE and injection findings could not be confirmed:",
            why="deciding them needs a crafted request, and "
                "`allow_active_exploit` is off for this engagement.",
            fix="Turn it on in the engagement to let the safe-PoC checks and "
                "the adaptive prober settle them.",
        ))

    if stop_reason in ("exploit_denied", "stopped", "cancelled"):
        out.append(Limit(
            key="run_ended_early",
            what="Active verification did not run:",
            why=f"the run ended as '{stop_reason}' before that phase.",
            fix="Re-run, and approve the exploitation checkpoint when it asks.",
        ))

    if not captured_js_files and (classes & CAPTURE_FED_CLASSES):
        out.append(Limit(
            key="no_captured_javascript",
            what="Client-side findings could not be checked:",
            why="retire.js, jsluice and trufflehog read files, and no "
                "JavaScript was captured through the proxy.",
            fix="Browse the target through the MITM proxy once, then re-run "
                "the analysis.",
        ))

    for tool in sorted({str(t) for t in tools_unavailable if t}):
        out.append(Limit(
            key=f"tool_missing:{tool}",
            what=f"Tests belonging to {tool} were skipped:",
            why="its binary is not present in this image.",
            fix="Rebuild the image, or accept the gap - the orchestrator skips "
                "those catalog items rather than failing the run.",
        ))

    return out


def unverified_classes_of(findings: Sequence[Any]) -> List[str]:
    """Classes of findings no oracle settled - the input to limits_for."""
    out = []
    for f in findings:
        status = str(getattr(f, "status", "") or "").lower()
        if status in ("likely", "unconfirmed"):
            out.append(str(getattr(f, "vuln_class", "") or ""))
    return out


def summary_line(limits: Sequence[Limit]) -> str:
    """One line for the live console, or '' when nothing limited the run."""
    if not limits:
        return ""
    return (f"{len(limits)} thing(s) limited verification: "
            + " | ".join(l.sentence for l in limits))
