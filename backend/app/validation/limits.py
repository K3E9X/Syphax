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
from typing import Any, Dict, List, Optional, Sequence


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
    # Everything below is a reason that ACTUALLY bites in a normal install.
    # This function used to report exactly four things, and every default in a
    # normal install is operator-friendly: allow_active_exploit defaults True,
    # auto_run_public_poc defaults True, the refine loop defaults to 2 rounds.
    # So on the run where nothing got proven, the panel printed nothing at all -
    # which reads as "no limits, the scanner simply found nothing".
    sandbox_error: str = "",
    llm_configured: bool = True,
    auto_run_poc: bool = True,
    inspection_refusals: int = 0,
    routeless_findings: int = 0,
    routeless_reasons: Optional[Dict[str, int]] = None,
    # None = unknown (do not claim either way); False = the run ended before
    # the exploitation phase was ever planned, which outranks every other
    # explanation and was reported nowhere.
    reached_exploitation: Optional[bool] = None,
    last_phase: str = "",
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

    # The budget stops. These were not reported at all: a run whose job or time
    # budget ran out during recon/mapping never reaches the vuln and
    # exploitation phases, so it finds nothing but surface - and said nothing
    # about why. On a target whose crawl explodes into hundreds of endpoints
    # that is the normal outcome, and it reads as "the scanner found nothing".
    if stop_reason == "job_budget":
        out.append(Limit(
            key="job_budget_spent",
            what="The run stopped on its job budget:",
            why="every scan task counts against it, and recon plus mapping can "
                "spend all of it on a target whose crawl finds many endpoints. "
                "The phases after mapping were never planned.",
            fix="Raise 'budget_requests' on the engagement (default 200), or "
                "narrow the scope so the crawl produces fewer endpoints.",
        ))
    if stop_reason == "time_budget":
        out.append(Limit(
            key="time_budget_spent",
            what="The run stopped on its time budget:",
            why="the later phases were never reached.",
            fix="Raise 'budget_seconds' on the engagement (default 2 hours).",
        ))
    if stop_reason == "no_tools":
        out.append(Limit(
            key="no_launchable_tool",
            what="The run stopped because nothing could be launched:",
            why="three planning rounds in a row produced only tasks whose tool "
                "is missing from the image.",
            fix="Check the missing binaries listed below and rebuild.",
        ))

    # The headline, when it applies. Said first in the panel because every
    # other explanation is secondary to "the phase that proves things never
    # started".
    if reached_exploitation is False:
        out.insert(0, Limit(
            key="exploitation_never_started",
            what="Nothing was exploited because the exploitation phase never ran:",
            why="the run ended during "
                f"{last_phase or 'an earlier phase'}, so no injection, CVE or "
                "PoC test was ever planned. Findings carry the verdict their "
                "scanner gave them and nothing more.",
            fix="See the reason the run ended, below.",
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

    # The sandbox is where every proof happens. An unreachable runner, a runner
    # whose image predates per-request egress, or one with no HTTP client means
    # nothing can be proven - and the operator previously saw only "the exploit
    # did not work" for each PoC in turn.
    if sandbox_error:
        out.append(Limit(
            key="sandbox_unusable",
            what="No PoC could be executed:",
            why=sandbox_error,
            fix="Fix the sandbox runner, then re-run. Until it is usable every "
                "finding that needs a crafted request stays unproven.",
        ))

    if not llm_configured and (classes & ACTIVE_ONLY_CLASSES):
        out.append(Limit(
            key="no_llm_key",
            what="The model could not write an exploit for the findings no "
                 "template or tool covers:",
            why="no API key is configured for the planner role.",
            fix="Add a provider key in Settings. The deterministic checks run "
                "without one; authoring an exploit does not.",
        ))

    if not auto_run_poc:
        out.append(Limit(
            key="auto_run_off",
            what="PoCs were staged but never executed:",
            why="`auto_run_poc` is off in Settings, so each one waits for you "
                "to approve and run it.",
            fix="Turn it on, or open the PoC testing view and run them.",
        ))

    if inspection_refusals:
        out.append(Limit(
            key="inspection_refused",
            what=f"{inspection_refusals} PoC(s) were staged but held back:",
            why="static inspection found a critical signal in them - credential "
                "theft, a reverse shell, persistence or something destructive - "
                "which is a risk to YOU, not to the target.",
            fix="Read them in the PoC testing view and run them yourself if "
                "they are legitimate. A trojaned PoC in a fake exploit repo is "
                "a well-documented attack on researchers.",
        ))

    if routeless_findings:
        detail = ""
        if routeless_reasons:
            top = sorted(routeless_reasons.items(), key=lambda kv: -kv[1])[:2]
            detail = " Most common: " + "; ".join(f"{r} (x{n})" for r, n in top)
        out.append(Limit(
            key="no_exploit_route",
            what=f"{routeless_findings} finding(s) had no way to be proven:",
            why="no nuclei template, no tool and nothing the model can author "
                "covers them." + detail,
            fix="They stay at the verdict the scanner gave them. If a class "
                "here should be exploitable, it belongs in "
                "strategy.AUTHORABLE_CLASSES.",
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
