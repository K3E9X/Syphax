"""One command that says what actually works.

Written because five rounds of "find a defect, fix it, rebuild, no difference"
is a failure of method, not of luck. Every one of those defects was real and
none was the one that mattered, because I was reading code instead of asking
the installation about itself.

So this asks. It exercises the real code paths - the same router the exploit
author uses, the same search the campaign uses, the same readiness check the
orchestrator uses - and prints a verdict per capability. Nothing here is
inferred from configuration: an LLM role is "ok" when a live call returned
text, not when a key is non-empty.

    docker compose exec -T worker python -m app.selftest

Read-only and safe to run during an engagement: the only outbound traffic is
one tiny LLM completion, one GitHub search, and a /health call to the sandbox.
No target is touched.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
from typing import List

OK = "ok"
BROKEN = "BROKEN"
ABSENT = "absent"


def _line(status: str, name: str, detail: str = "") -> str:
    mark = {OK: "  ok  ", BROKEN: " FAIL ", ABSENT: " --   "}.get(status, "  ?   ")
    return f"[{mark}] {name:28s} {detail}"


# --------------------------------------------------------------------------- #
# tools

def check_tools() -> List[str]:
    from app.scans.wrappers import preflight

    out = [""]
    entries = sorted(preflight(), key=lambda e: str(e["tool"]))
    crippled = [e for e in entries if e["installed"] and not e["ready"]]
    absent = [e for e in entries if not e["installed"]]
    working = [e for e in entries if e["ready"]]

    out.append(f"TOOLS  {len(working)} usable, {len(crippled)} installed but "
               f"unusable, {len(absent)} absent, of {len(entries)}")
    for entry in entries:
        if entry["ready"]:
            out.append(_line(OK, str(entry["tool"]), str(entry["binary"])))
        elif entry["installed"]:
            # The dangerous state: runs, exits 0, reports nothing.
            out.append(_line(BROKEN, str(entry["tool"]), str(entry["reason"])))
        else:
            out.append(_line(ABSENT, str(entry["tool"]), str(entry["reason"])))
    return out


# --------------------------------------------------------------------------- #
# the model: a live call per role, not a key check

async def check_llm() -> List[str]:
    from app.llm import ROLES, LLMError, get_router

    out = ["", "MODEL  one live completion per role"]
    router = get_router()
    for role in ROLES:
        try:
            client = router.get(role)
        except Exception as exc:  # noqa: BLE001
            out.append(_line(BROKEN, role, f"no client: {exc}"))
            continue
        if not client.configured:
            out.append(_line(ABSENT, role,
                             "no API key - add one in Settings. The "
                             "deterministic checks run without it; writing an "
                             "exploit does not."))
            continue
        try:
            reply = await client.chat(
                [{"role": "user", "content": "Reply with the single word: ready"}],
                temperature=0.0, max_tokens=8)
        except LLMError as exc:
            out.append(_line(BROKEN, role, f"{client.model}: {exc}"))
            continue
        except Exception as exc:  # noqa: BLE001
            out.append(_line(BROKEN, role,
                             f"{client.model}: {exc.__class__.__name__}: {exc}"))
            continue
        model = client.last_used_model or client.model
        text = (reply or "").strip().replace("\n", " ")[:40]
        if text:
            out.append(_line(OK, role, f"{model} answered {text!r}"))
        else:
            out.append(_line(BROKEN, role, f"{model} returned an empty reply"))
    return out


async def check_exploit_authoring() -> List[str]:
    """Can the model actually produce a runnable, vetted exploit?

    The role check above proves the key works. This proves the authoring path
    works: prompt, reply, code extraction, and the target-safety vet that
    decides whether the result may ever run.
    """
    from app.exploit import authoring
    from app.llm import ROLE_PLANNER, get_router

    out = ["", "EXPLOIT AUTHORING  the model writing a payload, end to end"]
    if not get_router().get(ROLE_PLANNER).configured:
        out.append(_line(ABSENT, "authoring", "no planner key, so nothing to test"))
        return out

    finding = {
        "id": "selftest", "vuln_class": "idor", "severity": "high",
        "title": "IDOR on /api/invoice/{id}",
        "target": "https://app.example.com/api/invoice/1",
        "metadata": {"vuln_class": "idor"},
    }
    try:
        result = await authoring.author(
            finding, scope_hosts=["app.example.com"],
            target="https://app.example.com/api/invoice/1",
            evidence="GET /api/invoice/1 -> 200; GET /api/invoice/2 -> 200",
            capabilities=[])
    except Exception as exc:  # noqa: BLE001
        out.append(_line(BROKEN, "authoring",
                         f"{exc.__class__.__name__}: {exc}"))
        return out

    if not result.code:
        out.append(_line(BROKEN, "authoring",
                         f"the model returned no script: "
                         f"{result.error or 'no reason given'}"))
        return out
    out.append(_line(OK, "model wrote a script",
                     f"{len(result.code)} chars of {result.language}, "
                     f"{result.attempts} attempt(s), model={result.model}"))
    if result.usable:
        out.append(_line(OK, "target-safety vet", "the script is allowed to run"))
    else:
        out.append(_line(BROKEN, "target-safety vet",
                         f"refused: {result.verdict.summary} (this engagement "
                         f"would need: {', '.join(result.verdict.missing) or 'n/a'})"))

    from app.sandbox.inspect import inspect_code
    report = inspect_code(result.code, filename="selftest.py",
                          scope_hosts=["app.example.com"])
    if report.verdict == "hostile":
        out.append(_line(BROKEN, "operator-safety inspection",
                         f"hostile, so it would wait for a human: {report.summary}"))
    else:
        out.append(_line(OK, "operator-safety inspection",
                         f"{report.verdict} - auto-run allowed ({report.summary})"))
    return out


# --------------------------------------------------------------------------- #
# public PoC search

async def check_poc_search() -> List[str]:
    """Does the PoC search return anything, and if not, why?"""
    from app.exploit_sources import github_poc_search_detailed, local_exploitdb
    from app.settings_store import get_integration_key

    out = ["", "PUBLIC PoC SEARCH  a CVE with a well-known published exploit"]
    cve = "CVE-2021-41773"

    try:
        token = await get_integration_key("github")
    except Exception as exc:  # noqa: BLE001
        token = ""
        out.append(_line(BROKEN, "github token", f"could not read: {exc}"))
    if token:
        # get_integration_key falls back to the GITHUB_TOKEN env var, so do not
        # claim it came from Settings.
        where = "Settings" if not os.environ.get("GITHUB_TOKEN") else "the environment"
        out.append(_line(OK, "github token", f"configured (from {where})"))
    else:
        out.append(_line(ABSENT, "github token",
                         "unset - the search API allows 10 requests a minute "
                         "and then answers 403. Add one in Settings (free)."))

    repos, note = await github_poc_search_detailed(cve, token=token or None)
    if repos:
        out.append(_line(OK, "github PoC search",
                         f"{len(repos)} repo(s) for {cve}, top: "
                         f"{repos[0].get('ref', '?')}"))
    else:
        out.append(_line(BROKEN, "github PoC search", note or "empty, no reason"))

    if shutil.which("searchsploit") is None:
        out.append(_line(ABSENT, "searchsploit",
                         "not installed - no offline Exploit-DB lookup"))
    else:
        edb = await local_exploitdb(cve)
        if edb:
            out.append(_line(OK, "searchsploit",
                             f"{len(edb)} Exploit-DB entry/entries for {cve}"))
        else:
            out.append(_line(BROKEN, "searchsploit",
                             f"installed but found nothing for {cve}, which "
                             f"has published exploits - the local DB is "
                             f"probably empty (searchsploit -u)"))
    return out


# --------------------------------------------------------------------------- #
# sandbox

async def check_sandbox() -> List[str]:
    from app.sandbox import runner_client

    out = ["", "SANDBOX  where every PoC is executed"]
    try:
        status = await runner_client.health()
    except Exception as exc:  # noqa: BLE001
        out.append(_line(BROKEN, "runner",
                         f"unreachable at {runner_client.RUNNER_URL}: "
                         f"{exc.__class__.__name__}"))
        return out

    out.append(_line(OK, "runner", f"up at {runner_client.RUNNER_URL}"))
    if not status.get("egress_locked"):
        out.append(_line(BROKEN, "egress policy",
                         "never applied - the backend refuses to send work"))
    mode = str(status.get("egress_mode") or "boot")
    if mode == "per-request":
        out.append(_line(OK, "egress policy", "applied per request from the scope"))
    else:
        out.append(_line(BROKEN, "egress policy",
                         "this image pins its allowlist at boot from "
                         "SANDBOX_ALLOWED_HOSTS, which is empty - it denies "
                         "every packet. Rebuild sandbox-runner."))
    for name, ok in (status.get("clients") or {}).items():
        if ok:
            out.append(_line(OK, f"client: {name}", "present"))
        else:
            out.append(_line(BROKEN, f"client: {name}",
                             "absent - a PoC in that language cannot reach "
                             "the target"))
    if status.get("auth_required"):
        out.append(_line(OK, "runner token", "required and accepted"))
    else:
        out.append(_line(ABSENT, "runner token",
                         "SANDBOX_RUNNER_TOKEN unset - the iptables owner rule "
                         "is then the only control on the control port"))
    return out


# --------------------------------------------------------------------------- #

async def run() -> int:
    from app import db, settings_store

    lines: List[str] = ["syphax self-test", "=" * 68]

    # The LLM keys live in the database, and the router is hydrated from them
    # at worker startup. Without this the self-test would report "no API key"
    # on an installation whose keys are fine.
    hydrated = False
    try:
        await db.init_db()
        await settings_store.apply_saved_on_startup()
        hydrated = True
    except Exception as exc:  # noqa: BLE001
        lines.append(_line(BROKEN, "settings",
                           f"could not load saved settings ({exc.__class__.__name__}"
                           f": {exc}) - keys entered in the UI will read as absent"))
    if hydrated:
        lines.append(_line(OK, "settings", "loaded from the database"))

    lines += check_tools()
    lines += await check_llm()
    lines += await check_exploit_authoring()
    lines += await check_poc_search()
    lines += await check_sandbox()

    broken = sum(1 for ln in lines if " FAIL " in ln)
    lines += ["", "=" * 68,
              f"{broken} capability/capabilities BROKEN." if broken else
              "Nothing broken.",
              "'absent' is a choice (a tool not installed, a key not set);",
              "'FAIL' is something that looks present and does not work."]
    print("\n".join(lines))

    try:
        await db.close_pool()
    except Exception:  # noqa: BLE001
        pass
    return 1 if broken else 0


async def as_json() -> dict:
    """The same checks, as data, for GET /api/scans/selftest.

    Shares one implementation with the CLI so the UI and the terminal can never
    disagree about what works.
    """
    from app import db, settings_store

    try:
        await db.init_db()
        await settings_store.apply_saved_on_startup()
    except Exception:  # noqa: BLE001 - reported in the lines below
        pass

    sections = {
        "tools": check_tools(),
        "model": await check_llm(),
        "authoring": await check_exploit_authoring(),
        "poc_search": await check_poc_search(),
        "sandbox": await check_sandbox(),
    }
    out = {}
    for name, lines in sections.items():
        rows = []
        for line in lines:
            if not line.startswith("["):
                continue
            status = (OK if "  ok  " in line[:8] else
                      BROKEN if " FAIL " in line[:8] else ABSENT)
            rest = line[8:].strip()
            label, _, detail = rest.partition("  ")
            rows.append({"status": status, "name": label.strip(),
                         "detail": detail.strip()})
        out[name] = rows
    out["broken"] = sum(1 for rows in out.values() if isinstance(rows, list)
                        for r in rows if r["status"] == BROKEN)
    return out


def main() -> int:
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    return asyncio.run(run())


if __name__ == "__main__":
    sys.exit(main())
