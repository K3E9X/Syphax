"""Two failures OWASP GenAI measured in every agentic framework it tested.

From "LLM Exploit Generation - Phase 2" (GenAI Security Project, Oct 2026),
which ran four agent frameworks in nine configurations against live Hack The
Box targets. Two of its findings describe syphax as it was:

1. NOTHING RECORDED WHAT HAD BEEN TRIED. An agent "cracked one user's
   password, then looped on other users' hashes", and "tried to crack a hash
   against multiple wordlists without success, while ignoring a password
   reset route it had found" - "because it never ranked the value of its
   findings, it continued pursuing low-value leads to dead ends until it
   received manual prompting to stop". syphax ranks its leads, but only
   identity adoption ever marked one consumed and the strategist ignored
   consumed_by entirely, so the same top lead won every round.

2. THE OPERATOR HAD NO SIGNAL. "The volume of activity looks like progress",
   and "the agent reports a real breakthrough with the same confidence as a
   hallucinated dead end, so a novice has no signal to tell real progress
   from a loop that is only using up resources". Across both of the report's
   tracks, "a human was the success detector".
"""
from __future__ import annotations

import asyncio
import inspect


from app.orchestrator import blackboard as bb
from app.orchestrator.strategist import Strategist


class _State:
    engagement_id = "e"

    async def technologies(self):
        return []


def _lead(kind, value, lid, consumed=()):
    return bb.Lead(id=lid, engagement_id="e", kind=kind, value=value,
                   confidence=0.9, consumed_by=list(consumed))


# ---- 1. attention moves on ---------------------------------------------

def test_a_worked_lead_stops_being_the_first_thing_reached_for():
    """The report's scenario, in syphax's vocabulary: the injectable has been
    run against, and a password-reset route sits on the board untouched."""
    inject = _lead(bb.INJECTABLE, "https://t/p?id=1", 1)
    reset = _lead(bb.UNAUTH_ENDPOINT, "https://t/password-reset", 2)
    s = Strategist(_State())

    before = s._from_leads([inject, reset])
    assert before.chase_classes[0] == "sql_injection"

    inject.consumed_by = ["sqlmap"]
    after = s._from_leads([inject, reset])
    assert after.chase_classes[0] != "sql_injection", (
        "sqlmap already ran here and the strategist is still sending it back")
    assert after.chase_classes[0] in ("api_contract_violation", "multiple",
                                      "exposed_resource")


def test_a_consumed_lead_is_kept_not_deleted():
    """Consumed means acted on, not worthless. The fact stays on the board,
    in the report, and as an asset the planner still favours."""
    inject = _lead(bb.INJECTABLE, "https://t/p?id=1", 1, consumed=["sqlmap"])
    advice = Strategist(_State())._from_leads([inject])
    assert "https://t/p?id=1" in advice.hot_assets
    assert "sql_injection" in advice.chase_classes


def test_consumption_outranks_even_the_strongest_kind():
    """An injectable is the highest-priority kind there is. Worked once, it
    still yields to something untouched - that is the whole point."""
    inject = _lead(bb.INJECTABLE, "https://t/a", 1, consumed=["sqlmap"])
    weaker = _lead(bb.API_SCHEMA, "https://t/openapi.json", 2)
    advice = Strategist(_State())._from_leads([inject, weaker])
    assert advice.chase_classes[0] == "api_contract_violation"


def test_the_advice_says_how_much_is_left_untouched():
    """Zero untouched is a real, reportable state: it says the run acted on
    everything it knows, not that it found nothing."""
    s = Strategist(_State())
    fresh = s._from_leads([_lead(bb.INJECTABLE, "https://t/a", 1),
                           _lead(bb.CVE, "CVE-1", 2)])
    assert fresh.untouched == 2
    assert "2 of 2 not yet acted on" in fresh.rationale

    worked = s._from_leads([
        _lead(bb.INJECTABLE, "https://t/a", 1, consumed=["sqlmap"]),
        _lead(bb.CVE, "CVE-1", 2, consumed=["nuclei"])])
    assert worked.untouched == 0
    assert "has been acted on" in worked.rationale


def test_the_executor_records_what_it_ran_against():
    """Ranking is only half of it. Without recording what was TRIED, the
    ranking never changes and the same lead wins forever."""
    from app.orchestrator.executor import Executor
    src = inspect.getsource(Executor._consume_leads_for)
    assert "mark_consumed" in src
    assert "job.tool" in src
    # and it is called from the ingest, next to coverage
    ingest = inspect.getsource(Executor.ingest)
    assert "_consume_leads_for" in ingest
    assert ingest.index("mark_coverage") < ingest.index("_consume_leads_for")


def test_an_identity_lead_is_never_consumed_by_a_scan():
    """A credential stays usable however many tools ran against the URL it
    came from - consuming it would retire the run's own login."""
    from app.orchestrator.executor import Executor
    src = inspect.getsource(Executor._consume_leads_for)
    assert "grants_identity" in src


def test_consuming_never_fails_an_ingest():
    from app.orchestrator.executor import Executor
    src = inspect.getsource(Executor._consume_leads_for)
    assert "except Exception" in src


# ---- 2. the operator gets a signal -------------------------------------

def test_progress_is_counted_in_facts_not_in_activity():
    """"Jobs launched" is the number that goes up while nothing happens,
    which is exactly the illusion the report describes."""
    from app.orchestrator import loop
    src = inspect.getsource(loop._count_facts)
    for fact in ("assets", "jobs", "leads"):
        assert fact in src
    assert "jobs_launched" not in src


def test_a_single_quiet_iteration_is_not_a_stall():
    """A long scan finishing is normal. Three in a row is a loop."""
    from app.orchestrator.loop import STALL_ITERATIONS
    assert STALL_ITERATIONS >= 3


def _drive(monkeypatch, sequence):
    """Run _report_stall over a sequence of fact tuples; return what was said."""
    from app.orchestrator import loop

    said = []

    async def _emit(eid, kind, message="", **kw):
        said.append(message)

    monkeypatch.setattr(loop.events, "emit", _emit)

    state = {"i": 0}

    async def _facts(_eid):
        value = sequence[min(state["i"], len(sequence) - 1)]
        state["i"] += 1
        return value

    monkeypatch.setattr(loop, "_count_facts", _facts)

    class _E:
        id = "e"

    class _R:
        id = "r"

    seen = {}
    for _ in sequence:
        asyncio.run(loop._report_stall(_E(), _R(), seen))
    return said, seen


def test_the_run_says_when_it_stops_learning(monkeypatch):
    said, seen = _drive(monkeypatch, [(5, 2, 1)] * 5)
    assert said, "the run never said it had stopped learning"
    assert "not learning anything" in said[0]
    assert "activity, not progress" in said[0]


def test_it_says_it_once_not_every_iteration(monkeypatch):
    said, _ = _drive(monkeypatch, [(5, 2, 1)] * 12)
    assert len(said) == 1, f"the console was spammed: {said}"


def test_a_run_that_keeps_finding_things_is_never_called_stalled(monkeypatch):
    said, _ = _drive(monkeypatch, [(1, 0, 0), (2, 0, 0), (3, 1, 0),
                                   (4, 1, 1), (5, 2, 1)])
    assert said == []


def test_one_new_lead_alone_counts_as_progress(monkeypatch):
    """A lead is a fact the run learned, even when no finding came with it."""
    said, _ = _drive(monkeypatch, [(5, 2, 1), (5, 2, 2), (5, 2, 3), (5, 2, 4)])
    assert said == []


def test_recovering_is_announced_too(monkeypatch):
    said, _ = _drive(monkeypatch, [(5, 2, 1)] * 5 + [(6, 4, 2)])
    assert len(said) == 2
    assert "Moving again" in said[1]
    assert "1 new asset(s), 2 new finding(s), 1 new lead(s)" in said[1]


def test_an_unavailable_count_is_not_a_stall(monkeypatch):
    """No answer from the database is not evidence the run is looping."""
    said, seen = _drive(monkeypatch, [None] * 6)
    assert said == []


def test_the_stall_report_never_stops_the_run():
    """An operator who asked for no limits must not get a silent early exit;
    the phase budgets are what end a phase.

    Asserted on the CODE with its prose removed - the docstring contains the
    word "breakthrough", and a test that greps its own explanation passes for
    the wrong reason.
    """
    import ast

    from app.orchestrator import loop
    tree = ast.parse(inspect.getsource(loop._report_stall).strip())
    fn = tree.body[0]
    if (fn.body and isinstance(fn.body[0], ast.Expr)
            and isinstance(fn.body[0].value, ast.Constant)):
        fn.body = fn.body[1:]          # drop the docstring
    code = ast.unparse(fn)
    assert "break" not in code
    assert "stop_reason" not in code
    assert "run.status" not in code


def test_the_loop_checks_progress_every_iteration():
    from app.orchestrator import loop
    src = inspect.getsource(loop.run_engagement_loop)
    assert "_report_stall" in src
    assert src.index("_report_stall") < src.index("planner.plan(")
