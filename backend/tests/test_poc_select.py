"""Choosing which published PoC file to run, and saying why.

A CVE repository is rarely one file: the exploit, a detector, a helper, a
different CVE's PoC in the same repo. The heuristic that ranked by filename is
right often and wrong in the expensive case - it stages the detector and the
reviewer reads a script that was never going to demonstrate anything.

Two properties matter: the model can only choose among files already fetched
(it cannot widen what gets pulled), and any failure falls back to the heuristic
top rather than breaking the campaign.
"""
from __future__ import annotations

from app.exploit import poc_select

FINDING = {"title": "RCE", "vuln_class": "rce",
           "metadata": {"cve_id": "CVE-2024-9999"}}
CANDS = [
    {"path": "scanner.py", "language": "python", "size": 200},
    {"path": "CVE-2024-9999-exploit.py", "language": "python", "size": 1400},
    {"path": "helpers.py", "language": "python", "size": 90},
]


def test_the_prompt_lists_the_candidates_by_index_with_the_cve():
    prompt = poc_select.build_selection_prompt(FINDING, CANDS)
    assert "CVE-2024-9999" in prompt
    assert "0. scanner.py" in prompt and "1. CVE-2024-9999-exploit.py" in prompt


def test_a_valid_choice_is_read_with_its_reason():
    assert poc_select.parse_selection('{"index":1,"reason":"matches the CVE"}', 3) \
        == (1, "matches the CVE")


def test_a_bare_number_is_accepted():
    assert poc_select.parse_selection("I would pick 1", 3) == (1, "")


def test_an_out_of_range_index_is_rejected():
    """A model that picks file 7 of 3 has not chosen a real candidate; the
    caller falls back rather than indexing past the end of the list."""
    assert poc_select.parse_selection('{"index":7}', 3) is None
    assert poc_select.parse_selection("pick number 9", 3) is None
    assert poc_select.parse_selection('{"index":-1}', 3) is None


def test_garbage_is_no_selection():
    for bad in ("", "no idea", "{}", '{"reason":"x"}'):
        assert poc_select.parse_selection(bad, 3) is None


async def test_one_candidate_needs_no_model():
    chosen, reason = await poc_select.select_candidate(FINDING, [CANDS[1]])
    assert chosen == CANDS[1]
    assert "only candidate" in reason


async def test_no_configured_model_falls_back_to_the_heuristic_top(monkeypatch):
    class Client:
        configured = False

    class Router:
        def get(self, role):
            return Client()

    monkeypatch.setattr("app.llm.get_router", lambda: Router())
    chosen, reason = await poc_select.select_candidate(FINDING, CANDS)
    assert chosen == CANDS[0]
    assert reason == poc_select.HEURISTIC_REASON


async def test_the_model_pick_is_honoured_when_in_range(monkeypatch):
    class Client:
        configured = True

        async def chat(self, messages, **kw):
            return '{"index": 1, "reason": "filename names the CVE"}'

    class Router:
        def get(self, role):
            return Client()

    monkeypatch.setattr("app.llm.get_router", lambda: Router())
    chosen, reason = await poc_select.select_candidate(FINDING, CANDS)
    assert chosen == CANDS[1]
    assert "names the CVE" in reason


async def test_a_model_that_errors_falls_back_not_fails(monkeypatch):
    from app.llm import LLMError

    class Client:
        configured = True

        async def chat(self, messages, **kw):
            raise LLMError("down")

    class Router:
        def get(self, role):
            return Client()

    monkeypatch.setattr("app.llm.get_router", lambda: Router())
    chosen, reason = await poc_select.select_candidate(FINDING, CANDS)
    assert chosen == CANDS[0]
    assert reason == poc_select.HEURISTIC_REASON


async def test_an_out_of_range_model_answer_falls_back(monkeypatch):
    class Client:
        configured = True

        async def chat(self, messages, **kw):
            return '{"index": 99}'

    class Router:
        def get(self, role):
            return Client()

    monkeypatch.setattr("app.llm.get_router", lambda: Router())
    chosen, reason = await poc_select.select_candidate(FINDING, CANDS)
    assert chosen == CANDS[0]
