"""Replaying the proof the LLM judge suggested.

The judge pays a call per finding to produce one; until this existed the result
was written to metadata and never read. The verdict has to stay mechanical -
the judge already chose the observable, so confirming is a substring test, not
a second judgement call.
"""
from app.validation.proof_replay import proof_verdict, stored_proof

PROOF = {"method": "GET", "url": "https://t.example.com/x", "expect": "root:x:0:0"}


# ---- reading what was stored ------------------------------------------------
def test_a_usable_proof_is_returned():
    assert stored_proof({"suggested_proof": PROOF}) == PROOF


def test_incomplete_or_absent_proofs_are_ignored():
    assert stored_proof(None) is None
    assert stored_proof({}) is None
    assert stored_proof({"suggested_proof": None}) is None
    assert stored_proof({"suggested_proof": "GET /x"}) is None          # not a dict
    assert stored_proof({"suggested_proof": {"url": "https://t/x"}}) is None   # no expect
    assert stored_proof({"suggested_proof": {"expect": "x"}}) is None          # no url


# ---- the verdict ------------------------------------------------------------
def test_the_expected_observable_present_means_it_held():
    v = proof_verdict("root:x:0:0", "body\nroot:x:0:0:root:/root\n", 200)
    assert v["outcome"] == "held" and v["status_code"] == 200


def test_absent_observable_means_it_did_not_hold():
    v = proof_verdict("root:x:0:0", "<html>nothing here</html>", 200)
    assert v["outcome"] == "did_not_hold"


def test_no_response_is_inconclusive_not_a_refutation():
    # The target may simply have been down; that is not evidence the finding
    # was wrong, and recording it as one would silently drop a real issue.
    v = proof_verdict("root:x:0:0", None, None)
    assert v["outcome"] == "inconclusive"


def test_an_empty_expectation_cannot_hold():
    assert proof_verdict("", "any body at all", 200)["outcome"] == "did_not_hold"


def test_matching_is_exact_not_case_folded():
    # The judge copied the observable out of real evidence, so a case-insensitive
    # match would only widen it into false confirmations.
    assert proof_verdict("ROOT:X:0:0", "root:x:0:0", 200)["outcome"] == "did_not_hold"


def test_detail_names_the_observable_so_a_human_can_check():
    for body, expected in (("root:x:0:0", "present"), ("nope", "absent")):
        assert expected in proof_verdict("root:x:0:0", body, 200)["detail"]
