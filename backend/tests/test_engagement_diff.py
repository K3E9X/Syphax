"""Retest diff: what was fixed, what came back, what is new."""
from app.reporting.diff import OPEN_STATUSES, diff_findings, finding_key


def f(title, target="https://t.example.com/a", vuln_class="xss",
      severity="high", status="confirmed"):
    return {"title": title, "target": target, "vuln_class": vuln_class,
            "severity": severity, "status": status}


# ---- identity across runs ---------------------------------------------------
def test_same_issue_matches_despite_a_different_query_string():
    # ?id=1 vs ?id=7 is the same issue on the same endpoint; keeping the query
    # would report every retest as entirely new.
    a = f("Reflected XSS", "https://t.example.com/search?q=1")
    b = f("Reflected XSS", "https://t.example.com/search?q=9999")
    assert finding_key(a) == finding_key(b)


def test_different_endpoint_or_class_is_a_different_issue():
    base = f("Reflected XSS", "https://t.example.com/search?q=1")
    assert finding_key(base) != finding_key(
        f("Reflected XSS", "https://t.example.com/other?q=1"))
    assert finding_key(base) != finding_key(
        f("Reflected XSS", "https://t.example.com/search?q=1", vuln_class="sqli"))


# ---- the four outcomes ------------------------------------------------------
def test_new_fixed_and_still_open():
    previous = [f("Old XSS", "https://t/a"), f("Shared SQLi", "https://t/b", vuln_class="sqli")]
    current = [f("Shared SQLi", "https://t/b", vuln_class="sqli"), f("Fresh LFI", "https://t/c", vuln_class="lfi")]
    d = diff_findings(previous, current)
    assert [x["title"] for x in d.new] == ["Fresh LFI"]
    assert [x["title"] for x in d.fixed] == ["Old XSS"]
    assert [x["title"] for x in d.unchanged] == ["Shared SQLi"]


def test_severity_change_is_reported_as_worse_or_better():
    prev = [f("Creeping issue", severity="medium")]
    cur = [f("Creeping issue", severity="critical")]
    d = diff_findings(prev, cur)
    assert len(d.worsened) == 1 and d.worsened[0]["previous_severity"] == "medium"
    assert not d.unchanged

    d2 = diff_findings(cur, prev)
    assert len(d2.improved) == 1 and d2.improved[0]["previous_severity"] == "critical"


# ---- only real issues count -------------------------------------------------
def test_false_positives_are_neither_fixed_nor_regressed():
    # A finding the judge killed was never real; it must not read as a fix.
    previous = [f("Never real", status="false_positive")]
    d = diff_findings(previous, [])
    assert d.fixed == [] and d.new == []

    d2 = diff_findings([], [f("Never real", status="false_positive")])
    assert d2.new == []


def test_open_statuses_are_the_two_that_mean_live():
    assert OPEN_STATUSES == {"confirmed", "likely"}


# ---- shape ------------------------------------------------------------------
def test_empty_on_both_sides_says_so():
    d = diff_findings([], [])
    assert d.to_public()["counts"] == {"new": 0, "fixed": 0, "unchanged": 0,
                                       "worsened": 0, "improved": 0}
    assert "Nothing to compare" in d.summary()


def test_buckets_are_ordered_most_severe_first():
    current = [f("low one", "https://t/1", severity="low"),
               f("crit one", "https://t/2", severity="critical"),
               f("med one", "https://t/3", severity="medium")]
    d = diff_findings([], current)
    assert [x["severity"] for x in d.new] == ["critical", "medium", "low"]


def test_summary_is_human_readable():
    d = diff_findings([f("gone", "https://t/1")], [f("arrived", "https://t/2")])
    assert d.summary() == "1 new, 1 fixed, 0 still open."
