"""One issue, one row.

The operator reported seeing many duplicates. There were two sources, and they
are different problems:

  * ONE RESOURCE, SEVERAL SPELLINGS. The validation dedup key was
    (tool, title, raw target), so http://x/a, https://x/a, https://x/a/ and
    https://X:443/a were four findings about one page.
  * ONE ISSUE, SEVERAL TOOLS. The live view listed every validated finding
    ungrouped, so a weakness nuclei and nikto both reported appeared twice -
    while the global Findings page had grouped since it was written.
"""
from __future__ import annotations

import pytest

from app.findings_util import dedup, normalise_target


# ---- one resource, one spelling -----------------------------------------

@pytest.mark.parametrize("url", [
    "http://t.example/a",
    "https://t.example/a",
    "https://t.example/a/",
    "https://T.Example/a",
    "https://t.example:443/a",
    "http://t.example:80/a",
    "https://t.example/a#section",
])
def test_every_spelling_of_one_page_collapses(url):
    assert normalise_target(url) == "t.example/a", url


def test_one_dedup_key_for_all_of_them():
    spellings = ["http://t.example/a", "https://t.example/a/",
                 "https://T.Example:443/a"]
    assert len({dedup("xss", u) for u in spellings}) == 1


def test_the_query_string_is_not_normalised_away():
    """`?id=1` and `?id=2` are the same path but not the same test, and an
    IDOR that only shows on one of them would be merged away."""
    assert dedup("idor", "https://t.example/a?id=1") != \
        dedup("idor", "https://t.example/a?id=2")


def test_different_paths_stay_different():
    assert dedup("xss", "https://t.example/a") != \
        dedup("xss", "https://t.example/b")


def test_a_bare_host_survives():
    assert normalise_target("t.example") == "t.example"
    assert normalise_target("51.159.110.74:80") == "51.159.110.74:80"


def test_validation_keys_on_the_normalised_target():
    import inspect as _i

    from app.validation import run as vrun

    src = _i.getsource(vrun.validate_engagement)
    assert "normalise_target(f.target)" in src
    assert "(job.tool, f.title, f.target)" not in src


def test_the_title_stays_in_the_key():
    """Two different issues of the same class on the same URL are two
    findings, and the title is all that separates them."""
    import inspect as _i

    from app.validation import run as vrun

    src = _i.getsource(vrun.validate_engagement)
    # The key spans two lines and contains a nested call, so slice to the
    # assignment that follows it rather than to the first ")".
    key = src.split("dedup_key = (")[1].split("if dedup_key")[0]
    assert "f.title" in key, key


# ---- one issue, several tools -------------------------------------------

def _row(**kw):
    base = dict(id="vf", vuln_class="xss", target="https://t.example/a",
                severity="high", status="likely", tool="nuclei", proven=False)
    base.update(kw)
    return base


def _collapse(rows):
    """Reach the closure the endpoint defines, without a database."""
    import inspect as _i
    import textwrap

    from app.api import orchestrator

    src = _i.getsource(orchestrator)
    start = src.index("    def _collapse_duplicates(")
    end = src.index("    def _vf_public(")
    namespace: dict = {}
    exec(textwrap.dedent(src[start:end]), orchestrator.__dict__.copy(), namespace)
    return namespace["_collapse_duplicates"](rows)


def test_two_tools_agreeing_become_one_row_that_names_both():
    """Agreement is a signal, so they are merged, not dropped."""
    out = _collapse([_row(tool="nuclei"), _row(tool="nikto")])
    assert len(out) == 1
    assert out[0]["duplicates"] == 2
    assert set(out[0]["tools"]) == {"nuclei", "nikto"}


def test_the_strongest_verdict_survives():
    """One tool proving something is not weakened by another failing to."""
    out = _collapse([
        _row(tool="nikto", status="unconfirmed", proven=False),
        _row(tool="nuclei", status="confirmed", proven=True),
    ])
    assert len(out) == 1
    assert out[0]["proven"] is True
    assert out[0]["status"] == "confirmed"
    assert out[0]["duplicates"] == 2


def test_different_issues_are_not_merged():
    out = _collapse([
        _row(vuln_class="xss"),
        _row(vuln_class="sql_injection"),
        _row(target="https://t.example/b"),
    ])
    assert len(out) == 3


def test_the_url_spellings_merge_here_too():
    out = _collapse([
        _row(target="http://t.example/a"),
        _row(target="https://t.example/a/"),
    ])
    assert len(out) == 1 and out[0]["duplicates"] == 2


def test_a_single_finding_is_left_alone():
    out = _collapse([_row()])
    assert len(out) == 1 and out[0]["duplicates"] == 1
