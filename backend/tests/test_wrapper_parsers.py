"""Every wrapper parse() against malformed tool output.

These functions turn the stdout of an external process into severities, and
sqlmap already proved the failure mode is silent and expensive: a wrong answer
shipped as a confirmed critical. A parse crash is caught by the worker and
degraded to zero findings plus a job error - so a single corrupt line used to
throw away an entire scan's results.

Parametrised across the real registry, so a wrapper added later is covered the
day it lands.
"""
import pytest

from app.scans.wrappers import _WRAPPERS
from app.scans.wrappers.base import iter_json_lines

TARGET = "https://target.example.com/a?x=1"

MALFORMED = {
    "empty": b"",
    "plain_text": b"not json at all\nsecond line",
    "truncated_json": b'{"a": [1, 2',
    "top_level_list": b"[1, 2, 3]",
    "top_level_scalar": b'"just a string"',
    # json.loads sniffs the encoding of bytes; this used to be guessed as
    # UTF-16 and raise UnicodeDecodeError.
    "binary": b"\x00\xff\xfe\x01 garbage",
    "html_error_page": b"<html><body>500</body></html>",
    "null_byte_in_json": b'{"a":"b\x00c"}',
    "only_whitespace": b"   \n\t\n  ",
}


def _instance(w):
    return w() if isinstance(w, type) else w


@pytest.mark.parametrize("name", sorted(_WRAPPERS))
@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_parse_never_raises_on_malformed_output(name, case):
    """A bad byte stream must degrade, not raise."""
    result = _instance(_WRAPPERS[name]).parse(
        MALFORMED[case], b"some stderr text", 1, TARGET)
    assert result is not None
    assert isinstance(result.findings, list)


@pytest.mark.parametrize("name", sorted(_WRAPPERS))
def test_empty_output_yields_no_findings(name):
    """Nothing on stdout means nothing found - never an invented finding."""
    assert _instance(_WRAPPERS[name]).parse(b"", b"", 0, TARGET).findings == []


@pytest.mark.parametrize("name", sorted(_WRAPPERS))
def test_non_zero_exit_with_only_stderr_yields_no_findings(name):
    """Many scanners exit non-zero when they find nothing; stderr is not data."""
    assert _instance(_WRAPPERS[name]).parse(
        b"", b"error: connection refused", 1, TARGET).findings == []


# ---- the shared JSONL reader ------------------------------------------------
def test_jsonl_reader_keeps_good_records_around_a_corrupt_line():
    # The point of per-line handling: one bad line costs one record, not the scan.
    stream = b'{"a":1}\n{{{ broken\n{"a":2}\n'
    assert [o["a"] for o in iter_json_lines(stream)] == [1, 2]


def test_jsonl_reader_skips_non_dict_records():
    # A top-level list or string has no .get(); these used to raise AttributeError.
    assert list(iter_json_lines(b'[1,2]\n"str"\n3\n{"ok":1}\n')) == [{"ok": 1}]


def test_jsonl_reader_survives_binary_and_blank_lines():
    assert list(iter_json_lines(b"\x00\xff\xfe garbage")) == []
    assert list(iter_json_lines(b"\n   \n\t\n")) == []
    assert list(iter_json_lines(b"")) == []


# ---- gau: stdout is a URL list, and garbage used to become assets -----------
def test_gau_only_accepts_plausible_urls():
    gau = _instance(_WRAPPERS["gau"])

    # Each of these previously became a "Historical URL" finding, and findings
    # from gau are fed back as assets the scanners then target.
    for junk in (b"<html>500</html>", b'{"error":"nope"}', b"\x00\xff binary",
                 b"not a url at all", b"ftp://x.example.com/f",
                 b"https://nodot/path"):
        assert gau.parse(junk, b"", 0, TARGET).findings == [], junk


def test_gau_keeps_the_parameterised_urls_separate():
    """A URL with a query string is an injection point - seven catalog items
    apply only to an endpoint that has one - so it gets a row of its own and
    is declared as a scan target. A param-less path is inventory."""
    gau = _instance(_WRAPPERS["gau"])
    out = gau.parse(b"https://a.example.com/x?id=1\nhttp://b.example.com/y\n",
                    b"", 0, TARGET)
    params = [f for f in out.findings if (f.metadata or {}).get("has_params")]
    assert len(params) == 1
    assert params[0].metadata["asset"] == "https://a.example.com/x?id=1"
    assert params[0].metadata["asset_kind"] == "endpoint"


def test_gau_deduplicates():
    gau = _instance(_WRAPPERS["gau"])
    dupes = b"https://a.example.com/x\nhttps://a.example.com/x\n"
    kept = [f for f in gau.parse(dupes, b"", 0, TARGET).findings
            if (f.metadata or {}).get("asset")]
    assert len(kept) == 1


def test_gau_does_not_turn_an_archive_into_two_thousand_findings():
    """THE defect this parser had.

    gau returns a domain's historical URLs - thousands on a real target - and
    every one became its own `info` finding AND its own endpoint asset. A run
    on testfire.net produced 2176 findings of which 2175 were recon, and 2162
    assets; the planner multiplies assets by the catalog, so the run hit its
    TIME budget at iteration 8 having launched 62 jobs and tested nothing. The
    Findings page was 2175 rows of archived URLs.
    """
    from app.scans.wrappers.gau import MAX_PARAM_FINDINGS, MAX_PLAIN_ASSETS

    gau = _instance(_WRAPPERS["gau"])
    lines = []
    for i in range(2500):
        if i % 50 == 0:
            lines.append(f"http://t.example.com/search.jsp?query={i}")
        elif i % 7 == 0:
            lines.append(f"http://t.example.com/static/a{i}.css")
        else:
            lines.append(f"http://t.example.com/page{i}.jsp")

    out = gau.parse("\n".join(lines).encode(), b"", 0, TARGET)
    assert len(out.findings) <= MAX_PARAM_FINDINGS + MAX_PLAIN_ASSETS + 1, \
        f"{len(out.findings)} findings from one archive dump"

    assets = [f for f in out.findings if (f.metadata or {}).get("asset")]
    assert len(assets) <= MAX_PARAM_FINDINGS + MAX_PLAIN_ASSETS, \
        "the asset count is what multiplies the planner's task list"

    # The count is not lost - it is said once.
    summary = [f for f in out.findings if "archived URL(s)" in f.title]
    assert len(summary) == 1, "the total must still be reported, once"
    assert summary[0].metadata["archived_total"] >= 2000


def test_gau_drops_static_files():
    """A stylesheet has no parameters and no server-side behaviour; pointing a
    scanner at one burns a job per file."""
    gau = _instance(_WRAPPERS["gau"])
    out = gau.parse(b"https://a.example.com/app.css\n"
                    b"https://a.example.com/logo.png\n"
                    b"https://a.example.com/real.jsp\n", b"", 0, TARGET)
    assets = [f.metadata["asset"] for f in out.findings
              if (f.metadata or {}).get("asset")]
    assert assets == ["https://a.example.com/real.jsp"], assets
