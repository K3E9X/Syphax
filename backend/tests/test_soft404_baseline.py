"""Catch-all (soft-404) calibration.

Nothing in the validator knew what the target says about paths that do not
exist. On a server that answers 200 for everything, every path a scanner
guesses "exists": ffuf calibrates its own scan with -ac, but that never left
the ffuf process, so nikto's and nuclei's path findings on the same host were
all reported as real.

These tests cover the decision logic (pure) and the validator's use of it
(against a fake SafePoC - no network).
"""
import asyncio
from urllib.parse import urlparse

import pytest

from app.scans.models import Finding
from app.validation.baseline import (
    CATCH_ALL_STATUSES,
    NO_BASELINE,
    calibrate,
    derive,
    matches,
    probe_paths,
    probe_urls,
    shape_of,
    similar,
    title_of,
)
from app.validation.models import ValidationStatus
from app.validation.validator import FindingValidator

CATCH_ALL_BODY = "<html><head><title>Welcome</title></head><body>" + "x" * 400 + "</body></html>"
REAL_PAGE = "<html><head><title>Admin login</title></head><body>" + "y" * 900 + "</body></html>"


# --------------------------------------------------------------------------
# shapes
# --------------------------------------------------------------------------

def test_title_is_extracted_and_normalised():
    assert title_of("<html><TITLE>  Hello\n World </TITLE>") == "hello world"
    assert title_of("no title here") == ""
    assert title_of("") == ""
    assert title_of(None) == ""


def test_identical_answers_are_similar():
    a = shape_of(200, CATCH_ALL_BODY)
    b = shape_of(200, CATCH_ALL_BODY)
    assert similar(a, b)


def test_different_status_is_never_similar():
    assert not similar(shape_of(200, CATCH_ALL_BODY), shape_of(403, CATCH_ALL_BODY))


def test_different_title_is_never_similar():
    assert not similar(shape_of(200, CATCH_ALL_BODY), shape_of(200, REAL_PAGE))


def test_small_length_wobble_is_tolerated():
    a = shape_of(200, CATCH_ALL_BODY)
    b = shape_of(200, CATCH_ALL_BODY + "z" * 20)
    assert similar(a, b)


def test_large_length_difference_is_not_similar():
    same_title = CATCH_ALL_BODY.replace("</body>", "z" * 5000 + "</body>")
    assert not similar(shape_of(200, CATCH_ALL_BODY), shape_of(200, same_title))


def test_path_echo_is_allowed_for(  # a catch-all that prints the requested path
):
    short = shape_of(200, "<title>t</title>no page at /a", path="/a")
    long_path = "/" + "b" * 60
    echoed = shape_of(200, f"<title>t</title>no page at {long_path}", path=long_path)
    assert similar(short, echoed)


# --------------------------------------------------------------------------
# derive()
# --------------------------------------------------------------------------

def test_catch_all_is_detected():
    b = derive([shape_of(200, CATCH_ALL_BODY), shape_of(200, CATCH_ALL_BODY)])
    assert b.catch_all is True
    assert b.samples == 2
    assert "200" in b.reason


def test_a_real_404_is_not_a_catch_all():
    b = derive([shape_of(404, "Not Found"), shape_of(404, "Not Found")])
    assert b.catch_all is False
    assert "404" in b.reason


def test_one_sample_is_never_enough():
    b = derive([shape_of(200, CATCH_ALL_BODY)])
    assert b.catch_all is False
    assert b.samples == 1


def test_no_samples_degrades_to_no_baseline():
    b = derive([])
    assert b.catch_all is False
    assert b.shape is None


def test_per_path_generated_content_is_not_a_usable_baseline():
    """If the answers to missing paths differ, no single shape describes
    "missing" and we must not discard anything."""
    b = derive([shape_of(200, CATCH_ALL_BODY), shape_of(200, REAL_PAGE)])
    assert b.catch_all is False
    assert b.shape is None


@pytest.mark.parametrize("status", [200, 201, 301, 302, 401, 403])
def test_blanket_non_404_statuses_count_as_catch_all(status):
    body = "<title>gate</title>denied"
    assert derive([shape_of(status, body), shape_of(status, body)]).catch_all


@pytest.mark.parametrize("status", [404, 410, 400, 500, 503])
def test_real_missing_or_error_statuses_are_not_catch_all(status):
    body = "<title>err</title>"
    assert not derive([shape_of(status, body), shape_of(status, body)]).catch_all
    assert status not in CATCH_ALL_STATUSES


# --------------------------------------------------------------------------
# probes
# --------------------------------------------------------------------------

def test_probe_paths_are_unique_and_varied():
    paths = probe_paths(4)
    assert len(set(paths)) == 4
    assert len({p.rsplit(".", 1)[-1] for p in paths}) > 1
    for p in paths:
        assert p.startswith("/") and len(p) > 20


def test_probe_paths_never_returns_empty():
    assert probe_paths(0)


def test_probe_urls_are_rooted_at_the_origin():
    urls = probe_urls("https://target.example.com/deep/page?a=1", 2)
    assert len(urls) == 2
    for u in urls:
        parsed = urlparse(u)
        assert parsed.scheme == "https"
        assert parsed.netloc == "target.example.com"
        assert not parsed.query
        assert "/deep/" not in parsed.path


def test_probe_urls_reject_a_non_url():
    assert probe_urls("") == []
    assert probe_urls("target.example.com") == []


# --------------------------------------------------------------------------
# matches()
# --------------------------------------------------------------------------

def test_matches_requires_a_calibrated_catch_all():
    assert not matches(NO_BASELINE, 200, CATCH_ALL_BODY)
    honest = derive([shape_of(404, "nope"), shape_of(404, "nope")])
    assert not matches(honest, 404, "nope")


def test_matches_the_catch_all_page():
    b = derive([shape_of(200, CATCH_ALL_BODY), shape_of(200, CATCH_ALL_BODY)])
    assert matches(b, 200, CATCH_ALL_BODY)


def test_a_genuinely_different_page_does_not_match():
    b = derive([shape_of(200, CATCH_ALL_BODY), shape_of(200, CATCH_ALL_BODY)])
    assert not matches(b, 200, REAL_PAGE)


# --------------------------------------------------------------------------
# calibrate() + the validator, against a fake SafePoC
# --------------------------------------------------------------------------

class Resp:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeSafePoC:
    """Serves a body per path prefix; records every URL fetched."""

    def __init__(self, default=(200, CATCH_ALL_BODY), routes=None):
        self.default = default
        self.routes = routes or {}
        self.fetched = []

    async def fetch(self, url, method="GET"):
        self.fetched.append(url)
        path = urlparse(url).path
        for prefix, answer in self.routes.items():
            if path.startswith(prefix):
                if answer is None:
                    return None
                return Resp(*answer)
        return Resp(*self.default)


def run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def test_calibrate_detects_a_catch_all_target():
    safe = FakeSafePoC()
    b = run(calibrate(safe, "https://target.example.com/"))
    assert b.catch_all is True
    assert len(safe.fetched) == 3


def test_calibrate_leaves_an_honest_target_alone():
    safe = FakeSafePoC(default=(404, "<title>404</title>Not Found"))
    b = run(calibrate(safe, "https://target.example.com/"))
    assert b.catch_all is False


def test_calibrate_survives_an_unreachable_target():
    class Broken(FakeSafePoC):
        async def fetch(self, url, method="GET"):
            raise RuntimeError("dns")

    b = run(calibrate(Broken(), "https://target.example.com/"))
    assert b.catch_all is False
    assert b.samples == 0


def test_calibrate_without_a_url_makes_no_requests():
    safe = FakeSafePoC()
    b = run(calibrate(safe, ""))
    assert b is NO_BASELINE
    assert safe.fetched == []


def _finding(url, cls="content_discovery", sev="medium"):
    return Finding(severity=sev, title=f"found {url}", description="",
                   target=url, evidence="", metadata={"vuln_class": cls})


def test_path_finding_on_a_catch_all_is_a_false_positive():
    safe = FakeSafePoC()
    baseline = run(calibrate(safe, "https://target.example.com/"))
    v = FindingValidator(safe, baseline=baseline)
    res = run(v.validate(_finding("https://target.example.com/backup.sql"),
                         "nikto", "information_disclosure"))
    assert res.status is ValidationStatus.FALSE_POSITIVE
    assert res.method == "baseline (catch-all)"


def test_a_path_that_really_differs_survives_the_baseline():
    safe = FakeSafePoC(routes={"/admin": (200, REAL_PAGE)})
    baseline = run(calibrate(safe, "https://target.example.com/"))
    v = FindingValidator(safe, baseline=baseline)
    res = run(v.validate(_finding("https://target.example.com/admin"),
                         "nikto", "information_disclosure"))
    assert res.status is not ValidationStatus.FALSE_POSITIVE


def test_the_baseline_never_touches_an_injection_finding():
    """A SQLi response looking like the home page means nothing; only
    path-existence claims may be discarded this way."""
    safe = FakeSafePoC()
    baseline = run(calibrate(safe, "https://target.example.com/"))
    before = len(safe.fetched)
    v = FindingValidator(safe, baseline=baseline)
    res = run(v.validate(_finding("https://target.example.com/x?id=1",
                                  cls="sql_injection"),
                         "nuclei", "sql_injection"))
    assert res.status is not ValidationStatus.FALSE_POSITIVE
    assert len(safe.fetched) == before  # no extra request either


def test_an_honest_target_costs_no_extra_request():
    safe = FakeSafePoC(default=(404, "<title>404</title>gone"),
                       routes={"/backup.sql": (200, REAL_PAGE)})
    baseline = run(calibrate(safe, "https://target.example.com/"))
    n = len(safe.fetched)
    v = FindingValidator(safe, baseline=baseline)
    run(v.validate(_finding("https://target.example.com/backup.sql"),
                   "nikto", "information_disclosure"))
    assert len(safe.fetched) == n


def test_the_home_page_is_not_a_path_existence_claim():
    safe = FakeSafePoC()
    baseline = run(calibrate(safe, "https://target.example.com/"))
    v = FindingValidator(safe, baseline=baseline)
    res = run(v.validate(_finding("https://target.example.com/"),
                         "nikto", "information_disclosure"))
    assert res.status is not ValidationStatus.FALSE_POSITIVE


def test_validator_without_a_baseline_behaves_as_before():
    safe = FakeSafePoC()
    v = FindingValidator(safe)
    assert v.baseline is NO_BASELINE
    res = run(v.validate(_finding("https://target.example.com/backup.sql"),
                         "nikto", "information_disclosure"))
    assert res.status is not ValidationStatus.FALSE_POSITIVE


def test_baseline_to_public_is_json_ready():
    b = derive([shape_of(200, CATCH_ALL_BODY), shape_of(200, CATCH_ALL_BODY)])
    pub = b.to_public()
    assert pub["catch_all"] is True
    assert pub["shape"]["status"] == 200
    assert NO_BASELINE.to_public()["shape"] is None
