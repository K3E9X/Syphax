"""Ownership proof: the third-party path that authorises an engagement.

A comparison that accepts a near-miss authorises scanning a host the operator
does not control, so these are deliberately exhaustive about what must NOT
pass.
"""
from app.engagements.verifier import (expected_txt_value, txt_matches,
                                      txt_record_value, well_known_matches)

TOKEN = "abc123def456"


class _Rdata:
    """Stand-in for a dnspython TXT answer."""
    def __init__(self, strings=None, text=None):
        if strings is not None:
            self.strings = strings
        self._text = text

    def __str__(self):
        return self._text if self._text is not None else ""


# ---- reading a TXT answer ---------------------------------------------------
def test_txt_chunks_are_joined():
    # A long TXT record arrives split into chunks; comparing one chunk would
    # never match the published value.
    full = expected_txt_value(TOKEN)
    half = len(full) // 2
    split = _Rdata(strings=[full[:half].encode(), full[half:].encode()])
    assert txt_record_value(split) == full
    assert txt_matches(split, TOKEN)


def test_txt_falls_back_to_str_and_strips_quotes():
    quoted = _Rdata(text=f'"{expected_txt_value(TOKEN)}"')
    assert txt_record_value(quoted) == expected_txt_value(TOKEN)
    assert txt_matches(quoted, TOKEN)


def test_txt_tolerates_surrounding_whitespace():
    padded = _Rdata(strings=[f"  {expected_txt_value(TOKEN)}  ".encode()])
    assert txt_matches(padded, TOKEN)


# ---- what must NOT authorise ------------------------------------------------
def test_txt_rejects_other_records_on_the_domain():
    for other in ("v=spf1 include:example.com ~all",
                  "google-site-verification=xyz",
                  "syphax-verify=", "syphax-verify=someoneelsestoken"):
        assert not txt_matches(_Rdata(strings=[other.encode()]), TOKEN), other


def test_txt_rejects_a_token_merely_contained_in_a_longer_value():
    # Substring matching here would let any record that happens to embed the
    # token authorise the engagement.
    longer = _Rdata(strings=[f"{expected_txt_value(TOKEN)} extra".encode()])
    assert not txt_matches(longer, TOKEN)
    prefixed = _Rdata(strings=[f"x {expected_txt_value(TOKEN)}".encode()])
    assert not txt_matches(prefixed, TOKEN)


def test_txt_rejects_the_bare_token_without_the_prefix():
    assert not txt_matches(_Rdata(strings=[TOKEN.encode()]), TOKEN)


def test_empty_token_never_matches_anything():
    # A blank token must not turn every record into a proof.
    assert not txt_matches(_Rdata(strings=[b"syphax-verify="]), "")
    assert not well_known_matches("", "")
    assert not well_known_matches("anything", "")


def test_malformed_rdata_does_not_crash():
    assert txt_record_value(None) == ""
    assert not txt_matches(None, TOKEN)
    assert not txt_matches(_Rdata(strings=[object()]), TOKEN)


# ---- the .well-known file ---------------------------------------------------
def test_well_known_accepts_the_token_with_trailing_whitespace():
    # Editors add a newline; that is not a reason to refuse a valid proof.
    for body in (TOKEN, TOKEN + "\n", f"  {TOKEN}  \r\n"):
        assert well_known_matches(body, TOKEN), repr(body)


def test_well_known_rejects_a_page_that_merely_contains_the_token():
    # An error page echoing the requested URL would otherwise authorise us.
    assert not well_known_matches(f"<html>404: syphax-{TOKEN}.txt not found</html>", TOKEN)
    assert not well_known_matches(f"{TOKEN} plus other content", TOKEN)
    assert not well_known_matches(None, TOKEN)
    assert not well_known_matches("", TOKEN)


def test_well_known_rejects_someone_elses_token():
    assert not well_known_matches("someoneelsestoken", TOKEN)
