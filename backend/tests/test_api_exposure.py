"""What the API hands back: secret fields and personal data."""
import pytest

from app.analysis.api_exposure import (collect_field_names, luhn_ok,
                                       pii_fields_in, pii_values,
                                       secret_fields_in, severity_for_pii)


def _names(doc):
    out = set()
    collect_field_names(doc, out)
    return out


def test_luhn_filters_random_digit_runs():
    assert luhn_ok("4539578763621486")        # valid test PAN
    assert not luhn_ok("1234567890123")
    assert not luhn_ok("0000")                 # too short


def test_secret_fields_are_found_nested():
    names = _names({"data": {"users": [{"id": 1, "password_hash": "x"}]}})
    assert secret_fields_in(names) == ["password_hash"]


def test_ordinary_payload_has_no_secret_fields():
    assert secret_fields_in(_names({"id": 1, "title": "a", "count": 3})) == []


def test_pii_field_names():
    names = _names({"email": "a@b.fr", "iban": "FR76...", "colour": "red"})
    assert set(pii_fields_in(names)) >= {"email", "iban"}


def test_pii_values_counts_distinct():
    counts = pii_values("a@b.fr, a@b.fr, c@d.fr")
    assert counts["email"] == 2


def test_example_and_asset_emails_are_ignored():
    assert pii_values("test@example.com logo@2x.png") == {}


def test_card_number_needs_luhn():
    assert "card_number" in pii_values("pan 4539578763621486")
    assert "card_number" not in pii_values("id 1234567890123456789")


@pytest.mark.parametrize("counts,keys,expected", [
    # A sensitive class is only HIGH once a surrounding key agrees it is
    # personal data: the IBAN/NIR patterns have no checksum and Luhn leaks a
    # few numeric ids, so an ETag or an order reference used to ship as high.
    ({"card_number": 1}, {"card_number"}, "high"),
    ({"iban": 1}, {"iban"}, "high"),
    ({"french_nir": 1}, {"ssn"}, "high"),
    ({"card_number": 1}, set(), "low"),        # bare match, no key
    ({"iban": 1}, set(), "low"),
    ({"email": 50}, {"email"}, "medium"),
    ({"email": 2}, {"email"}, "low"),
])
def test_severity_scales_with_sensitivity_and_volume(counts, keys, expected):
    assert severity_for_pii(counts, keys) == expected


def test_clean_json_yields_nothing():
    assert pii_values('{"status":"ok","items":[1,2,3]}') == {}


# ---- false positives found in review ---------------------------------------

def test_oauth_token_response_is_not_a_leak():
    """An /oauth/token endpoint returning access_token IS the product. Flagging
    it as "API returns secret fields" was a false positive."""
    from app.analysis.api_exposure import is_token_endpoint
    names = _names({"access_token": "ey", "refresh_token": "r",
                    "token_type": "Bearer", "expires_in": 3600})
    assert is_token_endpoint("/oauth/token", names)
    assert secret_fields_in(names, token_endpoint=True) == []


def test_token_shape_alone_identifies_a_token_endpoint():
    from app.analysis.api_exposure import is_token_endpoint
    names = _names({"access_token": "ey", "token_type": "Bearer", "expires_in": 60})
    assert is_token_endpoint("/v2/exchange", names)


def test_a_user_list_leaking_tokens_is_still_reported():
    """The exemption is for token endpoints only - not for every response."""
    from app.analysis.api_exposure import is_token_endpoint
    names = _names({"users": [{"password_hash": "x", "access_token": "y"}]})
    assert not is_token_endpoint("/api/users", names)
    assert secret_fields_in(names, token_endpoint=False) == [
        "access_token", "password_hash"]
