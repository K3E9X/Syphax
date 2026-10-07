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


@pytest.mark.parametrize("counts,expected", [
    ({"card_number": 1}, "high"),
    ({"iban": 1}, "high"),
    ({"french_nir": 1}, "high"),
    ({"email": 50}, "medium"),
    ({"email": 2}, "low"),
])
def test_severity_scales_with_sensitivity_and_volume(counts, expected):
    assert severity_for_pii(counts) == expected


def test_clean_json_yields_nothing():
    assert pii_values('{"status":"ok","items":[1,2,3]}') == {}
