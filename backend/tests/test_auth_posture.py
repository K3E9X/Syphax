"""Identity + authentication posture (OWASP IDNT/ATHN, previously untested)."""
import pytest

from app.analysis.auth_posture import (bypass_succeeded, carries_secret,
                                       enumeration_phrase, is_auth_url,
                                       looks_protected, weak_min_length)


@pytest.mark.parametrize("url,expected", [
    ("https://h/api/login", True),
    ("https://h/account/password/reset", True),
    ("https://h/oauth/token", True),
    ("https://h/signup", True),
    ("https://h/static/logo.png", False),
    ("https://h/products", False),
])
def test_auth_url_detection(url, expected):
    assert is_auth_url(url) is expected


def test_carries_secret_form_json_and_basic():
    assert carries_secret("user=a&password=b", [])
    assert carries_secret('{"username":"a","passwd":"b"}', [])
    assert carries_secret("q=1", [["Authorization", "Basic dXNlcjpwdw=="]])


def test_carries_secret_ignores_ordinary_requests():
    assert not carries_secret("q=1&page=2", [])
    assert not carries_secret("", [["Authorization", "Bearer abc"]])  # not Basic


@pytest.mark.parametrize("body,hit", [
    ("Error: user not found", True),
    ("That email is not registered", True),
    ("Compte introuvable", True),
    ("Invalid username.", True),               # singles out the account
    ("Invalid username or password", False),   # the correct, generic message
    ("Identifiant ou mot de passe incorrect", False),
    ("Invalid credentials", False),
    ("Login failed", False),
])
def test_enumeration_phrase(body, hit):
    assert (enumeration_phrase(body) is not None) is hit


def test_generic_combined_message_wins_over_ambiguous_wording():
    """"invalid username or password" must never be reported as enumeration -
    it is exactly the message the remediation asks for."""
    assert enumeration_phrase("Invalid username or password") is None
    # ...but a strong phrase still counts even alongside generic wording.
    assert enumeration_phrase(
        "Invalid username or password. (user not found)") == "user not found"


def test_weak_password_policy_from_the_page_itself():
    assert weak_min_length('<input type="password" minlength="4">') == 4
    assert weak_min_length('<input type="password" minlength="12">') is None
    assert weak_min_length("no rule here") is None


def test_weak_password_policy_takes_the_shortest():
    page = ('<input type="password" minlength="6">'
            '<input name="new_password" minlength="4">')
    assert weak_min_length(page) == 4


def test_a_non_password_field_is_ignored():
    """A search box with minlength=3 was reported as a password policy."""
    assert weak_min_length('<input type="search" name="q" minlength="3">') is None


def test_protected_status():
    assert looks_protected(401) and looks_protected(403)
    assert not looks_protected(200) and not looks_protected(404)


def test_bypass_only_counts_protected_to_success():
    assert bypass_succeeded(403, 200)
    assert bypass_succeeded(401, 204)
    assert not bypass_succeeded(403, 403)
    assert not bypass_succeeded(200, 200)     # was never protected
    assert not bypass_succeeded(403, None)
    assert not bypass_succeeded(403, 500)
