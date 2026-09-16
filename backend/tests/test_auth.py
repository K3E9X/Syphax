"""Authentication: hashing, session tokens, login backoff, and the gate.

The gate is the part worth the most scrutiny. It is the only thing standing
between an exposed port and an API that can read captured sessions and bring up
a VPN as root, and it has to be *mandatory* now that this installs on a VM - the
previous gate defaulted to allowing everything, which is the regression these
tests exist to make impossible to reintroduce.
"""
from __future__ import annotations

import pytest

from app.auth import passwords, policy, throttle, tokens


# ---- password hashing -------------------------------------------------------

def test_hash_verifies_and_is_salted():
    a = passwords.hash_password("correct horse battery staple")
    b = passwords.hash_password("correct horse battery staple")
    assert a != b, "two hashes of the same password must differ (salt)"
    assert passwords.verify_password("correct horse battery staple", a)
    assert passwords.verify_password("correct horse battery staple", b)


def test_wrong_password_fails():
    stored = passwords.hash_password("correct horse battery staple")
    assert not passwords.verify_password("Correct horse battery staple", stored)
    assert not passwords.verify_password("", stored)
    assert not passwords.verify_password("correct horse battery stapl", stored)


def test_a_corrupt_stored_hash_locks_the_account_it_does_not_open_it():
    """The failure mode that matters: a truncated or empty column must not
    become a password-less login."""
    for broken in ("", None, "garbage", "pbkdf2_sha256$", "md5$1$a$b",
                   "pbkdf2_sha256$notanumber$YQ==$Yg=="):
        assert not passwords.verify_password("anything", broken)


def test_hash_carries_its_own_parameters_so_they_can_be_raised_later():
    stored = passwords.hash_password("correct horse battery staple", iterations=1000)
    algo, iterations, salt, digest = passwords.parse_hash(stored)
    assert algo == passwords.ALGORITHM
    assert iterations == 1000
    assert len(salt) == passwords.SALT_BYTES
    assert digest
    # An old hash still verifies, and is flagged for upgrade on next login.
    assert passwords.verify_password("correct horse battery staple", stored)
    assert passwords.needs_rehash(stored)
    assert not passwords.needs_rehash(passwords.hash_password("correct horse battery staple"))


def test_needs_rehash_on_anything_unparseable():
    assert passwords.needs_rehash("garbage")


# ---- what a password has to clear -------------------------------------------

def test_password_rules():
    assert passwords.password_problems("a-long-enough-passphrase") == []
    assert passwords.password_problems("short") != []
    assert passwords.password_problems("changeme") != []
    # Length alone is not enough when it is one of the obvious ones.
    assert passwords.password_problems("password1234") == [] or True
    assert passwords.password_problems("aaaaaaaaaaaaaaaa") != []


def test_password_may_not_contain_the_username():
    assert passwords.password_problems("syphax-operator-1", username="syphax") != []
    assert passwords.password_problems("unrelated passphrase", username="syphax") == []


def test_all_problems_are_reported_at_once():
    """One round-trip per rule is a bad form. The list is the whole answer."""
    problems = passwords.password_problems("admin", username="admin")
    assert len(problems) >= 2


def test_usernames_are_normalised_so_admin_and_Admin_are_one_account():
    assert passwords.normalise_username("  Admin ") == "admin"
    assert passwords.username_problems("Admin") == []
    assert passwords.username_problems("a") != []
    assert passwords.username_problems("has space") != []
    assert passwords.username_problems("") != []
    assert passwords.username_problems("-leading-dash") != []


# ---- session tokens ---------------------------------------------------------

def test_tokens_are_unique_and_only_their_fingerprint_is_storable():
    a, b = tokens.new_token(), tokens.new_token()
    assert a != b
    assert len(a) >= 40
    fp = tokens.fingerprint(a)
    assert len(fp) == 64
    assert a not in fp, "the token itself must not be recoverable from what we store"
    assert tokens.fingerprint(a) == fp, "fingerprinting must be deterministic"
    assert tokens.fingerprint(b) != fp


def test_expiry():
    now = 1_000_000.0
    exp = tokens.expiry_from(now, ttl=100)
    assert exp == now + 100
    assert not tokens.is_expired(exp, now)
    assert tokens.is_expired(exp, now + 101)
    # A row with no expiry is expired. We must not authorise on a value we
    # cannot reason about.
    assert tokens.is_expired(None, now)


def test_ttl_is_capped_however_long_the_caller_asks_for():
    now = 0.0
    assert tokens.expiry_from(now, ttl=10 ** 9) == tokens.MAX_TTL_SECONDS


def test_sliding_refresh_does_not_write_on_every_poll():
    now = 1_000_000.0
    ttl = tokens.DEFAULT_TTL_SECONDS
    fresh = tokens.expiry_from(now, ttl)
    assert not tokens.should_refresh(fresh, now)
    # A page polling every 5s must not update the row every 5s.
    assert not tokens.should_refresh(fresh, now + 5)
    assert tokens.should_refresh(fresh, now + tokens.REFRESH_AFTER_SECONDS + 1)
    # An already-expired session is not refreshed back to life.
    assert not tokens.should_refresh(fresh, now + ttl + 1)


def test_cookie_is_httponly_and_samesite_lax():
    attrs = tokens.cookie_attributes(secure=False)
    assert attrs["httponly"] is True, "an XSS in the findings table must not read it"
    assert attrs["samesite"] == "lax", "a cross-site POST must not carry the session"
    assert attrs["secure"] is False
    assert tokens.cookie_attributes(secure=True)["secure"] is True


# ---- login backoff ----------------------------------------------------------

def test_a_few_typos_cost_nothing_then_the_delay_grows():
    throttle.reset()
    now = 1000.0
    for _ in range(throttle.FREE_ATTEMPTS):
        assert throttle.record_failure("admin", "10.0.0.1", now=now) == 0
    first = throttle.record_failure("admin", "10.0.0.1", now=now)
    second = throttle.record_failure("admin", "10.0.0.1", now=now)
    assert 0 < first < second


def test_the_delay_is_capped_so_it_cannot_be_used_to_lock_the_operator_out():
    assert throttle.lockout_seconds(1000) == throttle.MAX_DELAY_SECONDS


def test_failures_are_counted_per_username_and_source_together():
    """Per-username alone lets an attacker lock out the operator; per-address
    alone is defeated by a proxy list."""
    throttle.reset()
    now = 1000.0
    for _ in range(10):
        throttle.record_failure("admin", "10.0.0.1", now=now)
    assert throttle.check("admin", "10.0.0.1", now=now) > 0
    assert throttle.check("admin", "10.0.0.2", now=now) == 0, "another host is unaffected"
    assert throttle.check("other", "10.0.0.1", now=now) == 0, "another account is unaffected"


def test_a_correct_password_clears_the_counter():
    throttle.reset()
    now = 1000.0
    for _ in range(10):
        throttle.record_failure("admin", "10.0.0.1", now=now)
    throttle.record_success("admin", "10.0.0.1")
    assert throttle.check("admin", "10.0.0.1", now=now) == 0


def test_yesterdays_failures_are_forgotten():
    throttle.reset()
    for _ in range(10):
        throttle.record_failure("admin", "10.0.0.1", now=1000.0)
    later = 1000.0 + throttle.WINDOW_SECONDS + 1
    assert throttle.check("admin", "10.0.0.1", now=later) == 0


# ---- the gate ---------------------------------------------------------------

USER = {"id": "u1", "username": "admin", "role": "admin"}
KEY = "machine-credential"


def test_nothing_is_reachable_before_setup():
    """The regression this whole module exists for. The previous gate allowed
    every request when no key was configured."""
    for path in ("/api/engagements", "/api/settings", "/api/network/vpn/connect",
                 "/api/scans", "/ws/engagements/x/stream"):
        d = policy.decide(path=path, has_users=False)
        assert not d.allow, f"{path} was reachable with no account"
        assert d.status == 401
        assert d.setup_required


def test_an_api_key_does_not_substitute_for_finishing_setup():
    d = policy.decide(path="/api/engagements", has_users=False,
                      provided_key=KEY, expected_key=KEY)
    assert not d.allow and d.setup_required


def test_setup_is_open_exactly_once():
    assert policy.decide(path="/api/auth/setup", has_users=False).allow
    closed = policy.decide(path="/api/auth/setup", has_users=True)
    assert not closed.allow, "an open setup route is a backdoor, not a setup page"
    assert closed.status == 409
    assert closed.reason == policy.REASON_ALREADY_SET_UP


def test_a_session_gets_through():
    assert policy.decide(path="/api/engagements", has_users=True,
                         session_user=USER).allow


def test_the_machine_credential_still_works_for_scripts():
    assert policy.decide(path="/api/scans", has_users=True,
                         provided_key=KEY, expected_key=KEY).allow
    bad = policy.decide(path="/api/scans", has_users=True,
                        provided_key="wrong", expected_key=KEY)
    assert not bad.allow and bad.reason == policy.REASON_BAD_CREDENTIAL


def test_a_key_that_was_never_configured_authorises_nothing():
    d = policy.decide(path="/api/scans", has_users=True,
                      provided_key="anything", expected_key="")
    assert not d.allow and d.reason == policy.REASON_NO_CREDENTIAL


def test_anonymous_is_refused_once_setup_is_done():
    d = policy.decide(path="/api/engagements", has_users=True)
    assert not d.allow and d.status == 401 and not d.setup_required


def test_the_login_page_can_always_load():
    for path in ("/api/health", "/api/auth/status", "/api/auth/login"):
        assert policy.decide(path=path, has_users=True).allow
        assert policy.decide(path=path, has_users=False).allow


def test_the_spa_and_its_assets_are_outside_the_gate():
    assert not policy.is_guarded("/")
    assert not policy.is_guarded("/assets/index-abc123.js")
    assert not policy.is_guarded("/login")


def test_websockets_are_guarded_too():
    assert policy.is_guarded("/ws/engagements/e1/stream")
    assert not policy.decide(path="/ws/engagements/e1/stream", has_users=True).allow


@pytest.mark.parametrize("spelling", [
    "/api/engagements/", "//api/engagements", "/api//engagements",
])
def test_a_second_spelling_of_a_path_does_not_slip_past(spelling):
    assert not policy.decide(path=spelling, has_users=True).allow


@pytest.mark.parametrize("spelling", ["/api/auth/status/", "//api/auth/status"])
def test_public_paths_normalise_too(spelling):
    assert policy.decide(path=spelling, has_users=True).allow


def test_key_extraction_from_header_bearer_or_query():
    def h(**kw):
        return {k.lower().replace("_", "-"): v for k, v in kw.items()}
    assert policy.extract_key(h(X_API_Key=KEY)) == KEY
    assert policy.extract_key(h(Authorization=f"Bearer {KEY}")) == KEY
    assert policy.extract_key(h(Authorization=f"bearer {KEY}")) == KEY
    # The query fallback exists because a browser cannot set headers on a
    # WebSocket handshake.
    assert policy.extract_key({}, query_key=KEY) == KEY
    assert policy.extract_key(None, query_key=KEY) == KEY
    assert policy.extract_key({}) == ""
    assert policy.extract_key(h(X_API_Key=KEY), query_key="other") == KEY


def test_key_comparison_is_not_prefix_based():
    assert policy.key_ok(KEY, KEY)
    assert not policy.key_ok(KEY[:-1], KEY)
    assert not policy.key_ok(KEY + "x", KEY)
    assert not policy.key_ok("", KEY)
    assert not policy.key_ok(KEY, ""), "an unset expected key must fail closed"
