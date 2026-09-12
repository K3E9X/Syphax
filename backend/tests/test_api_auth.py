"""API key gate. Pure decision logic - main.py only wires it as middleware."""
from app.api_auth import authorize, extract_key, is_guarded, key_ok

KEY = "s3cret-key"


def _h(**kw):
    return {k.lower().replace("_", "-"): v for k, v in kw.items()}


# ---- what is guarded --------------------------------------------------------
def test_api_paths_are_guarded_health_is_not():
    assert is_guarded("/api/engagements")
    assert is_guarded("/api/network/vpn/connect")
    assert not is_guarded("/api/health")
    # non-/api paths are outside the gate entirely
    assert not is_guarded("/")
    assert not is_guarded("/assets/index.js")


# ---- reading the key --------------------------------------------------------
def test_key_read_from_header_bearer_or_query():
    assert extract_key(_h(X_API_Key=KEY)) == KEY
    assert extract_key(_h(Authorization=f"Bearer {KEY}")) == KEY
    assert extract_key(_h(Authorization=f"bearer {KEY}")) == KEY
    # query fallback exists for WebSockets, which cannot carry headers
    assert extract_key({}, query_key=KEY) == KEY
    assert extract_key(None, query_key=KEY) == KEY
    assert extract_key({}) == ""


def test_header_wins_over_query():
    assert extract_key(_h(X_API_Key=KEY), query_key="other") == KEY


# ---- comparison -------------------------------------------------------------
def test_key_ok_rejects_empty_and_wrong():
    assert key_ok(KEY, KEY)
    assert not key_ok("wrong", KEY)
    assert not key_ok("", KEY)
    # an unset expected key must never authorise through this function
    assert not key_ok(KEY, "")
    assert not key_ok("", "")


def test_key_ok_is_not_prefix_based():
    assert not key_ok(KEY[:-1], KEY)
    assert not key_ok(KEY + "x", KEY)


# ---- whole decision ---------------------------------------------------------
def test_auth_disabled_when_no_key_configured():
    # the default local setup must keep working untouched
    assert authorize("/api/engagements", {}, expected="")


def test_guarded_request_needs_the_key():
    assert not authorize("/api/engagements", {}, expected=KEY)
    assert not authorize("/api/engagements", _h(X_API_Key="nope"), expected=KEY)
    assert authorize("/api/engagements", _h(X_API_Key=KEY), expected=KEY)


def test_health_stays_reachable_even_with_auth_on():
    # the compose healthcheck and the UI's "backend up" badge must not break
    assert authorize("/api/health", {}, expected=KEY)


def test_websocket_style_query_key_is_accepted():
    assert authorize("/api/engagements", {}, expected=KEY, query_key=KEY)
    assert not authorize("/api/engagements", {}, expected=KEY, query_key="nope")
