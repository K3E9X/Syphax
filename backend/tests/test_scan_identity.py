"""How the tools present themselves on the wire, chosen per engagement.

Two properties are worth more than the rest:

  * a profile is a WHOLE header set, not a User-Agent string. A request
    claiming to be Firefox while sending Sec-CH-UA client hints - which Firefox
    does not implement - is more conspicuous than one with no User-Agent at
    all, so the header set has to match the engine the string claims.
  * an unrecognised or empty choice must never become "send nothing". Silently
    stripping the headers would change how every tool behaves, invisibly.
"""
from __future__ import annotations

import pytest

from app.scans import identity


def headers_of(args, flag="-H"):
    """Pull `Name: value` pairs back out of a tool's argv."""
    out = {}
    for i, token in enumerate(args):
        if token == flag and i + 1 < len(args):
            name, _, value = args[i + 1].partition(": ")
            out[name] = value
    return out


# ---- the catalog ------------------------------------------------------------

def test_every_profile_has_an_id_a_label_and_a_coherent_header_set():
    for profile in identity.BROWSER_PROFILES:
        assert profile["id"], f"{profile['ua'][:40]} has no id"
        assert profile["label"]
        assert profile["ua"].startswith("Mozilla/5.0")
        assert profile["headers"]["Accept"]
        assert profile["headers"]["Accept-Language"]


def test_profile_ids_are_unique():
    ids = [p["id"] for p in identity.BROWSER_PROFILES]
    assert len(ids) == len(set(ids))


def test_client_hints_are_sent_by_chromium_and_by_nothing_else():
    """The signature this exists to avoid. Firefox does not implement client
    hints; a Firefox User-Agent that sends them is a tell."""
    for profile in identity.BROWSER_PROFILES:
        ua = profile["ua"].lower()
        has_hints = "Sec-CH-UA" in profile["headers"]
        chromium = "chrome/" in ua or "edg/" in ua
        assert has_hints == chromium, f"{profile['id']} disagrees with its own engine"


def test_the_choices_offered_cover_every_profile_plus_the_three_modes():
    offered = {c["id"] for c in identity.choices()}
    assert {p["id"] for p in identity.BROWSER_PROFILES} <= offered
    assert {identity.MODE_ROTATE, identity.MODE_CUSTOM, identity.MODE_TOOL} <= offered
    for choice in identity.choices():
        assert choice["label"] and choice["note"], choice


def test_every_offered_choice_actually_resolves():
    """A UI offering something the backend does not know would fall back to
    rotating, and the operator would have no way to tell."""
    for choice in identity.choices():
        assert identity.is_valid_choice(choice["id"]), choice["id"]


# ---- resolution -------------------------------------------------------------

def test_a_named_browser_resolves_to_exactly_that_browser():
    profile = identity.resolve_profile("firefox-127-linux")
    assert "Firefox/127.0" in profile["ua"]
    assert "Sec-CH-UA" not in profile["headers"]


def test_rotate_picks_from_the_catalog():
    seen = {identity.resolve_profile("rotate")["id"] for _ in range(60)}
    assert seen <= {p["id"] for p in identity.BROWSER_PROFILES}
    assert len(seen) > 1, "rotation that never rotates is a fixed User-Agent"


def test_tool_mode_means_send_nothing_which_is_not_the_same_as_an_empty_string():
    """None tells the caller to omit the flags entirely. A profile with an
    empty User-Agent would STRIP the one the tool would have sent."""
    assert identity.resolve_profile("tool") is None


def test_a_custom_string_gets_the_header_set_of_the_engine_it_claims():
    firefox = identity.resolve_profile("custom", "MyCorp/1.0 Firefox/123")
    assert "Sec-CH-UA" not in firefox["headers"]
    chrome = identity.resolve_profile("custom", "MyCorp/1.0 Chrome/126")
    assert "Sec-CH-UA" in chrome["headers"]
    safari = identity.resolve_profile("custom", "MyApp Version/17.0 Safari/605")
    assert "Sec-CH-UA" not in safari["headers"]


def test_a_custom_mode_with_no_string_falls_back_rather_than_sending_nothing():
    """That combination is a misconfiguration, not an instruction to send an
    empty User-Agent."""
    profile = identity.resolve_profile("custom", "")
    assert profile is not None and profile["ua"]


@pytest.mark.parametrize("mode", ["", "rotate", "nonsense", "CHROME-126-WINDOWS"])
def test_no_input_ever_produces_a_headerless_request_by_accident(mode):
    profile = identity.resolve_profile(mode)
    assert profile is not None
    assert profile["ua"]


def test_an_unknown_mode_is_rejected_at_the_api_boundary_not_silently_accepted():
    assert identity.is_valid_choice("chrome-126-windows")
    assert identity.is_valid_choice("")           # means "use the environment"
    assert not identity.is_valid_choice("internet-explorer-6")


# ---- how it reaches each tool ----------------------------------------------

def test_the_chosen_browser_reaches_a_dash_h_tool():
    args = identity.identity_args("nuclei", mode="firefox-127-linux")
    sent = headers_of(args)
    assert "Firefox/127.0" in sent["User-Agent"]
    assert "Sec-CH-UA" not in sent


def test_sqlmap_gets_its_own_spelling():
    args = identity.identity_args("sqlmap", mode="chrome-126-windows")
    assert "--user-agent" in args
    assert args[args.index("--user-agent") + 1].startswith("Mozilla/5.0")


def test_tool_mode_sends_no_identity_flags_at_all():
    for tool in ("nuclei", "sqlmap", "commix", "whatweb", "nikto", "wpscan"):
        assert identity.identity_args(tool, mode="tool") == [], tool


def test_recon_tools_that_make_no_http_request_get_nothing():
    for tool in ("nmap", "subfinder", "dnsx", "gau", "testssl", "naabu"):
        assert identity.identity_args(tool, mode="chrome-126-windows") == []


def test_wpscan_never_gets_both_a_pinned_ua_and_random_rotation():
    """The two flags conflict, and wpscan exits rather than picking one."""
    rotating = identity.identity_args("wpscan", mode="rotate")
    assert "--user-agent" not in rotating
    pinned = identity.identity_args("wpscan", mode="chrome-126-windows")
    assert "--user-agent" in pinned


def test_the_attribution_header_survives_tool_mode(monkeypatch):
    """X-Pentest-ID tells the client's SOC the traffic is authorised. That is
    orthogonal to which User-Agent the tool uses, so choosing 'each tool's own'
    must not drop it."""
    from app.config import settings
    monkeypatch.setattr(settings, "pentest_id", "ENG-2026-014")
    args = identity.identity_args("nuclei", mode="tool")
    assert headers_of(args).get("X-Pentest-ID") == "ENG-2026-014"


def test_no_engagement_preference_falls_back_to_the_environment(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "user_agent_mode", "fixed")
    monkeypatch.setattr(settings, "user_agent", "Mozilla/5.0 Firefox/127.0")
    sent = headers_of(identity.identity_args("nuclei"))
    assert sent["User-Agent"] == "Mozilla/5.0 Firefox/127.0"


# ---- the engagement carries the choice --------------------------------------

def test_an_engagement_stores_the_choice_normalised():
    from app.engagements.models import Engagement

    e = Engagement.create("https://app.example.com", attested=True,
                          user_agent_mode="  Firefox-127-Linux  ")
    assert e.user_agent_mode == "firefox-127-linux"


def test_an_engagement_with_no_preference_stays_empty():
    """Empty means "use the environment", which is what every engagement
    created before this feature existed has."""
    from app.engagements.models import Engagement

    e = Engagement.create("https://app.example.com", attested=True)
    assert e.user_agent_mode == ""
    assert e.user_agent == ""


def test_the_choice_is_visible_to_the_ui_and_the_credentials_still_are_not():
    from app.engagements.models import Engagement

    e = Engagement.create("https://app.example.com", attested=True,
                          user_agent_mode="custom", user_agent="MyApp/2.0",
                          primary_auth=[{"name": "Cookie", "value": "secret"}])
    public = e.to_public()
    assert public["user_agent_mode"] == "custom"
    assert public["user_agent"] == "MyApp/2.0"
    assert "primary_auth" not in public


def test_a_custom_chromium_string_gets_client_hints_that_match_it():
    """This returned the Chromium `Accept` with no Sec-CH-UA at all: a request
    claiming Chrome while sending none of the headers Chrome always sends,
    which is the exact incoherence this module exists to avoid."""
    profile = identity.resolve_profile(
        "custom",
        "Mozilla/5.0 (Linux; Android 14; Pixel 9) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36")
    hints = profile["headers"]["Sec-CH-UA"]
    assert '"131"' in hints, "the version in the hints must match the one in the string"
    assert "Google Chrome" in hints
    assert profile["headers"]["Sec-CH-UA-Mobile"] == "?1"
    assert profile["headers"]["Sec-CH-UA-Platform"] == '"Android"'


def test_a_custom_edge_string_is_not_labelled_as_chrome():
    profile = identity.resolve_profile(
        "custom", "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0 Edg/126.0.0.0")
    assert "Microsoft Edge" in profile["headers"]["Sec-CH-UA"]
