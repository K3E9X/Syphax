"""Make scan traffic look like an ordinary browser.

Same shape as `auth_args` / `waf_args`: the wrappers stay pure, and this is
the single place that knows how each binary spells "User-Agent" and "header".

Why profiles rather than a list of User-Agent strings
-----------------------------------------------------
Rotating only the User-Agent is itself a signature. A real Chrome sends
Sec-CH-UA client hints, a specific Accept ordering and Sec-Fetch-* metadata;
Firefox sends none of the client hints and a different Accept. A request that
claims to be Firefox while sending Sec-CH-UA, or that claims Chrome while
sending a bare `Accept: */*`, stands out more than one with no User-Agent at
all - naive filters look at the UA, better ones look at whether the whole set
is self-consistent.

So each profile bundles a User-Agent with the exact headers that browser
really sends, and rotation picks a whole profile.

What this does not do
---------------------
It does not make a scan invisible. Your source IP is in their logs, the
request rate and ordering are a far stronger signal than any header, and the
payloads themselves are recorded. This defeats fingerprinting of *the tool*;
it does nothing against rate-based or behavioural detection. Use the scope
rate limit for that.
"""
from __future__ import annotations

import random
import re
from typing import Dict, List, Optional

from app.config import settings

MODE_FIXED = "fixed"
MODE_ROTATE = "rotate"

# Accept strings, verbatim from each engine. Chromium's is the long one with
# the signed-exchange suffix; sending Firefox's with a Chrome UA is a tell.
_ACCEPT_CHROMIUM = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
)
_ACCEPT_FIREFOX = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
    "image/webp,*/*;q=0.8"
)
_ACCEPT_SAFARI = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

# Navigation metadata every modern browser sends on a top-level request.
_FETCH_NAV = {
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


def _chromium(ua: str, brand: str, version: str, platform: str,
              mobile: str = "?0", lang: str = "en-US,en;q=0.9",
              id: str = "", label: str = "") -> Dict[str, object]:
    return {
        "id": id,
        "label": label or f"{brand} {version} on {platform}",
        "ua": ua,
        "headers": {
            "Accept": _ACCEPT_CHROMIUM,
            "Accept-Language": lang,
            # Client hints: Chromium only. Order and the padding brand entry
            # match what the browser actually emits.
            "Sec-CH-UA": f'"Not/A)Brand";v="8", "Chromium";v="{version}", "{brand}";v="{version}"',
            "Sec-CH-UA-Mobile": mobile,
            "Sec-CH-UA-Platform": f'"{platform}"',
            **_FETCH_NAV,
        },
    }


def _gecko(ua: str, lang: str = "en-US,en;q=0.5", id: str = "",
           label: str = "") -> Dict[str, object]:
    return {
        "id": id,
        "label": label or "Firefox",
        "ua": ua,
        # No Sec-CH-UA: Firefox does not implement client hints.
        "headers": {"Accept": _ACCEPT_FIREFOX, "Accept-Language": lang, **_FETCH_NAV},
    }


def _webkit(ua: str, lang: str = "en-US,en;q=0.9", id: str = "",
            label: str = "") -> Dict[str, object]:
    return {
        "id": id,
        "label": label or "Safari",
        "ua": ua,
        "headers": {"Accept": _ACCEPT_SAFARI, "Accept-Language": lang, **_FETCH_NAV},
    }


# Common, boring, current browsers. A rare browser is as memorable as a
# scanner UA, so nothing exotic here on purpose.
BROWSER_PROFILES: List[Dict[str, object]] = [
    _chromium(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google Chrome", "126", "Windows", id="chrome-126-windows",
    ),
    _chromium(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/125.0.0.0 Safari/537.36",
        "Google Chrome", "125", "Windows", id="chrome-125-windows",
    ),
    _chromium(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google Chrome", "126", "macOS", id="chrome-126-macos",
    ),
    _chromium(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36",
        "Google Chrome", "126", "Linux", id="chrome-126-linux",
    ),
    _chromium(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
        "Microsoft Edge", "126", "Windows", id="edge-126-windows",
    ),
    _chromium(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/126.0.0.0 Mobile Safari/537.36",
        "Google Chrome", "126", "Android", mobile="?1", id="chrome-126-android",
    ),
    _gecko(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        id="firefox-127-windows", label="Firefox 127 on Windows",
    ),
    _gecko("Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
           id="firefox-127-linux", label="Firefox 127 on Linux"),
    _webkit(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.5 Safari/605.1.15",
        id="safari-17-macos", label="Safari 17 on macOS",
    ),
    _webkit(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        id="safari-17-ios", label="Safari 17 on iPhone",
    ),
]

# Tools that accept repeated `-H "Name: value"`.
_DASH_H = {"nuclei", "ffuf", "dalfox", "katana", "httpx"}

# Recon tools that never make an HTTP app request: nothing to set.
_NO_HTTP = {"subfinder", "dnsx", "naabu", "gau", "nmap", "testssl"}


BY_ID: Dict[str, Dict[str, object]] = {str(p["id"]): p for p in BROWSER_PROFILES}

# Modes that are not a specific browser.
#   rotate - a different real browser per job. The default, and the right
#            answer when nobody has a reason to prefer another.
#   tool   - send nothing, and let each binary use its own User-Agent. An
#            honest option, not a lesser one: on an announced test the client's
#            SOC often WANTS to see `sqlmap/1.8` in the logs, and pretending to
#            be Chrome while hammering their login makes the report harder to
#            defend, not easier.
#   custom - the operator supplies the string. For matching a mobile app's own
#            client, a partner integration, or an allowlist the client keeps.
MODE_TOOL = "tool"
MODE_CUSTOM = "custom"


def profile_for_ua(ua: str) -> Dict[str, object]:
    """Build a coherent profile around an arbitrary User-Agent string.

    The headers matter as much as the string. A request claiming to be Firefox
    while sending Sec-CH-UA client hints - which Firefox does not implement -
    is more conspicuous than one with no User-Agent at all, so the engine is
    inferred from the string and the header set matched to it.
    """
    pinned = (ua or "").strip()
    for profile in BROWSER_PROFILES:
        if profile["ua"] == pinned:
            return profile
    low = pinned.lower()
    if "firefox" in low:
        return _gecko(pinned, id=MODE_CUSTOM, label="Custom")
    if "safari" in low and "chrome" not in low and "edg/" not in low:
        return _webkit(pinned, id=MODE_CUSTOM, label="Custom")

    # Anything else is treated as Chromium, which is what an unrecognised
    # string most often is. The client hints have to come with it: this used to
    # return the Chromium `Accept` and no Sec-CH-UA at all, producing exactly
    # the incoherent set this module exists to avoid - a request claiming
    # Chrome while sending none of the headers Chrome always sends.
    match = re.search(r"(?:edg|chrome)/(\d+)", low)
    version = match.group(1) if match else "126"
    brand = "Microsoft Edge" if "edg/" in low else "Google Chrome"
    platform = "Windows"
    for needle, name in (("android", "Android"), ("iphone", "iOS"),
                         ("mac os x", "macOS"), ("linux", "Linux")):
        if needle in low:
            platform = name
            break
    mobile = "?1" if ("mobile" in low or "android" in low or "iphone" in low) else "?0"
    return _chromium(pinned, brand, version, platform, mobile=mobile,
                     id=MODE_CUSTOM, label="Custom")


def resolve_profile(mode: str, custom_ua: str = "") -> Optional[Dict[str, object]]:
    """The profile for one job, from an explicit choice.

    Pure apart from `rotate`, which is random by definition. `None` means "send
    nothing" - the tool's own default - and is distinct from a profile with an
    empty User-Agent, which would strip the header the tool would have sent.
    """
    choice = (mode or "").strip().lower()

    if choice == MODE_TOOL:
        return None
    if choice in (MODE_ROTATE, ""):
        return random.choice(BROWSER_PROFILES)
    if choice in BY_ID:
        return BY_ID[choice]
    if choice == MODE_CUSTOM:
        # A custom mode with no string is a misconfiguration, not an
        # instruction to send an empty User-Agent. Fall back to rotating.
        return profile_for_ua(custom_ua) if custom_ua.strip() else random.choice(BROWSER_PROFILES)
    if choice == MODE_FIXED:
        # The historical env-var spelling: USER_AGENT_MODE=fixed plus USER_AGENT.
        pinned = custom_ua.strip() or (settings.user_agent or "").strip()
        return profile_for_ua(pinned) if pinned else BROWSER_PROFILES[0]

    # An unrecognised mode must not silently become "no headers at all".
    return random.choice(BROWSER_PROFILES)


def current_profile() -> Dict[str, object]:
    """The browser profile for a job with no engagement preference.

    Falls back to the environment: USER_AGENT_MODE / USER_AGENT. Used by the
    recon view, which runs before any engagement exists, and by any scan
    submitted without one.
    """
    profile = resolve_profile(settings.user_agent_mode or MODE_ROTATE,
                              settings.user_agent or "")
    return profile if profile is not None else BROWSER_PROFILES[0]


def current_user_agent() -> str:
    """The User-Agent to use for the next job"""
    return str(current_profile()["ua"])


def choices() -> List[Dict[str, str]]:
    """What the engagement form offers, with what each one is for.

    Served rather than hardcoded in the frontend so the list and the profiles
    behind it cannot drift - a UI offering a browser the backend does not know
    would silently fall back to rotating.
    """
    out = [
        {"id": MODE_ROTATE, "label": "Rotate (default)",
         "note": "A different real browser per job, headers included. Right "
                 "unless you have a reason to prefer another."},
    ]
    out += [{"id": str(p["id"]), "label": str(p["label"]),
             "note": str(p["ua"])} for p in BROWSER_PROFILES]
    out += [
        {"id": MODE_CUSTOM, "label": "Custom User-Agent",
         "note": "Your own string. The other headers are matched to the engine "
                 "it claims, because a Firefox User-Agent sending Chrome client "
                 "hints stands out more than no User-Agent at all."},
        {"id": MODE_TOOL, "label": "Each tool's own",
         "note": "Send nothing and let sqlmap look like sqlmap. On an announced "
                 "test the client's SOC often wants exactly that."},
    ]
    return out


def is_valid_choice(mode: str) -> bool:
    choice = (mode or "").strip().lower()
    return choice == "" or choice in {MODE_ROTATE, MODE_FIXED, MODE_TOOL,
                                      MODE_CUSTOM} | set(BY_ID)


def _headers_for_job(profile: Optional[Dict[str, object]] = None) -> Dict[str, str]:
    """Full header set for this job: browser profile, plus the optional
    attribution header when the operator explicitly set one.

    `profile` is the engagement's choice. Passing None means "decide from the
    environment", which is what a scan with no engagement gets.
    """
    if profile is None:
        profile = current_profile()
    headers: Dict[str, str] = {"User-Agent": str(profile["ua"])}
    headers.update(profile["headers"])  # type: ignore[arg-type]

    # Off unless PENTEST_ID is set. It marks the traffic as an authorized test
    # so the client's SOC can tell it apart from a real intrusion - useful on
    # some engagements, and exactly what you do not want when the point is to
    # blend in or to test their detection.
    pentest_id = (settings.pentest_id or "").strip()
    if pentest_id:
        headers["X-Pentest-ID"] = pentest_id
    return headers


def identity_args(tool: str, *, mode: str = "", custom_ua: str = "") -> List[str]:
    """CLI flags carrying the browser profile headers for `tool`.

    `mode` is the engagement's identity choice; empty means "use the
    environment", which is what a scan submitted without an engagement gets.
    """
    if tool in _NO_HTTP:
        return []

    if mode:
        profile = resolve_profile(mode, custom_ua)
        if profile is None:
            # "Each tool's own": send nothing and let the binary identify
            # itself. The attribution header still applies if one is set - it
            # is about telling the client's SOC this is authorised, which is
            # orthogonal to which User-Agent the tool uses.
            pentest_id = (settings.pentest_id or "").strip()
            return _as_args(tool, "", {"X-Pentest-ID": pentest_id} if pentest_id else {},
                            rotating=False)
    else:
        profile = None

    rotating = (mode or settings.user_agent_mode or MODE_ROTATE).strip().lower() == MODE_ROTATE
    headers = _headers_for_job(profile)
    ua = headers.pop("User-Agent", "")
    return _as_args(tool, ua, headers, rotating=rotating)


def _as_args(tool: str, ua: str, headers: Dict[str, str], *, rotating: bool) -> List[str]:
    """Spell one header set the way `tool` wants it."""
    if not ua and not headers:
        return []

    if tool in _DASH_H:
        args: List[str] = []
        if ua:
            args += ["-H", f"User-Agent: {ua}"]
        for name, value in headers.items():
            args += ["-H", f"{name}: {value}"]
        return args

    if tool == "sqlmap":
        args = []
        if ua:
            args += ["--user-agent", ua]
        for name, value in headers.items():
            args += ["-H", f"{name}: {value}"]
        return args

    if tool == "commix":
        args = []
        if ua:
            args += ["--user-agent", ua]
        if headers:
            # commix takes every extra header in one \n-separated blob.
            args += ["--headers", "\\n".join(f"{n}: {v}" for n, v in headers.items())]
        return args

    if tool == "wpscan":
        # In rotate mode the wrapper adds --random-user-agent and we must not
        # also pass --user-agent: the two conflict.
        args = []
        if ua and not rotating:
            args += ["--user-agent", ua]
        for name, value in headers.items():
            args += ["--headers", f"{name}: {value}"]
        return args

    if tool == "whatweb":
        args = []
        if ua:
            args += [f"--user-agent={ua}"]
        args += [f"--header={n}: {v}" for n, v in headers.items()]
        return args

    if tool == "nikto":
        # nikto has no repeatable header flag worth relying on; UA only.
        return ["-useragent", ua] if ua else []

    return []


# How each binary spells "route through this proxy". Tools missing from the
# map get nothing rather than a wrong flag - a scan that silently ignores the
# proxy is worse than one that never claimed to use it.
_PROXY_FLAG = {
    "nuclei": lambda p: ["-proxy", p],
    "katana": lambda p: ["-proxy", p],
    "httpx": lambda p: ["-proxy", p],
    "dalfox": lambda p: ["--proxy", p],
    "ffuf": lambda p: ["-x", p],
    "sqlmap": lambda p: [f"--proxy={p}"],
    "commix": lambda p: [f"--proxy={p}"],
    "wpscan": lambda p: ["--proxy", p],
    "nikto": lambda p: ["-useproxy", p],
}


def proxy_args(tool: str, proxy_url: str) -> List[str]:
    """CLI flags routing `tool` through `proxy_url`, empty if unsupported"""
    if not proxy_url:
        return []
    builder = _PROXY_FLAG.get(tool)
    return builder(proxy_url) if builder else []


def supports_proxy(tool: str) -> bool:
    return tool in _PROXY_FLAG
