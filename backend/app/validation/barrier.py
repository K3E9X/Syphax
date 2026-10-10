"""Was the check blocked, or did it actually tell us something?

A finding the scanner reported and the validator could not reproduce is filed
`unconfirmed`, which reads as "we looked and found nothing". But there are two
very different reasons to end up there:

  * the check ran and the issue did not reproduce - that IS evidence, weak but
    real, and the finding is probably noise;
  * the check never ran, because a WAF, a rate limiter or an authentication
    wall answered instead of the application. That is NOT evidence about the
    vulnerability at all. Filing it as "could not reproduce" invites the
    conclusion that the target is clean, when nothing was tested.

The operator asked for the second to be qualified differently, and they are
right: it is the difference between "we tested it" and "we were not allowed
to". Everything here is pure, so the rules are readable and testable on their
own.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

# Vendor fingerprints that appear in a block page or its headers. Deliberately
# specific: a false "blocked" claim would excuse a finding that the target
# genuinely disproved.
_VENDORS = (
    ("cloudflare", ("cloudflare", "cf-ray", "attention required", "__cf_bm")),
    ("akamai", ("akamaighost", "akamai", "reference #")),
    ("aws waf", ("awswaf", "aws waf", "x-amzn-waf")),
    ("imperva", ("incapsula", "imperva", "_incap_ses")),
    ("f5 big-ip asm", ("bigipserver", "the requested url was rejected",
                       "f5-")),
    ("sucuri", ("sucuri", "access denied - sucuri")),
    ("mod_security", ("mod_security", "modsecurity", "not acceptable!")),
    ("fortinet", ("fortigate", "fortiweb", "web page blocked")),
    ("barracuda", ("barra_counter", "barracuda")),
)

# Wording a block page uses when it names no vendor.
_GENERIC = (
    "access denied", "request blocked", "forbidden by administrative rules",
    "your request has been blocked", "security policy", "waf",
    "unusual traffic", "bot detection", "are you a robot",
    "rate limit exceeded", "too many requests",
)


def detect(status_code: Optional[int], body: str = "",
           headers: Optional[Dict[str, Any]] = None) -> str:
    """The barrier that answered, or "" when the application did.

    Returns a short human phrase, because it goes in front of an operator.
    """
    text = (body or "")[:4000].lower()
    header_blob = " ".join(
        f"{k} {v}" for k, v in (headers or {}).items()).lower()
    haystack = f"{text} {header_blob}"

    for vendor, markers in _VENDORS:
        if any(marker in haystack for marker in markers):
            return vendor

    # A status code alone is not proof: 403 is also how an application says
    # "you are not logged in", and that is a real answer about the target.
    # It only counts as a barrier when the body or headers say so too.
    if status_code in (401, 403, 406, 418, 429, 503):
        if any(phrase in haystack for phrase in _GENERIC):
            return "a WAF or rate limiter"
        if status_code == 429:
            return "rate limiting"
    return ""


def describe(barrier: str, status_code: Optional[int] = None) -> str:
    """The sentence an operator reads next to the finding."""
    code = f" (HTTP {status_code})" if status_code else ""
    return (f"not tested: {barrier} answered instead of the application{code}. "
            f"This says nothing about whether the issue is real - the check "
            f"never reached it.")
