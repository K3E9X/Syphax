"""Generic registrable-domain ("eTLD+1") computation for scope expansion.

When an engagement scopes a single host, the same organisation's other hosts
under the same registrable domain are usually in scope too (prospex.datax.
iliad.fr -> everything under iliad.fr). We derive that domain generically for
ANY target rather than hard-coding one.

Two guards keep this from over-reaching:
  * a compact multi-label public-suffix set, so eTLD+1 is computed correctly for
    ccTLDs like co.uk / com.br / co.jp (where the registrable domain is 3 labels);
  * a shared-platform denylist (herokuapp.com, vercel.app, github.io, S3, ...):
    a host sitting directly on one of these is a TENANT, so expanding to the
    whole platform would pull in other people's sites. For those we return None
    and the scope is NOT widened.

This is a heuristic, not the full Public Suffix List, but it covers the cases
that matter for an authorised engagement and fails closed (no expansion) when
unsure about a shared platform.
"""
from __future__ import annotations

from typing import Optional

# Two-label public suffixes: when a host ends with one of these, the registrable
# domain is the last THREE labels (acme.co.uk, loja.com.br, foo.co.jp).
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.in", "net.in", "org.in", "gen.in", "firm.in",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw", "com.ua",
    "co.kr", "or.kr", "co.il", "co.id", "com.pl", "com.ru", "co.th", "com.vn",
}

# Shared hosting / SaaS platforms: a host here is one tenant among many, so the
# registrable domain is the platform, not the customer. Never expand to these.
_SHARED_SUFFIXES = {
    "herokuapp.com", "herokudns.com",
    "azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
    "appspot.com", "run.app", "web.app", "firebaseapp.com", "cloudfunctions.net",
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "r2.dev",
    "vercel.app", "now.sh", "netlify.app", "netlify.com",
    "amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "awsapprunner.com",
    "fastly.net", "akamaihd.net", "akamaized.net", "cdn.cloudflare.net",
    "wordpress.com", "wpengine.com", "myshopify.com", "squarespace.com", "wixsite.com",
    "surge.sh", "render.com", "onrender.com", "fly.dev", "glitch.me",
    "s3.amazonaws.com", "digitaloceanspaces.com", "ondigitalocean.app",
    "translate.goog", "googleusercontent.com", "ngrok.io", "ngrok.app",
    "readthedocs.io", "zendesk.com", "freshdesk.com", "atlassian.net",
}


def registrable_domain(host: str) -> Optional[str]:
    """The eTLD+1 of `host`, or None when scope must not be widened.

    None is returned for an empty/IP input, a bare TLD, or a host that sits on a
    known shared platform (expanding there would scope other tenants).
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or _is_ip(host):
        return None
    labels = host.split(".")
    if len(labels) < 2:
        return None

    # Refuse shared platforms: any suffix of the host matching the denylist.
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in _SHARED_SUFFIXES:
            return None

    last2 = ".".join(labels[-2:])
    if last2 in _MULTI_SUFFIXES:
        if len(labels) < 3:
            return None               # the host IS the public suffix
        return ".".join(labels[-3:])
    return last2


def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_ip(host: str) -> bool:
    """Public alias: is this string a literal IP address?"""
    return _is_ip(host)


def same_registrable_domain(a: str, b: str) -> bool:
    """Do two hosts share the same registrable domain (and is it expandable)?"""
    ra, rb = registrable_domain(a), registrable_domain(b)
    return bool(ra) and ra == rb


def same_server(candidate_ips, target_ips) -> bool:
    """True when the candidate shares an IP, or the same netblock, with the
    target (/24 for IPv4, /64 for IPv6) - i.e. it is the same server/infra."""
    import ipaddress

    cand = {str(i) for i in candidate_ips}
    tgt = {str(i) for i in target_ips}
    if cand & tgt:
        return True
    nets = []
    for ip in tgt:
        try:
            addr = ipaddress.ip_address(ip)
            prefix = 24 if addr.version == 4 else 64
            nets.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
        except ValueError:
            continue
    for ip in cand:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if any(addr in n for n in nets):
            return True
    return False
