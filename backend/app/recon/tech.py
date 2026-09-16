"""What is this thing built out of, from one response.

A signature table, not a scanner. Everything here runs against material the
target already sent back for a single GET of `/` - headers, cookies and the
first few hundred KB of HTML - so recognising a technology costs nothing beyond
the request that was made anyway.

Three layers, because the operator is asking three different questions:

    frontend        what runs in the browser. Decides whether DOM XSS and
                    client-side routing are even on the table, and which JS
                    bundles are worth pulling apart later.
    backend         what runs on the server. Decides which injection families
                    are plausible and which CVE feeds are worth reading.
    infrastructure  what sits in front. A WAF changes how everything else has
                    to be approached; a CDN means the origin is somewhere else
                    and half of what you fingerprint belongs to the edge.

That last distinction is the one people skip and then misread their own
results: `Server: cloudflare` says nothing whatsoever about the application.

Confidence is deliberately coarse - `certain` for a header or cookie the
software emits and nothing else does, `likely` for a body pattern that a
determined author could have written by hand. Every hit carries the evidence
that produced it, so a wrong one can be dismissed by looking at it rather than
by trusting this file.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

LAYER_FRONTEND = "frontend"
LAYER_BACKEND = "backend"
LAYER_INFRA = "infrastructure"
LAYERS = (LAYER_FRONTEND, LAYER_BACKEND, LAYER_INFRA)

CERTAIN = "certain"
LIKELY = "likely"

WHERE_HEADER = "header"
WHERE_COOKIE = "cookie"
WHERE_BODY = "body"


@dataclass(frozen=True)
class Signature:
    name: str
    layer: str
    category: str
    where: str
    pattern: str
    header: str = ""              # only for WHERE_HEADER
    confidence: str = CERTAIN
    version_group: int = 0        # regex group holding a version, 0 = none
    note: str = ""

    def compiled(self):
        return re.compile(self.pattern, re.IGNORECASE)


@dataclass
class Detection:
    name: str
    layer: str
    category: str
    confidence: str
    evidence: str
    version: Optional[str] = None
    note: str = ""

    def to_public(self) -> dict:
        return {
            "name": self.name, "layer": self.layer, "category": self.category,
            "confidence": self.confidence, "evidence": self.evidence,
            "version": self.version, "note": self.note,
        }


def _h(name, layer, category, header, pattern, **kw) -> Signature:
    return Signature(name=name, layer=layer, category=category,
                     where=WHERE_HEADER, header=header, pattern=pattern, **kw)


def _c(name, layer, category, pattern, **kw) -> Signature:
    return Signature(name=name, layer=layer, category=category,
                     where=WHERE_COOKIE, pattern=pattern, **kw)


def _b(name, layer, category, pattern, **kw) -> Signature:
    kw.setdefault("confidence", LIKELY)
    return Signature(name=name, layer=layer, category=category,
                     where=WHERE_BODY, pattern=pattern, **kw)


# ---- infrastructure: what is in front ---------------------------------------

_INFRA: Tuple[Signature, ...] = (
    _h("Cloudflare", LAYER_INFRA, "cdn", "server", r"^cloudflare",
       note="the origin is behind this; most of what you fingerprint here is the edge"),
    _h("Cloudflare", LAYER_INFRA, "cdn", "cf-ray", r"."),
    _h("Amazon CloudFront", LAYER_INFRA, "cdn", "x-amz-cf-id", r"."),
    _h("Amazon CloudFront", LAYER_INFRA, "cdn", "via", r"cloudfront"),
    _h("Fastly", LAYER_INFRA, "cdn", "x-served-by", r"cache-\w+"),
    _h("Fastly", LAYER_INFRA, "cdn", "x-fastly-request-id", r"."),
    _h("Akamai", LAYER_INFRA, "cdn", "x-akamai-transformed", r"."),
    _h("Akamai", LAYER_INFRA, "cdn", "server", r"^akamaighost"),
    _h("Azure Front Door", LAYER_INFRA, "cdn", "x-azure-ref", r"."),
    _h("Vercel", LAYER_INFRA, "hosting", "x-vercel-id", r"."),
    _h("Netlify", LAYER_INFRA, "hosting", "x-nf-request-id", r"."),
    _h("GitHub Pages", LAYER_INFRA, "hosting", "x-github-request-id", r"."),
    _h("Amazon S3", LAYER_INFRA, "hosting", "server", r"^amazons3"),
    _h("Google Frontend", LAYER_INFRA, "cdn", "server", r"^(gws|gse|google frontend)"),

    _h("AWS Elastic Load Balancer", LAYER_INFRA, "load-balancer", "server", r"^awselb"),
    _c("AWS Application Load Balancer", LAYER_INFRA, "load-balancer", r"^AWSALB"),
    _h("Envoy", LAYER_INFRA, "proxy", "x-envoy-upstream-service-time", r"."),
    _h("Envoy", LAYER_INFRA, "proxy", "server", r"^envoy"),
    _h("Kong", LAYER_INFRA, "api-gateway", "x-kong-upstream-latency", r"."),
    _h("Varnish", LAYER_INFRA, "cache", "via", r"varnish"),
    _h("Varnish", LAYER_INFRA, "cache", "x-varnish", r"."),
    _h("nginx", LAYER_INFRA, "web-server", "server", r"^nginx(?:/([\d.]+))?", version_group=1),
    _h("OpenResty", LAYER_INFRA, "web-server", "server", r"^openresty(?:/([\d.]+))?", version_group=1),
    _h("Apache httpd", LAYER_INFRA, "web-server", "server", r"^apache(?:/([\d.]+))?", version_group=1),
    _h("Microsoft IIS", LAYER_INFRA, "web-server", "server", r"^microsoft-iis/([\d.]+)", version_group=1),
    _h("LiteSpeed", LAYER_INFRA, "web-server", "server", r"^litespeed"),
    _h("Caddy", LAYER_INFRA, "web-server", "server", r"^caddy"),
    _h("Traefik", LAYER_INFRA, "proxy", "server", r"^traefik"),

    # WAFs. Worth their own category: one in the path changes how every later
    # test has to be run, and not noticing is how an engagement produces a
    # page of 403s that get read as "not vulnerable".
    _h("Sucuri WAF", LAYER_INFRA, "waf", "x-sucuri-id", r"."),
    _h("Imperva Incapsula", LAYER_INFRA, "waf", "x-iinfo", r"."),
    _c("Imperva Incapsula", LAYER_INFRA, "waf", r"^(incap_ses|visid_incap)"),
    _h("F5 BIG-IP", LAYER_INFRA, "waf", "server", r"^bigip"),
    _c("F5 BIG-IP", LAYER_INFRA, "load-balancer", r"^BIGipServer"),
    _h("Barracuda", LAYER_INFRA, "waf", "server", r"barracuda"),
    _h("Wallarm", LAYER_INFRA, "waf", "server", r"wallarm"),
    _h("AWS WAF", LAYER_INFRA, "waf", "x-amzn-waf-action", r"."),
)

# ---- backend: what runs on the server ---------------------------------------

_BACKEND: Tuple[Signature, ...] = (
    _h("PHP", LAYER_BACKEND, "language", "x-powered-by", r"^php/?([\d.]+)?", version_group=1),
    _c("PHP", LAYER_BACKEND, "language", r"^PHPSESSID"),
    _h("ASP.NET", LAYER_BACKEND, "framework", "x-powered-by", r"^asp\.net"),
    _h("ASP.NET", LAYER_BACKEND, "framework", "x-aspnet-version", r"([\d.]+)", version_group=1),
    _h("ASP.NET MVC", LAYER_BACKEND, "framework", "x-aspnetmvc-version", r"([\d.]+)", version_group=1),
    _c("ASP.NET", LAYER_BACKEND, "framework", r"^ASP\.NET_SessionId"),
    _h("Express", LAYER_BACKEND, "framework", "x-powered-by", r"^express"),
    _c("Express", LAYER_BACKEND, "framework", r"^connect\.sid"),
    _h("Next.js", LAYER_BACKEND, "framework", "x-powered-by", r"^next\.js"),
    _h("Nuxt", LAYER_BACKEND, "framework", "x-powered-by", r"^nuxt"),
    _c("Java", LAYER_BACKEND, "language", r"^JSESSIONID"),
    _h("Apache Tomcat", LAYER_BACKEND, "app-server", "server", r"^apache-coyote"),
    _h("Jetty", LAYER_BACKEND, "app-server", "server", r"^jetty"),
    _h("Gunicorn", LAYER_BACKEND, "app-server", "server", r"^gunicorn(?:/([\d.]+))?", version_group=1),
    _h("Uvicorn", LAYER_BACKEND, "app-server", "server", r"^uvicorn"),
    _h("Werkzeug", LAYER_BACKEND, "app-server", "server", r"^werkzeug(?:/([\d.]+))?", version_group=1),
    _h("Kestrel", LAYER_BACKEND, "app-server", "server", r"^kestrel"),
    _h("Ruby on Rails", LAYER_BACKEND, "framework", "x-runtime", r"^[\d.]+$"),
    _c("Ruby on Rails", LAYER_BACKEND, "framework", r"_session=|^_rails"),
    _c("Laravel", LAYER_BACKEND, "framework", r"^laravel_session"),
    _c("Django", LAYER_BACKEND, "framework", r"^(csrftoken|django_language)"),
    _c("CodeIgniter", LAYER_BACKEND, "framework", r"^ci_session"),
    _c("Flask", LAYER_BACKEND, "framework", r"^session=eyJ"),
    _h("FastAPI", LAYER_BACKEND, "framework", "x-fastapi", r"."),

    _h("WordPress", LAYER_BACKEND, "cms", "x-pingback", r"xmlrpc\.php"),
    _c("WordPress", LAYER_BACKEND, "cms", r"^wordpress_"),
    _h("Drupal", LAYER_BACKEND, "cms", "x-drupal-cache", r"."),
    _h("Drupal", LAYER_BACKEND, "cms", "x-generator", r"^drupal\s*([\d]+)?", version_group=1),
    _h("Shopify", LAYER_BACKEND, "cms", "x-shopid", r"."),
    _h("Shopify", LAYER_BACKEND, "cms", "x-shopify-stage", r"."),
    _h("Wix", LAYER_BACKEND, "cms", "x-wix-request-id", r"."),
    _h("Ghost", LAYER_BACKEND, "cms", "x-ghost-cache-status", r"."),

    _b("WordPress", LAYER_BACKEND, "cms",
       r'<meta name="generator" content="WordPress\s*([\d.]+)?', version_group=1,
       confidence=CERTAIN),
    _b("WordPress", LAYER_BACKEND, "cms", r"/wp-(content|includes)/"),
    _b("Joomla", LAYER_BACKEND, "cms", r'<meta name="generator" content="Joomla!?\s*([\d.]+)?',
       version_group=1, confidence=CERTAIN),
    _b("Drupal", LAYER_BACKEND, "cms", r"drupal-settings-json|Drupal\.settings"),
    _b("Magento", LAYER_BACKEND, "cms", r"Mage\.Cookies|/static/version\d+/frontend/"),
    _b("TYPO3", LAYER_BACKEND, "cms", r'<meta name="generator" content="TYPO3'),
    _b("Squarespace", LAYER_BACKEND, "cms", r"static1\.squarespace\.com"),
    _b("Webflow", LAYER_BACKEND, "cms", r"data-wf-(page|site)"),
    _b("Django", LAYER_BACKEND, "framework", r"csrfmiddlewaretoken"),
    _b("Ruby on Rails", LAYER_BACKEND, "framework", r'name="authenticity_token"|csrf-param'),
    _b("Laravel Livewire", LAYER_BACKEND, "framework", r"livewire\.js|wire:id="),
)

# ---- frontend: what runs in the browser -------------------------------------

_FRONTEND: Tuple[Signature, ...] = (
    _b("Next.js", LAYER_FRONTEND, "framework", r"__NEXT_DATA__|/_next/static/", confidence=CERTAIN),
    _b("Nuxt", LAYER_FRONTEND, "framework", r"__NUXT__|/_nuxt/", confidence=CERTAIN),
    _b("Angular", LAYER_FRONTEND, "framework", r'ng-version="([\d.]+)"', version_group=1,
       confidence=CERTAIN),
    _b("Angular", LAYER_FRONTEND, "framework", r"\bng-app\b|\[ngIf\]|_angular_"),
    _b("React", LAYER_FRONTEND, "framework", r"data-reactroot|__REACT_DEVTOOLS|react(?:-dom)?[.-]\w*\.js"),
    _b("Remix", LAYER_FRONTEND, "framework", r"__remixContext", confidence=CERTAIN),
    _b("Vue.js", LAYER_FRONTEND, "framework", r"data-v-[0-9a-f]{8}|__VUE__|vue(?:\.min)?\.js"),
    _b("Svelte", LAYER_FRONTEND, "framework", r"__SVELTE|svelte-\w{6,}"),
    _b("Ember.js", LAYER_FRONTEND, "framework", r"ember(?:\.min)?\.js|id=\"ember\d"),
    _b("Alpine.js", LAYER_FRONTEND, "framework", r"\bx-data=|alpinejs"),
    _b("htmx", LAYER_FRONTEND, "framework", r"\bhx-(get|post|target)=|htmx\.(min\.)?js"),
    _b("jQuery", LAYER_FRONTEND, "library", r"jquery[.-]?([\d.]+)?(?:\.min)?\.js", version_group=1),
    _b("Bootstrap", LAYER_FRONTEND, "ui", r"bootstrap[.-]?([\d.]+)?(?:\.min)?\.(css|js)", version_group=1),
    _b("Tailwind CSS", LAYER_FRONTEND, "ui", r"tailwind(?:css)?(?:\.min)?\.css|\bclass=\"[^\"]*\b(flex|grid) items-"),
    _b("Font Awesome", LAYER_FRONTEND, "ui", r"font-?awesome"),

    _b("Google Analytics", LAYER_FRONTEND, "analytics", r"google-analytics\.com|gtag\(|googletagmanager\.com/gtag"),
    _b("Google Tag Manager", LAYER_FRONTEND, "analytics", r"googletagmanager\.com/gtm\.js"),
    _b("Matomo", LAYER_FRONTEND, "analytics", r"matomo\.js|piwik\.js"),
    _b("Segment", LAYER_FRONTEND, "analytics", r"cdn\.segment\.com"),
    _b("Hotjar", LAYER_FRONTEND, "analytics", r"static\.hotjar\.com"),
    _b("Sentry", LAYER_FRONTEND, "monitoring", r"sentry-cdn\.com|@sentry/browser",
       note="a public DSN in the page is normal; the project slug it leaks is not always meant to be"),
    _b("Stripe", LAYER_FRONTEND, "payments", r"js\.stripe\.com"),
    _b("reCAPTCHA", LAYER_FRONTEND, "anti-bot", r"google\.com/recaptcha"),
    _b("hCaptcha", LAYER_FRONTEND, "anti-bot", r"hcaptcha\.com"),
    _b("Cloudflare Turnstile", LAYER_FRONTEND, "anti-bot", r"challenges\.cloudflare\.com/turnstile"),
)

SIGNATURES: Tuple[Signature, ...] = _INFRA + _BACKEND + _FRONTEND

# Generic `<meta name="generator">` catch-all, applied when nothing above
# matched it. A CMS nobody has written a signature for still announces itself.
_GENERATOR = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']{1,80})["\']', re.IGNORECASE)


def detect(*, headers: Optional[Dict[str, str]] = None,
           cookies: Optional[Sequence[str]] = None,
           body: str = "") -> List[Detection]:
    """Everything the response gives away, strongest evidence first.

    `headers` is case-insensitive by convention here: keys are lowercased on
    the way in, because httpx, a raw socket and a test fixture all disagree
    about capitalisation and none of them is wrong.
    """
    lower = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cookie_names = list(cookies or [])
    text = body or ""

    found: Dict[str, Detection] = {}

    for sig in SIGNATURES:
        hit, evidence, version = _match(sig, lower, cookie_names, text)
        if not hit:
            continue
        existing = found.get(sig.name)
        candidate = Detection(
            name=sig.name, layer=sig.layer, category=sig.category,
            confidence=sig.confidence, evidence=evidence, version=version,
            note=sig.note,
        )
        # Keep the strongest evidence, and never lose a version we found once.
        if existing is None:
            found[sig.name] = candidate
        else:
            if existing.confidence == LIKELY and sig.confidence == CERTAIN:
                candidate.version = candidate.version or existing.version
                found[sig.name] = candidate
            elif existing.version is None and version:
                existing.version = version

    for name, version in _generator_hits(text, found):
        found[name] = Detection(
            name=name, layer=LAYER_BACKEND, category="cms", confidence=LIKELY,
            evidence=f'<meta name="generator" content="{name}{" " + version if version else ""}">',
            version=version,
            note="from the generator tag; no dedicated signature for this one")

    order = {CERTAIN: 0, LIKELY: 1}
    return sorted(found.values(),
                  key=lambda d: (order.get(d.confidence, 2), d.layer, d.name.lower()))


def _match(sig: Signature, headers, cookie_names, body):
    rx = sig.compiled()
    if sig.where == WHERE_HEADER:
        value = headers.get(sig.header, "")
        if not value:
            return False, "", None
        m = rx.search(value)
        if not m:
            return False, "", None
        return True, f"{sig.header}: {value[:120]}", _version(m, sig)

    if sig.where == WHERE_COOKIE:
        for name in cookie_names:
            m = rx.search(name)
            if m:
                return True, f"cookie {name[:60]}", _version(m, sig)
        return False, "", None

    m = rx.search(body)
    if not m:
        return False, "", None
    return True, _snippet(body, m), _version(m, sig)


def _version(match, sig: Signature) -> Optional[str]:
    if not sig.version_group:
        return None
    try:
        value = match.group(sig.version_group)
    except (IndexError, re.error):
        return None
    return value.strip() if value else None


def _snippet(body: str, match) -> str:
    start = max(0, match.start() - 20)
    end = min(len(body), match.end() + 20)
    return "…" + " ".join(body[start:end].split()) + "…"


def _generator_hits(body: str, already: Dict[str, Detection]) -> Iterable[tuple]:
    for raw in _GENERATOR.findall(body or "")[:3]:
        content = raw.strip()
        name = re.split(r"\s+v?[\d.]+$", content)[0].strip() or content
        if not name or name in already:
            continue
        version_match = re.search(r"([\d]+(?:\.[\d]+)*)\s*$", content)
        yield name[:60], (version_match.group(1) if version_match else None)


def by_layer(detections: Sequence[Detection]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {layer: [] for layer in LAYERS}
    for d in detections:
        out.setdefault(d.layer, []).append(d.to_public())
    return out


def waf_names(detections: Sequence[Detection]) -> List[str]:
    return sorted({d.name for d in detections if d.category == "waf"})


def cdn_names(detections: Sequence[Detection]) -> List[str]:
    return sorted({d.name for d in detections if d.category in ("cdn", "hosting")})
