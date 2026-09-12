"""Declarative test catalog: the methodology engine's source of truth.

The planner reasons over this data, not over hardcoded steps. Each entry maps
an OWASP WSTG test to the MITRE ATT&CK technique(s) it relates to, the tool
that performs it, and an `applies_when` condition evaluated against the live
engagement context (fingerprint, discovered assets, ...). The coverage matrix
tracks which items have run against which assets.

`applies_when` is intentionally a small structured dict (not a lambda) so it
is serializable, inspectable in the UI, and safe to ship to the LLM planner:

    {"always": true}                  - run on the base target
    {"requires_params": true}         - only on URLs that have query params
    {"tech_any": ["wordpress"]}       - only if a fingerprint matched one of these
    {"is_host": true}                 - run against a host, not a URL (nmap/naabu/dns)
    {"path_any": ["openapi"]}         - only on an asset whose URL says so
    {"is_base": true}                 - only the engagement's own target URL,
                                        for tools that work per host
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# PTES-aligned phases the planner walks in order.
PHASE_RECON = "recon"
PHASE_MAPPING = "mapping"
PHASE_VULN = "vuln_analysis"
PHASE_EXPLOIT = "exploitation"

PHASE_ORDER = [PHASE_RECON, PHASE_MAPPING, PHASE_VULN, PHASE_EXPLOIT]


@dataclass
class CatalogItem:
    id: str
    wstg_id: str
    attack_techniques: List[str]
    vuln_class: str
    phase: str
    tool: str
    description: str
    severity_default: str = "info"
    default_options: List[str] = field(default_factory=list)
    applies_when: Dict[str, Any] = field(default_factory=lambda: {"always": True})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "wstg_id": self.wstg_id,
            "attack_techniques": self.attack_techniques,
            "vuln_class": self.vuln_class,
            "phase": self.phase,
            "tool": self.tool,
            "description": self.description,
            "severity_default": self.severity_default,
            "default_options": self.default_options,
            "applies_when": self.applies_when,
        }


# ---------------------------------------------------------------------------
# The catalog. Ordered roughly by phase; the planner re-orders within budget.
# Every tool referenced here is a registered wrapper (app/scans/wrappers).
# ---------------------------------------------------------------------------
CATALOG: List[CatalogItem] = [
    # ----- RECON -----
    CatalogItem(
        id="RECON-SUBDOMAINS",
        wstg_id="WSTG-INFO-04",
        attack_techniques=["T1590", "T1595"],
        vuln_class="recon",
        phase=PHASE_RECON,
        tool="subfinder",
        description="Enumerate subdomains of the target apex domain (all sources).",
        default_options=["-all"],
        applies_when={"is_host": True},
    ),
    CatalogItem(
        id="RECON-DNS",
        wstg_id="WSTG-INFO-04",
        attack_techniques=["T1590"],
        vuln_class="recon",
        phase=PHASE_RECON,
        tool="dnsx",
        description="Resolve DNS records (A/AAAA/CNAME) for the host.",
        applies_when={"is_host": True},
    ),
    CatalogItem(
        id="RECON-PORTS",
        wstg_id="WSTG-INFO-02",
        attack_techniques=["T1595"],
        vuln_class="recon",
        phase=PHASE_RECON,
        tool="naabu",
        description="Scan top TCP ports to find exposed services.",
        applies_when={"is_host": True},
    ),
    CatalogItem(
        id="RECON-NMAP-SERVICES",
        wstg_id="WSTG-INFO-02",
        attack_techniques=["T1046"],
        vuln_class="recon",
        phase=PHASE_RECON,
        tool="nmap",
        description="Service/version detection + default scripts on common ports.",
        default_options=["-sC", "--top-ports", "1000"],
        applies_when={"is_host": True},
    ),
    CatalogItem(
        id="RECON-HTTP-PROBE",
        wstg_id="WSTG-INFO-02",
        attack_techniques=["T1595"],
        vuln_class="recon",
        phase=PHASE_RECON,
        tool="httpx",
        description="Probe HTTP(S): status, title, tech, favicon hash, JARM, ASN.",
        default_options=["-favicon", "-jarm", "-asn"],
        applies_when={"always": True},
    ),
    CatalogItem(
        id="RECON-ARCHIVE-URLS",
        wstg_id="WSTG-INFO-04",
        attack_techniques=["T1595"],
        vuln_class="recon",
        phase=PHASE_RECON,
        tool="gau",
        description="Collect historical URLs (Wayback/Common Crawl/OTX).",
        applies_when={"is_host": True},
    ),

    # ----- MAPPING / FINGERPRINT -----
    CatalogItem(
        id="MAP-FINGERPRINT",
        wstg_id="WSTG-INFO-08",
        attack_techniques=["T1592"],
        vuln_class="fingerprint",
        phase=PHASE_MAPPING,
        tool="whatweb",
        description="Fingerprint server, framework, CMS and language.",
        applies_when={"always": True},
    ),
    CatalogItem(
        id="MAP-WAF",
        wstg_id="WSTG-INFO-00",
        attack_techniques=["T1595"],
        vuln_class="fingerprint",
        phase=PHASE_MAPPING,
        tool="wafw00f",
        description="Detect a WAF so later phases can adapt payloads and rate.",
        applies_when={"always": True},
    ),
    CatalogItem(
        id="MAP-CRAWL",
        wstg_id="WSTG-INFO-07",
        attack_techniques=["T1595"],
        vuln_class="recon",
        phase=PHASE_MAPPING,
        tool="katana",
        description="Crawl endpoints/forms/params, parsing JavaScript and known files.",
        default_options=["-jc", "-known-files", "all"],
        applies_when={"always": True},
    ),
    CatalogItem(
        id="MAP-CONTENT-DISCOVERY",
        wstg_id="WSTG-CONF-04",
        attack_techniques=["T1595"],
        vuln_class="content_discovery",
        phase=PHASE_MAPPING,
        tool="ffuf",
        description="Brute-force paths/files with recursion + backup extensions "
                    "(admin, backups, .git, .env, .bak/.old/.zip/.sql).",
        default_options=["-recursion", "-recursion-depth", "2",
                         "-e", ".bak,.old,.zip,.tar.gz,.sql,.json,.config,~",
                         "-ac"],
        applies_when={"always": True},
    ),
    CatalogItem(
        id="MAP-HIDDEN-PARAMS",
        wstg_id="WSTG-INFO-07",
        attack_techniques=["T1595"],
        vuln_class="recon",
        phase=PHASE_MAPPING,
        tool="arjun",
        description="Discover undocumented HTTP parameters by differential "
                    "analysis - the injection points every later test needs.",
        applies_when={"is_endpoint": True},
    ),
    CatalogItem(
        id="MAP-JS-ENDPOINTS",
        wstg_id="WSTG-INFO-07",
        attack_techniques=["T1595"],
        vuln_class="recon",
        phase=PHASE_MAPPING,
        tool="jsluice",
        description="Extract endpoints and parameters from the captured "
                    "JavaScript with a real parser (not regex).",
        default_options=["urls"],
        applies_when={"is_base": True},
    ),
    CatalogItem(
        id="MAP-TAKEOVER",
        wstg_id="WSTG-CONF-10",
        attack_techniques=["T1584.001"],
        vuln_class="subdomain_takeover",
        phase=PHASE_MAPPING,
        tool="nuclei",
        description="Detect dangling DNS / subdomain takeover on discovered hosts.",
        severity_default="high",
        default_options=["-tags", "takeover"],
        applies_when={"is_host": True},
    ),

    # ----- VULN ANALYSIS -----
    CatalogItem(
        id="VULN-NUCLEI",
        wstg_id="WSTG-CONF-01",
        attack_techniques=["T1190"],
        vuln_class="multiple",
        phase=PHASE_VULN,
        tool="nuclei",
        description="Template scan: CVEs, exposures, misconfig, default creds.",
        severity_default="medium",
        applies_when={"always": True},
    ),
    CatalogItem(
        id="VULN-NMAP-NSE",
        wstg_id="WSTG-INFO-02",
        attack_techniques=["T1046", "T1190"],
        vuln_class="cve",
        phase=PHASE_VULN,
        tool="nmap",
        description="NSE vulnerability scripts (vuln category) on exposed services.",
        severity_default="high",
        default_options=["-sV", "--script", "vuln", "--top-ports", "200"],
        applies_when={"is_host": True},
    ),
    CatalogItem(
        id="VULN-SERVER-MISCONFIG",
        wstg_id="WSTG-CONF-02",
        attack_techniques=["T1190"],
        vuln_class="misconfiguration",
        phase=PHASE_VULN,
        tool="nikto",
        description="Web-server misconfig, dangerous methods, backup/old files.",
        severity_default="low",
        applies_when={"always": True},
    ),
    CatalogItem(
        id="VULN-TLS",
        wstg_id="WSTG-CRYP-01",
        attack_techniques=["T1190"],
        vuln_class="weak_tls",
        phase=PHASE_VULN,
        tool="testssl",
        description="TLS/SSL audit: ciphers, protocol versions, TLS CVEs.",
        severity_default="medium",
        applies_when={"is_https": True},
    ),
    CatalogItem(
        id="VULN-WORDPRESS",
        wstg_id="WSTG-CONF-01",
        attack_techniques=["T1190"],
        vuln_class="cms_vulnerability",
        phase=PHASE_VULN,
        tool="wpscan",
        description="WordPress plugins/themes/users + known CVEs.",
        severity_default="medium",
        applies_when={"tech_any": ["wordpress", "wp"]},
    ),
    CatalogItem(
        id="VULN-EXPOSURES",
        wstg_id="WSTG-CONF-04",
        attack_techniques=["T1592"],
        vuln_class="exposed_resource",
        phase=PHASE_VULN,
        tool="nuclei",
        description="Exposed files, configs, backups and secrets (.git/.env/...).",
        severity_default="medium",
        # info-level included on purpose: many exposure templates are info/low.
        default_options=["-tags", "exposure,exposures,config,backup,disclosure",
                         "-severity", "info,low,medium,high,critical"],
        applies_when={"always": True},
    ),
    CatalogItem(
        id="VULN-CLIENT-LIBS",
        wstg_id="WSTG-CONF-01",
        attack_techniques=["T1190"],
        vuln_class="vulnerable_component",
        phase=PHASE_VULN,
        tool="retirejs",
        description="Rate the client-side JavaScript libraries the page loads "
                    "against the known-vulnerable version database.",
        severity_default="medium",
        applies_when={"is_base": True},
    ),
    CatalogItem(
        id="VULN-API-CONTRACT",
        wstg_id="WSTG-INPV-00",
        attack_techniques=["T1190"],
        vuln_class="api_contract_violation",
        phase=PHASE_VULN,
        tool="schemathesis",
        description="Property-test every documented operation against the API's "
                    "own OpenAPI contract (unhandled 500s, schema violations, "
                    "ignored auth).",
        severity_default="medium",
        applies_when={"path_any": ["openapi", "swagger", "api-docs", "openapi.json",
                                   "swagger.json", ".well-known/openapi"]},
    ),
    CatalogItem(
        id="VULN-GIT-DUMP",
        wstg_id="WSTG-CONF-04",
        attack_techniques=["T1213"],
        vuln_class="source_code_disclosure",
        phase=PHASE_VULN,
        tool="gitdumper",
        description="Recover the source tree from an exposed .git directory, "
                    "turning a readable path into the actual source.",
        severity_default="high",
        applies_when={"is_base": True},
    ),
    CatalogItem(
        id="VULN-VERIFIED-SECRETS",
        wstg_id="WSTG-CONF-04",
        attack_techniques=["T1552.001"],
        vuln_class="secret_exposure",
        phase=PHASE_VULN,
        tool="trufflehog",
        description="Verify each secret found in the recovered source and the "
                    "captured JavaScript against its own provider - a hit is a "
                    "credential that answered, not a pattern that matched.",
        severity_default="high",
        applies_when={"is_base": True},
    ),
    CatalogItem(
        id="VULN-AUTH",
        wstg_id="WSTG-ATHN-01",
        attack_techniques=["T1110", "T1078"],
        vuln_class="auth",
        phase=PHASE_VULN,
        tool="nuclei",
        description="Default credentials and known authentication bypasses.",
        severity_default="high",
        default_options=["-tags", "default-login,auth-bypass,auth"],
        applies_when={"always": True},
    ),

    # ----- EXPLOITATION (parameter-driven, safe-ish active tests) -----
    CatalogItem(
        id="EXP-DAST",
        wstg_id="WSTG-INPV-00",
        attack_techniques=["T1190"],
        vuln_class="multiple",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="DAST fuzzing of parameters: SSRF, LFI, XXE, SSTI, "
                    "open redirect, SQLi, XSS, command injection.",
        severity_default="high",
        default_options=["-dast"],
        applies_when={"is_endpoint": True},
    ),
    CatalogItem(
        id="EXP-SQLI",
        wstg_id="WSTG-INPV-05",
        attack_techniques=["T1190"],
        vuln_class="sql_injection",
        phase=PHASE_EXPLOIT,
        tool="sqlmap",
        description="Test injectable parameters and forms for SQL injection "
                    "(forms, threaded; batch/level/risk/random-agent from the wrapper).",
        severity_default="high",
        default_options=["--forms", "--threads=4"],
        applies_when={"is_endpoint": True},
    ),
    CatalogItem(
        id="EXP-XSS",
        wstg_id="WSTG-INPV-01",
        attack_techniques=["T1190"],
        vuln_class="xss",
        phase=PHASE_EXPLOIT,
        tool="dalfox",
        description="Test reflected/DOM XSS on parameters (deep DOM analysis).",
        severity_default="medium",
        default_options=["--deep-domxss"],
        applies_when={"is_endpoint": True},
    ),
    CatalogItem(
        id="EXP-CMDI",
        wstg_id="WSTG-INPV-12",
        attack_techniques=["T1190"],
        vuln_class="command_injection",
        phase=PHASE_EXPLOIT,
        tool="commix",
        description="Test parameters for OS command injection.",
        severity_default="critical",
        applies_when={"requires_params": True},
    ),
    # Dedicated injection-family items: focused DAST per class so each is
    # tracked, classified and prioritised on its own (with out-of-band/blind
    # confirmation via interactsh), instead of being buried in the generic fuzz.
    CatalogItem(
        id="EXP-SSRF",
        wstg_id="WSTG-INPV-19",
        attack_techniques=["T1190"],
        vuln_class="ssrf",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="Fuzz parameters for SSRF, confirmed out-of-band via interactsh.",
        severity_default="high",
        default_options=["-dast", "-tags", "ssrf"],
        applies_when={"requires_params": True},
    ),
    CatalogItem(
        id="EXP-SSTI",
        wstg_id="WSTG-INPV-18",
        attack_techniques=["T1190"],
        vuln_class="ssti",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="Fuzz parameters for server-side template injection.",
        severity_default="high",
        default_options=["-dast", "-tags", "ssti"],
        applies_when={"requires_params": True},
    ),
    CatalogItem(
        id="EXP-LFI",
        wstg_id="WSTG-ATHZ-01",
        attack_techniques=["T1190"],
        vuln_class="lfi",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="Fuzz parameters for local file inclusion / path traversal.",
        severity_default="high",
        default_options=["-dast", "-tags", "lfi,fileinclusion,traversal"],
        applies_when={"requires_params": True},
    ),
    CatalogItem(
        id="EXP-XXE",
        wstg_id="WSTG-INPV-07",
        attack_techniques=["T1190"],
        vuln_class="xxe",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="Fuzz parameters for XML external entity injection.",
        severity_default="high",
        default_options=["-dast", "-tags", "xxe"],
        applies_when={"requires_params": True},
    ),
    CatalogItem(
        id="EXP-REDIRECT",
        wstg_id="WSTG-CLNT-04",
        attack_techniques=["T1190"],
        vuln_class="open_redirect",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="Fuzz parameters for open redirect.",
        severity_default="medium",
        default_options=["-dast", "-tags", "redirect"],
        applies_when={"requires_params": True},
    ),
    CatalogItem(
        id="EXP-CRLF",
        wstg_id="WSTG-INPV-15",
        attack_techniques=["T1190"],
        vuln_class="crlf_injection",
        phase=PHASE_EXPLOIT,
        tool="nuclei",
        description="Fuzz parameters for CRLF / HTTP response splitting.",
        severity_default="medium",
        default_options=["-dast", "-tags", "crlf"],
        applies_when={"requires_params": True},
    ),
]


CATALOG_BY_ID: Dict[str, CatalogItem] = {item.id: item for item in CATALOG}


def items_for_phase(phase: str) -> List[CatalogItem]:
    return [i for i in CATALOG if i.phase == phase]


def applies(item: CatalogItem, context: Dict[str, Any]) -> bool:
    """Evaluate an item's applies_when against an asset/engagement context.

    context keys:
      is_host          - the target is a bare host (no path)
      is_https         - target uses https
      requires_params  - target URL has query parameters
      url              - the asset's value, for path_any matching
      source           - where the asset came from ("engagement" = the target)
      tech             - list[str] of fingerprinted technologies (lowercased)
    """
    cond = item.applies_when or {"always": True}

    if cond.get("always"):
        return True
    if cond.get("is_host") and not context.get("is_host"):
        return False
    if cond.get("is_https") and not context.get("is_https"):
        return False
    if cond.get("requires_params") and not context.get("requires_params"):
        return False
    # is_endpoint: applies to any endpoint asset (not a bare host), whether or
    # not it carries query params - for tools that discover params/forms
    # themselves (sqlmap --forms, nuclei -dast, dalfox mining).
    if cond.get("is_endpoint") and context.get("is_host"):
        return False
    # path_any: only on an asset whose URL contains one of these markers. Used
    # for tools that need a specific document rather than any endpoint -
    # schemathesis needs the OpenAPI schema, not the home page, and running it
    # on the wrong URL just produces a load error every engagement.
    # is_base: only the engagement's own target, not every endpoint the crawl
    # found. For tools that work per HOST rather than per URL - git-dumper
    # dumps one .git, trufflehog and retire.js scan one artifact directory -
    # running them on fifty discovered endpoints is fifty identical scans.
    if cond.get("is_base") and context.get("source") != "engagement":
        return False
    path_any = cond.get("path_any")
    if path_any:
        url = str(context.get("url") or "").lower()
        if not any(str(want).lower() in url for want in path_any):
            return False
    tech_any = cond.get("tech_any")
    if tech_any:
        tech = [t.lower() for t in context.get("tech", [])]
        if not any(any(want in have for have in tech) for want in tech_any):
            return False
    # If we reach here every present condition passed.
    return True
