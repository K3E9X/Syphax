"""vuln_class -> standards mapping for the report (WSTG / ATT&CK / CWE) and the
test-category taxonomy shared by the report and the live UI.

Validated findings carry a coarse vuln_class; the report enriches each with
the relevant OWASP WSTG id, MITRE ATT&CK technique(s), CWE and a default
remediation line. Every class also belongs to one canonical CATEGORY so the
UI and report partition findings homogeneously across phases (recon ->
enumeration -> access control -> injection -> auth/secrets -> config).
Unknown classes fall back to generic values.
"""
from __future__ import annotations

from typing import Any, Dict

# Canonical test categories (ordered the way an engagement progresses).
CATEGORY_ORDER = [
    "recon", "enumeration", "access_control", "injection",
    "auth_secrets", "config", "other",
]
CATEGORY_LABELS = {
    "recon": "Reconnaissance",
    "enumeration": "Mapping & enumeration",
    "access_control": "Access control",
    "injection": "Injection & exploitation",
    "auth_secrets": "Auth & secrets",
    "config": "Server & config",
    "other": "Other",
}

MAPPING: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "category": "injection",
        "wstg": "WSTG-INPV-05", "attack": ["T1190"], "cwe": "CWE-89",
        "remediation": "Use parameterized queries / prepared statements; never "
                       "concatenate user input into SQL. Apply least-privilege DB accounts.",
    },
    "command_injection": {
        "category": "injection",
        "wstg": "WSTG-INPV-12", "attack": ["T1190"], "cwe": "CWE-78",
        "remediation": "Avoid shelling out with user input; use safe APIs and "
                       "strict allow-list validation. Drop privileges.",
    },
    "xss": {
        "category": "injection",
        "wstg": "WSTG-INPV-01", "attack": ["T1059.007"], "cwe": "CWE-79",
        "remediation": "Context-aware output encoding, a strict CSP, and input "
                       "validation. Prefer framework auto-escaping.",
    },
    "ssrf": {
        "category": "injection",
        "wstg": "WSTG-INPV-19", "attack": ["T1190"], "cwe": "CWE-918",
        "remediation": "Validate and allow-list outbound URLs/hosts; block internal "
                       "ranges and cloud metadata (169.254.169.254); don't follow "
                       "redirects to private targets.",
    },
    "ssti": {
        "category": "injection",
        "wstg": "WSTG-INPV-18", "attack": ["T1190"], "cwe": "CWE-1336",
        "remediation": "Never render user input as a template; use logic-less "
                       "templates / strict sandboxing and escape all variables.",
    },
    "lfi": {
        "category": "injection",
        "wstg": "WSTG-ATHZ-01", "attack": ["T1190"], "cwe": "CWE-22",
        "remediation": "Resolve and canonicalise paths against an allow-list; reject "
                       "traversal sequences; never pass user input to file APIs.",
    },
    "xxe": {
        "category": "injection",
        "wstg": "WSTG-INPV-07", "attack": ["T1190"], "cwe": "CWE-611",
        "remediation": "Disable external entities and DTD processing in the XML "
                       "parser; prefer JSON or a hardened parser configuration.",
    },
    "open_redirect": {
        "category": "injection",
        "wstg": "WSTG-CLNT-04", "attack": ["T1190"], "cwe": "CWE-601",
        "remediation": "Don't redirect to user-supplied URLs; use an allow-list or "
                       "indirect (mapped) redirect targets.",
    },
    "crlf_injection": {
        "category": "injection",
        "wstg": "WSTG-INPV-15", "attack": ["T1190"], "cwe": "CWE-93",
        "remediation": "Strip/encode CR and LF in any user input reflected into "
                       "response headers; use the framework's header APIs.",
    },
    "cors": {
        "category": "access_control",
        "wstg": "WSTG-CLNT-07", "attack": ["T1190"], "cwe": "CWE-942",
        "remediation": "Never reflect arbitrary Origins; use a strict allow-list and "
                       "only set Allow-Credentials for trusted origins (never with *).",
    },
    "misconfiguration": {
        "category": "config",
        "wstg": "WSTG-CONF-02", "attack": ["T1190"], "cwe": "CWE-16",
        "remediation": "Harden the server: disable dangerous methods and "
                       "directory listing, remove backup/old files, restrict admin paths.",
    },
    "weak_tls": {
        "category": "config",
        "wstg": "WSTG-CRYP-01", "attack": ["T1190"], "cwe": "CWE-326",
        "remediation": "Disable legacy protocols/ciphers (SSLv3/TLS1.0/1.1, RC4, "
                       "3DES); enable HSTS; keep certificates valid and strong.",
    },
    "cms_vulnerability": {
        "category": "config",
        "wstg": "WSTG-CONF-01", "attack": ["T1190"], "cwe": "CWE-1035",
        "remediation": "Update the CMS core, plugins and themes; remove unused "
                       "extensions; restrict user enumeration.",
    },
    "cve": {
        "category": "config",
        "wstg": "WSTG-CONF-01", "attack": ["T1190"], "cwe": "CWE-1395",
        "remediation": "Patch or upgrade the affected component to a fixed "
                       "version; apply the vendor advisory and a WAF virtual "
                       "patch as defence in depth.",
    },
    "subdomain_takeover": {
        "category": "config",
        "wstg": "WSTG-CONF-10", "attack": ["T1584.001"], "cwe": "CWE-350",
        "remediation": "Remove dangling DNS records pointing at deprovisioned "
                       "services; claim or delete the CNAME target; monitor DNS.",
    },
    "exposed_resource": {
        "category": "enumeration",
        "wstg": "WSTG-CONF-04", "attack": ["T1592"], "cwe": "CWE-538",
        "remediation": "Remove publicly accessible source/config (.git, .env, "
                       "backups); block them at the web server.",
    },
    "exposed_bucket": {
        "category": "config",
        "wstg": "WSTG-CONF-11", "attack": ["T1530", "T1580"], "cwe": "CWE-284",
        "remediation": "Make cloud storage private by default: block public ACLs "
                       "and anonymous access (S3 Block Public Access / Azure "
                       "'disallow public blob access' / uniform bucket-level access "
                       "on GCS); grant read only to named principals; audit object ACLs.",
    },
    "content_discovery": {
        "category": "enumeration",
        "wstg": "WSTG-CONF-04", "attack": ["T1595"], "cwe": "CWE-538",
        "remediation": "Review discovered paths; remove or protect anything not "
                       "meant to be public (admin, backups, debug).",
    },
    "multiple": {
        "category": "config",
        "wstg": "WSTG-CONF-01", "attack": ["T1190"], "cwe": "CWE-693",
        "remediation": "Review each templated finding individually and apply the "
                       "vendor's guidance.",
    },
    "auth": {
        "category": "auth_secrets",
        "wstg": "WSTG-ATHN-01", "attack": ["T1110", "T1078"], "cwe": "CWE-287",
        "remediation": "Remove default/weak credentials, enforce strong auth and "
                       "rate limiting, and fix authentication-bypass paths.",
    },
    "secret_exposure": {
        "category": "auth_secrets",
        "wstg": "WSTG-CONF-04", "attack": ["T1552.001"], "cwe": "CWE-798",
        "remediation": "Never ship secrets in client code. Rotate the exposed "
                       "credential immediately and move it server-side / to a vault.",
    },
    "jwt": {
        "category": "auth_secrets",
        "wstg": "WSTG-SESS-10", "attack": ["T1606.001", "T1552"], "cwe": "CWE-347",
        "remediation": "Use a strong, random signing secret (or asymmetric keys); "
                       "reject alg=none and unexpected algs; set exp; validate kid/jku.",
    },
    "idor": {
        "category": "access_control",
        "wstg": "WSTG-ATHZ-04", "attack": ["T1190"], "cwe": "CWE-639",
        "remediation": "Enforce object-level authorization server-side: check the "
                       "current user owns/may access every referenced object id.",
    },
    "csrf": {
        "category": "access_control",
        "wstg": "WSTG-SESS-05", "attack": ["T1190"], "cwe": "CWE-352",
        "remediation": "Require an anti-CSRF token (or SameSite=strict cookies + "
                       "origin checks) on all state-changing requests.",
    },
    "privilege_escalation": {
        "category": "access_control",
        "wstg": "WSTG-ATHZ-02", "attack": ["T1068", "T1078.003"], "cwe": "CWE-285",
        "remediation": "Enforce function-level authorization server-side: check the "
                       "caller's role/permissions on every privileged endpoint and "
                       "action; deny by default. Don't rely on hiding admin UI.",
    },
    "broken_access_control": {
        "category": "access_control",
        "wstg": "WSTG-ATHZ-01", "attack": ["T1190"], "cwe": "CWE-284",
        "remediation": "Require authentication and authorization on every non-public "
                       "endpoint; deny by default; don't rely on the UI hiding it.",
    },
    "access_control_review": {
        "category": "access_control",
        "wstg": "WSTG-ATHZ-01", "attack": ["T1190"], "cwe": "CWE-284",
        "remediation": "Verify state-changing endpoints enforce method and role "
                       "checks; reject verb overrides and unauthorized callers.",
    },
    "mass_assignment": {
        "category": "access_control",
        "wstg": "WSTG-BUSL-08", "attack": ["T1190"], "cwe": "CWE-915",
        "remediation": "Bind only an explicit allow-list of fields from request "
                       "bodies; never trust client-supplied role/privilege fields.",
    },
    "graphql": {
        "category": "config",
        "wstg": "WSTG-APIT-01", "attack": ["T1190"], "cwe": "CWE-200",
        "remediation": "Disable GraphQL introspection in production; enforce "
                       "authorization per field/operation and add query depth/cost "
                       "limits.",
    },
    "param_discovery": {
        "category": "enumeration",
        "wstg": "WSTG-INFO-07", "attack": ["T1595"], "cwe": "CWE-200",
        "remediation": "Reflected/undocumented parameters widen attack surface; "
                       "remove unused params and validate/encode all that remain.",
    },
    "endpoint_discovery": {
        "category": "recon",
        "wstg": "WSTG-INFO-07", "attack": ["T1595"], "cwe": "CWE-200",
        "remediation": "Audit endpoints exposed in client code; remove/secure any "
                       "internal or unauthenticated API not meant to be public.",
    },
    "recon": {"category": "recon", "wstg": "WSTG-INFO-02", "attack": ["T1595"], "cwe": "CWE-200", "remediation": "Reduce exposed surface; restrict information disclosure."},
    "fingerprint": {"category": "recon", "wstg": "WSTG-INFO-08", "attack": ["T1592"], "cwe": "CWE-200", "remediation": "Suppress version banners where practical."},
}

_FALLBACK = {"category": "other", "wstg": "WSTG-INFO-00", "attack": ["T1595"],
             "cwe": "CWE-0", "remediation": "Review the finding and apply standard hardening."}


def for_class(vuln_class: str) -> Dict[str, Any]:
    return MAPPING.get((vuln_class or "").lower(), _FALLBACK)


def category_for_class(vuln_class: str) -> str:
    return for_class(vuln_class).get("category", "other")
