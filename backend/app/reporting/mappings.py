"""vuln_class -> standards mapping for the report (WSTG / ATT&CK / CWE / OWASP
API Top 10) and the test-category taxonomy shared by the report and the live UI.

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
    "rce": {
        "category": "injection",
        "wstg": "WSTG-INPV-12", "attack": ["T1190", "T1059"], "cwe": "CWE-94",
        "remediation": "Eliminate the code/command sink: never pass untrusted input "
                       "to eval/exec, deserializers, template engines or OS calls; "
                       "use safe APIs, strict allow-lists, and patch the affected "
                       "component. Sandbox and drop privileges on any required native call.",
    },
    "deserialization": {
        "category": "injection",
        "wstg": "WSTG-INPV-11", "attack": ["T1190"], "cwe": "CWE-502",
        "remediation": "Do not deserialize untrusted data; use data-only formats "
                       "(JSON) with schema validation, signed/encrypted payloads, and "
                       "allow-list of permitted types.",
    },
    "nosql_injection": {
        "category": "injection",
        "wstg": "WSTG-INPV-05", "attack": ["T1190"], "cwe": "CWE-943",
        "remediation": "Validate and type-cast query inputs; reject object/operator "
                       "syntax ($ne/$gt/$where/$regex) from client input; use the "
                       "driver's parameterised query builders, never raw dict merges.",
    },
    "xss": {
        "category": "injection",
        "wstg": "WSTG-INPV-01", "attack": ["T1059.007"], "cwe": "CWE-79",
        "remediation": "Context-aware output encoding, a strict CSP, and input "
                       "validation. Prefer framework auto-escaping.",
    },
    "ssrf": {
        "category": "injection", "owasp_api": "API7:2023",
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
    "excessive_data_exposure": {
        "category": "config",
        "wstg": "WSTG-APIT-01", "attack": ["T1530"], "cwe": "CWE-213",
        "remediation": "Return only the fields the caller needs: serialise through "
                       "an explicit allow-list per endpoint and per role, never the "
                       "whole ORM object. Filter server-side, not in the UI.",
    },
    "pii_exposure": {
        "category": "config",
        "wstg": "WSTG-APIT-01", "attack": ["T1530"], "cwe": "CWE-359",
        "remediation": "Minimise and mask personal data in responses; return it "
                       "only to a caller entitled to it, and log/retain it under "
                       "the applicable data-protection rules (GDPR).",
    },
    "cleartext_credentials": {
        "category": "auth_secrets",
        "wstg": "WSTG-ATHN-01", "attack": ["T1040"], "cwe": "CWE-319",
        "remediation": "Serve the login over HTTPS only and redirect HTTP to it "
                       "with HSTS; never submit credentials to an http:// URL.",
    },
    "user_enumeration": {
        "category": "auth_secrets",
        "wstg": "WSTG-IDNT-04", "attack": ["T1589.001"], "cwe": "CWE-204",
        "remediation": "Return one generic message and the same timing for "
                       "unknown users and wrong passwords, on login, password "
                       "reset and registration alike.",
    },
    "weak_password_policy": {
        "category": "auth_secrets",
        "wstg": "WSTG-ATHN-07", "attack": ["T1110"], "cwe": "CWE-521",
        "remediation": "Require a reasonable minimum length (>= 8, ideally 12), "
                       "check candidates against a breached-password list, and "
                       "enforce it server-side - not only in the browser.",
    },
    "auth_bypass": {
        "category": "access_control", "owasp_api": "API2:2023",
        "wstg": "WSTG-ATHN-04", "attack": ["T1078"], "cwe": "CWE-287",
        "remediation": "Do not let request headers override the routed path or the "
                       "caller's address for authorization. Ignore X-Original-URL / "
                       "X-Rewrite-URL, and never trust a client-supplied "
                       "X-Forwarded-For for an access decision.",
    },
    "cookie_security": {
        "category": "auth_secrets",
        "wstg": "WSTG-SESS-02", "attack": ["T1539"], "cwe": "CWE-614",
        "remediation": "Set Secure, HttpOnly and SameSite on every session/auth "
                       "cookie. SameSite=None requires Secure. Scope cookies with "
                       "Path and avoid a wildcard Domain.",
    },
    "security_headers": {
        "category": "config",
        "wstg": "WSTG-CONF-07", "attack": ["T1190"], "cwe": "CWE-693",
        "remediation": "Send the defence-in-depth headers: a strict "
                       "Content-Security-Policy, Strict-Transport-Security, "
                       "X-Content-Type-Options: nosniff and a Referrer-Policy.",
    },
    "clickjacking": {
        "category": "config",
        "wstg": "WSTG-CLNT-09", "attack": ["T1185"], "cwe": "CWE-1021",
        "remediation": "Send Content-Security-Policy: frame-ancestors 'none' (or an "
                       "explicit allow-list), and X-Frame-Options: DENY for old browsers.",
    },
    "information_disclosure": {
        "category": "config",
        "wstg": "WSTG-ERRH-01", "attack": ["T1592"], "cwe": "CWE-200",
        "remediation": "Return generic error pages; never ship stack traces, SQL "
                       "errors, internal paths or component versions to the client. "
                       "Log the detail server-side instead.",
    },
    "api_route": {
        "category": "enumeration", "owasp_api": "API9:2023",
        "wstg": "WSTG-APIT-01", "attack": ["T1595"], "cwe": "CWE-200",
        "remediation": "Inventory and authenticate every API route; remove or "
                       "protect undocumented/legacy endpoints; deny by default.",
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
        "category": "auth_secrets", "owasp_api": "API2:2023",
        "wstg": "WSTG-SESS-10", "attack": ["T1606.001", "T1552"], "cwe": "CWE-347",
        "remediation": "Use a strong, random signing secret (or asymmetric keys); "
                       "reject alg=none and unexpected algs; set exp; validate kid/jku.",
    },
    "idor": {
        "category": "access_control", "owasp_api": "API1:2023",
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
        "category": "access_control", "owasp_api": "API5:2023",
        "wstg": "WSTG-ATHZ-02", "attack": ["T1068", "T1078.003"], "cwe": "CWE-285",
        "remediation": "Enforce function-level authorization server-side: check the "
                       "caller's role/permissions on every privileged endpoint and "
                       "action; deny by default. Don't rely on hiding admin UI.",
    },
    "broken_access_control": {
        "category": "access_control", "owasp_api": "API1:2023",
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
        "category": "access_control", "owasp_api": "API3:2023",
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
    "recon": {"category": "recon", "wstg": "WSTG-INFO-02", "attack": ["T1595"], "cwe": "CWE-200", "remediation": "Reduce the exposed surface: this is inventory rather "
                             "than a weakness, and it is in the report so the "
                             "tested surface is on the record."},
    "fingerprint": {"category": "recon", "wstg": "WSTG-INFO-08", "attack": ["T1592"], "cwe": "CWE-200", "remediation": "Suppress version banners where practical. This is "
                                   "inventory: it tells an attacker which "
                                   "advisories to read, and it is in the report "
                                   "so the tested surface is on the record."},

    # The rest of what the exploit strategy is willing to author a PoC for.
    # A class the campaign will spend a model call on, whose finding the
    # report then cannot categorise, is the same gap one step later.
    "weak_credentials": {
        "category": "auth_secrets", "owasp_api": "API2:2023",
        "wstg": "WSTG-ATHN-07", "attack": ["T1110"], "cwe": "CWE-521",
        "remediation": "Enforce a length-first password policy, check new "
                       "credentials against a breached-password list, and add "
                       "per-account rate limiting so guessing costs time.",
    },
    "race_condition": {
        "category": "access_control", "owasp_api": "API6:2023",
        "wstg": "WSTG-BUSL-07", "attack": ["T1190"], "cwe": "CWE-362",
        "remediation": "Make the check and the act one transaction: a database "
                       "constraint, a row lock or an idempotency key. "
                       "Validating and then writing in two steps is the bug, "
                       "whatever the window is.",
    },
    "host_header": {
        "category": "config", "wstg": "WSTG-CONF-07",
        "attack": ["T1190"], "cwe": "CWE-644",
        "remediation": "Resolve absolute URLs from configuration, never from "
                       "the Host or X-Forwarded-Host header, and reject a Host "
                       "that is not in the expected set at the edge.",
    },
    "insecure_cookie": {
        "category": "auth_secrets", "wstg": "WSTG-SESS-02",
        "attack": ["T1539"], "cwe": "CWE-1004",
        "remediation": "Set Secure, HttpOnly and SameSite on every session "
                       "cookie, and scope it to the narrowest path and domain "
                       "the application needs.",
    },
    "redirect": {
        "category": "config", "wstg": "WSTG-CLNT-04",
        "attack": ["T1566"], "cwe": "CWE-601",
        "remediation": "Redirect only to an allow-list of paths or hosts. "
                       "Validating that the target 'contains' your domain is "
                       "not validation.",
    },
    "template_injection": {
        "category": "injection", "wstg": "WSTG-INPV-18",
        "attack": ["T1190", "T1059"], "cwe": "CWE-1336",
        "remediation": "Never compile a template from request input. Pass the "
                       "input as DATA to a fixed template, and use a sandboxed "
                       "engine where templates must be user-supplied.",
    },
    "prototype_pollution": {
        "category": "injection", "wstg": "WSTG-CLNT-13",
        "attack": ["T1190"], "cwe": "CWE-1321",
        "remediation": "Reject __proto__, constructor and prototype keys when "
                       "merging untrusted objects; use Object.create(null) or "
                       "a Map for anything built from request data.",
    },
    "ldap_injection": {
        "category": "injection", "wstg": "WSTG-INPV-06",
        "attack": ["T1190"], "cwe": "CWE-90",
        "remediation": "Escape LDAP special characters with the library's own "
                       "encoder and bind parameters rather than building the "
                       "filter string by concatenation.",
    },
    "xpath_injection": {
        "category": "injection", "wstg": "WSTG-INPV-09",
        "attack": ["T1190"], "cwe": "CWE-643",
        "remediation": "Use parameterised XPath or escape the input with the "
                       "library's encoder; validate against an allow-list "
                       "where the value selects a node.",
    },

    # Accepted by the exploit strategy under these names, so a module that
    # emits one must not fall through to CWE-0.
    "bola": {
        "category": "access_control", "owasp_api": "API1:2023",
        "wstg": "WSTG-ATHZ-04", "attack": ["T1190"], "cwe": "CWE-639",
        "remediation": "Check on every request that the authenticated subject "
                       "is entitled to the object the request names - at the "
                       "data layer, not in the handler that happened to be "
                       "reviewed.",
    },
    "bfla": {
        "category": "access_control", "owasp_api": "API5:2023",
        "wstg": "WSTG-ATHZ-02", "attack": ["T1190", "T1078"], "cwe": "CWE-285",
        "remediation": "Authorise the FUNCTION as well as the object: an "
                       "administrative operation must refuse a non-"
                       "administrative caller even when the route is guessed "
                       "correctly. Deny by default per route.",
    },
    "business_logic": {
        "category": "access_control", "owasp_api": "API6:2023",
        "wstg": "WSTG-BUSL-01", "attack": ["T1190"], "cwe": "CWE-840",
        "remediation": "Enforce the rule server-side and in one place. A flow "
                       "that depends on the client following the intended "
                       "order is not enforced, it is suggested.",
    },

    # ----- API security -------------------------------------------------
    #
    # Fifteen classes the toolchain emits had no entry here, so the report
    # printed WSTG-INFO-00, CWE-0, category "other" and "review the finding
    # and apply standard hardening" for every one of them - including the
    # whole API suite, nikto's signature table and the two highest-value
    # schemathesis checks. `owasp_api` is carried for the classes where the
    # API Top 10 says something the WSTG id does not, and is deliberately
    # ABSENT where no item honestly fits: a wrong mapping sends a reader to
    # the wrong control.
    "broken_authentication": {
        "category": "auth_secrets", "owasp_api": "API2:2023",
        "wstg": "WSTG-ATHN-01", "attack": ["T1078", "T1190"], "cwe": "CWE-287",
        "remediation": "Require a verified credential on every non-public "
                       "operation, declare it in the API contract so a "
                       "reviewer and a gateway can both see it, and deny by "
                       "default rather than listing what to protect.",
    },
    "default_credentials": {
        "category": "auth_secrets", "owasp_api": "API2:2023",
        "wstg": "WSTG-ATHN-02", "attack": ["T1078.001"], "cwe": "CWE-1392",
        "remediation": "Change the credential now and treat the account as "
                       "compromised. Force a credential change at first boot "
                       "instead of shipping one that works.",
    },
    "shadow_api": {
        "category": "enumeration", "owasp_api": "API9:2023",
        "wstg": "WSTG-APIT-01", "attack": ["T1595", "T1190"], "cwe": "CWE-1059",
        "remediation": "Decommission the version rather than leaving it "
                       "answering: an endpoint nobody calls is an endpoint "
                       "nobody patches. If it must stay, put it behind the "
                       "same authentication, rate limiting and review as the "
                       "current one, and add it to the inventory so the next "
                       "audit sees it.",
    },
    "rate_limit": {
        "category": "config", "owasp_api": "API4:2023",
        "wstg": "WSTG-BUSL-05", "attack": ["T1110", "T1499"], "cwe": "CWE-770",
        "remediation": "Throttle per identity and per IP at the gateway, "
                       "answer 429 with Retry-After, and set the limit from "
                       "what the operation costs - a cheap read and an export "
                       "do not deserve the same quota.",
    },
    "api_contract_violation": {
        "category": "config", "owasp_api": "API8:2023",
        "wstg": "WSTG-CONF-01", "attack": ["T1190"], "cwe": "CWE-684",
        "remediation": "Make the implementation and the published schema "
                       "agree: validate requests and responses against the "
                       "contract in CI, so a response the spec does not "
                       "describe fails a test rather than reaching a client.",
    },
    "missing_security_header": {
        "category": "config", "owasp_api": "API8:2023",
        "wstg": "WSTG-CONF-07", "attack": ["T1190"], "cwe": "CWE-693",
        "remediation": "Set the headers at the edge so no application can "
                       "forget them: HSTS, a restrictive CSP, "
                       "X-Content-Type-Options, and frame-ancestors.",
    },
    "unhandled_error": {
        "category": "config", "owasp_api": "API8:2023",
        "wstg": "WSTG-ERRH-01", "attack": ["T1190"], "cwe": "CWE-248",
        "remediation": "Handle the exception and answer a generic 500. The "
                       "input that caused it is also the input to check: an "
                       "unhandled error is often the visible end of a "
                       "validation gap.",
    },
    "input_validation": {
        "category": "injection", "wstg": "WSTG-INPV-01",
        "attack": ["T1190"], "cwe": "CWE-20",
        "remediation": "Validate against an allow-list at the boundary, and "
                       "make the schema the validator rather than a document "
                       "alongside one - a constraint the contract states and "
                       "the server does not enforce is worse than no "
                       "constraint, because it is relied upon.",
    },
    "graphql_introspection": {
        "category": "enumeration", "owasp_api": "API8:2023",
        "wstg": "WSTG-APIT-01", "attack": ["T1595"], "cwe": "CWE-200",
        "remediation": "Disable introspection AND field suggestions in "
                       "production - suggestions leak the same schema one "
                       "guess at a time, and disabling only introspection is "
                       "the common half-measure. Remove any console "
                       "(GraphiQL, Playground, Altair) or put it behind "
                       "authentication.",
    },
    "dangerous_http_method": {
        "category": "config", "wstg": "WSTG-CONF-06",
        "attack": ["T1190"], "cwe": "CWE-650",
        "remediation": "Allow only the methods each route needs; disable "
                       "TRACE, TRACK, PUT and DELETE at the server unless the "
                       "application implements them deliberately.",
    },
    "file_inclusion": {
        "category": "injection", "wstg": "WSTG-INPV-11",
        "attack": ["T1190"], "cwe": "CWE-98",
        "remediation": "Never build a filesystem or include path from request "
                       "input. Map an identifier to a path server-side and "
                       "reject anything that is not in the map.",
    },
    "path_traversal": {
        "category": "injection", "wstg": "WSTG-ATHZ-01",
        "attack": ["T1190", "T1083"], "cwe": "CWE-22",
        "remediation": "Resolve the path and confirm it is inside the allowed "
                       "directory after normalisation, not before; reject "
                       "rather than sanitise.",
    },
    "source_code_disclosure": {
        "category": "config", "wstg": "WSTG-CONF-04",
        "attack": ["T1213", "T1592"], "cwe": "CWE-540",
        "remediation": "Remove the exposed source or repository metadata from "
                       "the web root, and treat every secret it contained as "
                       "compromised - the source is readable, so the "
                       "credentials in it are too.",
    },
    "vulnerable_component": {
        "category": "config", "wstg": "WSTG-CONF-01",
        "attack": ["T1190"], "cwe": "CWE-1104",
        "remediation": "Upgrade the component to a supported version. Pin "
                       "versions and run a dependency audit in CI so the next "
                       "one is caught before it ships.",
    },
    "outdated_component": {
        "category": "config", "wstg": "WSTG-CONF-01",
        "attack": ["T1190"], "cwe": "CWE-1104",
        "remediation": "Upgrade the component to a supported version; an "
                       "out-of-support release receives no security fixes at "
                       "all, so its known-CVE count only grows.",
    },
}

_FALLBACK = {"category": "other", "wstg": "WSTG-INFO-00", "attack": ["T1595"],
             "cwe": "CWE-0", "remediation": "Review the finding and apply standard hardening."}


def for_class(vuln_class: str) -> Dict[str, Any]:
    return MAPPING.get((vuln_class or "").lower(), _FALLBACK)


def owasp_api_for_class(vuln_class: str) -> str:
    """The OWASP API Security Top 10 item, or "".

    Empty is a real answer, not a missing one: path traversal and vulnerable
    components are web weaknesses the API list does not cover, and mapping
    them to the nearest item would send a reader to the wrong control.
    """
    return str(for_class(vuln_class).get("owasp_api") or "")


def category_for_class(vuln_class: str) -> str:
    return for_class(vuln_class).get("category", "other")
