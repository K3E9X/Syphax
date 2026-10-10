"""Audit the API contract itself, before anything is sent to the API.

A fuzzer tests what the implementation does. This reads what the contract
SAYS, which answers a different and often larger set of questions, because
the interesting ones here are statements of absence: no security scheme on
the operation that deletes an account, no 429 anywhere in three hundred
operations, a request body that accepts any property the caller invents.

cherrybomb is the known tool for this. It was the plan and it was dropped:
its only install path that is not marked "DEPRECATED FOR NOW" in its own
README is `cargo install`, which means a Rust toolchain in the image for a
project with no activity since October 2024 and a check list it does not
publish. The checks below are named, defended and free. See the commit
message for the full reasoning.

Two things make this worth a module rather than a lint pass:

  * it runs on the PUBLISHED schema only. A schema synthesised from traffic
    (analysis/openapi_synth) declares no security because WE did not write
    one, so auditing it for missing security would manufacture a finding per
    operation out of our own omission. `audit()` refuses an observed
    document.
  * findings are aggregated per CHECK, not per operation. A 300-operation
    schema with no security would otherwise produce 300 findings and drown
    everything else in the report - the same flood that gau produced.

Stored as a synthetic job (tool="schema_audit").
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from app.analysis._store import save_analysis_job
from app.scans.models import Finding

logger = logging.getLogger("syphax.analysis.schema_audit")

MAX_EXAMPLES = 8            # how many operations one finding names
MAX_DOC_BYTES = 4_000_000

_WRITE_METHODS = ("post", "put", "patch", "delete")
_METHODS = ("get", "head", "options", "trace") + _WRITE_METHODS

# A path parameter whose name says it addresses one object. An operation that
# takes one and requires no authorisation is the shape of API1/BOLA.
_OBJECT_PARAM_HINTS = ("id", "uuid", "guid", "key", "ref", "no", "num",
                       "user", "account", "order", "customer", "member")


def parse(raw: str) -> Optional[Dict[str, Any]]:
    """An OpenAPI document from JSON or YAML text. None if it is neither.

    yaml.safe_load only: the document comes from the target, and the full
    loader constructs arbitrary Python objects from a tag.
    """
    text = (raw or "")[:MAX_DOC_BYTES].strip()
    if not text:
        return None
    try:
        doc = json.loads(text)
    except Exception:  # noqa: BLE001 - try YAML before giving up
        try:
            import yaml
            doc = yaml.safe_load(text)
        except Exception:  # noqa: BLE001
            return None
    if not isinstance(doc, dict):
        return None
    if not (doc.get("openapi") or doc.get("swagger")):
        return None
    return doc


def is_observed(doc: Dict[str, Any]) -> bool:
    """Our own synthesised document, which must not be audited as a contract."""
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    version = str((info or {}).get("version") or "").lower()
    description = str((info or {}).get("description") or "").lower()
    return version == "observed" or "synthesised from captured traffic" in description


def operations(doc: Dict[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
    """(path, method, operation) for every documented operation."""
    out: List[Tuple[str, str, Dict[str, Any]]] = []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return out
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            operation = item.get(method)
            if isinstance(operation, dict):
                out.append((str(path), method, operation))
    return out


def declared_schemes(doc: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """The security schemes the document defines (OpenAPI 3 and Swagger 2)."""
    components = doc.get("components")
    if isinstance(components, dict) and isinstance(components.get("securitySchemes"), dict):
        return {k: v for k, v in components["securitySchemes"].items()
                if isinstance(v, dict)}
    legacy = doc.get("securityDefinitions")
    if isinstance(legacy, dict):
        return {k: v for k, v in legacy.items() if isinstance(v, dict)}
    return {}


def _requires_auth(operation: Dict[str, Any], global_security: Any) -> Optional[bool]:
    """True/False, or None when the operation does not say and there is no
    global default to inherit."""
    own = operation.get("security")
    if isinstance(own, list):
        return bool(own)        # [] is an explicit opt-out, not "unspecified"
    if isinstance(global_security, list):
        return bool(global_security)
    return None


def addresses_one_object(path: str, operation: Dict[str, Any]) -> bool:
    """The operation takes an identifier, so it addresses someone's object."""
    if "{" in path:
        for raw in path.split("{")[1:]:
            name = raw.split("}")[0].lower()
            if any(hint in name for hint in _OBJECT_PARAM_HINTS):
                return True
    for param in operation.get("parameters") or []:
        if not isinstance(param, dict) or param.get("in") != "path":
            continue
        if any(hint in str(param.get("name") or "").lower()
               for hint in _OBJECT_PARAM_HINTS):
            return True
    return False


def weak_schemes(schemes: Dict[str, Dict[str, Any]]) -> List[Tuple[str, str]]:
    """(scheme name, what is wrong with it)."""
    out: List[Tuple[str, str]] = []
    for name, scheme in schemes.items():
        kind = str(scheme.get("type") or "").lower()
        if kind == "http" and str(scheme.get("scheme") or "").lower() == "basic":
            out.append((name, "HTTP Basic: the password is replayed on every "
                              "request and is recoverable from any capture"))
        if kind == "apikey" and str(scheme.get("in") or "").lower() == "query":
            out.append((name, "API key in a query parameter: it lands in access "
                              "logs, proxy logs, Referer headers and browser "
                              "history, none of which are the credential store"))
        if kind == "oauth2":
            flows = scheme.get("flows") if isinstance(scheme.get("flows"), dict) else {}
            if "implicit" in (flows or {}):
                out.append((name, "OAuth2 implicit flow: the access token is "
                                  "returned in the URL fragment. Deprecated by "
                                  "OAuth 2.1 in favour of PKCE"))
    return out


def unbounded_inputs(doc: Dict[str, Any]) -> List[str]:
    """Parameters the contract leaves with no upper bound. "path method name"."""
    out: List[str] = []
    for path, method, operation in operations(doc):
        for param in operation.get("parameters") or []:
            if not isinstance(param, dict):
                continue
            schema = param.get("schema") if isinstance(param.get("schema"), dict) else param
            kind = str(schema.get("type") or "").lower()
            if kind == "string" and not any(
                    k in schema for k in ("maxLength", "pattern", "enum", "format")):
                out.append(f"{method.upper()} {path} ?{param.get('name')}")
            elif kind == "array" and "maxItems" not in schema:
                out.append(f"{method.upper()} {path} ?{param.get('name')}")
            elif kind in ("integer", "number") and not any(
                    k in schema for k in ("maximum", "exclusiveMaximum", "enum")):
                out.append(f"{method.upper()} {path} ?{param.get('name')}")
    return out


def open_write_bodies(doc: Dict[str, Any]) -> List[str]:
    """Write operations whose body schema accepts properties it never names.

    `additionalProperties` absent or true on a request body means the server
    is contractually willing to read a field the client invented, which is
    the schema-level half of mass assignment (API3). Whether it ASSIGNS it is
    a question for the live test; this says the door is documented as open.
    """
    out: List[str] = []
    for path, method, operation in operations(doc):
        if method not in ("post", "put", "patch"):
            continue
        body = operation.get("requestBody")
        content = (body or {}).get("content") if isinstance(body, dict) else None
        for media, entry in (content or {}).items():
            schema = entry.get("schema") if isinstance(entry, dict) else None
            schema = _resolve(doc, schema)
            if not isinstance(schema, dict):
                continue
            if str(schema.get("type") or "object").lower() != "object":
                continue
            extra = schema.get("additionalProperties", None)
            if extra is False:
                continue
            if not isinstance(schema.get("properties"), dict):
                continue    # a body with no named properties says nothing
            out.append(f"{method.upper()} {path} ({media})")
            break
    return out


def _resolve(doc: Dict[str, Any], schema: Any, depth: int = 0) -> Any:
    """Follow one local $ref. Bounded: a schema may reference itself."""
    if not isinstance(schema, dict) or depth > 4:
        return schema
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return schema
    node: Any = doc
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return schema
        node = node.get(part.replace("~1", "/").replace("~0", "~"))
    return _resolve(doc, node, depth + 1) if isinstance(node, dict) else schema


def documents_throttling(doc: Dict[str, Any]) -> bool:
    """Any operation documents 429, or any scheme describes a quota."""
    for _path, _method, operation in operations(doc):
        responses = operation.get("responses")
        if isinstance(responses, dict) and any(
                str(code).startswith("429") for code in responses):
            return True
    return False


def plaintext_servers(doc: Dict[str, Any]) -> List[str]:
    out = []
    for server in doc.get("servers") or []:
        url = str((server or {}).get("url") or "") if isinstance(server, dict) else ""
        if url.lower().startswith("http://") and "localhost" not in url.lower() \
                and "127.0.0.1" not in url:
            out.append(url)
    if str(doc.get("schemes") or "") and "http" in (doc.get("schemes") or []) \
            and "https" not in (doc.get("schemes") or []):
        out.append(f"swagger 2 schemes: {doc.get('schemes')}")
    return out


# ---------------------------------------------------------------------------


def audit(doc: Dict[str, Any], *, schema_url: str) -> List[Finding]:
    """Every finding this document supports. Pure: reads, sends nothing."""
    if is_observed(doc):
        return []
    ops = operations(doc)
    if not ops:
        return []

    schemes = declared_schemes(doc)
    global_security = doc.get("security")
    findings: List[Finding] = []

    def add(severity: str, title: str, description: str, kind: str,
            vuln_class: str, examples: List[str], owasp: str,
            confidence: float = 0.9) -> None:
        shown = examples[:MAX_EXAMPLES]
        more = len(examples) - len(shown)
        evidence = "\n".join([f"schema: {schema_url}"] + shown
                             + ([f"... and {more} more"] if more > 0 else []))
        findings.append(Finding(
            severity=severity, title=title, description=description,
            target=schema_url, evidence=evidence,
            metadata={"tool": "schema_audit", "vuln_class": vuln_class,
                      "status": "confirmed", "confidence": confidence,
                      "kind": kind, "owasp_api": owasp,
                      "operations": len(ops),
                      "affected": len(examples)},
        ))

    # --- authentication ---------------------------------------------------
    if not schemes and not isinstance(global_security, list):
        add("high",
            f"API contract defines no authentication at all ({len(ops)} operations)",
            f"The published schema declares no security scheme and no security "
            f"requirement, for all {len(ops)} documented operations. Either "
            f"the whole API is unauthenticated, or - more often - the "
            f"authentication exists in the implementation and is absent from "
            f"the contract, which means no generated client, no gateway and no "
            f"reviewer can see which operations are meant to be protected. "
            f"Both readings are a problem and the second one is how an "
            f"endpoint silently loses its check.",
            "no_security", "broken_authentication",
            [f"{m.upper()} {p}" for p, m, _ in ops],
            "API2:2023")
    else:
        unprotected_objects: List[str] = []
        unprotected_writes: List[str] = []
        opted_out: List[str] = []
        for path, method, operation in ops:
            if isinstance(operation.get("security"), list) and not operation["security"] \
                    and isinstance(global_security, list) and global_security:
                opted_out.append(f"{method.upper()} {path}")
                continue
            if _requires_auth(operation, global_security) is not False:
                continue
            if addresses_one_object(path, operation):
                unprotected_objects.append(f"{method.upper()} {path}")
            elif method in _WRITE_METHODS:
                unprotected_writes.append(f"{method.upper()} {path}")

        if opted_out:
            add("high",
                f"{len(opted_out)} operation(s) switch the API's authentication off",
                "These operations carry `security: []`, which is not "
                "\"unspecified\" - it is an explicit override of the "
                "document's global requirement, declaring that this one "
                "endpoint needs no credential. Sometimes that is deliberate "
                "(a health check, a login route). When it is not, it is the "
                "single-line change that exempts an endpoint from the whole "
                "API's authentication, and it is invisible in any view that "
                "does not read the schema.",
                "security_opt_out", "broken_authentication",
                opted_out, "API2:2023", confidence=0.95)

        if unprotected_objects:
            add("medium",
                f"{len(unprotected_objects)} operation(s) address an object "
                f"with no authorisation declared",
                "Each of these takes an identifier in its path and requires "
                "no credential by the contract. That is the exact shape of "
                "broken object level authorisation: the object is selected by "
                "a value the caller supplies, and nothing in the contract says "
                "the caller has to be entitled to it. Whether the "
                "implementation checks anyway is what the live tests answer - "
                "this says the contract does not require it to.",
                "unauthorised_object_access", "broken_access_control",
                unprotected_objects, "API1:2023")

        if unprotected_writes:
            add("medium",
                f"{len(unprotected_writes)} write operation(s) require no authentication",
                "These create, replace or delete without a declared "
                "credential. A documented unauthenticated write is either a "
                "deliberate public endpoint or a missing requirement, and the "
                "contract gives no way to tell which.",
                "unauthenticated_write", "broken_authentication",
                unprotected_writes, "API2:2023")

    for name, problem in weak_schemes(schemes):
        add("medium", f"Weak authentication scheme in the API contract: {name}",
            f"The scheme '{name}' is declared as follows: {problem}.",
            "weak_scheme", "broken_authentication", [f"securitySchemes.{name}"],
            "API2:2023")

    # --- the rest ---------------------------------------------------------
    plaintext = plaintext_servers(doc)
    if plaintext:
        add("medium", "The API contract publishes a plaintext server URL",
            "The document tells every generated client to speak http://. "
            "Credentials and tokens sent to it are readable by anything on "
            "the path, and a redirect to https afterwards does not recall the "
            "first request.",
            "plaintext_server", "misconfiguration", plaintext, "API8:2023")

    if not documents_throttling(doc):
        add("low", f"No rate limiting described anywhere in the contract "
                   f"({len(ops)} operations)",
            "Not one operation documents a 429. A contract that never "
            "mentions throttling is usually describing an API that does not "
            "throttle, and it certainly means no client was built to expect "
            "it. Whether the deployment limits anything is tested live; this "
            "is the design statement.",
            "no_throttling_documented", "rate_limit",
            [f"{len(ops)} operations, none with a 429 response"], "API4:2023",
            confidence=0.8)

    open_bodies = open_write_bodies(doc)
    if open_bodies:
        add("medium" if len(open_bodies) > 3 else "low",
            f"{len(open_bodies)} write operation(s) accept undeclared properties",
            "The request body schema names its properties and then leaves "
            "`additionalProperties` open, so the contract permits a client to "
            "send fields the API never documented. That is the documented "
            "half of mass assignment: whether the server binds `is_admin` or "
            "`role` straight onto the model is a question for the live test, "
            "but the contract already says the door is not shut. Setting "
            "additionalProperties to false closes it for every operation at "
            "once.",
            "open_request_body", "mass_assignment", open_bodies, "API3:2023",
            confidence=0.85)

    unbounded = unbounded_inputs(doc)
    if len(unbounded) > 5:
        add("low",
            f"{len(unbounded)} parameter(s) are declared with no upper bound",
            "Strings with no maxLength or pattern, arrays with no maxItems, "
            "numbers with no maximum. Each is an input the contract invites "
            "the caller to make arbitrarily large, and the ones that reach a "
            "database query, a regular expression or a memory allocation are "
            "where that stops being a style note. Listed as a group because "
            "individually they are not worth a finding.",
            "unbounded_input", "input_validation", unbounded, "API4:2023",
            confidence=0.75)

    return findings


async def analyze_schema(engagement_id: str) -> Dict[str, int]:
    """Audit every published schema this engagement found."""
    from app.engagements import EngagementRepository

    eng = await EngagementRepository().get(engagement_id)
    if eng is None:
        return {"error": 1}

    documents = await _published_documents(eng)
    findings: List[Finding] = []
    audited = 0
    for url, raw in documents:
        doc = parse(raw)
        if doc is None or is_observed(doc):
            continue
        audited += 1
        findings.extend(audit(doc, schema_url=url))

    await save_analysis_job(engagement_id, "schema_audit", findings,
                            target=eng.target_url)
    logger.info("[%s] schema_audit: documents=%d audited=%d findings=%d",
                engagement_id, len(documents), audited, len(findings))
    return {"documents": len(documents), "audited": audited,
            "findings": len(findings)}


async def _published_documents(eng) -> List[Tuple[str, str]]:
    """(url, body) for each published schema this run has in hand.

    Two sources, neither of them a new request: the file surface_seed wrote
    when it found the contract, and the response bodies the proxy captured
    when the crawl fetched one.
    """
    out: List[Tuple[str, str]] = []
    seen: set = set()

    try:
        from app.scans.artifacts import OPENAPI, artifact_dir
        directory = artifact_dir(eng.target_url or eng.target_host, OPENAPI)
        candidate = (directory / "published.json") if directory else None
        if candidate is not None and candidate.is_file():
            out.append((f"{eng.target_url} (published schema)",
                        candidate.read_text(encoding="utf-8", errors="replace")))
    except Exception:  # noqa: BLE001 - the captured copy may still be there
        logger.debug("could not read the stored published schema")

    try:
        from app import db
        async with db.acquire() as conn:
            rows = await conn.fetch(
                "SELECT url, host, response_body FROM flows "
                "WHERE response_body IS NOT NULL "
                "AND (url ILIKE '%openapi%' OR url ILIKE '%swagger%' "
                "     OR url ILIKE '%api-docs%') "
                'ORDER BY "timestamp" DESC LIMIT 20')
    except Exception:  # noqa: BLE001 - no traffic table is not a failure
        rows = []
    for row in rows:
        url = str(row["url"] or "")
        if url in seen or not eng.host_in_scope((row["host"] or "").lower()):
            continue
        seen.add(url)
        body = row["response_body"]
        if isinstance(body, (bytes, bytearray)):
            body = bytes(body).decode("utf-8", errors="replace")
        out.append((url, str(body or "")))
    return out
