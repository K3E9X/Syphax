"""GraphQL beyond introspection: the checks a single query can settle.

The existing analyser answered one question - is introspection on? That is the
first question and the least interesting, because it is the one thing teams
actually switch off. Everything below survives introspection being disabled.

graphql-cop and graphw00f are the known tools here and both look unmaintained,
so these are in-house. Each check is one GET with a benign query, which keeps
them inside the SafePoC model (GET/HEAD, in scope, one request, capped body).

  * FIELD SUGGESTIONS. Ask for a field that does not exist and a server with
    suggestions on answers "Did you mean 'users'?". That is schema disclosure
    with introspection off, and it is enough to walk the whole type graph one
    guess at a time. This is the check that matters most.
  * PARTIAL INTROSPECTION. Many deployments block the literal string
    "__schema" at the WAF and leave __type reachable. Then introspection is
    not off, it is misspelt.
  * ALIAS SUPPORT. One query may repeat a field under N aliases, and the
    server does N times the work for one request. We send TWO aliases and
    report that the primitive is available - never the thousands that would
    make it an outage. The report says so explicitly.
  * DUPLICATE DIRECTIVES. The spec says a directive may appear once per
    location. A server that accepts @skip twice will accept it ten thousand
    times, which is the same amplification by another route. Again: we send
    two.
  * QUERIES OVER GET. A query the server accepts in a URL is a query an
    attacker can put in an <img> tag. On its own that is a read; it becomes
    CSRF the moment a mutation is reachable the same way, which we do not
    test because sending a mutation is a write.
  * THE CONSOLE. GraphiQL, Playground, Altair or Voyager served in production
    is an interactive API client handed to anyone who finds the path.
  * THE ENGINE. Error wording identifies the implementation, which is what
    makes a CVE search meaningful. "" when the wording is not distinctive -
    a guessed engine is worse than none.

Nothing here sends a mutation, a batch, or a deep nested query. Those are the
checks that cannot be done without either writing to the target or degrading
it, and this is an authorised-testing tool, not a stress test.
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple

# A field name no schema will have, distinctive enough to find in a response.
NONSENSE_FIELD = "syphaxNoSuchField"
# A near-miss of a field every schema has: a server with suggestions on will
# offer "__typename", which proves the feature without needing a real field.
NEAR_MISS_FIELD = "__typenam"

QUERY_SUGGESTION = "{%s}" % NEAR_MISS_FIELD
QUERY_NONSENSE = "{%s}" % NONSENSE_FIELD
QUERY_TYPENAME = "{__typename}"
# __type instead of __schema: the string a WAF rule usually misses.
QUERY_PARTIAL_INTROSPECTION = '{__type(name:"Query"){name fields{name}}}'
# Two aliases. Two, deliberately - see the module docstring.
QUERY_ALIASES = "{a:__typename b:__typename}"
# Two @skip directives on one field. The spec allows one.
QUERY_DUPLICATE_DIRECTIVE = "{__typename @skip(if:false) @skip(if:false)}"

_SUGGESTION = re.compile(r"did you mean\s*[\"'`]?", re.I)

# Error wording that identifies an implementation. High-confidence only: a
# guessed engine sends an operator looking for the wrong CVEs.
ENGINE_SIGNATURES: List[Tuple[str, str]] = [
    ("graphql_validation_failed", "Apollo Server"),
    ("doesn't exist on type", "graphql-ruby"),
    ("not found in type: 'query_root'", "Hasura"),
    ("query_root", "Hasura"),
    ("validation error of type fieldundefined", "graphql-java"),
    ("unknown field", "Juniper (Rust)"),
    ("expected at least one definition", "gqlgen (Go)"),
    ("syntax error: unexpected <eof>", "graphql-php"),
    ("query does not pass validation", "Sangria (Scala)"),
    ("the query must be a string", "Ariadne (Python)"),
    ("debugmessage", "Lighthouse (Laravel)"),
    ("graphql.error.graphqlerror", "graphql-core (Python)"),
    ("strawberry", "Strawberry (Python)"),
]

# Markers of an interactive console served as HTML.
CONSOLE_MARKERS: List[Tuple[str, str]] = [
    ("graphiql", "GraphiQL"),
    ("graphql-playground", "GraphQL Playground"),
    ("altair", "Altair"),
    ("graphql-voyager", "GraphQL Voyager"),
    ("apollo-server-landing-page", "Apollo landing page"),
    ("__apollo_devtools", "Apollo devtools"),
]


def _errors_of(text: str) -> List[Dict]:
    """The GraphQL `errors` array, or []. Tolerates a non-JSON body."""
    try:
        obj = json.loads(text or "")
    except Exception:  # noqa: BLE001 - an HTML error page has no errors array
        return []
    if not isinstance(obj, dict):
        return []
    errors = obj.get("errors")
    return [e for e in errors if isinstance(e, dict)] if isinstance(errors, list) else []


def error_messages(text: str) -> List[str]:
    out = [str(e.get("message") or "") for e in _errors_of(text)]
    return [m for m in out if m]


def suggests_fields(text: str) -> Tuple[bool, str]:
    """(suggestions on?, the suggestion). Schema disclosure with
    introspection off - the one check that matters most here."""
    for message in error_messages(text):
        if _SUGGESTION.search(message):
            return True, message[:300]
    # Some servers answer with a bare string body rather than the errors array.
    if _SUGGESTION.search(text or ""):
        window = _SUGGESTION.search(text).start()
        return True, (text or "")[max(0, window - 120):window + 180]
    return False, ""


def schema_readable(text: str) -> bool:
    """A full introspection result came back."""
    if "__schema" not in (text or ""):
        return False
    try:
        obj = json.loads(text)
    except Exception:  # noqa: BLE001
        return "queryType" in text
    data = obj.get("data") if isinstance(obj, dict) else None
    return isinstance(data, dict) and isinstance(data.get("__schema"), dict)


def type_readable(text: str) -> Tuple[bool, int]:
    """(did __type answer?, how many field names it named).

    The count is the evidence: "__type returned 48 field names of Query" is a
    statement about disclosure, where "it answered 200" is not.
    """
    try:
        obj = json.loads(text or "")
    except Exception:  # noqa: BLE001
        return False, 0
    data = (obj.get("data") if isinstance(obj, dict) else None) or {}
    node = data.get("__type") if isinstance(data, dict) else None
    if not isinstance(node, dict) or not node.get("name"):
        return False, 0
    fields = node.get("fields")
    return True, len(fields) if isinstance(fields, list) else 0


def aliases_executed(text: str) -> bool:
    """Both aliases of the two-alias query came back with a value."""
    try:
        obj = json.loads(text or "")
    except Exception:  # noqa: BLE001
        return False
    data = (obj.get("data") if isinstance(obj, dict) else None) or {}
    if not isinstance(data, dict):
        return False
    return bool(data.get("a")) and bool(data.get("b"))


def duplicate_directive_accepted(text: str) -> bool:
    """The server ran a field carrying @skip twice. The spec says it must not.

    Accepted means the amplification primitive is there; it does not mean we
    used it.
    """
    try:
        obj = json.loads(text or "")
    except Exception:  # noqa: BLE001
        return False
    if not isinstance(obj, dict):
        return False
    if _errors_of(text):
        return False
    data = obj.get("data")
    return isinstance(data, dict) and bool(data.get("__typename"))


def console_in_response(text: str, content_type: str = "") -> str:
    """The console this HTML page is, or ""."""
    if "html" not in (content_type or "").lower() and "<html" not in (text or "")[:2000].lower():
        return ""
    lowered = (text or "")[:60_000].lower()
    for marker, name in CONSOLE_MARKERS:
        if marker in lowered:
            return name
    return ""


def engine_from(text: str) -> str:
    """The implementation this error wording belongs to, or ""."""
    haystack = " ".join(error_messages(text)) + " " + (text or "")[:4000]
    lowered = haystack.lower()
    for marker, engine in ENGINE_SIGNATURES:
        if marker in lowered:
            return engine
    return ""


def responds_to_graphql(text: str, status: int) -> bool:
    """This endpoint is a GraphQL server, whatever it thought of the query."""
    if "__typename" in (text or "") or _errors_of(text):
        return True
    lowered = (text or "").lower()
    return status in (200, 400, 422) and any(
        sign in lowered for sign in
        ("must provide query", "cannot query field", "graphql",
         "syntax error", "query string", "no query string"))


def worth_reporting(checks: Dict[str, object]) -> bool:
    """Whether anything beyond "an endpoint exists" was established."""
    return any(bool(checks.get(k)) for k in
               ("introspection", "partial_introspection", "suggestions",
                "aliases", "duplicate_directives", "console"))
