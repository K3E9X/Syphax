"""GraphQL discovery + introspection detection helpers.

The two renamed helpers moved to app.analysis.graphql_probes when the suite
grew past introspection: `schema_readable` and `responds_to_graphql` are the
same questions under names that say which one they answer.
"""
import json

from app.analysis.graphql import _is_graphql_path, _with_query
from app.analysis.graphql_probes import (responds_to_graphql as _looks_like_graphql,
                                         schema_readable as _introspection_ok)


def test_is_graphql_path():
    assert _is_graphql_path("https://t/graphql")
    assert _is_graphql_path("https://t/api/graphql")
    assert _is_graphql_path("https://t/v1/graphql/")
    assert not _is_graphql_path("https://t/api/users")


def test_with_query_encodes():
    u = _with_query("https://t/graphql", "{__typename}")
    assert u.startswith("https://t/graphql?query=")
    assert "%7B__typename%7D" in u  # { } encoded


def test_introspection_ok_true():
    body = json.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}})
    assert _introspection_ok(body)


def test_introspection_ok_false_on_error():
    body = json.dumps({"errors": [{"message": "introspection disabled"}]})
    assert not _introspection_ok(body)


def test_introspection_ok_handles_truncated_schema():
    # Schema-shaped but not valid JSON (truncated capture) still counts.
    assert _introspection_ok('{"data":{"__schema":{"queryType":{"name":"Que')


def test_looks_like_graphql():
    assert _looks_like_graphql('{"errors":[{"message":"Must provide query string"}]}', 400)
    assert _looks_like_graphql("Cannot query field x on type Y", 400)
    assert not _looks_like_graphql('{"users":[]}', 200)
