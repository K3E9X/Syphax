"""A deliberately weak API, so the analysers can be checked against traffic.

Every flaw is one a module in app/analysis claims to find. Nothing is subtle:
the point is to prove the detection fires at all, which no unit test can -
they exercise the pure half, and every "it found nothing" so far has been in
the other half.

Served on localhost only, by tests/live/test_the_api_suite_finds_things.py.
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

NOTES: dict = {}
NEXT_ID = {"n": 4820}

SCHEMA_FIELDS = ["me", "users", "notes", "adminAuditLog", "resetPassword"]

# The published contract, with several documented weaknesses.
SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Weak API", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:8899"}],            # plaintext
    "components": {"securitySchemes": {
        "basic": {"type": "http", "scheme": "basic"},          # weak
        "qkey": {"type": "apiKey", "in": "query", "name": "token"},  # weak
    }},
    "security": [{"basic": []}],
    "paths": {
        "/api/v2/users/{userId}": {"get": {
            "parameters": [{"name": "userId", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/api/v1/users/{userId}": {"get": {
            "security": [],                                     # opt-out
            "parameters": [{"name": "userId", "in": "path", "required": True,
                            "schema": {"type": "string"}}],
            "responses": {"200": {"description": "ok"}}}},
        "/api/notes": {"post": {
            "security": [],
            "requestBody": {"content": {"application/json": {"schema": {
                "type": "object",
                "properties": {"title": {"type": "string"}}}}}},  # open body
            "responses": {"201": {"description": "created"}}}},
        "/api/items": {"get": {
            "parameters": [{"name": n, "in": "query",
                            "schema": {"type": "string"}}
                           for n in ("q", "sort", "from", "to", "tag", "ref")],
            "responses": {"200": {"description": "ok"}}}},       # no 429
    },
}


@app.get("/")
def home():
    return HTMLResponse("<html><body><h1>Weak</h1></body></html>")


@app.get("/openapi.json")
def spec():
    return JSONResponse(SPEC)


@app.get("/api/v2/users/{user_id}")
def v2_user(user_id: str):
    """The current version: authenticated."""
    return JSONResponse({"error": "authentication required"}, status_code=401)


@app.get("/api/v1/users/{user_id}")
def v1_user(user_id: str):
    """The forgotten one: same route, no authentication."""
    return {"id": user_id, "email": f"user{user_id}@example.test"}


@app.get("/api/internal/users/{user_id}")
def internal_user(user_id: str):
    return {"id": user_id, "internal": True}


@app.get("/api/items")
def items(q: str = "", page: int = 1):
    """No throttling and no rate-limit headers."""
    return {"items": [{"id": i} for i in range(5)], "page": page, "q": q}


@app.post("/api/notes")
async def create_note(request: Request):
    """Binds whatever it is given and echoes it back: mass assignment."""
    body = await request.json()
    NEXT_ID["n"] += 1
    note = {"id": NEXT_ID["n"], **body}
    NOTES[str(NEXT_ID["n"])] = note
    return JSONResponse(note, status_code=201)


@app.get("/api/notes/{note_id}")
def read_note(note_id: str):
    """No authorisation: anyone may read any note, ours or not."""
    note = NOTES.get(note_id)
    if note is None:
        return {"id": note_id, "title": "someone else's note", "owner": "sofia"}
    return note


@app.get("/graphql")
async def graphql(request: Request):
    """Most specific branch first. A real server parses; matching substrings
    loosely made this target answer the wrong thing twice while it was being
    written, which is its own small lesson about ordering."""
    accept = request.headers.get("accept", "")
    query = (request.query_params.get("query") or "").replace(" ", "")
    if not query:
        if "text/html" in accept:
            return HTMLResponse(
                "<html><head><title>GraphiQL</title></head><body>"
                "<div id='graphiql'>Loading GraphiQL...</div></body></html>")
        return JSONResponse(
            {"errors": [{"message": "Must provide query string"}]},
            status_code=400)
    if "a:__typename" in query:                      # alias overloading
        return {"data": {"a": "Query", "b": "Query"}}
    if "@skip" in query:                             # duplicate directives
        return {"data": {"__typename": "Query"}}
    if "__typenam}" in query or "__typenam)" in query:
        return JSONResponse({"errors": [{
            "message": 'Cannot query field "__typenam" on type "Query". '
                       'Did you mean "__typename"?',
            "extensions": {"code": "GRAPHQL_VALIDATION_FAILED"}}]},
            status_code=400)
    if "__schema" in query:
        return {"data": {"__schema": {
            "queryType": {"name": "Query"},
            "types": [{"name": "Query", "kind": "OBJECT"},
                      {"name": "User", "kind": "OBJECT"}]}}}
    if "__type(" in query:
        return {"data": {"__type": {
            "name": "Query",
            "fields": [{"name": f} for f in SCHEMA_FIELDS]}}}
    if "__typename" in query:
        return {"data": {"__typename": "Query"}}
    return JSONResponse({"errors": [{"message": "Must provide query string"}]},
                        status_code=400)
