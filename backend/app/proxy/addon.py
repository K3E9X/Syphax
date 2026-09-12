"""mitmproxy addon: persist every intercepted flow to Postgres.

Loaded by `mitmdump -s` in entrypoint.sh. Runs in the mitmproxy process,
not inside FastAPI, so it uses synchronous psycopg.

Configuration is taken from environment:
  - DATABASE_URL : same Postgres the FastAPI process uses.

Optional flow filtering is done by mitmproxy itself via CLI flags
(see entrypoint.sh, e.g. `--allow-hosts '^(?!.*localhost)'`).
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from typing import List, Tuple

from mitmproxy import http

from app.proxy.storage import init_schema_sync, insert_flow_sync

logger = logging.getLogger("syphax.proxy.addon")

# Max body bytes we store. Above this we truncate (users can re-fetch from the
# target if they need the full payload; we are a pentest bench, not an archive).
MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB


class FlowLogger:
    def __init__(self) -> None:
        # Make sure the schema exists. The FastAPI process also runs init_db()
        # at startup, but mitmdump can come up first; this keeps us safe.
        try:
            init_schema_sync()
        except Exception:  # noqa: BLE001
            logger.exception("schema bootstrap failed; will retry per-flow")
        logger.info("FlowLogger ready (writing to Postgres)")

    def response(self, flow: http.HTTPFlow) -> None:
        """Called by mitmproxy once the response is complete."""
        try:
            self._persist(flow)
        except Exception:  # noqa: BLE001 - never crash the proxy
            logger.exception("Failed to persist flow %s", flow.id)

    def error(self, flow: http.HTTPFlow) -> None:
        """Called when a flow fails: connection reset, timeout, TLS failure.

        Persistence used to happen only in response(), so a request that made
        the target drop the connection left no row at all - which on a pentest
        is precisely the request worth looking at. The row is stored with no
        response; the tag carries the reason.
        """
        try:
            self._persist(flow, error=str(getattr(flow, "error", "") or "failed"))
        except Exception:  # noqa: BLE001 - never crash the proxy
            logger.exception("Failed to persist failed flow %s", flow.id)

    def _persist(self, flow: http.HTTPFlow, error: str = "") -> None:
        req = flow.request
        resp = flow.response

        request_headers = _headers_to_list(req.headers)
        request_body = _truncate(req.raw_content or b"")

        if resp is not None:
            response_headers = _headers_to_list(resp.headers)
            response_body = _truncate(resp.raw_content or b"")
            response_status = resp.status_code
            response_ct = resp.headers.get("content-type")
            response_size = len(resp.raw_content or b"")
            duration_ms = (
                int((resp.timestamp_end - req.timestamp_start) * 1000)
                if resp.timestamp_end and req.timestamp_start
                else None
            )
        else:
            response_headers = []
            response_body = None
            response_status = None
            response_ct = None
            response_size = None
            duration_ms = None

        row = {
            "id": flow.id or str(uuid.uuid4()),
            "timestamp": req.timestamp_start or time.time(),
            "duration_ms": duration_ms,
            "method": req.method,
            "scheme": req.scheme,
            "host": req.pretty_host,
            "port": req.port,
            "path": req.path,
            "url": req.pretty_url,
            "request_headers_json": json.dumps(request_headers),
            "request_body": request_body,
            "request_content_type": req.headers.get("content-type"),
            "request_size": len(req.raw_content or b""),
            "status_code": response_status,
            "response_headers_json": json.dumps(response_headers),
            "response_body": response_body,
            "response_content_type": response_ct,
            "response_size": response_size,
            "tag": ("error:" + error[:120]) if error else None,
        }

        insert_flow_sync(row)


def _headers_to_list(headers) -> List[Tuple[str, str]]:
    """mitmproxy headers preserve order and can repeat keys; keep that."""
    return [[name, value] for name, value in headers.items(multi=True)]


def _truncate(body: bytes) -> bytes:
    if len(body) <= MAX_BODY_BYTES:
        return body
    return body[:MAX_BODY_BYTES]


addons = [FlowLogger()]
