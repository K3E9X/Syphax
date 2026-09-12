#!/usr/bin/env bash
# API entrypoint. mitmdump used to run alongside uvicorn here; it now has its
# own container (entrypoint-proxy.sh) so mitmproxy's cryptography pin stops
# constraining the API's dependency set.
set -euo pipefail

export DATA_DIR="${DATA_DIR:-/data}"
mkdir -p "${DATA_DIR}"

echo "[entrypoint] starting uvicorn on 0.0.0.0:8000"
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
