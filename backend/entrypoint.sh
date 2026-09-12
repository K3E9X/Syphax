#!/usr/bin/env bash
# Container entrypoint: run mitmdump and uvicorn side by side.
#
# mitmdump listens on 0.0.0.0:${MITM_PORT} and loads app/proxy/addon.py,
# which writes each intercepted flow to /data/syphax.db.
# uvicorn serves the FastAPI app on 0.0.0.0:8000.
#
# Both processes share /data (mounted from the host). If either process dies
# the container exits so Docker restarts it.

set -euo pipefail

MITM_PORT="${MITM_PORT:-8080}"
DATA_DIR="${DATA_DIR:-/data}"
MITM_CONFDIR="${DATA_DIR}/mitm"

mkdir -p "${MITM_CONFDIR}"

echo "[entrypoint] starting mitmdump on 0.0.0.0:${MITM_PORT}"
echo "[entrypoint] mitm confdir: ${MITM_CONFDIR}"
echo "[entrypoint] sqlite db:    ${DATA_DIR}/syphax.db"

# PYTHONPATH lets the addon import app.proxy.storage.
export PYTHONPATH="/app:${PYTHONPATH:-}"
export DATA_DIR

mitmdump \
    --listen-host 0.0.0.0 \
    --listen-port "${MITM_PORT}" \
    --set confdir="${MITM_CONFDIR}" \
    --quiet \
    -s /app/app/proxy/addon.py \
    &
MITM_PID=$!
echo "[entrypoint] mitmdump pid=${MITM_PID}"

# Make sure mitmdump is killed if uvicorn exits.
trap 'kill ${MITM_PID} 2>/dev/null || true' EXIT

# Exec uvicorn as PID 1 replacement so signals are handled cleanly.
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
