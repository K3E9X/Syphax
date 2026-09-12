#!/usr/bin/env bash
# mitmproxy entrypoint. Loads app/proxy/addon.py, which writes every
# intercepted flow to Postgres (app.proxy.storage).
#
# Its own container: mitmproxy pins cryptography<44.1, and while it shared an
# environment with the API that pin applied to the whole stack.
set -euo pipefail

MITM_PORT="${MITM_PORT:-8080}"
export DATA_DIR="${DATA_DIR:-/data}"
MITM_CONFDIR="${DATA_DIR}/mitm"
mkdir -p "${MITM_CONFDIR}"

# Lets the addon import app.proxy.storage.
export PYTHONPATH="/app:${PYTHONPATH:-}"

echo "[proxy] mitmdump on 0.0.0.0:${MITM_PORT} (confdir ${MITM_CONFDIR})"
exec mitmdump \
    --listen-host 0.0.0.0 \
    --listen-port "${MITM_PORT}" \
    --set confdir="${MITM_CONFDIR}" \
    --quiet \
    -s /app/app/proxy/addon.py
