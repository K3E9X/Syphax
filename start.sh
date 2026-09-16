#!/usr/bin/env bash
# start.sh - start the stack in the background and print access info.
#
# Usage:
#   ./start.sh            # start detached
#   ./start.sh --logs     # start detached and follow logs
#   ./start.sh stop       # stop and remove containers
#   ./start.sh restart    # restart cleanly

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { printf '[start] %s\n' "$*"; }
fail() { printf '[start] ERROR: %s\n' "$*" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    fail "Docker Compose not found. Run ./install.sh first."
fi

if [ ! -f .env ]; then
    fail ".env not found. Run ./install.sh first."
fi

case "${1:-up}" in
    stop)
        log "Stopping stack..."
        $COMPOSE_CMD down
        exit 0
        ;;
    restart)
        log "Restarting stack..."
        $COMPOSE_CMD down
        $COMPOSE_CMD up -d
        ;;
    up|--logs|"")
        log "Starting stack..."
        $COMPOSE_CMD up -d
        ;;
    *)
        fail "Unknown command: ${1}. Use: up | stop | restart | --logs"
        ;;
esac

# Print the address the stack is actually reachable on. "localhost" is a lie on
# a VM the operator reached over SSH, and it is the line they copy.
bind="$(grep -E '^BIND_ADDRESS=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)"
proxy_bind="$(grep -E '^PROXY_BIND_ADDRESS=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)"
host="${bind:-127.0.0.1}"
if [ "$host" = "0.0.0.0" ] || [ -z "$host" ]; then
    host="$(hostname -I 2>/dev/null | awk '{print $1}')"
    [ -n "$host" ] || host="<this host>"
fi

printf '\n'
log "Stack is up."
log "  UI:         http://${host}:3000"
log "  API:        http://${host}:8000"
log "  API docs:   http://${host}:8000/docs"
if [ "${proxy_bind:-127.0.0.1}" = "127.0.0.1" ]; then
    log "  MITM proxy: http://127.0.0.1:8080  (loopback only; see PROXY_BIND_ADDRESS)"
else
    log "  MITM proxy: http://${proxy_bind}:8080  (set as your browser HTTP/HTTPS proxy)"
fi
log ""
log "First run: create the operator account, then connect a model. The tool"
log "does not start a run without either."
printf '\n'

if [ "${1:-}" = "--logs" ]; then
    log "Following logs (Ctrl+C to detach, stack keeps running)..."
    $COMPOSE_CMD logs -f
fi
