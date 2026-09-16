#!/usr/bin/env bash
# install.sh - prepare a host to run Syphax.
#
# Targets a laptop (macOS, Linux, WSL2) and a headless VM equally. The
# difference between the two is one flag:
#
#   ./install.sh                     UI on 127.0.0.1 only - a laptop
#   ./install.sh --bind 0.0.0.0      UI on every interface - a VM you reach
#                                    over the network
#
# What it does:
#   1. Check Docker, Compose, disk and the TUN device.
#   2. Create .env, and GENERATE the secrets in it - the database password and
#      the at-rest key for the stored provider keys. Shipping a default for
#      either is how an install ends up with POSTGRES_PASSWORD=syphax on a
#      public interface.
#   3. Create ./data.
#   4. Build the images.
#
# Unattended (a VM built by a provisioning script):
#   ./install.sh --yes --bind 0.0.0.0 \
#       --admin-user operator --admin-password "$(cat /run/secrets/pw)"
#
# The operator account is otherwise created on first use, in the browser: the
# tool does not start without one, and there is no flag that disables that.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARNING: %s\n' "$*" >&2; }
fail() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

ASSUME_YES=0
BIND_ADDRESS=""
PROXY_BIND_ADDRESS=""
ADMIN_USER=""
ADMIN_PASSWORD=""
SKIP_BUILD=0

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'USAGE'

Options:
  --yes, -y                 no prompts
  --bind ADDR               interface for the UI and API (default 127.0.0.1)
  --proxy-bind ADDR         interface for the mitmproxy port (default 127.0.0.1)
  --admin-user NAME         seed the operator account without a browser
  --admin-password PASS     ...its password (at least 12 characters)
  --skip-build              set up .env and ./data, do not build images
  --help, -h                this text
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --yes|-y)         ASSUME_YES=1 ;;
        --bind)           BIND_ADDRESS="${2:-}"; shift ;;
        --proxy-bind)     PROXY_BIND_ADDRESS="${2:-}"; shift ;;
        --admin-user)     ADMIN_USER="${2:-}"; shift ;;
        --admin-password) ADMIN_PASSWORD="${2:-}"; shift ;;
        --skip-build)     SKIP_BUILD=1 ;;
        --help|-h)        usage; exit 0 ;;
        *) fail "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# ---- host checks ------------------------------------------------------------

case "$(uname -s)" in
    Linux*)  OS="linux"  ;;
    Darwin*) OS="macos"  ;;
    *)       fail "Unsupported OS. Supported: Linux, macOS, Windows via WSL2." ;;
esac
log "Host: ${OS} ($(uname -m))"

if [ "$OS" = "linux" ] && grep -qiE "microsoft|wsl" /proc/version 2>/dev/null; then
    log "Running under WSL2 - Docker must be reachable from inside this distro."
fi

COMPOSE_CMD=""

# With --skip-build this script only writes .env and ./data, so it must run on a
# host where Docker is not installed yet - the usual order in a provisioning
# script is "lay down the config, then install the runtime". Checking for a
# daemon there would fail the step that has nothing to do with the daemon.
if [ "$SKIP_BUILD" = "1" ]; then
    log "Configuration only (--skip-build); not checking for Docker."
else
    if ! command -v docker >/dev/null 2>&1; then
        if [ "$OS" = "macos" ]; then
            fail "Docker not found. Install Docker Desktop or OrbStack, then re-run."
        fi
        fail "Docker not found. Install with: curl -fsSL https://get.docker.com | sh"
    fi
    docker info >/dev/null 2>&1 || fail "The Docker daemon is not running. Start it and re-run."

    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD="docker-compose"
    else
        fail "Docker Compose v2 not found."
    fi
    log "Compose: ${COMPOSE_CMD}"

    # The image carries every scanner binary; a VM sized for "a small web app"
    # runs out mid-build and the error it prints is about a layer, not disk.
    avail_gb="$(df -Pk . | awk 'NR==2 {printf "%d", $4/1024/1024}')"
    if [ "${avail_gb:-0}" -lt 12 ]; then
        warn "only ${avail_gb}GB free here; the image needs roughly 12GB to build."
    fi
fi

# WireGuard/OpenVPN need this to create the tunnel interface. Absent, wg-quick
# fails with "Cannot find device", which reads like a missing binary.
if [ ! -e /dev/net/tun ] && [ "$OS" = "linux" ]; then
    warn "/dev/net/tun is missing. The VPN endpoints will fail until the host"
    warn "loads the tun module (modprobe tun). Everything else works."
fi

# ---- secrets ----------------------------------------------------------------

# openssl is not guaranteed on a minimal VM image; /dev/urandom is.
random_hex() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex "${1:-24}"
    else
        head -c "$(( ${1:-24} * 2 ))" /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c "1-$(( ${1:-24} * 2 ))"
    fi
}

# Replace KEY=<empty-or-default> with a generated value, in place, without
# touching the comments around it.
set_env() {
    local key="$1" value="$2"
    if grep -qE "^${key}=" .env; then
        # A literal | in a generated secret would break the sed expression;
        # hex and base64url never contain one, which is why both are used.
        sed -i.bak -E "s|^${key}=.*|${key}=${value}|" .env && rm -f .env.bak
    else
        printf '%s=%s\n' "$key" "$value" >> .env
    fi
}

current_env() {
    grep -E "^$1=" .env 2>/dev/null | head -1 | cut -d= -f2- || true
}

if [ ! -f .env ]; then
    [ -f .env.example ] || fail ".env.example not found."
    cp .env.example .env
    log "Created .env"
    FRESH_ENV=1
else
    log ".env exists - keeping it, filling only what is empty or still a default."
    FRESH_ENV=0
fi

# The database password. The example ships "syphax" so that a first-time reader
# can see the shape; leaving it is fine on loopback and indefensible anywhere
# else, so it is replaced on every fresh install.
if [ "$(current_env POSTGRES_PASSWORD)" = "syphax" ] || [ -z "$(current_env POSTGRES_PASSWORD)" ]; then
    if [ "$FRESH_ENV" = "1" ]; then
        set_env POSTGRES_PASSWORD "$(random_hex 24)"
        log "Generated POSTGRES_PASSWORD"
    else
        warn "POSTGRES_PASSWORD is still the default. Change it, then:"
        warn "  docker compose down -v   (this DELETES the database)"
    fi
fi

# The at-rest key for the stored provider API keys. Without a fixed value the
# backend mints one into ./data on first start - which works until ./data is
# not durable, and then every stored key silently stops decrypting.
if [ -z "$(current_env SYPHAX_SECRET_KEY)" ]; then
    if command -v openssl >/dev/null 2>&1; then
        secret="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
    else
        secret="$(random_hex 32)"
    fi
    set_env SYPHAX_SECRET_KEY "$secret"
    log "Generated SYPHAX_SECRET_KEY"
fi

# Written as `if`, not `[ ... ] && { ... }`: under `set -e` a false test on the
# last line of that form exits the script, which would end the install silently
# whenever --bind was not passed.
if [ -n "$BIND_ADDRESS" ]; then
    set_env BIND_ADDRESS "$BIND_ADDRESS"
    log "UI/API bind: ${BIND_ADDRESS}"
fi
if [ -n "$PROXY_BIND_ADDRESS" ]; then
    set_env PROXY_BIND_ADDRESS "$PROXY_BIND_ADDRESS"
    log "Proxy bind: ${PROXY_BIND_ADDRESS}"
fi

if [ -n "$ADMIN_USER" ] || [ -n "$ADMIN_PASSWORD" ]; then
    if [ -z "$ADMIN_USER" ] || [ -z "$ADMIN_PASSWORD" ]; then
        fail "--admin-user and --admin-password go together."
    fi
    if [ "${#ADMIN_PASSWORD}" -lt 12 ]; then
        fail "--admin-password must be at least 12 characters."
    fi
    set_env SYPHAX_ADMIN_USER "$ADMIN_USER"
    set_env SYPHAX_ADMIN_PASSWORD "$ADMIN_PASSWORD"
    log "Operator account '${ADMIN_USER}' will be created on first start."
    warn "That password is now in .env in plaintext. Remove the two"
    warn "SYPHAX_ADMIN_* lines once the account exists; they are ignored"
    warn "from then on anyway."
fi

chmod 600 .env 2>/dev/null || true

# ---- exposure warning -------------------------------------------------------

effective_bind="$(current_env BIND_ADDRESS)"
effective_proxy="$(current_env PROXY_BIND_ADDRESS)"

if [ "$effective_bind" != "127.0.0.1" ] && [ -n "$effective_bind" ]; then
    printf '\n'
    warn "The UI and API will listen on ${effective_bind}."
    warn "There is no TLS in this stack. Put a reverse proxy with a"
    warn "certificate in front of it, or restrict the port with a firewall."
    warn "The login page protects the API; it does not encrypt it, and a"
    warn "password sent over plain HTTP is a password on the wire."
    if [ "$ASSUME_YES" != "1" ]; then
        printf '[install] Continue? [y/N] '
        read -r reply
        case "$reply" in [yY]*) ;; *) fail "Stopped. Re-run without --bind for a loopback install." ;; esac
    fi
fi

if [ -n "$effective_proxy" ] && [ "$effective_proxy" != "127.0.0.1" ]; then
    warn "PROXY_BIND_ADDRESS is ${effective_proxy}: port 8080 is an"
    warn "unauthenticated HTTPS-intercepting proxy. Anyone who can reach it"
    warn "can relay through it. Only do this on a network you control."
fi

mkdir -p ./data
log "Data directory: ./data"

# ---- build ------------------------------------------------------------------

if [ "$SKIP_BUILD" = "1" ]; then
    log "Skipping the image build (--skip-build)."
else
    log "Building images. The backend carries ~20 scanner binaries, so the"
    log "first build takes several minutes."
    $COMPOSE_CMD build
fi

printf '\n'
log "Done. Next:"
log "  ./start.sh"
if [ -n "$ADMIN_USER" ]; then
    log "  then sign in as '${ADMIN_USER}'."
else
    log "  then open the UI and create the operator account. The tool does not"
    log "  run without one."
fi
log "  Then connect a model - the UI asks before it lets you do anything else."
