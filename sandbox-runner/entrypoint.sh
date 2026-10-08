#!/usr/bin/env bash
# Build the egress jail, then serve. The PoC is what gets dropped to an
# unprivileged user - not this process.
#
# WHY THE PRIVILEGE SPLIT CHANGED
#
# This script used to resolve SANDBOX_ALLOWED_HOSTS at boot, append a REJECT,
# and then `exec gosu poc uvicorn`. Two things were wrong with that:
#
#   1. SANDBOX_ALLOWED_HOSTS is empty in every normal install. Nothing in the
#      backend ever set it, docker-compose defaults it to "", the k3s manifest
#      hardcodes "", and .env.example never mentioned it. Empty means deny all,
#      so every PoC got icmp-port-unreachable on its first request, exited
#      non-zero, and the operator was told the exploit had failed - when what
#      had actually failed was the firewall.
#   2. A boot-time allowlist cannot work here even when it is set. The scope is
#      per engagement and is usually a wildcard like *.example.com, which has
#      no address to resolve at boot. The scope_hosts the backend sent with
#      each request were decorative.
#
# So the allowlist is now applied PER REQUEST, from the scope the backend
# sends, into the SYPHAX_EGRESS chain. Applying it needs CAP_NET_ADMIN, which
# means the HTTP server has to keep it - and that is safe only if the PoC
# cannot reach that server. Hence:
#
#   * uvicorn runs as root and holds NET_ADMIN.
#   * each PoC is spawned through `gosu poc`, so it holds nothing.
#   * rule 1 below rejects any packet to the control port that comes from the
#     poc uid, on every interface including loopback. Without it, a PoC could
#     POST to the runner and ask for its own allowlist.
#   * SANDBOX_TOKEN, when set, is required on /v1/run and is never placed in
#     the PoC's environment.
#
# SANDBOX_ALLOWED_HOSTS still works and is still honoured, as a permanent pin
# applied on top of the per-request one. It is now optional rather than the
# only thing standing between the PoC and the internet.
set -euo pipefail

ALLOWED="${SANDBOX_ALLOWED_HOSTS:-}"
PORT="${SANDBOX_PORT:-8090}"
POC_USER="${SANDBOX_POC_USER:-poc}"

# Refusing to start is the correct answer to "I cannot enforce egress" - a
# sandbox that runs untrusted code without a policy is worse than no sandbox.
# But the operator only ever saw the UI say "runner unavailable", so say here,
# in the container log, exactly which step failed and what it usually means.
die() {
  echo "[sandbox] FATAL: $1" >&2
  echo "[sandbox] the runner refuses to start without an egress policy:" >&2
  echo "[sandbox]   untrusted PoC code would run with unrestricted network." >&2
  echo "[sandbox] check 'docker compose logs sandbox-runner' for the line above." >&2
  exit 1
}

if ! command -v iptables >/dev/null 2>&1; then
  die "iptables is not installed in this image"
fi
if ! command -v gosu >/dev/null 2>&1; then
  die "gosu is not installed in this image - the PoC could not be de-privileged"
fi
if ! id "$POC_USER" >/dev/null 2>&1; then
  die "the unprivileged user '$POC_USER' does not exist in this image"
fi

echo "[sandbox] applying egress policy"

# The first rule is also the probe: if the kernel backing this container has no
# nf_tables (Docker Desktop's LinuxKit VM is the common case) or the container
# was started without NET_ADMIN, it fails here rather than halfway through a
# half-applied policy.
if ! iptables -F OUTPUT 2>/tmp/iptables.err; then
  echo "[sandbox] iptables said: $(cat /tmp/iptables.err)" >&2
  die "cannot write firewall rules. Either the container lacks NET_ADMIN \
(check cap_add in docker-compose.yml) or this kernel has no nf_tables support \
- which is the usual case on Docker Desktop for Mac and Windows."
fi

# Two chains, both jumped to from OUTPUT:
#   SYPHAX_EGRESS      - rewritten by runner.py for each request. Empty at rest,
#                        so a container sitting idle still denies everything.
#   SYPHAX_EGRESS_PIN  - written once, here, from SANDBOX_ALLOWED_HOSTS. Never
#                        touched again, so a per-request flush cannot drop it.
for chain in SYPHAX_EGRESS SYPHAX_EGRESS_PIN; do
  iptables -N "$chain" 2>/dev/null || iptables -F "$chain"
done

# Rule 1, and it has to be first: the PoC must never reach the control port.
# uvicorn keeps NET_ADMIN so that it can set the allowlist; a PoC that could
# talk to it could set its own. `-m owner` is OUTPUT-only, which is exactly
# where we need it. Fail closed if the match is unavailable.
if ! iptables -A OUTPUT -p tcp --dport "$PORT" \
        -m owner --uid-owner "$POC_USER" -j REJECT 2>/tmp/owner.err; then
  echo "[sandbox] iptables said: $(cat /tmp/owner.err)" >&2
  # Two controls stand between a PoC and the control port: this rule, and the
  # token on /v1/run. Refusing to boot without the rule when a token IS set
  # would trade "a PoC might reach the port it cannot authenticate to" for "no
  # sandbox at all, so nothing can ever be proven" - the worse of the two.
  # With no token, there is nothing left, so we do refuse.
  if [ -n "${SANDBOX_RUNNER_TOKEN:-}" ]; then
    echo "[sandbox] WARNING: the 'owner' match is unavailable (xt_owner is not" >&2
    echo "[sandbox]   loadable on this kernel). A PoC could reach the control" >&2
    echo "[sandbox]   port; SANDBOX_RUNNER_TOKEN is set, so it still cannot" >&2
    echo "[sandbox]   drive it. Continuing with the token as the only control." >&2
  else
    die "the 'owner' match is unavailable (xt_owner), so a PoC could reach the \
runner's control port and widen its own egress allowlist - and no \
SANDBOX_RUNNER_TOKEN is set, so nothing else would stop it. Set one (install.sh \
generates it) and restart."
  fi
fi

iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS to this container's own resolvers only, so a PoC cannot use an arbitrary
# resolver as a covert channel. Read from resolv.conf rather than hardcoding
# Docker's 127.0.0.11, because under k3s it is a cluster address.
# `|| true`: under `set -euo pipefail` a failing awk (no /etc/resolv.conf, or
# an unreadable one) fails the pipeline, fails the assignment, and kills the
# script - crash-looping the container over a missing file we handle two lines
# below anyway.
RESOLVERS="$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u || true)"
if [ -z "$RESOLVERS" ]; then
  echo "[sandbox]   WARNING: no nameserver in /etc/resolv.conf; DNS will fail" >&2
else
  for ns in $RESOLVERS; do
    case "$ns" in
      *:*) continue ;;  # v6 resolver, handled by the ip6tables block below
    esac
    iptables -A OUTPUT -p udp --dport 53 -d "$ns" -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 53 -d "$ns" -j ACCEPT
    echo "[sandbox]   allow DNS -> $ns"
  done
fi

# The backend reaches us; we never need to reach it. No rule for it on purpose.
iptables -A OUTPUT -j SYPHAX_EGRESS_PIN
iptables -A OUTPUT -j SYPHAX_EGRESS

if [ -n "$ALLOWED" ]; then
  IFS=',' read -ra HOSTS <<< "$ALLOWED"
  for h in "${HOSTS[@]}"; do
    h="$(echo "$h" | xargs)"
    [ -z "$h" ] && continue
    # Resolve now, while we still can, and pin the addresses. Resolving later
    # would let a rebinding trick point the allowlisted name somewhere else.
    for ip in $(getent ahostsv4 "$h" 2>/dev/null | awk '{print $1}' | sort -u); do
      iptables -A SYPHAX_EGRESS_PIN -d "$ip" -j ACCEPT
      echo "[sandbox]   pin $h -> $ip"
    done
  done
else
  echo "[sandbox]   no SANDBOX_ALLOWED_HOSTS pin: the per-request allowlist is"
  echo "[sandbox]   the only one, which is the normal and intended setup."
fi

iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable

# IPv6. Previously unconfigured, which meant that on any host with working v6
# the whole policy above could be walked around by using a v6 literal or a
# AAAA record. Deny it the same way, with the same two chains.
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L OUTPUT >/dev/null 2>&1; then
  ip6tables -F OUTPUT
  for chain in SYPHAX_EGRESS SYPHAX_EGRESS_PIN; do
    ip6tables -N "$chain" 2>/dev/null || ip6tables -F "$chain"
  done
  ip6tables -A OUTPUT -p tcp --dport "$PORT" \
      -m owner --uid-owner "$POC_USER" -j REJECT || true
  ip6tables -A OUTPUT -o lo -j ACCEPT
  ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  for ns in $RESOLVERS; do
    case "$ns" in
      *:*) ip6tables -A OUTPUT -p udp --dport 53 -d "$ns" -j ACCEPT
           ip6tables -A OUTPUT -p tcp --dport 53 -d "$ns" -j ACCEPT ;;
    esac
  done
  ip6tables -A OUTPUT -j SYPHAX_EGRESS_PIN
  ip6tables -A OUTPUT -j SYPHAX_EGRESS
  ip6tables -A OUTPUT -j REJECT
  echo "[sandbox]   IPv6 egress denied by default"
  echo "per-request" > /run/egress.v6
else
  echo "[sandbox]   no usable ip6tables; assuming no IPv6 stack"
fi

# Markers the /health endpoint reports, so the backend can tell a runner that
# applies the scope per request from one that was built before this change and
# would silently deny everything.
mkdir -p /run
touch /run/egress.locked
echo "per-request" > /run/egress.mode

echo "[sandbox] egress jail ready; serving as root, PoCs run as '$POC_USER'"
exec "$@"
