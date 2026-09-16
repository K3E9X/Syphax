# Syphax

[![CI](https://github.com/K3E9X/Syphax/actions/workflows/ci.yml/badge.svg)](https://github.com/K3E9X/Syphax/actions/workflows/ci.yml)

An autonomous web-application penetration tester you self-host. You authorize a
target, the agent walks an OWASP-WSTG × MITRE-ATT&CK methodology end to end,
every finding is confirmed with a **safe** proof-of-exploit, findings are linked
into kill-chains, and you ship a client report.

It orchestrates mature CLI tools — nuclei, sqlmap, ffuf, dalfox, nmap and a
dozen more — rather than reinventing scanners, and uses an LLM to plan, reorder
and judge. The methodology engine underneath is deterministic, but the model is
**required**: it decides what to do next, reads what the tools said, and
confirms or kills every finding. A run without one is a scanner printing raw
output, so the tool refuses to start one.

> For authorized testing only. Use it on systems you own or have written
> permission to test.

---

## Quick start

**Requirements:** Docker with the Compose plugin. Nothing else — no Python, no
Node, no tools to install on the host.

| Host | Notes |
| --- | --- |
| Linux | `docker-ce` + `docker-compose-plugin` |
| macOS (Intel or Apple Silicon) | Docker Desktop or OrbStack |
| Windows | Inside **WSL2** — clone into the WSL filesystem, not `/mnt/c` |

Images are multi-arch (`amd64` + `arm64`); every Python pin ships an aarch64
wheel, so Apple Silicon needs no compiler.

```bash
git clone https://github.com/K3E9X/Syphax && cd Syphax

./install.sh               # writes .env, generates its secrets, builds images
./start.sh                 # `docker compose up -d`  (also: stop | restart | --logs)
```

`install.sh` creates `.env` from the example and **generates** the database
password and the at-rest encryption key — it does not leave you a default to
forget about. Then open the UI: it asks you to create the operator account and
connect a model, in that order, and will not do anything else until both exist.

On a VM you reach over the network:

```bash
./install.sh --bind 0.0.0.0
```

That publishes the UI and API on every interface and says, loudly, that there
is no TLS in this stack — put a reverse proxy with a certificate in front of it.
The mitmproxy port has its own variable (`PROXY_BIND_ADDRESS`) and stays on
loopback: it is an unauthenticated intercepting proxy with a trusted CA behind
it, and publishing it as a side effect of wanting the UI reachable would be an
open relay.

Fully unattended, from a provisioning script:

```bash
./install.sh --yes --bind 0.0.0.0 \
    --admin-user operator --admin-password "$(cat /run/secrets/syphax-admin)"
```

| Service | URL |
| --- | --- |
| UI | http://localhost:3000 |
| API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |
| MITM proxy | http://localhost:8080 (loopback only by default) |

### Signing in

There is no anonymous mode and no variable that disables the login. The first
visit creates the account; after that it is a password, an 8-hour session in an
httpOnly cookie, and a throttled login form. `SYPHAX_API_KEY` remains available
as a machine credential for scripts and CI — an alternative to a session, not a
way to skip having one.

### What to put in `.env`

`install.sh` fills in what must not be left at a default. Two things are worth
setting by hand:

```bash
# 1. Cost. WITHOUT THIS the dashboard shows real tokens against $0.00 spend,
#    because a model that is not listed is costed at zero.
LLM_PRICING=kimi-k3=3.0/15.0,glm-5.2=1.4/4.4

# 2. Where your traffic exits. Empty = your own IP.
REQUIRE_VPN=false          # true refuses to scan unless the exit IP changed
SCAN_PROXY=                # socks5://127.0.0.1:9050 for Tor — no privileges
VPN_CONFIG_PATH=           # /data/vpn/wg0.conf for WireGuard/OpenVPN
```

The LLM provider and key are **not** here. They are entered in the UI, stored
encrypted in the database, and never returned to the browser. The `PLANNER_*` /
`EXECUTOR_*` / `VALIDATOR_*` variables still work for unattended provisioning,
and anything set in the UI wins.

The providers offered: **Z.ai (GLM)**, **Moonshot (Kimi)**, **DeepSeek**,
**Qwen (DashScope)**, **OpenRouter**, and anything else that speaks
`/v1/chat/completions` — a self-hosted vLLM or Ollama, an in-house gateway. One
provider for all three roles is the default; splitting them (a strong model on
the planner, a cheap fast one on the executor) is a checkbox.

### Recon first

**Recon** sits between Home and Engagements. Paste a hostname, URL or IP and it
answers the four questions worth asking before you open an engagement: where it
actually lives, whose network that is (ASN and netblock — an address belonging
to a hosting provider is not one your client can authorize you to attack), what
it is built out of, split into frontend / backend / infrastructure, and what
else carries the same name.

It is passive by construction: DNS, RDAP and Certificate Transparency ask public
infrastructure *about* the target, and the only thing that reaches the target is
one TLS handshake, one `GET /`, and `robots.txt` / `sitemap.xml` /
`security.txt`. The page shows that list, served from the backend, next to the
button. Active testing needs an engagement — that is where the authorization
lives.

It is also the one page that works before you connect a model, because it is the
one page that never calls one.

### First engagement

1. **Engagements** → enter the target, tick the authorization attestation,
   create. Scope is enforced on every request; out-of-scope hosts are refused
   and audited.
2. **Live** → *Run*. Recon, mapping, vulnerability analysis and exploitation
   advance one phase at a time, streamed to the console as they happen.
3. **Findings** / **Reports** → confirmed findings, kill-chains, and an export
   (Markdown, PDF, JSON, SARIF).

Exploitation is gated twice: `allow_active_exploit` on the engagement, and an
approval checkpoint in the live view.

Day-to-day usage, authenticated testing, proof of impact, VPN setup (ProtonVPN
included) and wiping state: **[docs/OPERATING.md](docs/OPERATING.md)**.

---

## Architecture

```
      Frontend (React, nginx)                    :3000
              │  REST + WebSocket
      Auth gate (session cookie | X-API-Key)     every /api and /ws route
              │
      API (FastAPI)                              :8000
       │         │            │             │
   Recon     Engagements  Orchestrator   Proxy capture   :8080
  (passive)  + authz gate  (the brain)   (own image: mitmproxy → Postgres)
                                │
              Planner ──> Executor ──> Validator
              (catalog)   (arq worker)  (safe-PoC)
                                │
              Postgres  +  Redis (arq queue)
                                │
              Tool arsenal (worker image)

      sandbox-runner  ── isolated network, no secrets, pinned egress
```

Six app containers — `backend`, `proxy`, `worker`, `orchestrator`, `frontend`,
`sandbox-runner` — plus Postgres and Redis. Three details are load-bearing:

- The orchestrator has **its own arq queue**. A long autonomous run holds a
  worker slot for its whole life, so sharing one pool let a run starve the
  scans it was itself waiting on.
- `worker` and `orchestrator` run on **`network_mode: "service:backend"`**.
  Only `backend` has `NET_ADMIN` + `/dev/net/tun`, so it is the only namespace
  `wg-quick` can route — without sharing it the tools egressed directly while
  the UI reported a healthy tunnel. Changing this needs a full
  `docker compose down`, not a restart.
- `proxy` is a **separate image** (`--target proxy`). mitmproxy pins
  `cryptography<44.1`; while it shared an environment with the API that pin
  applied to the whole stack.

`sandbox-runner` sits on a separate Docker network with no route to Postgres,
Redis or the backend's secrets. It is where untrusted third-party PoCs run,
after a human has read them.

## How it works

- **Authentication** — mandatory, with no variable that disables it. A password
  (PBKDF2-HMAC-SHA256, 600k iterations), an 8-hour sliding session in an
  httpOnly cookie of which only the SHA-256 is stored, and a login form
  throttled per username *and* source address together. The gate sits in front
  of the router, so no page can forget it, and in the middleware, so no browser
  can skip it.
- **Authorization gate** — every scan is tied to an authorized engagement whose
  scope covers the host. Enforced in `Runner.submit()`, the single chokepoint
  every caller passes through, so the autonomous and manual paths are covered
  by the same check.
- **Recon is outside that gate, and therefore bounded by a list.** It runs
  before an engagement exists, so there is no scope to check against. What may
  leave the machine is a constant in `app/recon/budget.py` — four paths, GET and
  HEAD, six requests — not a judgement call, and every run is audited.
- **A model is required** — the planner decides the next move, the executor
  reads what the tools said, the validator confirms or kills each finding. A run
  with no provider configured is refused with a 409 that names the fix, rather
  than degrading into a scanner printing raw output.
- **Methodology engine** — a declarative catalog maps each OWASP WSTG test to
  its MITRE ATT&CK technique and the tool that runs it, gated by what has been
  discovered so far.
- **Agent loop** — the planner builds the next batch from the catalog filtered
  by live state; the executor runs each task through the queue and folds the
  results back in, expanding the surface as it learns. The LLM may reorder a
  batch and propose targeted hunts — it never invents a target.
- **Correlation** — when vulnerability analysis starts, the planner gets the
  whole picture at once (assets, fingerprints, WAF, findings so far, captured
  traffic) and joins signals no single tool sees together.
- **Validation** — tool-confirmed where possible, otherwise re-checked with one
  in-scope read-only request and a benign marker. An LLM judge kills false
  positives and proposes a replayable proof. Status is confirmed / likely /
  unconfirmed / false_positive.
- **Kill-chains** — confirmed findings are linked into multi-step attack paths.
- **Live view** — the loop emits typed events to Postgres; a WebSocket tails
  them, so the console, phase timeline and findings update in real time.

Nothing a model produces reaches a target unfiltered: proposals are matched
against assets that already exist, tool flags against per-tool allowlists, and
proofs against a read-only policy.

## Tests

```bash
cd backend  && pytest -q && ruff check .     # no network, no database needed
cd frontend && npm test && npm run lint && npm run build
```

Five CI jobs on every push: backend (compile, lint, unit tests), frontend (lint,
tests, build), compose + hadolint on all three Dockerfiles + shellcheck on the
shell scripts, a dependency audit (`pip-audit`, `npm audit`), and a pre-flight
that every pinned tool download still exists on both architectures.

The nightly, on `main` only, additionally builds every image for `amd64` and
`arm64`, re-runs the suite against the latest dependency releases, checks that
each test module still imports with only the CI dependency set, and runs a
**smoke test**: a fresh install, booted, exercised from outside — nothing
reachable before setup, setup closing after the first account, a wrong password
refused, a run refused with no model, logout ending the session.

## License

MIT.
