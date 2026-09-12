# Operating guide

What the README leaves out: running an engagement day to day, authenticated
testing, proof of impact, platform specifics, and wiping state.

## Run an engagement

1. **Engagements** -> enter a target you own, tick the authorization box,
   create. Attestation authorizes it immediately; the scope list bounds what
   gets touched.
2. Open its **live view** -> **Run**. Watch recon -> mapping -> vuln ->
   exploitation -> validation stream in the agent console; if you enabled
   "require approval before exploitation", approve the checkpoint.
3. Download the **report** (`.md` or printable HTML) once findings are
   validated and chains are built.

You can also drive tools manually: browse the target through the MITM proxy
(install its CA from the Proxy page), inspect captured requests, and launch
individual scans from the Scans page.

### Authenticated, traffic-driven testing

For real coverage, run it authenticated:

- **Authenticated scan** - paste the primary identity's headers (Cookie /
  Authorization) in the engagement form. They're injected into every scanner
  (nuclei/sqlmap/ffuf/dalfox/katana/...) so it tests *behind the login*.
- **Real surface from the proxy** - browse the app through the MITM proxy
  while logged in; the autonomous run seeds those captured (parameterized)
  requests as scan targets, so sqlmap/dalfox/nuclei-dast hit the endpoints
  you actually exercised.
- **Grey-box IDOR/BOLA/BFLA** - add a *second* (low-privilege) identity's
  headers; the analysis replays captured requests as the other user to prove
  broken object-level authorization and privilege escalation (BFLA).
- **Out-of-band (blind) confirmation** - nuclei confirms blind SSRF/XXE/RCE
  via interactsh. By default it uses ProjectDiscovery's free public servers
  (no infra); set `INTERACTSH_SERVER` in `.env` to self-host.

The **deep analysis** pass (autorun in the validation phase, or on demand via
*Deep analysis* on the live view) mines everything captured through the proxy:

- **Secret & endpoint mining** - scans every captured text response (JS
  bundles, HTML, JSON, source maps) for secrets (cloud keys, tokens, private
  keys, JWTs) and pulls hidden API endpoints out of client code; discovered
  endpoints are seeded as new scan targets.
- **JWT analysis** - flags `alg=none`, cracks weak/known HMAC secrets offline,
  spots `kid`/`jku` injection surface, missing `exp`, and authz claims.
- **Access control in depth** - replays authenticated GETs anonymously to find
  missing-auth/broken-access-control, and flags method-tampering and
  mass-assignment candidates for manual review (writes are never executed).

Findings are partitioned into homogeneous categories (recon, enumeration,
access control, injection, auth & secrets, server & config) in both the live
view and the report.

### Proof of impact (opt-in)

Detection isn't proof. With **"Prove impact"** enabled on the engagement, after
a tool *confirms* an injection the agent demonstrates real impact by running a
**benign, read-only** command through it:

- **RCE / command injection** - re-runs commix with `--os-cmd` executing a
  read-only post-exploitation enumeration in one shot (privilege context,
  host/container detection, listening services & routes, scheduled tasks, SUID
  binaries, users). The output proves execution and maps the blast radius. It
  also **detects (never exploits) local privilege-escalation vectors** -
  passwordless `sudo` and GTFOBins-known SUID binaries - which feed an
  RCE → root kill-chain.
- **SQLi** - re-runs sqlmap in read-only context mode (`--current-user`,
  `--is-dba`, `--banner`, ...); OS command execution through the DB is a
  separate sub-opt-in.
- **Data-breach proof** (separate sub-opt-in) - retrieves a small, **bounded
  sample (≤3 rows)** of likely-sensitive tables via a confirmed SQLi to prove a
  real data exposure - far from a mass exfiltration.

It is **double-gated** (the opt-in flag *and* the exploitation approval
checkpoint), in-scope only, and strictly non-destructive: no writes, deletes,
persistence or lateral movement. The exact command and its raw output are
visible in the Jobs tab.

- **Known-CVE exploitation** - from the fingerprinted stack (WordPress,
  Atlassian, GitLab, Jenkins, Tomcat, Struts, ...) the agent runs the matching
  nuclei CVE templates (vetted public PoCs, out-of-band confirmed). Gated by the
  same `allow_active_exploit` opt-in.
- **Targeted CVE checks** - a curated set of high-value, actively-exploited CVEs
  (Apache 2.4.49/50 path traversal, Citrix, F5 BIG-IP, Pulse Secure, FortiOS file
  read) confirmed with a single read-only in-scope GET and a high-confidence file
  signature - near-zero false positives, no OOB infra. On a hit the CVE is
  reported with a redacted proof snippet.
- **Public-exploit aggregation (all sources)** - for every detected CVE the
  agent gathers the public PoCs that exist across sources - Exploit-DB (offline
  via `searchsploit`), Metasploit, GitHub, NVD, Vulners, Packet Storm - and
  shows them per finding with a runnable tier: `auto` (vetted, run in-scope:
  nuclei / Metasploit check), `sandbox` (raw scripts fetched and staged for an
  approved run in the isolated sandbox), `reference` (links). Raw public code is
  never auto-run - it is reviewed/run only via the approved sandbox.

Confirmed findings are then linked into **kill-chains** automatically:
leaked-secret → server compromise, broken-access-control → bulk data exposure,
weak-JWT → account takeover, SSRF → cloud credential theft, subdomain takeover
→ session theft, GraphQL introspection → authorization abuse (plus an optional
LLM pass for additional chains).

## Platform specifics


Everything runs in containers, so the tool behaves the same everywhere. Three
things do differ, and all three are about talking to the host's network stack:

| | Linux | macOS (Docker Desktop / OrbStack) | Windows (WSL2) |
| --- | --- | --- | --- |
| Scans, proxy mode, sandbox runner | yes | yes | yes |
| VPN from the UI (`wg-quick` in the container) | yes | usually — userspace WireGuard via `/dev/net/tun` | usually — same |
| VPN on the host instead | yes | yes | yes |

The container ships `wireguard-tools` and `openvpn` and is given
`/dev/net/tun`, which is what the userspace implementation needs when the host
does not expose the kernel module — the normal situation on Docker Desktop. If
`POST /api/network/vpn/connect` fails on your machine, bring the tunnel up on
the host instead and leave the tool in `off` mode: the kill switch compares
exit IPs, so it protects the scan whoever owns the tunnel.

### Windows (WSL2)

The tool is Linux/Docker only, so on Windows run it inside WSL2:

1. Install WSL2 with a distro: `wsl --install` (PowerShell, admin), reboot.
2. Either install Docker Desktop and enable **Settings -> Resources -> WSL
   integration** for your distro, or install `docker-ce` directly inside the
   WSL distro.
3. Open the WSL shell (Ubuntu), `git clone` the repo **inside** the WSL
   filesystem (e.g. `~/syphax`, not `/mnt/c/...` - native FS is much faster),
   then run `./install.sh` / `./start.sh` exactly as on Linux.
4. Browse to http://localhost:3000 from Windows - WSL2 forwards localhost.

### ProtonVPN

A paid or free Proton account both work — you need a **WireGuard** config, not
the desktop app:

1. account.protonvpn.com -> **Downloads** -> **WireGuard configuration**
2. Name the key, pick a server, download the `.conf`
3. `mkdir -p data/vpn` and drop it there — `./data` is already bind-mounted
   into the backend as `/data`, and is gitignored so the key never gets committed
4. `.env`: `VPN_CONFIG_PATH=/data/vpn/<file>.conf`, then Connect from the Home
   card — or set `REQUIRE_VPN=true` first so no scan can start without it

Two things in a stock Proton config break inside a container, and the tool
rewrites a corrected copy rather than making you hand-edit the provider's file:

- `DNS = 10.2.0.1` would replace Docker's resolver, and the backend would stop
  resolving `postgres` — an outage that looks like a database problem, not a VPN
  one. The line is dropped; traffic still exits through the tunnel.
- The filename becomes the interface name, and `ch-fr-01.protonvpn.udp` is over
  the kernel's 15-character limit and contains dots. wg-quick rejects it with
  "invalid interface name", which reads like a malformed config. The copy is
  named `wg0.conf`.

Your original file is never modified. After connecting, hit **Check IP** — the
two IPs on the card must differ, and the Proton exit should show a Proton
netblock. `NAT-PMP (port forwarding)` and `NetShield` do not matter here;
NetShield's DNS filtering is irrelevant once the DNS line is dropped.

`wipe.sh` is a bash script. On Windows run it from the WSL shell, like the rest.

Shell scripts are pinned to LF by `.gitattributes`. If you clone with Git for
Windows and `core.autocrlf=true`, a CRLF shebang would make Docker report
`exec /usr/local/bin/entrypoint.sh: no such file or directory` for a file that
plainly exists.

## Tools bundled in the worker image

Recon: `nmap`, `naabu`, `subfinder`, `dnsx`, `httpx`, `katana`, `gau`.
Fingerprint / WAF: `whatweb`, `httpx`, `wafw00f`.
Content discovery: `ffuf`.
Parameter discovery: `arjun`, `jsluice`.
Vuln / CMS / server: `nuclei`, `nikto`, `wpscan`.
API: `schemathesis`. Client-side: `retire.js`.
Secrets / source: `trufflehog` (verified), `git-dumper`.
Injection: `sqlmap` (SQLi), `commix` (command).
XSS: `dalfox`. TLS: `testssl.sh`. Capture: `mitmproxy`.

`GET /api/scans/tools` reports each tool's category and whether its binary is
present. WordPress CVE correlation needs `WPSCAN_API_TOKEN` (free, optional).

### The six that need a word of explanation

- **`arjun`** (mapping) discovers undocumented HTTP parameters by differential
  response analysis. It produces **injection points, not findings**: every
  injection test can only decide things that have parameters, and `?debug=1`
  is in neither the HTML nor the JS. Discovered parameters are attached to the
  endpoint so the later phases pick them up.
- **`schemathesis`** (vuln) property-tests a published OpenAPI schema against
  the API's **own contract** — unhandled 500s, responses that violate the
  schema the API publishes, undocumented status codes, an operation that
  ignores the auth it declares. Runs only on an asset whose URL looks like a
  schema (`openapi`, `swagger`, `api-docs`), and only the fuzzing/examples
  phases: the coverage phase sends PUT/DELETE/TRACE to every operation, which
  is a write against a live target. Add `--phases=coverage` per scan if you
  want it.
- **`retire.js`** (vuln) rates the **client-side** libraries. Nothing else in
  the image looks at them: httpx and whatweb fingerprint the server, nuclei
  matches server-side CVEs. A page shipping jQuery 1.7.2 was invisible.
- **`jsluice`** (mapping) extracts URLs, parameters and secrets from a real
  JavaScript AST, so it sees endpoints built by string concatenation that a
  regex pass cannot, and reports the method and parameter names with them.
- **`git-dumper`** (vuln) **acts** on an exposed `.git` instead of only
  reporting that the path is readable: it rebuilds the working tree into
  `{DATA_DIR}/artifacts/{host}/git/`.
- **`trufflehog`** (vuln) scans that recovered tree and the captured
  JavaScript in `--results=verified` mode: it **authenticates each candidate
  secret against its own provider**, so a hit is a credential that answered,
  not a pattern that matched. It is the only tool here whose verdict is
  `confirmed` without syphax touching the target — the provider decided.
  Verification is an outbound call to AWS/GitHub/Stripe, never to the target.

`retire.js`, `jsluice` and `trufflehog` read files, not URLs. The proxy's
captured JavaScript is written to `{DATA_DIR}/artifacts/{host}/js/` at the
mapping → vuln-analysis boundary, so those tasks have something to read.
A directory that was never produced yields zero findings, not an error.

## Full configuration reference

| Variable                       | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `PLANNER/EXECUTOR/VALIDATOR_BASE_URL` `_API_KEY` `_MODEL` | Per-role LLM. Default `.env` puts the **planner on Kimi K3** (`https://api.moonshot.ai/v1`, `kimi-k3`) and the **executor + validator on Z.ai GLM** (`glm-5.2`); set the keys to activate. |
| `LLM_PRICING`                  | `model=IN/OUT` USD per 1M tokens. **Without it the dashboard shows real token counts against $0.00 spend** — every unlisted model costs 0. |
| `USER_AGENT_MODE`              | `rotate` (default) impersonates a different real browser per job, headers included. `fixed` pins `USER_AGENT`. |
| `REQUIRE_VPN` / `SCAN_PROXY` / `VPN_CONFIG_PATH` | Route scan traffic through a proxy or tunnel, and refuse to scan when the exit IP still matches your real one. |
| `RESET_ON_START`               | Wipe scan artefacts on every boot (default `true`). See **Full wipe** below for what it does *not* cover. |
| `OPENROUTER_API_KEY` / `_MODEL` / `_FALLBACK_MODELS` | **Optional** free fallback aggregator, used only for roles whose own key is blank. |
| `SYPHAX_API_KEY`               | **Optional.** Empty = no authentication, which is fine while `:8000` / `:8080` are bound to `127.0.0.1` (the compose default). Set it before exposing either, then paste the same value into **Settings → API key**. Enforced on `/api` and on the WebSocket (as `?key=`, since a browser cannot set headers on a WS handshake). `/api/health` stays open for the healthcheck. |
| `LLM_RECON_MAX_FLOWS` / `_BODY_CHARS` / `_BUDGET_CHARS` | How much captured traffic the LLM response analyst sees. Defaults suit ~128K context; raise to `200` / `600000` for a 262K model. Flows are ranked (server errors > auth/validation errors > parameterised > plain 200s > 404s) and added until either cap binds. |
| `POSTGRES_*`                   | Database credentials (defaults work out of the box). |
| `WPSCAN_API_TOKEN`             | Optional WordPress CVE lookups.                    |

Set a Z.ai (or Kimi) key on each role for the real thing; leave keys blank and
it falls back to OpenRouter's free models, so the stack works with a single key
or none.

### Full wipe

`RESET_ON_START=true` clears scan artefacts (jobs, findings, flows, events,
runs, LLM usage) and the queued jobs in Redis every time the backend starts.
Engagement scope and the audit log survive on purpose — one is what makes a
scan legal, the other is the record of what ran.

Three things live outside that and explain why a "from scratch" restart can
still feel like it remembers:

| What | Survives `down` | Survives `down -v` |
| ---- | --------------- | ------------------ |
| `postgres-data` (named volume) | yes | no |
| `redis-data` (named volume)    | yes | no |
| `./data` (**bind mount**: mitmproxy CA, settings key) | yes | **yes** |

The bind mount is the surprising one. To remove everything:

```bash
./wipe.sh              # asks first
./wipe.sh --yes        # no prompt
./wipe.sh --keep-ca    # keep the mitmproxy CA so clients stay trusted
```

Dropping the CA means every client you configured must trust the new one, and
stored provider API keys become undecryptable — `--keep-ca` avoids both.

## Repository layout

```
backend/         FastAPI app + arq worker (one image, two roles)
  app/
    api/         REST + WebSocket routers
    engagements/ authorization gate + scope
    methodology/ WSTG x ATT&CK test catalog
    orchestrator/ planner, executor, run loop, state, approvals
    scans/       wrappers + queue runner + job storage
    validation/  safe-PoC validators + kill-chaining
    reporting/   client report (Markdown / HTML)
    proxy/       mitmproxy addon + flow storage
    events.py    live event stream
    db.py        Postgres pool
  Dockerfile     multi-arch, bundles all CLI tools
frontend/        React + plain CSS, served by nginx
docker-compose.yml   postgres, redis, backend, worker, frontend
install.sh / start.sh
```

## Architecture notes

- Single Postgres holds everything (engagements, jobs, findings, proxy flows,
  events, audit log); Redis is the arq job queue.
- The backend never spawns tools; it enqueues and a separate **worker**
  container runs them. The autonomous run is itself a long-lived worker task
  that launches scan sub-tasks concurrently.
- The MITM addon writes flows via sync psycopg; everything else uses asyncpg.

## Retesting the same target

Two things make a second engagement on a target worth more than the first.

**Diff.** `GET /api/engagements/<new>/diff?against=<old>` answers the retest
question: what was fixed, what came back, what is new. Findings are matched on
(class, endpoint path, title) with the query string dropped, because `?id=1`
and `?id=7` are the same issue - keeping it would report every retest as
entirely new. Only `confirmed` and `likely` findings are compared: one the
judge killed was never real, so it is neither a fix nor a regression.

**Memory.** After each validation, the engagement's final verdicts are folded
into a shared store keyed on (normalised technology, vuln_class). The planner
then puts classes that held up on this stack first *within a phase* -
`GET /api/engagements/<id>/memory` shows what it learned and why, and the Live
view prints it as a strip above the tabs.

It is deliberately conservative. Only final verdicts count (a `likely` is an
opinion, and remembering opinions compounds them), a lesson needs at least two
observations and better than 50% precision before it steers anything, and it
never adds or drops a task or touches a gate. On a fresh install it is empty
and does nothing.

## When a run is interrupted

The loop writes a heartbeat every iteration. If the worker dies, the run stays
at `running` with nothing driving it - which used to make `POST .../run` refuse
every new run with a 409 that never cleared. Starting a run now reclaims
anything with no live loop first, and marks it `failed` with
`stop_reason: interrupted`. The Live view shows `no worker reporting` on such a
run.

Coverage rows are kept on purpose: the planner skips what already ran, so the
next run **continues** rather than redoing the work. Just press Run again.

## Verifying a finding by hand

When an LLM validator role is configured, the judge proposes a *proof* for each
finding it reviews: one read-only request, plus the exact substring that
settles the question. The Live view shows it under the finding, and **Verify
proof** replays it through SafePoC and reports whether it held.

The verdict is a substring test, not a second opinion - the judge already chose
the observable. No response at all is reported as `inconclusive`, never as a
refutation: the target may simply have been down.

## How a finding gets its verdict (and why the FP rate is what it is)

Validation runs in two passes, and the report separates what the passes could
prove from what they could not.

**Per-finding.** In order, first match wins:

1. **Provider-verified.** trufflehog authenticated a secret against its own
   provider → `confirmed`. The provider decided, not us.
2. **Tool-confirmed.** sqlmap/commix/dalfox actively proved their own finding.
3. **Safe-PoC re-check.** An exposed resource is fetched and must match a real
   content signature (a dotenv line, an `.htaccess` directive, `[core]`); a
   reflected-XSS candidate gets a benign unique marker in **every** parameter.
4. **Catch-all baseline.** Once per engagement, syphax asks the target for a
   few paths that cannot exist and remembers the shape of the answer. On a
   server that returns 200 for everything, every guessed path "exists", so a
   path-existence finding whose answer has that same shape is `false_positive`,
   not `likely`. An honest 404 costs no extra request; a failed calibration
   discards nothing.
5. **Surface inventory.** A live host, a banner, a discovered path is not a
   weakness — it cannot be "likely vulnerable", so it is filed as
   informational and stays out of the FP-rate denominator. Previously nine
   registered tools had no class at all and their output shipped as `likely`
   findings next to real ones.
6. **Heuristic.** The scanner's own match, scaled by severity. nikto's
   findings are now rated from the message it prints, so an exposed `.git` and
   an `X-Powered-By` header are no longer the same finding.

**Across findings.** The whole validated set is then arbitrated, grouped by
`(vuln_class, target-without-query)` so sqlmap's `?id=1`, nuclei's bare path
and nikto's `:443` land in the same group:

- independent agreement raises confidence, counted by **distinct tool** — one
  noisy tool firing five templates is still one voice;
- an oracle that looked at the target and **could not reproduce** the class
  demotes the pattern matches that claimed it;
- a guess inherits ground from a proven sibling at the same target;
- a lone unchecked pattern match loses confidence.

Nothing is ever promoted to `confirmed` by agreement: agreement between
guesses is not proof, so unproven findings are capped below the confirmed
band. The reasoning is stored on the finding and printed in the report.

**Widening the oracle.** The adaptive prober used to reach query parameters
only, so a finding on `POST /api/login` or `GET /api/users/1337` could never
be *decided*. It now addresses three channels — query, a field of a request
body we actually captured, and a path segment that looks like a value. The
body channel is never invented: no captured request, no body channel, because
POSTing a guessed form to a guessed endpoint creates orders and sends mail.

**The report** puts proven findings in section 3 with their proofs and
unverified ones in section 4 as leads for manual confirmation. `meta` carries
`proven_findings`, `unverified_findings` and the real `false_positive_rate_pct`.

## Is the tunnel actually covering DNS?

A tunnel can carry the traffic while name lookups still go to the host resolver
in cleartext. `wg-quick` replaces `/etc/resolv.conf` with the provider's `DNS`,
which breaks resolution of `postgres` and `redis` inside the container - so the
DNS line used to be stripped, and every target lookup leaked.

Now the internal service IPs are resolved and pinned into `/etc/hosts` *before*
the tunnel comes up, which lets the tunnel keep its own DNS. The Home page
reports which of the two you have under **Target DNS via tunnel**; if pinning
failed it says so rather than pretending.
