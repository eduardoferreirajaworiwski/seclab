# seclab

A personal security laboratory: one monorepo, one shared core, and a set of
pluggable modules for offensive and defensive security work — phishing/brand
protection, authorized bug-bounty recon, Certificate Transparency monitoring,
and active-deception honeypots.

It consolidates four previously separate tools (`phantomscope`,
`scopepilot`, `project-chimera`, `hydra-mapper`) into one codebase with a
shared core: config, auth/RBAC, a hardened HTTP client, persistence, an
audit log, and a human-in-the-loop approval workflow, so every module gets
the same security posture for free instead of reimplementing it.

## Contents

- [Requirements](#requirements)
- [Layout](#layout)
- [Quickstart (local, no Docker)](#quickstart-local-no-docker)
- [Quickstart (Docker)](#quickstart-docker)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security notes](#security-notes)
- [Roadmap](#roadmap)

## Requirements

| | Local | Docker |
|---|---|---|
| Python | 3.11+ | — |
| Node.js | 20+ | — |
| Docker / Compose | — | v2 |

## Layout

```
seclab/
  packages/
    seclab-core/           shared: config, logging, hardened HTTP client,
                           persistence, provider registry, event bus,
                           scheduler, auth/RBAC, scope guard, approval
                           workflow, audit log, evidence store, reporting
    modules/
      phantom/              lookalike/typosquat domain detection
                            (from phantomscope)
      recon/                authorized bug-bounty workflow, human-in-
                            the-loop (from scopepilot)
      monitor/              real-time Certificate Transparency stream
                            monitor (absorbed from hydra-mapper)
      threatlens/            weekly security-news digest with
                            deterministic attack-vector tagging
      cve_watch/             NVD + CISA KEV exploit tracker
      osint_breach/          breach/leak watcher (HIBP)
      attack_surface/        lightweight external ASM (scope-guarded)
      sensor_chimera/       active-deception honeypot — separately
                            deployable, never mounted on the gateway
                            (from project-chimera)
  apps/
    gateway/               FastAPI gateway mounting every module above
                           (except sensor_chimera) under /api/v1/<module>
    cli/                   `seclab` command (Typer), offline-first
    web/                   Next.js dashboard (forked from scopepilot's
                            frontend, repointed at the gateway)
  docker-compose.yml
```

## Architecture

    ┌─────────────┐        ┌──────────────────────────────┐
    │  apps/web   │  HTTP  │        apps/gateway           │
    │  (Next.js)  │ ─────► │  FastAPI + auth + rate limit  │
    └─────────────┘        │  mounts one router per module │
                            └──────────┬─────────────────────┘
                                       │ ModuleManifest
        ┌───────────┬─────────┬───────┼──────────┬──────────────┬───────────────┐
        ▼           ▼         ▼       ▼          ▼              ▼               ▼
    phantom       recon    monitor threatlens cve_watch   osint_breach   attack_surface
        │           │         │       │          │              │               │
        └───────────┴─────────┴───────┴──────────┴──────────────┴── seclab-core ┘
                                                                     │
                          config · hardened HTTP client (egress-    │
                          checked) · db · events · scheduler ·      │
                          auth/RBAC · scope guard · approval ·      │
                          audit log · evidence store · reporting    │

    sensor_chimera runs standalone, on its own Docker network -
    never mounted on the gateway, never given DB credentials.

## Modules

| Module | Mounted at | Approval gate? | Scope-checked? | Summary |
|---|---|---|---|---|
| `phantom` | `/api/v1/phantom` | no | no | Lookalike/typosquat domain detection via CT logs + infra enrichment |
| `recon` | `/api/v1/recon` | yes | yes | Authorized bug-bounty workflow: program → target → hypothesis → approval → execution → finding |
| `monitor` | `/api/v1/monitor` | no | no | Real-time CT-stream monitoring, scored through the phantom pipeline |
| `threatlens` | `/api/v1/threatlens` | no | no | Weekly security-news ingestion, deterministic attack-vector tagging, Gemini-assisted digest narrative |
| `cve_watch` | `/api/v1/cve_watch` | no | no | NVD + CISA KEV exploit tracker, deterministic product/vendor watchlist tagging |
| `osint_breach` | `/api/v1/osint_breach` | no | no | Breach/leak watcher for tracked emails/domains (HIBP, offline-fixture-first) |
| `attack_surface` | `/api/v1/attack_surface` | no | yes | Lightweight external ASM: CT-based subdomain discovery + bounded TCP-connect port probing, gated by scope-guard |
| `fusion` | `/api/v1/fusion` | no | no | Read-only cross-module correlation feed (monitor + threatlens + cve_watch), no own persistence |
| `sensor_chimera` | *(standalone, not mounted)* | no | no | Active-deception honeypot, isolated network, no DB credentials |

(This table is hand-maintained today; each row's "Approval gate?"/
"Scope-checked?" columns mirror that module's `ModuleManifest.needs_approval`
/`needs_scope_guard` flags — keep it in sync when adding a module, or see
the "Roadmap" idea below to generate it instead.)

## Quickstart (local, no Docker)

```bash
python -m venv .venv
.venv/Scripts/activate   # or: source .venv/bin/activate

pip install -r requirements-dev.txt   # editable install of every workspace package

seclab init
# generates SECLAB_API_KEY_PEPPER, sets up the database, and creates your
# first user - prints an API key, shown once. Paste it into the dashboard's
# "Set API key" control in the topbar.

# Terminal 1 — gateway
uvicorn seclab_gateway.main:app --reload --app-dir apps/gateway/src

# Terminal 2 — dashboard
cd apps/web && npm install && npm run dev
```

Both processes need to be running at the same time: the gateway on
`:8000`, the dashboard on `:3000`. See [Troubleshooting](#troubleshooting)
if the dashboard reports "API Unreachable".

Everything defaults to `SECLAB_OFFLINE_MODE=true` — phantom and monitor run
against mock providers with zero network calls, so the whole lab is usable
and testable offline. Live mode (real crt.sh/RDAP/DNS calls) can be enabled
per-request from the dashboard or the API.

## Quickstart (Docker)

```bash
cp .env.example .env   # set SECLAB_API_KEY_PEPPER to a real secret
docker compose up                        # gateway + web
docker compose --profile monitor up      # + live CertStream listener
docker compose --profile sensor up       # + honeypot sensor (isolated network)
```

The honeypot (`sensor-chimera`) runs on its own Docker network
(`sensor-net`), separate from `lab-net` where the gateway and its database
volume live, so it can never reach the lab's internal state — only speak
outbound (GeoIP, Discord webhook).

## Testing

Every package ships its own `tests/`. Run them all from the repo root:

```bash
pytest packages/seclab-core/tests packages/modules/phantom/tests \
       packages/modules/recon/tests packages/modules/sensor_chimera/tests \
       packages/modules/monitor/tests packages/modules/threatlens/tests \
       packages/modules/cve_watch/tests packages/modules/osint_breach/tests \
       packages/modules/attack_surface/tests apps/gateway/tests apps/cli/tests \
       --import-mode=importlib
```

(`--import-mode=importlib` is set as the default in the workspace
`pyproject.toml`, so a plain `pytest` from the root also works.)

```bash
cd apps/web && npm run typecheck && npm run build
```

## Troubleshooting

### Dashboard says "API Unreachable" (and everything feels slow)

This means the browser's `fetch` to the gateway is failing at the network
level — almost always because **the gateway process isn't running**, not
because of a bad API key (`/health` is unauthenticated, so a missing or
invalid key never produces "unreachable"). The perceived slowness is React
Query retrying each failed request up to twice with backoff
(`apps/web/lib/api/query-client.ts`) before it gives up and shows the
error, so every page load stalls for a few seconds.

Fix:

```bash
# from the repo root, with the venv active
curl http://127.0.0.1:8000/api/v1/health   # should return {"status": "ok", ...}

uvicorn seclab_gateway.main:app --reload --app-dir apps/gateway/src
```

Then reload the dashboard. If it's still unreachable, check:

- `apps/web/.env.local` (if present) — `NEXT_PUBLIC_SECLAB_API_URL` may be
  pointing at the wrong host/port. Default is
  `http://127.0.0.1:8000/api/v1` (see `apps/web/.env.example`).
- The gateway logs an error on startup — usually a missing
  `packages/*[dev]` install; re-run `pip install -r requirements-dev.txt`.
- You're running the Docker Compose stack instead of local processes — in
  that case check `docker compose ps` / `docker compose logs gateway`
  rather than starting `uvicorn` by hand.

### "API key set" but requests get 401

The topbar's API key control only stores a bearer token for authenticated
routes — it doesn't affect reachability. Get a valid key with
`seclab users create <name> --role analyst` (printed once to stdout) and
paste it in via "Set API key".

### Live-mode lookups fall back to mock data / crt.sh returns 429

crt.sh and rdap.org are free, unauthenticated public services with tight
and undocumented rate limits. The CT and RDAP providers pace their own
requests to stay under a conservative threshold, but a burst of prior
requests (e.g. repeated test runs in a short window) can still trigger a
temporary block on those services' side, independent of anything this
codebase controls. Wait a few minutes and retry, or lower `max_variants` to
reduce the number of concurrent lookups in a single analysis.

## Security notes

- Every route the gateway mounts requires a valid API key
  (`Depends(get_current_user)`, enforced once at the mount point in
  `seclab_gateway.registry.mount_routers` so a new module or route can't
  ship unauthenticated by accident) — only `/api/v1/health` is public.
  `/docs`, `/redoc`, and `/openapi.json` are disabled too, so the route
  and schema surface isn't browsable without a key either.
- API keys are hashed with HMAC-SHA256 and a server-side pepper
  (`seclab.security.keys`), not unsalted SHA-256 like the original
  scopepilot. The gateway and CLI refuse to start if
  `SECLAB_API_KEY_PEPPER` is missing or left at its placeholder value.
- The gateway's rate limit (`rate_limit_default`, 60/minute by default) is
  enforced on every request via `SlowAPIMiddleware`.
- All outbound HTTP goes through `seclab.core.http.HttpProvider`, which
  resolves each destination once, rejects anything that isn't a public IP
  (blocking private/loopback/link-local/multicast/CGNAT ranges by
  construction instead of an enumerated list), and connects directly to
  that validated address — closing the DNS-rebinding window a
  resolve-then-connect design would otherwise leave open. Every redirect
  hop is re-validated the same way before it's followed.
- No module can treat a target as authorized without an explicit allowlist
  match (`seclab.security.scope_guard`) — missing allowlist means nothing
  is in scope, by design (fail-closed).
- Every scope decision, approval decision, and execution is written to the
  audit log (`seclab.security.audit`) and, where relevant, the evidence
  store (`seclab.security.evidence`) with a SHA-256 content hash.
- A hypothesis's `required_role` is a real enum, not free text — an
  unrecognized role is rejected outright instead of silently ranking as
  the weakest possible approver.
- The honeypot sensor never holds credentials to the lab's database and
  runs on an isolated Docker network. Evidence it captures (CT-matched
  domain names) is filename-sanitized before being written to disk.

## Roadmap

Planned modules follow the same contract as the existing ones — a
`manifest.py` exposing a `ModuleManifest`, its own
`models.py`/`routes.py`/`service.py`/`cli.py`, and reuse of `seclab-core`
for everything cross-cutting:

- **OSINT**: `recon_dns`, `osint_username`, `ip_asn_intel`, `metadata_exif`
  (`osint_breach` shipped — see the Modules table above)
- **Fusion / correlation view**: shipped as the `fusion` module (option 1
  from its original design note: thin read-only aggregator, no own
  persistence) — revisit that choice if the lab grows past ~4 feeder
  modules per the module's own README.
- **AppSec, Cloud/DevSecOps, Blue Team, and Threat Modeling** modules
- **Docs**: the Modules table above is hand-maintained; a `seclab docs
  modules` CLI command that renders it from every registered
  `ModuleManifest` (name, mount path, `needs_approval`, `needs_scope_guard`,
  `description`) would remove the risk of it drifting from the code.
