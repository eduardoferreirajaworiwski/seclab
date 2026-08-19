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
      sensor_chimera/       active-deception honeypot — separately
                            deployable, never mounted on the gateway
                            (from project-chimera)
  apps/
    gateway/               FastAPI gateway mounting phantom + recon +
                           monitor under /api/v1/<module>
    cli/                   `seclab` command (Typer), offline-first
    web/                   Next.js dashboard (forked from scopepilot's
                            frontend, repointed at the gateway)
  docker-compose.yml
```

## Quickstart (local, no Docker)

```bash
python -m venv .venv
.venv/Scripts/activate   # or: source .venv/bin/activate

pip install -r requirements-dev.txt   # editable install of every workspace package

# Create your first user (needed for the recon module's auth). This prints
# an API key, shown once — paste it into the dashboard's "Set API key"
# control in the topbar.
seclab users create alice --role security_lead

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
       packages/modules/monitor/tests apps/gateway/tests apps/cli/tests \
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

- API keys are hashed with HMAC-SHA256 and a server-side pepper
  (`seclab.security.keys`), not unsalted SHA-256 like the original
  scopepilot.
- All outbound HTTP goes through `seclab.core.http.HttpProvider`, which
  blocks private/loopback/link-local IP ranges and revalidates every
  redirect hop against the same policy before following it — so a
  malicious or compromised redirect can't be used to reach internal
  infrastructure.
- No module can treat a target as authorized without an explicit allowlist
  match (`seclab.security.scope_guard`) — missing allowlist means nothing
  is in scope, by design (fail-closed).
- Every scope decision, approval decision, and execution is written to the
  audit log (`seclab.security.audit`) and, where relevant, the evidence
  store (`seclab.security.evidence`) with a SHA-256 content hash.
- The honeypot sensor never holds credentials to the lab's database and
  runs on an isolated Docker network.

## Roadmap

Planned modules follow the same contract as the existing ones — a
`manifest.py` exposing a `ModuleManifest`, its own
`models.py`/`routes.py`/`service.py`/`cli.py`, and reuse of `seclab-core`
for everything cross-cutting:

- **OSINT**: `recon_dns`, `osint_breach`, `osint_username`, `ip_asn_intel`,
  `metadata_exif`
- **AppSec, Cloud/DevSecOps, Blue Team, and Threat Modeling** modules
