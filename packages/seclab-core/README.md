# seclab-core

Shared core library for the `seclab` personal security laboratory.

Provides the building blocks every module (phantom, recon, monitor,
sensor_chimera, and future OSINT modules) reuses instead of reinventing:

- `seclab.core.config` - unified `Settings` (env prefix `SECLAB_`)
- `seclab.core.logging` - structured JSON logging with secret redaction
- `seclab.core.http` - SSRF-hardened HTTP client + egress policy (blocks private/loopback/link-local ranges, optional host allowlist)
- `seclab.core.db` - shared SQLAlchemy `Base`/session/engine
- `seclab.core.registry` - live/mock provider registry driven by `offline_mode`
- `seclab.core.events` - pluggable event/alert bus (log sink always on, Discord sink optional)
- `seclab.core.scheduler` - lightweight in-process asyncio job scheduler
- `seclab.security.auth` / `keys` - Bearer auth + HMAC-SHA256(pepper) API key hashing
- `seclab.security.scope_guard` - fail-closed target/action allowlist gate
- `seclab.security.approval` - human-in-the-loop approval state machine
- `seclab.security.audit` - append-only audit log
- `seclab.security.evidence` - generic chain-of-custody evidence store
- `seclab.reporting` - shared risk scoring primitives + report builders

See `C:\Users\eduar\.claude\plans\ol-tudo-bem-estou-linked-turtle.md` for the full migration plan this package implements.
