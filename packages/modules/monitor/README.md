# seclab-monitor

Real-time Certificate Transparency stream monitor, absorbing the standalone
`hydra-mapper` prototype (2 commits, abandoned) into the `seclab` monorepo
as the "scheduled monitoring" module `phantom`'s own roadmap wanted.

Watches the public CertStream feed for newly issued certificates whose
domain contains a configured brand keyword, runs each match through
`seclab_phantom`'s enrichment + scoring pipeline (the same one used for
on-demand lookalike analysis), and persists scored matches plus optional
forensic capture (screenshot + HTML) to the shared evidence store.

## What changed vs. the original hydra-mapper

- **Keywords are configurable** (`SECLAB_MONITOR_KEYWORDS`), not hardcoded.
- **Matches are scored**, not just printed - they flow through
  `seclab_phantom.scoring.score_asset` for an explainable, comparable score
  instead of being a raw keyword hit.
- **Capture is pooled, not spawned-per-domain**: one Chromium instance is
  launched once and reused across captures instead of a fresh
  `sync_playwright()` context per match, which would not scale to
  CertStream's real volume.
- **Capture is an optional wrapper**: if Playwright isn't installed, the
  module still ingests and scores matches - it just skips the
  screenshot/HTML step and says so, rather than crashing.
- **Evidence goes through `seclab.security.evidence`** (SHA-256
  chain-of-custody rows in the DB) instead of loose `<file>.hash` sidecars.
- **Fixed the wildcard-stripping bug**: the original used
  `domain.lstrip("*.")`, which strips a *character set* (any leading `*` or
  `.` chars), not the literal `"*."` prefix. This version uses
  `removeprefix("*.")`.
- **Unused dependencies dropped**: `tldextract`, `stix2`, `python-dotenv`,
  `requests` were declared but never imported in the original.

Mounted by the gateway at `/api/v1/monitor` (read-only match history); the
listener itself runs as a background job via `seclab.core.scheduler`.
