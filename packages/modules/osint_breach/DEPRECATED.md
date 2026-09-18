# DEPRECATED

This module is **unmounted** as of the "consolidate/deprecate modules" pass
(see `.hermes/plans/2026-09-18_001233-consolidate-deprecate-modules.md` in
the repo root for the full rationale).

- Not registered in `apps/gateway/src/seclab_gateway/registry.py`'s
  `MODULE_MANIFEST_PATHS` anymore — its routes (`/api/v1/osint_breach/*`)
  are gone, not just hidden.
- Not registered in `apps/cli/src/seclab_cli/main.py`'s `MODULE_CLI_APPS`
  anymore — `seclab osint_breach ...` no longer exists as a CLI command.
- Not linked from the dashboard sidebar.

**Why:** structurally redundant with the ThreatLens/CVE Watch digest shape
once those two were merged into `/intel` (ingest → tag → AI summary →
report, three times over), narrowest personal-lab utility of the digest
modules (requires curating your own list of watched emails/domains, where
ThreatLens/CVE Watch are useful with zero setup), and the only one of the
three requiring a paid third-party API key (`SECLAB_HIBP_API_KEY`) for its
live path.

**What's kept, deliberately:** the module's code, its own tests
(`packages/modules/osint_breach/tests/`), and its own `README.md` all stay
in place for at least one release cycle. Nothing was deleted outright so
this decision is cheap to reverse — re-add its manifest path to the
gateway registry and CLI main.py to remount it. If it turns out nobody
re-mounts it after a while, physical deletion is a separate, later,
even-more-deliberate step (not part of this pass).
