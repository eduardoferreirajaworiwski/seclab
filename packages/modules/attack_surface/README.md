# seclab-attack-surface

Lightweight external attack-surface mapper ("map *my own* real footprint",
distinct from `phantom`'s lookalike-of-a-brand use case). Given a domain,
enumerates subdomains via Certificate Transparency logs (reuses
`seclab_phantom.providers.CrtShProvider` directly - the third module that
would otherwise re-implement crt.sh querying), resolves each hostname to
its IP addresses, and probes a short fixed list of common ports
(`80, 443, 22, 21, 3389`) via a plain TCP-connect reachability check
(`asyncio.open_connection`, 1.5s timeout, semaphore-bounded concurrency -
never a bare unbounded `socket.connect`). Ports are tagged deterministically
against a small port -> exposure-tag map (`tagging.py`), e.g. `3389 ->
"rdp-exposed"`, `21 -> "ftp-exposed"`.

## Risk profile: this module makes outbound network connections to targets

Every other module in this repo (`phantom`, `monitor`, `threatlens`,
`cve_watch`, `osint_breach`) only calls third-party **metadata** APIs
(crt.sh, rdap.org, NVD, KEV, RSS feeds, HIBP) - never the target's own
infrastructure. `attack_surface` is different: it opens real TCP
connections directly to hosts discovered under an arbitrary domain. Even
though each probe is a passive connect-and-close with no protocol data
exchanged, this is active network scanning, not a read-only lookup.

**Mandatory scope-guard gate.** Per the project plan, this is the one
module that must not ship without an explicit allowlist check:
`ModuleManifest(needs_scope_guard=True)`, and every scan request must
carry a `ProgramPolicy` (the same allowlist type `recon` uses via
`seclab.security.scope_guard.ScopeGuardService`). The service validates
the target domain against `scope_policy.allowed_domains` **before**
calling `CrtShProvider`, before resolving any DNS, and before opening a
single socket. If the domain is not in scope, the scan short-circuits
with `in_scope=False`, `hosts=[]`, and an explanatory
`report_markdown` - zero discovery, zero probing, zero outbound calls of
any kind. This is enforced with a dedicated test that injects fakes which
raise if ever called, proving the short-circuit is real and not just
documented behavior.

Since this module has no separate "Program" registration step (unlike
`recon`), the caller supplies the `ProgramPolicy` allowlist directly,
inline, in the scan request itself (`SurfaceScanRequest.scope_policy`).

## API

Mounted by the gateway at `/api/v1/attack_surface`:
`POST /scans` (submit `AssetTarget` + `scope_policy`, run scan),
`GET /scans` (list recent scans), `GET /scans/{scan_id}`.

CLI: `seclab attack_surface scan <domain> --allow <domain-or-*.domain>`.

## Tests

100% offline/deterministic - every test injects a fake CT provider, fake
DNS resolver, and/or fake port connector. No real network I/O ever runs
in the test suite, live or otherwise.
