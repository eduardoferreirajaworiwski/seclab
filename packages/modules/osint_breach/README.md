# seclab-osint-breach

Breach/leak watcher: given a list of watched email/domain identifiers,
checks them against breach-notification data and produces a deterministic
exposure report, following the same module pattern as `seclab-threatlens`
and `seclab-cve-watch`.

Offline-fixture-first (`SECLAB_OFFLINE_MODE=true`, the default): every
lookup resolves against a bundled fixture set
(`data/mock/exposures.json`), so the module runs with zero network calls
and no API key. Live mode adds a thin `HttpProvider`-based client for the
Have I Been Pwned API v3 (`GET /breachedaccount/{account}`), gated behind
`SECLAB_HIBP_API_KEY` being set - exactly like `threatlens` gates its
`SECLAB_GEMINI_API_KEY` AI path. Only email identifiers are checked live
(HIBP's endpoint takes a single account, not a domain); domain identifiers
always resolve against the offline fixture set regardless of mode. If the
live call fails for any reason, the lookup falls back to the offline
fixture set rather than surfacing an error to the caller.

Mounted by the gateway at `/api/v1/osint_breach`. CLI:
`seclab osint_breach run --email you@example.com --domain example.com`.

## Security note: identifier logging

Watched identifiers checked by this module can include raw email
addresses, which are potentially sensitive even in a personal lab. No log
line in this module emits a raw email at any level - `sources.py`'s
`_log_safe_identifier()` truncates an email to a short SHA-256 hash
(`email:sha256:<12 hex chars>`) before it reaches any `logger.*` call;
domain identifiers are logged as-is since a domain alone isn't sensitive.

This is worth calling out because it's a deliberate departure from an
existing pattern elsewhere in the repo:
`seclab_phantom.ai_summary`'s `ai_summary_failed` log line logs its raw
`target` value. That's acceptable there because `phantom`'s `target` is
always a domain or brand name, never an email - but the same pattern
would **not** be acceptable in this module, where a "target" can be a raw
email address. `phantom`'s code is intentionally left unchanged (per the
plan, this refactor's scope is `osint_breach` only); this paragraph is the
explicit flag for that inconsistency rather than a silent divergence.
