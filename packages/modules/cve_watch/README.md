# seclab-cve-watch

CVE / CISA-KEV exploit tracker. Pulls newly published CVEs from NVD's
public CVE API 2.0 and cross-references them against CISA's Known
Exploited Vulnerabilities (KEV) catalog, then tags each CVE by
product/vendor keyword overlap with a configurable watchlist
(`WatchedProduct` entries submitted per digest request).

**Data sources** (both public JSON APIs, no API key required - a
deliberately zero-paid-dependency module):
- NVD CVE API 2.0 (`https://services.nvd.nih.gov/rest/json/cves/2.0`)
- CISA KEV catalog
  (`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`)

Offline by default (`SECLAB_OFFLINE_MODE=true`): both feeds have a
trimmed JSON fixture under `src/seclab_cve_watch/data/mock/` so the whole
digest pipeline runs with zero network calls. Live mode fetches both
feeds via `seclab.core.http.HttpProvider.get_json` (egress-checked, same
as every other module's live path) and merges the two by CVE ID -  a CVE
present in both feeds keeps NVD's CVSS score/description but is marked
`is_actively_exploited=True` and gets KEV's vendor/product names.

Tagging (`tagging.py`) is a deterministic keyword match against the
request's `watched_products` list, in the same "named, explainable
signal" style as `seclab_threatlens`'s `VECTOR_KEYWORDS` - no ML
classifier, every match is traceable to the exact vendor/product string
that triggered it. An empty watchlist means "track only KEV entries
regardless of product" per the module's design.

Mounted by the gateway at `/api/v1/cve_watch`
(`POST /digests`, `GET /digests`, `GET /digests/{digest_id}`). CLI:
`seclab cve_watch run`.

## Deferred: ThreatLens cross-reference

The plan for this module calls for a `correlate_with_threatlens(cves,
threatlens_articles)` pure function that flags a `TrackedCve` as
`mentioned_in_threatlens=True` when its CVE ID or product name
string-matches a ThreatLens article's title/summary - giving a combined
"what's being exploited and what's in the news about it" view. This is
intentionally **not implemented yet**: it's optional per the module's
design and is left as a follow-up. When built, it should be a read-only
function in a new `correlation.py` that imports `seclab_threatlens.models`
for its pydantic types only (mirroring how `seclab_monitor` already
imports from `seclab_phantom`) - no new table, no new dependency
direction beyond that.
