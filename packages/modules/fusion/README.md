# seclab-fusion

Cross-module correlation feed. Reads recent results from `monitor`,
`threatlens`, and `cve_watch` and surfaces one prioritized, explainable
feed of correlated findings - e.g. a domain `monitor` flagged this week
whose matched keyword also appears in a product `cve_watch` says has an
actively-exploited CVE right now, or in a trending `threatlens` article.

## Design choice: option 1 (thin read-only aggregator, no own persistence)

Per the hardening plan's Part C, this module intentionally has **no
database table of its own**. `FusionService` opens the *existing*
`db: Session` dependency and reads directly from `seclab_monitor`'s
`MonitorMatch` ORM model and `seclab_threatlens`/`seclab_cve_watch`'s
`DigestRepository`/`CveDigestRepository`, then joins everything in plain
Python (`correlation.py`) on every request. Nothing is cached or written
back - the feed is always computed fresh.

This trades a little request-time CPU for zero migration/consistency
risk, and is appropriate while only three modules feed fusion. The plan
calls out a rule of thumb: revisit this (event-bus-driven correlation
with fusion maintaining its own lightweight table, option 2) if the lab
grows past roughly four feeder modules, since direct-repository-import
coupling gets unwieldy past that point.

## Correlation heuristic (deterministic, explainable, no ML)

For each of the most recent `MonitorMatch` rows (limit configurable,
default 100):

- **`exploited_cve` signal**: the match's `matched_keyword` or `domain`
  case-insensitively substring-matches an entry in a `TrackedCve.matched_products`
  from the single most recent `cve_watch` digest. Weighted **+3** if that
  CVE `is_actively_exploited` (CISA KEV), **+1** otherwise.
- **`threat_vector` signal**: the match's `matched_keyword`
  case-insensitively substring-matches a word in a `ThreatArticle`'s
  `title`/`summary` from the single most recent `threatlens` digest,
  *and* that article has at least one tagged `vectors` entry. Weighted
  **+1** per matching article (capped to avoid one noisy digest dominating
  the score).
- Every finding also carries the monitor match's own `score`, contributed
  as `+round(score / 10)`.

A `MonitorMatch` with **zero** correlation signals produces **no**
finding - fusion only surfaces genuinely correlated activity, not a dump
of everything `monitor` has ever seen. Findings are sorted by score
descending; every signal that contributed is listed on the finding with
its own human-readable label so the score is always traceable back to the
exact keyword/product/article that triggered it (same "named, weighted,
explainable signal" philosophy as `seclab.reporting.scoring.RiskSignal`
used elsewhere in the repo).

## Graceful degradation

If `threatlens` or `cve_watch` has no digest yet (`list_recent()` returns
empty), fusion proceeds with an empty article/CVE list rather than
erroring - it simply can't produce `exploited_cve`/`threat_vector`
signals for that source until a digest exists. If `monitor` has no
matches yet, the feed is an empty list.

Mounted by the gateway at `/api/v1/fusion` (`GET /feed`, read-only - there
is nothing to create in this module). CLI: `seclab fusion feed`.
