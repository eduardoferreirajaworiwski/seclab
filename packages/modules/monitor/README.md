# seclab-monitor

Real-time Certificate Transparency stream monitor, absorbed from the
standalone `hydra-mapper` project. Listens to a CertStream websocket feed
for newly issued certificates matching configured brand keywords
(`SECLAB_MONITOR_KEYWORDS`), and for each match runs the exact same
enrichment + scoring pipeline `phantom` uses for an on-demand analysis
(`MatchPipeline` reuses `seclab_phantom`'s `CompositeEnrichmentProvider`
and `score_asset` directly - one scoring rule-set, not two).

Optionally captures a screenshot + HTML dump of the matched domain
(`capture.py`, headless browser) before storing it as evidence
(`seclab.security.evidence`) - gated by the same `EgressPolicy` every
other outbound request goes through, so a certificate for a
privately-routed hostname is never fetched.

Mounted by the gateway at `/api/v1/monitor` (read-only match list). CLI:
`seclab monitor run` (long-running listener, Ctrl+C to stop).
