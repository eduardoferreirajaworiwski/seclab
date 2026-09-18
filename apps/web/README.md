# seclab-web

The unified dashboard, forked from `scopepilot/frontend` and repointed at
the `seclab-gateway` API instead of scopepilot's standalone backend.

Kept from the original: the typed `request<T>` API client wrapper with
`ApiError`, React Query setup, the shadcn-style UI primitives
(`components/ui/*`), the app shell/sidebar/topbar layout, and the
API-key-in-`localStorage` auth flow.

Rewritten for seclab's actual routes: `lib/types/api.ts`, `lib/api/client.ts`,
`lib/api/hooks.ts`, `lib/api/query-client.ts`, `lib/api/auth.ts`,
`lib/format.ts`, `lib/utils.ts`, and the page set: Phantom (submit/browse
analyses), Recon (programs → targets → hypotheses → approvals → executions
→ findings, plus a per-target "map attack surface" action), Monitor
(CT-stream matches), Intel (ThreatLens + CVE Watch digests behind one
tabbed page, since both follow the exact same ingest → tag → AI-summary →
report shape), and Fusion (read-only correlated feed). OSINT Breach was
deprecated and unmounted from the gateway (see
`packages/modules/osint_breach/DEPRECATED.md`), so it has no page here
either. Attack Surface has no standalone page anymore — it's reachable
only from a Recon program's target row, since its scope-guard model
mirrors Recon's exactly.

Run: `npm install && npm run dev` (needs `NEXT_PUBLIC_SECLAB_API_URL`
pointing at the gateway, see `.env.example`).
