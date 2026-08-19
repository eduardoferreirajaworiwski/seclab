# seclab-web

The unified dashboard, forked from `scopepilot/frontend` and repointed at
the `seclab-gateway` API instead of scopepilot's standalone backend.

Kept from the original: the typed `request<T>` API client wrapper with
`ApiClientError`, React Query setup, the shadcn-style UI primitives
(`components/ui/*`), the app shell/sidebar/topbar layout, and the
API-key-in-`localStorage` auth flow.

Rewritten for seclab's actual routes: `lib/types/api.ts`, `lib/api/client.ts`,
`lib/api/hooks.ts`, `lib/api/query-keys.ts`, and the page set - now covering
Phantom (submit/browse analyses), Recon (programs → targets → hypotheses →
approvals → executions → findings), and Monitor (CT-stream matches) instead
of scopepilot's original page set alone.

Run: `npm install && npm run dev` (needs `NEXT_PUBLIC_SECLAB_API_URL`
pointing at the gateway, see `.env.example`).
