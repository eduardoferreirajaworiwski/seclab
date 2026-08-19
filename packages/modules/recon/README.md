# seclab-recon

Authorized bug-bounty / pentest workflow module, ported from the standalone
`scopepilot` project into the `seclab` monorepo. Strict human-in-the-loop:
AI/automation never executes anything without prior human approval, every
target is scope-checked, every decision is audited.

Pipeline: `program -> target (scope-checked) -> hypothesis -> approval (human)
-> execution (gated) -> finding`.

Reuses `seclab.security` for scope guarding, approval workflow, and audit -
this module owns only the domain tables/routes specific to the bug-bounty
workflow (Program, Target, Hypothesis, Execution, Finding). Compared to the
original scopepilot, this port intentionally drops the `app/agents/` wrapper
layer (routes call services directly) and the separate FlowSnapshot/
ReportDraft tables (superseded by the shared `seclab.security.evidence`
store and `seclab.security.audit` log).

Mounted by the gateway at `/api/v1/recon`.
