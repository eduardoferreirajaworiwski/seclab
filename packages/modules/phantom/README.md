# seclab-phantom

Lookalike/typosquat domain detection, ported from the standalone
`phantomscope` project into the `seclab` monorepo. Generates candidate
lookalike domains for a brand or domain, checks Certificate Transparency
logs (crt.sh) and RDAP/DNS enrichment for each candidate, scores every
finding with named, weighted, explainable signals
(`seclab.reporting.scoring`), and produces an optional AI-assisted analyst
summary (OpenAI, falls back to a deterministic summary when no key is
configured or the call fails - see `ai_summary.py`).

Offline by default (`SECLAB_OFFLINE_MODE=true`): every provider has a
mock/fixture path so the whole analysis runs with zero network calls.
Live mode makes real requests to crt.sh and rdap.org, rate-limited
per-host to stay under their undocumented public limits.

Mounted by the gateway at `/api/v1/phantom`. CLI: `seclab phantom analyze <target>`.
