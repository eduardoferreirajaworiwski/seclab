# seclab-phantom

Lookalike/typosquat domain detection module, ported from the standalone
`phantomscope` project into the `seclab` monorepo. Given a brand or domain:
generates suspicious domain variants, checks Certificate Transparency logs,
enriches with DNS/RDAP/ASN infrastructure data, scores risk with named
explainable rules, and produces a Markdown/JSON report.

Mounted by the gateway at `/api/v1/phantom`. Runs fully offline with mock
providers by default (`SECLAB_OFFLINE_MODE=true`).
