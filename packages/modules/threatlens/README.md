# seclab-threatlens

Weekly security-news ingestion, deterministic attack-vector tagging, and
AI-assisted (Gemini) threat digest narrative, following the same module
pattern as `seclab-phantom`.

Exposed on the gateway at `/api/v1/threatlens` (create/list/get digests)
and in the dashboard at `/threatlens` (run a digest, browse recent ones,
view the report and tagged articles). Also usable standalone offline via
`seclab threatlens run`.
