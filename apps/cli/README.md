# seclab-cli

The `seclab` command: one entrypoint that mounts every module's own Typer
sub-app (`seclab phantom analyze ...`, `seclab recon list-programs`,
`seclab monitor run`) plus lab-wide commands that don't belong to any single
module (`seclab init`, `seclab users create`, `seclab retention purge`).

`seclab init` is the one-shot setup command for a fresh checkout: it
generates `SECLAB_API_KEY_PEPPER` into `.env` if missing or still the
placeholder, initializes the database, and interactively creates your first
user, printing its API key once. Run it before starting the gateway for the
first time; `seclab users create <name> --role <role>` remains the way to
add additional users afterward.

Fully usable offline, with zero servers running - each subcommand calls its
module's service layer directly. Every module's DB/settings-dependent
imports are deferred to inside each command function (not module top-level)
so `seclab --help` and `seclab init` both work on a fresh checkout with no
`.env` yet - see `seclab.core.db`'s lazy `engine`/`SessionLocal`.
