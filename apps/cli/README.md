# seclab-cli

The `seclab` command: one entrypoint that mounts every module's own Typer
sub-app (`seclab phantom analyze ...`, `seclab recon list-programs`,
`seclab monitor run`) plus lab-wide commands that don't belong to any single
module (`seclab users create`).

Fully usable offline, with zero servers running - each subcommand calls its
module's service layer directly.
