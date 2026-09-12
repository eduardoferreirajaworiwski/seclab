from __future__ import annotations

import typer
from seclab.core.config import get_settings
from seclab.core.db import SessionLocal, init_db

from seclab_fusion.service import DEFAULT_FEED_LIMIT, FusionService

app = typer.Typer(help="Cross-module correlation feed (monitor + threatlens + cve_watch).")


@app.command()
def feed(
    limit: int = typer.Option(DEFAULT_FEED_LIMIT, help="Max number of top findings to print."),
) -> None:
    """Print the top correlated findings across monitor/threatlens/cve_watch."""
    import seclab_cve_watch.db  # noqa: F401  (register tables before init_db)
    import seclab_monitor.models  # noqa: F401
    import seclab_threatlens.db  # noqa: F401

    get_settings()
    init_db()
    session = SessionLocal()
    try:
        service = FusionService(session)
        result = service.get_feed(limit=limit)
        if not result.findings:
            typer.echo("No correlated findings.")
            typer.echo(
                f"(monitor_matches={result.monitor_match_count}, "
                f"threatlens_digest={result.threatlens_digest_id}, "
                f"cve_watch_digest={result.cve_watch_digest_id})"
            )
            return
        for finding in result.findings:
            typer.echo(f"[{finding.score:>3}] {finding.title}")
            for signal in finding.signals:
                typer.echo(f"        - ({signal.kind}) {signal.label}")
    finally:
        session.close()


if __name__ == "__main__":
    app()
