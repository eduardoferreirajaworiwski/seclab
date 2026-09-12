from __future__ import annotations

import asyncio

import typer
from seclab.core.config import get_settings
from seclab.core.db import SessionLocal, init_db

from seclab_cve_watch.models import DigestRequest
from seclab_cve_watch.service import CveWatchService

app = typer.Typer(help="CVE / CISA-KEV exploit tracker and watchlist tagging.")


@app.command()
def run(
    offline: bool = typer.Option(True, help="Use offline mock feeds (no network calls)."),
    lookback_days: int = typer.Option(7, help="Lookback window in days."),
) -> None:
    """Fetch the latest NVD + CISA KEV CVEs, tag against the watchlist, and print the report."""
    import seclab_cve_watch.db  # noqa: F401  (register tables before init_db)

    init_db()
    settings = get_settings()
    session = SessionLocal()
    try:
        service = CveWatchService(settings, session)
        request = DigestRequest(offline_mode=offline, lookback_days=lookback_days)
        result = asyncio.run(service.run_digest(request))
        typer.echo(result.report_markdown)
    finally:
        session.close()


if __name__ == "__main__":
    app()
