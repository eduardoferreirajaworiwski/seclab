from __future__ import annotations

import asyncio

import typer

from seclab_threatlens.models import DigestRequest
from seclab_threatlens.service import ThreatLensService

app = typer.Typer(help="Weekly security-news digest and attack-vector tagging.")


@app.command()
def run(
    offline: bool = typer.Option(True, help="Use offline mock articles (no network calls)."),
    lookback_days: int = typer.Option(7, help="Lookback window in days."),
) -> None:
    """Fetch this week's security news, tag attack vectors, and print the report."""
    from seclab.core.config import get_settings
    from seclab.core.db import SessionLocal, init_db

    import seclab_threatlens.db  # noqa: F401  (register tables before init_db)

    init_db()
    settings = get_settings()
    session = SessionLocal()
    try:
        service = ThreatLensService(settings, session)
        request = DigestRequest(offline_mode=offline, lookback_days=lookback_days)
        result = asyncio.run(service.run_digest(request))
        typer.echo(result.report_markdown)
    finally:
        session.close()


if __name__ == "__main__":
    app()
