from __future__ import annotations

import asyncio

import typer

from seclab_osint_breach.models import BreachCheckRequest, WatchedIdentifier
from seclab_osint_breach.service import BreachCheckService

app = typer.Typer(help="Breach/leak watcher: checks watched identifiers against HIBP or fixtures.")


@app.command()
def run(
    email: list[str] = typer.Option([], help="Watched email identifier(s) to check."),
    domain: list[str] = typer.Option([], help="Watched domain identifier(s) to check."),
    offline: bool = typer.Option(True, help="Use the offline fixture set (no network calls)."),
) -> None:
    """Check watched email/domain identifiers against breach data and print the report."""
    from seclab.core.config import get_settings
    from seclab.core.db import SessionLocal, init_db

    import seclab_osint_breach.db  # noqa: F401  (register tables before init_db)

    init_db()
    settings = get_settings()
    session = SessionLocal()
    try:
        service = BreachCheckService(settings, session)
        identifiers = [
            WatchedIdentifier(identifier=value, identifier_type="email") for value in email
        ] + [WatchedIdentifier(identifier=value, identifier_type="domain") for value in domain]
        request = BreachCheckRequest(offline_mode=offline, identifiers=identifiers)
        result = asyncio.run(service.run_check(request))
        typer.echo(result.report_markdown)
    finally:
        session.close()


if __name__ == "__main__":
    app()
