from __future__ import annotations

import asyncio

import typer
from seclab.core.config import get_settings
from seclab.core.db import SessionLocal, init_db

from seclab_phantom.models import TargetRequest, TargetType
from seclab_phantom.service import AnalysisService

app = typer.Typer(help="Lookalike/typosquat domain analysis (seclab phantom module).")


@app.command()
def analyze(
    target: str = typer.Argument(..., help="Brand keyword or domain to analyze."),
    target_type: str = typer.Option("domain", help="'domain' or 'brand'."),
    offline: bool = typer.Option(True, help="Use offline mock providers (no network calls)."),
    max_variants: int = typer.Option(10, help="Maximum lookalike domain variants to generate."),
) -> None:
    """Run a phantom analysis and print the Markdown report to stdout."""
    import seclab_phantom.db  # noqa: F401  (register phantom tables before init_db)

    init_db()
    settings = get_settings()
    session = SessionLocal()
    try:
        service = AnalysisService(settings, session)
        request = TargetRequest(
            target=target,
            target_type=TargetType(target_type),
            offline_mode=offline,
            max_variants=max_variants,
        )
        result = asyncio.run(service.analyze(request))
        typer.echo(result.report_markdown)
    finally:
        session.close()


if __name__ == "__main__":
    app()
