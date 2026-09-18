from __future__ import annotations

import asyncio

import typer
from seclab.security.scope_guard import ProgramPolicy
from seclab_phantom.providers import CrtShProvider

from seclab_attack_surface.models import AssetTarget, SurfaceScanRequest
from seclab_attack_surface.service import AttackSurfaceService

app = typer.Typer(
    help=(
        "Lightweight external attack-surface mapper. Requires an explicit "
        "allowlist (--allow) - a domain with no allowlist match is never "
        "probed."
    )
)


@app.command()
def scan(
    domain: str = typer.Argument(..., help="Domain to map (e.g. example.com)."),
    allow: list[str] = typer.Option(
        ..., "--allow", help="Allowed domain pattern(s), e.g. example.com or *.example.com."
    ),
    offline: bool = typer.Option(True, help="Use offline CT fixtures (no network calls)."),
) -> None:
    """Run a scope-gated attack-surface scan and print the report."""
    from seclab.core.config import get_settings
    from seclab.core.db import SessionLocal, init_db

    import seclab_attack_surface.db  # noqa: F401  (register tables before init_db)

    init_db()
    settings = get_settings()
    session = SessionLocal()
    try:
        ct_provider = CrtShProvider(settings, offline_mode=offline)
        service = AttackSurfaceService(ct_provider=ct_provider, db=session)
        request = SurfaceScanRequest(
            target=AssetTarget(domain=domain),
            scope_policy=ProgramPolicy(allowed_domains=allow),
        )
        result = asyncio.run(service.run_scan(request))
        typer.echo(result.report_markdown)
    finally:
        session.close()


if __name__ == "__main__":
    app()
