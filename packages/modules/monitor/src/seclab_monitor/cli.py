import asyncio

import typer

from seclab_monitor.listener import CertStreamMonitor

app = typer.Typer(help="Real-time Certificate Transparency stream monitor (seclab monitor module).")


@app.command()
def run() -> None:
    """Start the CertStream listener. Runs until interrupted (Ctrl+C)."""
    from seclab.core.db import init_db

    import seclab_monitor.models  # noqa: F401  (register monitor tables before init_db)

    init_db()
    monitor = CertStreamMonitor()
    typer.echo(f"[*] seclab monitor: watching for keywords {monitor.monitor_settings.keywords}")
    try:
        asyncio.run(monitor.run())
    except KeyboardInterrupt:
        typer.echo("\n[*] Shutting down seclab monitor...")


if __name__ == "__main__":
    app()
