import typer
from seclab.core.db import SessionLocal, init_db
from seclab.security.models import EvidenceArtifact

app = typer.Typer(help="Prune old evidence/audit rows (opt-in, explicit).")


@app.command()
def purge(
    days: int = typer.Option(90, help="Delete rows older than this many days."),
    dry_run: bool = typer.Option(True, help="Report counts without deleting."),
) -> None:
    import seclab.security.models  # noqa: F401

    init_db()
    session = SessionLocal()
    try:
        from seclab.core.retention import purge_older_than

        if dry_run:
            from datetime import UTC, datetime, timedelta

            cutoff = datetime.now(UTC) - timedelta(days=days)
            count = session.query(EvidenceArtifact).filter(EvidenceArtifact.created_at < cutoff).count()
            typer.echo(f"[dry-run] would delete {count} evidence_artifacts older than {days}d")
            return
        deleted = purge_older_than(session, EvidenceArtifact, days=days)
        typer.echo(f"deleted {deleted} evidence_artifacts older than {days}d")
    finally:
        session.close()


if __name__ == "__main__":
    app()
