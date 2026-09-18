import typer
from seclab.security.audit import AuditLogger

from seclab_recon.services import ProgramService

app = typer.Typer(help="Authorized bug-bounty workflow (seclab recon module).")


@app.command("list-programs")
def list_programs() -> None:
    """Print every registered program and its scope summary."""
    from seclab.core.db import SessionLocal, init_db

    import seclab_recon.models  # noqa: F401  (register recon tables before init_db)

    init_db()
    session = SessionLocal()
    try:
        programs = ProgramService(session, AuditLogger(session)).list_all()
        if not programs:
            typer.echo("No programs registered yet.")
            return
        for program in programs:
            allowed = program.scope_policy.get("allowed_domains", [])
            typer.echo(f"[{program.id}] {program.name} (owner={program.owner}) allowlist={allowed}")
    finally:
        session.close()


if __name__ == "__main__":
    app()
