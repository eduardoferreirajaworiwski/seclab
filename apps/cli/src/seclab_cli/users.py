import sys

import typer
from seclab.core.config import Settings, get_settings
from seclab.security.keys import generate_api_key, hash_api_key
from seclab.security.models import Role, User
from sqlalchemy import select
from sqlalchemy.orm import Session

app = typer.Typer(help="Manage lab users (identity shared across every module).")


def create_user_record(
    username: str, role: str, settings: Settings, db: Session
) -> tuple[User, str]:
    """Create a user row and return it with its raw (unhashed) API key.

    Extracted from the `users create` command so other entry points (e.g.
    `seclab init`) can create a user without shelling out to the CLI.
    Raises ValueError if the username already exists - callers decide how
    to present that (the Typer command turns it into a stderr message and
    exit code 1; other callers may want different handling).
    """
    existing = db.scalar(select(User).where(User.username == username))
    if existing is not None:
        raise ValueError(f"User '{username}' already exists (id={existing.id}).")

    raw_key = generate_api_key()
    user = User(username=username, role=role, api_key_hash=hash_api_key(raw_key, settings))
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, raw_key


@app.command("create")
def create_user(
    username: str = typer.Argument(...),
    role: str = typer.Option(Role.ANALYST.value, help="'analyst' or 'security_lead'."),
) -> None:
    """Create a user and print their API key once.

    Deliberately CLI-only, mirroring scopepilot's original design: an HTTP
    user-creation endpoint would need to decide who's allowed to call it
    before any user exists yet (a bootstrap-trust problem), so the first
    (and every) user is always minted out-of-band by whoever controls the
    machine running this CLI.
    """
    if role not in {Role.ANALYST.value, Role.SECURITY_LEAD.value}:
        typer.echo(f"Invalid role '{role}'. Use 'analyst' or 'security_lead'.", err=True)
        raise typer.Exit(code=1)

    from seclab.core.db import SessionLocal, init_db

    import seclab.security.models  # noqa: F401  (register core tables before init_db)

    init_db()
    settings = get_settings()

    with SessionLocal() as db:
        try:
            user, raw_key = create_user_record(username, role, settings, db)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from None

    typer.echo(f"Created user '{user.username}' (role={role}, id={user.id}).")
    typer.echo(f"API key (store securely, shown once): {raw_key}", file=sys.stdout)


if __name__ == "__main__":
    app()
