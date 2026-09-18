import secrets
from pathlib import Path

import typer
from seclab.core.config import DEFAULT_API_KEY_PEPPER
from seclab.security.models import Role

ENV_PATH = Path(".env")


def _ensure_api_key_pepper(env_path: Path = ENV_PATH) -> None:
    """Idempotent: does nothing if the .env file already has a real pepper.

    Generates and writes SECLAB_API_KEY_PEPPER when the file is missing or
    still holds the shipped placeholder - the one manual step
    (`python -c "import secrets; print(...)"` pasted into .env by hand)
    every prior quickstart silently assumed the reader would do before
    first boot (see seclab.core.config.Settings._reject_default_pepper).
    """
    lines = env_path.read_text().splitlines() if env_path.exists() else []
    pepper_line_index = next(
        (i for i, line in enumerate(lines) if line.startswith("SECLAB_API_KEY_PEPPER=")),
        None,
    )
    current_value = (
        lines[pepper_line_index].split("=", 1)[1] if pepper_line_index is not None else ""
    )

    if current_value and current_value != DEFAULT_API_KEY_PEPPER:
        return  # already set to something real - leave it alone

    new_pepper = secrets.token_urlsafe(32)
    new_line = f"SECLAB_API_KEY_PEPPER={new_pepper}"
    if pepper_line_index is not None:
        lines[pepper_line_index] = new_line
    else:
        lines.append(new_line)
    env_path.write_text("\n".join(lines) + "\n")
    typer.echo("Generated SECLAB_API_KEY_PEPPER and wrote it to .env.")


def init_lab(
    username: str = typer.Option(..., prompt="Your username"),
    role: str = typer.Option(
        Role.SECURITY_LEAD.value,
        prompt="Role (analyst / security_lead)",
    ),
) -> None:
    """Set up the lab in one step: pepper, database, and your first user."""
    if role not in {Role.ANALYST.value, Role.SECURITY_LEAD.value}:
        typer.echo(f"Invalid role '{role}'. Use 'analyst' or 'security_lead'.", err=True)
        raise typer.Exit(code=1)

    _ensure_api_key_pepper()

    # Deferred imports: these transitively construct Settings()/the DB engine
    # (see seclab.core.db), which must only happen *after*
    # _ensure_api_key_pepper() has had a chance to write a real pepper -
    # importing them at module load time would crash `seclab --help` itself
    # on a fresh checkout with no .env yet.
    from seclab.core.config import get_settings
    from seclab.core.db import SessionLocal, init_db

    # get_settings() is @lru_cache'd - if anything in this process already
    # called it before _ensure_api_key_pepper() ran, clear the stale cache
    # so this call picks up the pepper that was just written.
    get_settings.cache_clear()
    settings = get_settings()

    import seclab.security.models  # noqa: F401  (register core tables before init_db)

    from seclab_cli.users import create_user_record

    init_db()

    with SessionLocal() as db:
        try:
            user, raw_key = create_user_record(username, role, settings, db)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=1) from None

    typer.echo("")
    typer.echo(f"Lab initialized. User '{user.username}' created (role={role}).")
    typer.echo(f"API key (store securely, shown once): {raw_key}")
    typer.echo("")
    typer.echo("Next steps:")
    typer.echo("  uvicorn seclab_gateway.main:app --reload --app-dir apps/gateway/src")
    typer.echo("  cd apps/web && npm install && npm run dev")
    typer.echo('Then paste the API key into the dashboard\'s "Set API key" control.')
