from seclab_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_top_level_help_lists_every_module_subcommand():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ["users", "phantom", "recon", "monitor", "init"]:
        assert name in result.stdout


def test_users_create_prints_api_key_once():
    result = runner.invoke(app, ["users", "create", "test-analyst"])
    assert result.exit_code == 0
    assert "Created user 'test-analyst'" in result.stdout
    assert "API key" in result.stdout


def test_users_create_rejects_duplicate_username():
    runner.invoke(app, ["users", "create", "dup-user"])
    result = runner.invoke(app, ["users", "create", "dup-user"])
    assert result.exit_code == 1


def test_create_user_record_rejects_duplicate_username():
    from seclab.core.config import get_settings
    from seclab.core.db import SessionLocal, init_db
    from seclab_cli.users import create_user_record

    import seclab.security.models  # noqa: F401  (register core tables before init_db)

    init_db()
    settings = get_settings()

    with SessionLocal() as db:
        create_user_record("record-dup-user", "analyst", settings, db)

        try:
            create_user_record("record-dup-user", "analyst", settings, db)
        except ValueError as exc:
            assert "already exists" in str(exc)
        else:
            raise AssertionError("expected ValueError for duplicate username")


def test_phantom_analyze_offline_via_cli():
    result = runner.invoke(app, ["phantom", "analyze", "acme", "--target-type", "brand"])
    assert result.exit_code == 0
    assert "# PhantomScope Report" in result.stdout
