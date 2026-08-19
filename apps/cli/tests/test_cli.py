from seclab_cli.main import app
from typer.testing import CliRunner

runner = CliRunner()


def test_top_level_help_lists_every_module_subcommand():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for name in ["users", "phantom", "recon", "monitor"]:
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


def test_phantom_analyze_offline_via_cli():
    result = runner.invoke(app, ["phantom", "analyze", "acme", "--target-type", "brand"])
    assert result.exit_code == 0
    assert "# PhantomScope Report" in result.stdout
