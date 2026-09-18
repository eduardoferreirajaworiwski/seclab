from pathlib import Path

from seclab_cli.init import _ensure_api_key_pepper


def test_creates_env_with_generated_pepper_when_missing(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    assert not env_path.exists()

    _ensure_api_key_pepper(env_path)

    content = env_path.read_text()
    assert "SECLAB_API_KEY_PEPPER=" in content
    pepper = next(
        line.split("=", 1)[1] for line in content.splitlines() if line.startswith("SECLAB_API_KEY_PEPPER=")
    )
    assert pepper and pepper != "change-me-in-.env"


def test_replaces_placeholder_pepper(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("SOME_OTHER_VAR=1\nSECLAB_API_KEY_PEPPER=change-me-in-.env\n")

    _ensure_api_key_pepper(env_path)

    content = env_path.read_text()
    assert "SOME_OTHER_VAR=1" in content
    pepper = next(
        line.split("=", 1)[1] for line in content.splitlines() if line.startswith("SECLAB_API_KEY_PEPPER=")
    )
    assert pepper != "change-me-in-.env"


def test_leaves_real_pepper_untouched(tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("SECLAB_API_KEY_PEPPER=already-a-real-secret-value\n")

    _ensure_api_key_pepper(env_path)

    assert env_path.read_text() == "SECLAB_API_KEY_PEPPER=already-a-real-secret-value\n"
