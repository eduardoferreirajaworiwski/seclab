import pytest
from pydantic import ValidationError
from seclab.core.config import Settings


def test_default_api_key_pepper_is_rejected(monkeypatch):
    # conftest.py sets SECLAB_API_KEY_PEPPER for every other test in this
    # suite; unset it here to exercise the actual "nothing configured" path.
    monkeypatch.delenv("SECLAB_API_KEY_PEPPER", raising=False)
    with pytest.raises(ValidationError, match="SECLAB_API_KEY_PEPPER"):
        Settings(database_url="sqlite:///:memory:", _env_file=None)


def test_explicit_default_pepper_value_is_also_rejected():
    with pytest.raises(ValidationError, match="SECLAB_API_KEY_PEPPER"):
        Settings(api_key_pepper="change-me-in-.env", database_url="sqlite:///:memory:")


def test_real_pepper_is_accepted():
    settings = Settings(api_key_pepper="a-real-secret", database_url="sqlite:///:memory:")
    assert settings.api_key_pepper.get_secret_value() == "a-real-secret"
