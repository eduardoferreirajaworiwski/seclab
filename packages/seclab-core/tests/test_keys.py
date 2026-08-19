import hashlib

from seclab.core.config import Settings
from seclab.security.keys import generate_api_key, hash_api_key, verify_api_key


def _settings(pepper: str = "pepper-a") -> Settings:
    return Settings(api_key_pepper=pepper, database_url="sqlite:///:memory:")


def test_generated_key_is_high_entropy_and_url_safe():
    key = generate_api_key()
    assert len(key) >= 32
    assert " " not in key


def test_hash_is_not_plain_unsalted_sha256():
    key = generate_api_key()
    settings = _settings()
    plain_sha256 = hashlib.sha256(key.encode("utf-8")).hexdigest()
    assert hash_api_key(key, settings) != plain_sha256


def test_hash_round_trips_with_verify():
    key = generate_api_key()
    settings = _settings()
    digest = hash_api_key(key, settings)
    assert verify_api_key(key, digest, settings)
    assert not verify_api_key("wrong-key", digest, settings)


def test_different_pepper_produces_different_hash():
    key = generate_api_key()
    digest_a = hash_api_key(key, _settings("pepper-a"))
    digest_b = hash_api_key(key, _settings("pepper-b"))
    assert digest_a != digest_b
