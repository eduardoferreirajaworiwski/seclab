import hashlib
import hmac
import secrets

from seclab.core.config import Settings


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def hash_api_key(raw_key: str, settings: Settings) -> str:
    """HMAC-SHA256 with a server-side pepper.

    Fixes scopepilot's original app/core/security.py, which hashed API keys
    with plain, unsalted hashlib.sha256() - a lookup-table/rainbow-table risk
    if the DB ever leaks. Keying the hash with a pepper that lives only in
    Settings (never in the DB) means a DB-only leak can't be used to forge
    or precompute valid key hashes.
    """
    pepper = settings.api_key_pepper.get_secret_value().encode("utf-8")
    return hmac.new(pepper, raw_key.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_api_key(raw_key: str, expected_hash: str, settings: Settings) -> bool:
    return hmac.compare_digest(hash_api_key(raw_key, settings), expected_hash)
