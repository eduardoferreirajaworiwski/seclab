from functools import lru_cache

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_API_KEY_PEPPER = "change-me-in-.env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECLAB_", extra="ignore")

    env: str = "dev"
    version: str = "0.1.0"
    log_level: str = "INFO"
    offline_mode: bool = True

    app_host: str = "127.0.0.1"
    app_port: int = 8000

    database_url: str = "sqlite:///./seclab.db"

    http_timeout: float = 10.0
    http_retries: int = 2
    user_agent: str = "SecLab/0.1 (+personal-security-lab)"

    # Egress policy: hosts allowed to be contacted by the shared HTTP client.
    # Empty list means "no restriction beyond the private-range/redirect guard".
    http_egress_allowlist: list[str] = Field(default_factory=list)

    cors_allow_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    rate_limit_default: str = "60/minute"

    api_key_pepper: SecretStr = Field(default=SecretStr(DEFAULT_API_KEY_PEPPER))

    crtsh_base_url: str = "https://crt.sh/"
    rdap_base_url: str = "https://rdap.org/domain/"
    rdap_ip_base_url: str = "https://rdap.org/ip/"

    openai_api_key: SecretStr | None = Field(default=None)
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4.1-mini"

    gemini_api_key: SecretStr | None = Field(default=None)
    gemini_base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    gemini_model: str = "gemini-2.0-flash"


    discord_webhook_url: SecretStr | None = Field(default=None)

    certstream_url: str = "wss://certstream.calidog.io/"

    @model_validator(mode="after")
    def _reject_default_pepper(self) -> "Settings":
        # Every api_key_hash is HMAC(pepper, raw_key) (see seclab.security.keys)
        # - the whole point of the pepper is that it's a secret unknown to
        # anyone who only has DB access. Silently starting with the shipped
        # placeholder makes every hash forgeable by anyone who reads this
        # file, defeating that guarantee. Set a real value:
        #   python -c "import secrets; print(secrets.token_urlsafe(32))"
        if self.api_key_pepper.get_secret_value() == DEFAULT_API_KEY_PEPPER:
            raise ValueError(
                "SECLAB_API_KEY_PEPPER is unset or still the default placeholder. "
                "Set a real secret (see .env.example) before starting."
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
