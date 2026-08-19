from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    api_key_pepper: SecretStr = Field(default=SecretStr("change-me-in-.env"))

    crtsh_base_url: str = "https://crt.sh/"
    rdap_base_url: str = "https://rdap.org/domain/"
    rdap_ip_base_url: str = "https://rdap.org/ip/"

    openai_api_key: SecretStr | None = Field(default=None)
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4.1-mini"

    discord_webhook_url: SecretStr | None = Field(default=None)

    certstream_url: str = "wss://certstream.calidog.io/"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
