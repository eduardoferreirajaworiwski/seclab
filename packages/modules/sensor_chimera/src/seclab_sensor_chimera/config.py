from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ChimeraSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECLAB_CHIMERA_", extra="ignore")

    version: str = "1.0.0"
    allowed_hosts: list[str] = Field(default_factory=lambda: ["*"])
    cors_allow_origins: list[str] = Field(default_factory=lambda: ["*"])
    max_request_body_bytes: int = 1024 * 50
    tarpit_min_seconds: int = 5
    tarpit_max_seconds: int = 15
    rate_limit: str = "5/minute"
    port: int = 8000


@lru_cache(maxsize=1)
def get_chimera_settings() -> ChimeraSettings:
    return ChimeraSettings()
