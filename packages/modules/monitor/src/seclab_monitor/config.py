from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitorSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="SECLAB_MONITOR_", extra="ignore")

    keywords: list[str] = Field(
        default_factory=lambda: ["microsoft", "google", "binance", "netflix"]
    )
    certstream_url: str = "wss://certstream.calidog.io/"
    capture_enabled: bool = True
    capture_artifact_dir: str = "./data/monitor-captures"
    capture_navigation_timeout_ms: int = 30_000


@lru_cache(maxsize=1)
def get_monitor_settings() -> MonitorSettings:
    return MonitorSettings()
