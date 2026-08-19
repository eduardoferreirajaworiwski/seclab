from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TypeVar

T = TypeVar("T")


@dataclass
class ProviderRegistration:
    live: Any
    mock: Any


@dataclass
class ProviderRegistry:
    """Central live/mock provider registry.

    Any module registers its adapters here under a namespaced key
    (e.g. "phantom.ctlog", "osint_breach.hibp"). Resolution honors
    Settings.offline_mode so the whole lab can run/test with zero network
    by flipping a single flag, mirroring phantomscope's providers/mock_data.py
    live/mock swap.
    """

    _providers: dict[str, ProviderRegistration] = field(default_factory=dict)

    def register(self, key: str, *, live: Any, mock: Any) -> None:
        self._providers[key] = ProviderRegistration(live=live, mock=mock)

    def resolve(self, key: str, *, offline: bool) -> Any:
        try:
            registration = self._providers[key]
        except KeyError as exc:
            raise KeyError(f"no provider registered for {key!r}") from exc
        return registration.mock if offline else registration.live

    def keys(self) -> list[str]:
        return sorted(self._providers.keys())


_registry = ProviderRegistry()


def get_registry() -> ProviderRegistry:
    return _registry
