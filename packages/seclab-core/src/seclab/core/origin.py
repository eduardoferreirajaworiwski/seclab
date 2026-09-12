from __future__ import annotations

from enum import StrEnum


class DataOrigin(StrEnum):
    """Indicates whether a finding came from a live provider call, an
    offline fixture, or a fallback path taken after a live call failed.
    Shared across every module that distinguishes live data from offline
    fixtures (phantom, monitor, threatlens, osint_breach, ...)."""

    LIVE = "live"
    MOCK = "mock"
    FALLBACK = "fallback"
