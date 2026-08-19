from __future__ import annotations

import logging
import time
from collections import OrderedDict

from seclab.core.http import HttpProvider

logger = logging.getLogger("seclab.sensor_chimera")

_CACHE_TTL_SECONDS = 300
_MAX_FIELD_LEN = 80
_MAX_CACHE_ENTRIES = 2048


class GeoIpLookup:
    """Fixes two issues from the original project-chimera's get_geoip():
    it called plaintext http://ip-api.com on every single request with no
    caching and trusted the response body as-is. This version uses an
    HTTPS-native provider (ipapi.co) through the shared egress-checked HTTP
    client, caches per-IP for a few minutes, and clamps every field it
    reads before the value is ever embedded in a log line or Discord embed.

    The cache is bounded (LRU, _MAX_CACHE_ENTRIES) rather than a plain dict:
    this runs inside sensor_chimera, a honeypot deliberately exposed on the
    open internet, so an unbounded per-source-IP cache is itself a resource
    an attacker or scanner sending requests from many distinct IPs could
    grow without limit.
    """

    def __init__(self, http: HttpProvider, base_url: str = "https://ipapi.co/{ip}/json/") -> None:
        self._http = http
        self._base_url = base_url
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    async def lookup(self, ip: str) -> dict:
        cached = self._cache.get(ip)
        if cached and (time.monotonic() - cached[0]) < _CACHE_TTL_SECONDS:
            self._cache.move_to_end(ip)
            return cached[1]

        try:
            raw = await self._http.get_json(self._base_url.format(ip=ip))
        except Exception as exc:
            logger.warning("geoip_lookup_failed", extra={"ip": ip, "error": str(exc)})
            return {}

        if not isinstance(raw, dict):
            return {}

        result = {
            "country": _clamp(raw.get("country_name")),
            "countryCode": _clamp(raw.get("country_code", ""))[:2].lower(),
            "city": _clamp(raw.get("city")),
            "isp": _clamp(raw.get("org")),
        }
        self._cache[ip] = (time.monotonic(), result)
        self._cache.move_to_end(ip)
        if len(self._cache) > _MAX_CACHE_ENTRIES:
            self._cache.popitem(last=False)
        return result


def _clamp(value: object) -> str:
    if not isinstance(value, str):
        return "Unknown"
    cleaned = "".join(ch for ch in value if ch.isprintable())
    return cleaned[:_MAX_FIELD_LEN] or "Unknown"
