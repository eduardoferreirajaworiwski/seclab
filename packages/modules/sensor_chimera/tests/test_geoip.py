import httpx
import pytest
from seclab.core.config import Settings
from seclab.core.http import HttpProvider
from seclab_sensor_chimera.geoip import _MAX_CACHE_ENTRIES, GeoIpLookup


def _settings() -> Settings:
    return Settings(api_key_pepper="test-pepper-not-for-prod", database_url="sqlite:///:memory:")


class _AllowAll:
    def check(self, url: str) -> str:
        return "1.2.3.4"


def _provider() -> HttpProvider:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"country_name": "Testland", "org": "Test ISP"})

    return HttpProvider(
        _settings(), egress_policy=_AllowAll(), transport=httpx.MockTransport(handler)
    )


@pytest.mark.asyncio
async def test_lookup_caches_result_for_repeat_ip():
    geo = GeoIpLookup(_provider())
    first = await geo.lookup("203.0.113.1")
    assert first["country"] == "Testland"
    assert len(geo._cache) == 1

    second = await geo.lookup("203.0.113.1")
    assert second == first
    assert len(geo._cache) == 1


@pytest.mark.asyncio
async def test_cache_is_bounded_across_many_distinct_source_ips():
    # A honeypot sees requests from arbitrary, attacker-controlled source
    # IPs - an unbounded dict here would let a scanner grow this cache
    # without limit.
    geo = GeoIpLookup(_provider())
    for i in range(_MAX_CACHE_ENTRIES + 50):
        await geo.lookup(f"203.0.113.{i % 250}.{i}")

    assert len(geo._cache) <= _MAX_CACHE_ENTRIES
