import socket

import httpx
import pytest
from seclab.core.config import Settings
from seclab.core.http import EgressBlockedError, HttpProvider


def _settings() -> Settings:
    return Settings(api_key_pepper="test-pepper-not-for-prod", database_url="sqlite:///:memory:")


def _mock_getaddrinfo(monkeypatch, ip: str) -> None:
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *args, **kwargs: [(None, None, None, None, (ip, 0))]
    )


@pytest.mark.asyncio
async def test_get_json_connects_to_the_validated_ip_and_preserves_the_original_host(monkeypatch):
    _mock_getaddrinfo(monkeypatch, "93.184.216.34")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["host_header"] = request.headers.get("host")
        captured["sni_hostname"] = request.extensions.get("sni_hostname")
        return httpx.Response(200, json={"ok": True})

    provider = HttpProvider(_settings(), transport=httpx.MockTransport(handler))
    result = await provider.get_json("https://example.com/api")

    assert result == {"ok": True}
    # The connection itself goes to the validated IP, not a hostname httpx
    # would resolve again on its own - this is the TOCTOU fix.
    assert captured["url"] == "https://93.184.216.34/api"
    # ...while the origin still sees the real hostname, both for virtual
    # hosting (Host header) and TLS certificate verification (SNI).
    assert captured["host_header"] == "example.com"
    assert captured["sni_hostname"] == "example.com"


@pytest.mark.asyncio
async def test_get_json_blocks_before_any_request_reaches_a_private_destination(monkeypatch):
    _mock_getaddrinfo(monkeypatch, "10.0.0.5")
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, json={})

    provider = HttpProvider(_settings(), transport=httpx.MockTransport(handler))

    with pytest.raises(EgressBlockedError):
        await provider.get_json("https://internal.example.com/")

    assert called is False


@pytest.mark.asyncio
async def test_post_json_also_connects_to_the_validated_ip(monkeypatch):
    _mock_getaddrinfo(monkeypatch, "93.184.216.34")
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["host_header"] = request.headers.get("host")
        return httpx.Response(200, json={"ok": True})

    provider = HttpProvider(_settings(), transport=httpx.MockTransport(handler))
    result = await provider.post_json("https://example.com/webhook", {"a": 1})

    assert result == {"ok": True}
    assert captured["url"] == "https://93.184.216.34/webhook"
    assert captured["host_header"] == "example.com"
