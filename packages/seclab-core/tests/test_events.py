import json

import httpx
import pytest
from seclab.core.config import Settings
from seclab.core.events import DiscordSink, Event
from seclab.core.http import HttpProvider


def _settings() -> Settings:
    return Settings(api_key_pepper="test-pepper-not-for-prod", database_url="sqlite:///:memory:")


class _AllowAll:
    """Bypasses EgressPolicy's real DNS resolution so these tests are
    deterministic offline - what's under test here is the payload the
    DiscordSink builds, not egress policy (covered in test_http_egress.py)."""

    def check(self, url: str) -> str:
        return "1.2.3.4"


def _sink_and_capture():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["payload"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True})

    provider = HttpProvider(
        _settings(), egress_policy=_AllowAll(), transport=httpx.MockTransport(handler)
    )
    return DiscordSink(provider, "https://discord.com/api/webhooks/test"), captured


@pytest.mark.asyncio
async def test_emit_sets_allowed_mentions_to_suppress_pings():
    sink, captured = _sink_and_capture()
    event = Event(source="sensor_chimera", kind="trap_triggered", summary="hit", severity="info")

    await sink.emit(event)

    assert captured["payload"]["allowed_mentions"] == {"parse": []}


@pytest.mark.asyncio
async def test_emit_escapes_mention_and_markdown_syntax_in_summary():
    sink, captured = _sink_and_capture()
    event = Event(
        source="sensor_chimera",
        kind="trap_triggered",
        summary="Suspicious hit on /@everyone from 1.2.3.4 __bold__ *text*",
        severity="critical",
    )

    await sink.emit(event)

    description = captured["payload"]["embeds"][0]["description"]
    # The text is preserved, only escaped - Discord renders a literal "@"
    # instead of triggering mention-highlight styling or **/__ formatting.
    assert "\\@everyone" in description
    assert "__bold__" not in description
    assert "\\_\\_bold\\_\\_" in description
    assert "*text*" not in description
    assert "\\*text\\*" in description


@pytest.mark.asyncio
async def test_emit_sanitizes_backtick_in_field_value_so_it_cannot_escape_the_code_span():
    sink, captured = _sink_and_capture()
    event = Event(
        source="sensor_chimera",
        kind="trap_triggered",
        summary="hit",
        severity="warning",
        payload={"user_agent": "evil`**pwned**`agent"},
    )

    await sink.emit(event)

    field_value = captured["payload"]["embeds"][0]["fields"][0]["value"]
    assert "`" not in field_value.strip("`")
