from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

logger = logging.getLogger("seclab.events")


@dataclass
class Event:
    source: str
    kind: str
    summary: str
    severity: str = "info"
    payload: dict[str, Any] = field(default_factory=dict)
    occurred_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())


class EventSink(Protocol):
    async def emit(self, event: Event) -> None: ...


class LogSink:
    """Always-on sink: every event is at minimum written to structured logs."""

    async def emit(self, event: Event) -> None:
        logger.info(
            event.summary,
            extra={
                "event_source": event.source,
                "event_kind": event.kind,
                "event_severity": event.severity,
                "event_payload": event.payload,
            },
        )


class DiscordSink:
    """Generalized version of project-chimera's send_discord_alert, with the
    missing error handling added so a webhook outage can never crash a caller
    (chimera_listener.py's original post() had no try/except)."""

    def __init__(self, http: HttpProvider, webhook_url: str) -> None:
        self._http = http
        self._webhook_url = webhook_url

    async def emit(self, event: Event) -> None:
        color = {"critical": 15548997, "warning": 16705372}.get(event.severity, 3901635)
        fields = [
            {"name": key, "value": f"`{value}`", "inline": True}
            for key, value in list(event.payload.items())[:10]
        ]
        payload = {
            "embeds": [
                {
                    "title": f"[{event.severity.upper()}] {event.source}/{event.kind}",
                    "description": event.summary,
                    "color": color,
                    "fields": fields,
                    "footer": {"text": event.occurred_at},
                }
            ]
        }
        try:
            await self._http.post_json(self._webhook_url, payload)
        except Exception:
            logger.exception("discord_sink_failed", extra={"event_source": event.source})


class EventBus:
    def __init__(self, sinks: list[EventSink] | None = None) -> None:
        self._sinks: list[EventSink] = sinks or [LogSink()]

    def register(self, sink: EventSink) -> None:
        self._sinks.append(sink)

    async def publish(self, event: Event) -> None:
        for sink in self._sinks:
            try:
                await sink.emit(event)
            except Exception:
                logger.exception("event_sink_failed", extra={"sink": type(sink).__name__})


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


def configure_event_bus(settings: Settings, http: HttpProvider) -> EventBus:
    global _bus
    sinks: list[EventSink] = [LogSink()]
    if settings.discord_webhook_url is not None:
        webhook = settings.discord_webhook_url.get_secret_value()
        if webhook and "your_webhook" not in webhook:
            sinks.append(DiscordSink(http, webhook))
    _bus = EventBus(sinks)
    return _bus
