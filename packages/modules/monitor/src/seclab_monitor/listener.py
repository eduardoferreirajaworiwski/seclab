from __future__ import annotations

import asyncio
import logging
from typing import Any

import certstream
from seclab.core.config import Settings, get_settings
from seclab.core.events import EventBus, get_event_bus

from seclab_monitor.capture import CaptureWorker
from seclab_monitor.config import MonitorSettings, get_monitor_settings
from seclab_monitor.pipeline import MatchPipeline

logger = logging.getLogger("seclab.monitor.listener")


def _extract_matches(message: dict[str, Any], keywords: list[str]) -> list[tuple[str, str, str]]:
    """Pure keyword-matching logic, factored out for unit testing without a
    live CertStream connection."""
    if message.get("message_type") != "certificate_update":
        return []

    leaf_cert = message["data"]["leaf_cert"]
    all_domains = leaf_cert.get("all_domains", [])
    issuer = leaf_cert.get("issuer", {}).get("O", "unknown")

    matches: list[tuple[str, str, str]] = []
    for domain in all_domains:
        domain_lower = domain.lower()
        for keyword in keywords:
            if keyword in domain_lower:
                # hydra-mapper's original used domain.lstrip("*.") here, which
                # strips a *character set* (any leading '*'/'.' chars), not
                # the literal "*." prefix - removeprefix is the correct fix.
                clean_domain = domain.removeprefix("*.")
                matches.append((clean_domain, issuer, keyword))
                break
    return matches


class CertStreamMonitor:
    """Runs certstream's blocking listen_for_events() in a background
    thread (it manages its own websocket loop, not asyncio-native) and
    dispatches matches back onto the main asyncio event loop via
    run_coroutine_threadsafe, where each match gets its own short-lived DB
    session and flows through MatchPipeline."""

    def __init__(
        self,
        settings: Settings | None = None,
        monitor_settings: MonitorSettings | None = None,
        event_bus: EventBus | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.monitor_settings = monitor_settings or get_monitor_settings()
        self.event_bus = event_bus or get_event_bus()
        self.capture = CaptureWorker(
            navigation_timeout_ms=self.monitor_settings.capture_navigation_timeout_ms
        )
        self._loop: asyncio.AbstractEventLoop | None = None

    def _on_message(self, message: dict[str, Any], _context: Any) -> None:
        if message.get("message_type") == "heartbeat":
            return
        matches = _extract_matches(message, self.monitor_settings.keywords)
        for domain, issuer, keyword in matches:
            logger.info(
                "ct_match_found", extra={"domain": domain, "issuer": issuer, "keyword": keyword}
            )
            if self._loop is not None:
                asyncio.run_coroutine_threadsafe(
                    self._handle_match(domain, issuer, keyword), self._loop
                )

    async def _handle_match(self, domain: str, issuer: str, keyword: str) -> None:
        from seclab.core.db import SessionLocal

        session = SessionLocal()
        try:
            pipeline = MatchPipeline(
                session, self.settings, self.monitor_settings, self.capture, self.event_bus
            )
            await pipeline.handle_match(domain, issuer, keyword)
        except Exception:
            logger.exception("match_pipeline_failed", extra={"domain": domain})
        finally:
            session.close()

    async def run(self) -> None:
        self._loop = asyncio.get_running_loop()
        await self.capture.start()
        try:
            await asyncio.to_thread(
                certstream.listen_for_events,
                self._on_message,
                url=self.monitor_settings.certstream_url,
            )
        finally:
            await self.capture.stop()
