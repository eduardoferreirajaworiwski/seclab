from __future__ import annotations

import logging
from datetime import UTC, datetime

from seclab.core.config import Settings
from seclab.core.events import Event, EventBus
from seclab.security.evidence import EvidenceStore
from seclab_phantom.models import DomainVariation
from seclab_phantom.providers import CompositeEnrichmentProvider
from seclab_phantom.scoring import score_asset
from sqlalchemy.orm import Session

from seclab_monitor.capture import CaptureResult, CaptureWorker, write_artifact
from seclab_monitor.config import MonitorSettings
from seclab_monitor.models import MonitorMatch

logger = logging.getLogger("seclab.monitor.pipeline")

MODULE = "monitor"


class MatchPipeline:
    """Turns a raw CertStream keyword match into a scored, evidenced record
    by reusing seclab_phantom's own enrichment + scoring - the same
    pipeline an on-demand `phantom` analysis uses - instead of hydra-mapper's
    original bare "print the match" behavior."""

    def __init__(
        self,
        db: Session,
        settings: Settings,
        monitor_settings: MonitorSettings,
        capture: CaptureWorker,
        event_bus: EventBus,
    ) -> None:
        self.db = db
        self.settings = settings
        self.monitor_settings = monitor_settings
        self.capture = capture
        self.event_bus = event_bus
        self.evidence = EvidenceStore(db)
        self.enrichment_provider = CompositeEnrichmentProvider(
            settings, offline_mode=settings.offline_mode
        )

    async def handle_match(self, domain: str, issuer: str, matched_keyword: str) -> MonitorMatch:
        variation = DomainVariation(
            domain=domain, technique="live-ct-match", source_target=matched_keyword
        )
        infrastructure = await self.enrichment_provider.enrich(domain)
        score, priority, signals, rationale = score_asset(variation, [], infrastructure)

        match = MonitorMatch(
            domain=domain,
            issuer=issuer,
            matched_keyword=matched_keyword,
            technique="live-ct-match",
            score=score,
            priority=priority,
            score_rationale=rationale,
            capture_status="skipped",
        )
        self.db.add(match)
        self.db.flush()

        self.evidence.store(
            source_module=MODULE,
            subject_type="domain",
            subject_id=domain,
            evidence_type="ct_match_scoring",
            content=rationale,
            metadata={
                "score": score,
                "priority": priority,
                "signals": [s.model_dump(mode="json") for s in signals],
            },
        )

        if self.monitor_settings.capture_enabled:
            await self._capture_and_store(match, domain)

        self.db.commit()

        severity_by_priority = {"high": "critical", "medium": "warning"}
        severity = severity_by_priority.get(priority, "info")
        summary = (
            f"CT match for keyword '{matched_keyword}': {domain} "
            f"(score={score}, priority={priority})"
        )
        await self.event_bus.publish(
            Event(
                source=MODULE,
                kind="ct_match",
                summary=summary,
                severity=severity,
                payload={"domain": domain, "issuer": issuer, "score": score, "priority": priority},
            )
        )
        return match

    async def _capture_and_store(self, match: MonitorMatch, domain: str) -> None:
        result: CaptureResult = await self.capture.capture(domain)
        match.capture_status = result.status
        if result.status != "captured":
            return

        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        safe_name = domain.replace("*", "wildcard").replace("/", "_")

        if result.screenshot_bytes:
            path = write_artifact(
                self.monitor_settings.capture_artifact_dir,
                f"{safe_name}_{timestamp}.png",
                result.screenshot_bytes,
            )
            self.evidence.store_bytes(
                source_module=MODULE,
                subject_type="domain",
                subject_id=domain,
                evidence_type="screenshot",
                raw=result.screenshot_bytes,
                artifact_uri=path,
            )
        if result.html_content:
            self.evidence.store(
                source_module=MODULE,
                subject_type="domain",
                subject_id=domain,
                evidence_type="html_dump",
                content=result.html_content,
            )
