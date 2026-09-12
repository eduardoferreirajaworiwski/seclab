from __future__ import annotations

import logging

from seclab.core.config import Settings
from sqlalchemy.orm import Session

from seclab_osint_breach.db import BreachCheckRepository
from seclab_osint_breach.models import (
    BreachCheckListItem,
    BreachCheckRequest,
    BreachCheckResult,
    BreachExposure,
    BreachSummary,
)
from seclab_osint_breach.reporting import build_markdown_report
from seclab_osint_breach.sources import BreachLookupService

logger = logging.getLogger(__name__)


class BreachCheckService:
    def __init__(self, settings: Settings, db: Session) -> None:
        self.settings = settings
        self.repository = BreachCheckRepository(db)

    async def run_check(self, request: BreachCheckRequest) -> BreachCheckResult:
        offline_mode = (
            self.settings.offline_mode if request.offline_mode is None else request.offline_mode
        )
        lookup = BreachLookupService(self.settings, offline_mode=offline_mode)
        exposures = await lookup.check_all(request.identifiers)

        summary = _build_deterministic_summary(request.identifiers, exposures)

        draft = BreachCheckResult(
            identifiers_checked=request.identifiers,
            exposures=exposures,
            summary=summary,
            report_markdown="",
            metadata={
                "offline_mode": offline_mode,
                "identifier_count": len(request.identifiers),
                "exposure_count": len(exposures),
            },
        )
        result = draft.model_copy(update={"report_markdown": build_markdown_report(draft)})
        self.repository.save(result)
        logger.info(
            "osint_breach_check_completed",
            extra={
                "check_id": result.check_id,
                "identifier_count": len(request.identifiers),
                "exposure_count": len(exposures),
            },
        )
        return result

    def get_check(self, check_id: str) -> BreachCheckResult | None:
        return self.repository.get(check_id)

    def list_recent_checks(self, limit: int = 10) -> list[BreachCheckListItem]:
        return self.repository.list_recent(limit=limit)


def _build_deterministic_summary(
    identifiers: list, exposures: list[BreachExposure]
) -> BreachSummary:
    by_breach: dict[str, int] = {}
    for exposure in exposures:
        by_breach[exposure.breach_name] = by_breach.get(exposure.breach_name, 0) + 1
    ranked_breaches = sorted(by_breach.items(), key=lambda kv: kv[1], reverse=True)

    headline = (
        f"{len(identifiers)} identifier(s) checked; {len(exposures)} exposure(s) found "
        f"across {len(by_breach)} breach(es)"
        if exposures
        else f"{len(identifiers)} identifier(s) checked; no exposures found"
    )
    executive_summary = (
        f"OSINT Breach Watch checked {len(identifiers)} watched identifier(s) against breach "
        f"data. {len(exposures)} exposure(s) were found across {len(by_breach)} distinct "
        "breach(es)."
    )
    exposure_breakdown = [f"{name}: {count} exposure(s)" for name, count in ranked_breaches] or [
        "No exposures found this run."
    ]
    notable_exposures = [
        f"{exposure.identifier} in {exposure.breach_name} "
        f"({', '.join(exposure.data_classes) or 'unknown data classes'})"
        for exposure in exposures[:5]
    ] or ["No exposures found this run."]
    recommended_actions = [
        "Rotate credentials for any identifier found in a breach that exposed passwords.",
        "Enable MFA on any account tied to an exposed identifier, if not already enabled.",
        "Cross-check exposed domains against your own asset inventory for related accounts.",
    ]
    grounding_notes = [
        "Exposures reflect only the configured data source(s) (offline fixture set and/or "
        "Have I Been Pwned); absence of a hit is not proof of no exposure.",
        "This summary is deterministic, not AI-generated.",
    ]
    return BreachSummary(
        headline=headline,
        executive_summary=executive_summary,
        exposure_breakdown=exposure_breakdown,
        notable_exposures=notable_exposures,
        recommended_actions=recommended_actions,
        grounding_notes=grounding_notes,
        model_source="deterministic",
    )
