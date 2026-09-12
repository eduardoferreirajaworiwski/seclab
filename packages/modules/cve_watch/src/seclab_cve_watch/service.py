from __future__ import annotations

import logging

from seclab.core.config import Settings
from sqlalchemy.orm import Session

from seclab_cve_watch.db import CveDigestRepository
from seclab_cve_watch.models import DigestListItem, DigestRequest, DigestResult, DigestSummary
from seclab_cve_watch.reporting import build_markdown_report
from seclab_cve_watch.sources import CveIngestionService
from seclab_cve_watch.tagging import tag_cve

logger = logging.getLogger(__name__)


class CveWatchService:
    def __init__(self, settings: Settings, db: Session) -> None:
        self.settings = settings
        self.repository = CveDigestRepository(db)

    async def run_digest(self, request: DigestRequest) -> DigestResult:
        offline_mode = (
            self.settings.offline_mode if request.offline_mode is None else request.offline_mode
        )
        ingestion = CveIngestionService(self.settings, offline_mode=offline_mode)
        cves = await ingestion.fetch_all()

        tagged_cves = []
        for cve in cves:
            signals, matched_products = tag_cve(cve, request.watched_products)
            merged_products = list(dict.fromkeys(cve.matched_products + matched_products))
            tagged_cves.append(
                cve.model_copy(
                    update={"match_signals": signals, "matched_products": merged_products}
                )
            )

        summary = _build_deterministic_summary(tagged_cves)

        draft = DigestResult(
            lookback_days=request.lookback_days,
            cves=tagged_cves,
            summary=summary,
            report_markdown="",
            metadata={
                "offline_mode": offline_mode,
                "cve_count": len(tagged_cves),
                "actively_exploited_count": sum(
                    1 for c in tagged_cves if c.is_actively_exploited
                ),
            },
        )
        result = draft.model_copy(update={"report_markdown": build_markdown_report(draft)})
        self.repository.save(result)
        logger.info(
            "cve_watch_digest_completed",
            extra={"digest_id": result.digest_id, "cve_count": len(tagged_cves)},
        )
        return result

    def get_digest(self, digest_id: str) -> DigestResult | None:
        return self.repository.get(digest_id)

    def list_recent_digests(self, limit: int = 10) -> list[DigestListItem]:
        return self.repository.list_recent(limit=limit)


def _build_deterministic_summary(cves: list) -> DigestSummary:
    exploited = [cve for cve in cves if cve.is_actively_exploited]
    watchlisted = [cve for cve in cves if cve.matched_products]

    headline = (
        f"{len(cves)} CVE(s) reviewed; {len(exploited)} actively exploited (CISA KEV)"
        if cves
        else "No CVEs retrieved this run"
    )
    executive_summary = (
        f"CVE Watch reviewed {len(cves)} CVE(s) from NVD and CISA KEV. "
        f"{len(exploited)} are known to be actively exploited per CISA KEV, and "
        f"{len(watchlisted)} matched the configured product/vendor watchlist."
    )
    exploited_highlights = [
        f"{cve.cve_id} - {cve.description or 'no description available'}"
        for cve in exploited[:5]
    ] or ["No actively-exploited CVEs this run."]
    watchlist_matches = [
        f"{cve.cve_id} matched: {', '.join(cve.matched_products)}" for cve in watchlisted[:5]
    ] or ["No watchlist matches this run."]
    recommended_actions = [
        "Prioritize patching for any CVE flagged as actively exploited (CISA KEV).",
        "Cross-check watchlist matches against your own asset inventory for exposure.",
        "Review CVSS scores above 9.0 for emergency patch scheduling.",
    ]
    grounding_notes = [
        "Watchlist tags are deterministic keyword matches, not a machine-learning classification.",
        "is_actively_exploited reflects presence in the CISA KEV catalog only.",
    ]
    return DigestSummary(
        headline=headline,
        executive_summary=executive_summary,
        exploited_highlights=exploited_highlights,
        watchlist_matches=watchlist_matches,
        recommended_actions=recommended_actions,
        grounding_notes=grounding_notes,
        model_source="deterministic",
    )
