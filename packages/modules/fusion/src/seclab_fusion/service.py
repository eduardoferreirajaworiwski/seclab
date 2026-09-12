from __future__ import annotations

from seclab_cve_watch.db import CveDigestRepository
from seclab_monitor.models import MonitorMatch
from seclab_threatlens.db import DigestRepository
from sqlalchemy import select
from sqlalchemy.orm import Session

from seclab_fusion.correlation import correlate
from seclab_fusion.models import FusionFeedResponse

DEFAULT_MONITOR_LIMIT = 100
DEFAULT_FEED_LIMIT = 20


class FusionService:
    """Thin read-only aggregator: no own persistence. Pulls recent data
    straight from monitor/threatlens/cve_watch's existing tables/
    repositories via the shared `db` Session, joins it in Python
    (correlation.correlate), and computes the feed fresh every call."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def get_feed(
        self, *, limit: int = DEFAULT_FEED_LIMIT, monitor_limit: int = DEFAULT_MONITOR_LIMIT
    ) -> FusionFeedResponse:
        monitor_matches = list(
            self.db.scalars(
                select(MonitorMatch)
                .order_by(MonitorMatch.created_at.desc())
                .limit(monitor_limit)
            )
        )

        threatlens_repo = DigestRepository(self.db)
        threatlens_recent = threatlens_repo.list_recent(limit=1)
        threatlens_digest_id: str | None = None
        threatlens_articles = []
        if threatlens_recent:
            threatlens_digest_id = threatlens_recent[0].digest_id
            digest = threatlens_repo.get(threatlens_digest_id)
            if digest is not None:
                threatlens_articles = digest.articles

        cve_repo = CveDigestRepository(self.db)
        cve_recent = cve_repo.list_recent(limit=1)
        cve_watch_digest_id: str | None = None
        tracked_cves = []
        if cve_recent:
            cve_watch_digest_id = cve_recent[0].digest_id
            digest = cve_repo.get(cve_watch_digest_id)
            if digest is not None:
                tracked_cves = digest.cves

        findings = correlate(
            monitor_matches=monitor_matches,
            threatlens_articles=threatlens_articles,
            tracked_cves=tracked_cves,
        )[:limit]

        return FusionFeedResponse(
            findings=findings,
            monitor_match_count=len(monitor_matches),
            threatlens_digest_id=threatlens_digest_id,
            cve_watch_digest_id=cve_watch_digest_id,
        )
