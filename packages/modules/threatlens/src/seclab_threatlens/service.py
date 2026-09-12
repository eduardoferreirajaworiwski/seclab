from __future__ import annotations

import logging

from seclab.core.config import Settings
from sqlalchemy.orm import Session

from seclab_threatlens.ai_analysis import DigestNarrativeService
from seclab_threatlens.db import DigestRepository
from seclab_threatlens.models import DigestListItem, DigestRequest, DigestResult
from seclab_threatlens.reporting import build_markdown_report
from seclab_threatlens.sources import FeedIngestionService
from seclab_threatlens.vectors import tag_article

logger = logging.getLogger(__name__)


class ThreatLensService:
    def __init__(self, settings: Settings, db: Session) -> None:
        self.settings = settings
        self.repository = DigestRepository(db)
        self.narrative_service = DigestNarrativeService(settings)

    async def run_digest(self, request: DigestRequest) -> DigestResult:
        offline_mode = (
            self.settings.offline_mode if request.offline_mode is None else request.offline_mode
        )
        ingestion = FeedIngestionService(self.settings, offline_mode=offline_mode)
        articles = await ingestion.fetch_all(max_per_feed=request.max_articles_per_feed)

        tagged_articles = []
        for article in articles:
            signals, vectors = tag_article(article)
            tagged_articles.append(
                article.model_copy(update={"vector_signals": signals, "vectors": vectors})
            )

        summary = await self.narrative_service.build_summary(tagged_articles, offline_mode)

        draft = DigestResult(
            lookback_days=request.lookback_days,
            articles=tagged_articles,
            summary=summary,
            report_markdown="",
            metadata={
                "offline_mode": offline_mode,
                "article_count": len(tagged_articles),
                "tagged_count": sum(1 for a in tagged_articles if a.vectors),
            },
        )
        result = draft.model_copy(update={"report_markdown": build_markdown_report(draft)})
        self.repository.save(result)
        logger.info(
            "threatlens_digest_completed",
            extra={"digest_id": result.digest_id, "article_count": len(tagged_articles)},
        )
        return result

    def get_digest(self, digest_id: str) -> DigestResult | None:
        return self.repository.get(digest_id)

    def list_recent_digests(self, limit: int = 10) -> list[DigestListItem]:
        return self.repository.list_recent(limit=limit)
