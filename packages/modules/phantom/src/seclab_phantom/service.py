from __future__ import annotations

import asyncio
import logging

from seclab.core.config import Settings
from sqlalchemy.orm import Session

from seclab_phantom.ai_summary import AnalystSummaryService
from seclab_phantom.db import AnalysisRepository
from seclab_phantom.discovery import build_target_profile, generate_domain_variants
from seclab_phantom.enrichment import EnrichmentService
from seclab_phantom.models import AnalysisListItem, AnalysisResult, ScoredAsset, TargetRequest
from seclab_phantom.providers import CompositeEnrichmentProvider, CrtShProvider
from seclab_phantom.reporting import build_markdown_report
from seclab_phantom.scoring import score_asset

logger = logging.getLogger(__name__)


class AnalysisService:
    def __init__(self, settings: Settings, db: Session) -> None:
        self.settings = settings
        self.repository = AnalysisRepository(db)
        self.summary_service = AnalystSummaryService(settings)

    async def analyze(self, request: TargetRequest) -> AnalysisResult:
        offline_mode = (
            self.settings.offline_mode if request.offline_mode is None else request.offline_mode
        )
        target_profile = build_target_profile(request)
        variations = generate_domain_variants(target_profile, request.max_variants)
        enrichment_service = EnrichmentService(
            ct_provider=CrtShProvider(self.settings, offline_mode=offline_mode),
            enrichment_provider=CompositeEnrichmentProvider(
                self.settings, offline_mode=offline_mode
            ),
        )

        tasks = [enrichment_service.enrich_asset(variation) for variation in variations]
        enriched_assets = await asyncio.gather(*tasks)

        scored_assets: list[ScoredAsset] = []
        for variation, certificates, infrastructure in enriched_assets:
            score, priority, signals, rationale = score_asset(
                variation, certificates, infrastructure
            )
            if score == 0:
                continue
            scored_assets.append(
                ScoredAsset(
                    domain=variation.domain,
                    technique=variation.technique,
                    score=score,
                    priority=priority,
                    certificate_observations=certificates,
                    infrastructure=infrastructure,
                    risk_signals=signals,
                    score_rationale=rationale,
                    evidence_sources=sorted(
                        {certificate.source for certificate in certificates}
                        | {infrastructure.source}
                    ),
                )
            )

        scored_assets.sort(key=lambda item: item.score, reverse=True)
        summary = await self.summary_service.build_summary(
            target_profile, scored_assets, offline_mode
        )
        draft = AnalysisResult(
            target_profile=target_profile,
            assets=scored_assets,
            summary=summary,
            report_markdown="",
            metadata={
                "offline_mode": offline_mode,
                "generated_variants": len(variations),
                "scored_assets": len(scored_assets),
                "live_assets": sum(
                    1 for asset in scored_assets if asset.infrastructure.origin.value == "live"
                ),
                "mock_assets": sum(
                    1 for asset in scored_assets if asset.infrastructure.origin.value != "live"
                ),
                "ct_provider": "crt.sh",
            },
        )
        result = draft.model_copy(update={"report_markdown": build_markdown_report(draft)})
        self.repository.save(result)
        logger.info(
            "analysis_completed",
            extra={
                "event": "analysis_completed",
                "analysis_id": result.analysis_id,
                "target": target_profile.normalized_target,
            },
        )
        return result

    def get_analysis(self, analysis_id: str) -> AnalysisResult | None:
        return self.repository.get(analysis_id)

    def list_recent_analyses(self, limit: int = 10) -> list[AnalysisListItem]:
        return self.repository.list_recent(limit=limit)
