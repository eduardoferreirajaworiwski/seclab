from __future__ import annotations

import json
import logging

from seclab.core.ai_provider import AIProviderService
from seclab.core.config import Settings

from seclab_threatlens.models import DigestSummary, ThreatArticle

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a security analyst. Using ONLY the structured articles and "
    "vector tags given, write a JSON object with keys: headline, "
    "executive_summary, vector_breakdown (list of strings), "
    "notable_incidents (list of strings), recommended_actions (list of "
    "strings). Do not invent attacks, attribution, or details not present "
    "in the input."
)


class DigestNarrativeService:
    """Turns a batch of tagged threat articles into an analyst-facing weekly
    narrative. Always computes a deterministic summary first (see
    _build_deterministic_summary) and only replaces it with an AI-generated
    one when offline_mode is off, an AI provider is configured, and that
    provider actually returns something parseable - so a Gemini/OpenAI
    outage never blocks the digest from being produced."""

    def __init__(self, settings: Settings, ai: AIProviderService | None = None) -> None:
        self.settings = settings
        self.ai = ai or AIProviderService(settings)

    async def build_summary(
        self, articles: list[ThreatArticle], offline_mode: bool
    ) -> DigestSummary:
        fallback = _build_deterministic_summary(articles)
        if not articles:
            return fallback

        payload = _build_ai_payload(articles)
        result = await self.ai.generate_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=json.dumps(payload, indent=2),
            offline_mode=offline_mode,
        )
        if result is None:
            return fallback

        parsed = self.ai.parse_json(result.text)
        if parsed is None:
            return fallback

        return DigestSummary(
            headline=parsed.get("headline", fallback.headline),
            executive_summary=parsed.get("executive_summary", fallback.executive_summary),
            vector_breakdown=_coerce_list(
                parsed.get("vector_breakdown"), fallback.vector_breakdown
            ),
            notable_incidents=_coerce_list(
                parsed.get("notable_incidents"), fallback.notable_incidents
            ),
            recommended_actions=_coerce_list(
                parsed.get("recommended_actions"), fallback.recommended_actions
            ),
            grounding_notes=fallback.grounding_notes,
            model_source=result.provider.value,
        )


def _build_ai_payload(articles: list[ThreatArticle]) -> dict[str, object]:
    return {
        "article_count": len(articles),
        "articles": [
            {
                "title": article.title,
                "source": article.source,
                "link": article.link,
                "published_at": article.published_at.isoformat(),
                "vectors": [v.value for v in article.vectors],
                "summary": article.summary,
            }
            for article in articles[:30]
        ],
    }


def _coerce_list(value: object, fallback: list[str]) -> list[str]:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return fallback


def _build_deterministic_summary(articles: list[ThreatArticle]) -> DigestSummary:
    vector_counts: dict[str, int] = {}
    for article in articles:
        for vector in article.vectors:
            vector_counts[vector.value] = vector_counts.get(vector.value, 0) + 1
    ranked_vectors = sorted(vector_counts.items(), key=lambda kv: kv[1], reverse=True)

    headline = (
        f"{len(articles)} security articles reviewed; top vector: {ranked_vectors[0][0]}"
        if ranked_vectors
        else f"{len(articles)} security articles reviewed; no vectors matched"
    )
    executive_summary = (
        f"ThreatLens reviewed {len(articles)} articles from configured feeds. "
        f"{len(ranked_vectors)} distinct attack vectors were identified via deterministic "
        "keyword tagging: "
        + (", ".join(f"{name} ({count})" for name, count in ranked_vectors) or "none") + "."
    )
    vector_breakdown = [f"{name}: {count} article(s)" for name, count in ranked_vectors]
    notable_incidents = [
        f"{article.title} ({article.source}) - vectors: "
        f"{', '.join(v.value for v in article.vectors) or 'none'}"
        for article in articles[:5]
    ]
    recommended_actions = [
        "Cross-check any high-frequency vector against your own perimeter/EDR telemetry "
        "for matching indicators.",
        "Prioritize patching for any zero-day or RCE vector reported this week.",
        "Review vendor and dependency update advisories if a supply-chain vector appears.",
    ]
    grounding_notes = [
        "Vector tags are deterministic keyword matches, not a machine-learning classification.",
        "The narrative summarizes only the fetched articles; no external attribution is added.",
    ]
    return DigestSummary(
        headline=headline,
        executive_summary=executive_summary,
        vector_breakdown=vector_breakdown or ["No attack vectors matched this run."],
        notable_incidents=notable_incidents or ["No articles were retrieved this run."],
        recommended_actions=recommended_actions,
        grounding_notes=grounding_notes,
        model_source="deterministic-fallback",
    )
