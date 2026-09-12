from __future__ import annotations

import json
import logging

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

from seclab_threatlens.models import DigestSummary, ThreatArticle

logger = logging.getLogger(__name__)


class DigestNarrativeService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.http = HttpProvider(settings)

    async def build_summary(
        self, articles: list[ThreatArticle], offline_mode: bool
    ) -> DigestSummary:
        fallback = _build_deterministic_summary(articles)
        if offline_mode or not self.settings.gemini_api_key or not articles:
            return fallback

        payload = _build_ai_payload(articles)
        url = (
            f"{self.settings.gemini_base_url}/models/"
            f"{self.settings.gemini_model}:generateContent"
            f"?key={self.settings.gemini_api_key.get_secret_value()}"
        )
        body = {
            "contents": [
                {
                    "role": "user",
                    "parts": [
                        {
                            "text": (
                                "You are a security analyst. Using ONLY the structured "
                                "articles and vector tags below, write a JSON object with "
                                "keys: headline, executive_summary, vector_breakdown "
                                "(list of strings), notable_incidents (list of strings), "
                                "recommended_actions (list of strings). Do not invent "
                                "attacks, attribution, or details not present in the "
                                "input.\n\n" + json.dumps(payload, indent=2)
                            )
                        }
                    ],
                }
            ],
            "generationConfig": {
                "temperature": 0.2,
                "responseMimeType": "application/json",
            },
        }
        try:
            response = await self.http.post_json(url, json_body=body)
            return _parse_ai_summary(response, fallback)
        except Exception as exc:
            logger.warning("threatlens_ai_summary_failed", extra={"error": str(exc)})
            return fallback


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


def _parse_ai_summary(response: dict[str, object], fallback: DigestSummary) -> DigestSummary:
    candidates = response.get("candidates", [])
    if not isinstance(candidates, list) or not candidates:
        return fallback
    first = candidates[0]
    if not isinstance(first, dict):
        return fallback
    content = first.get("content", {})
    parts = content.get("parts", []) if isinstance(content, dict) else []
    text = "".join(
        part.get("text", "") for part in parts if isinstance(part, dict)
    )
    if not text:
        return fallback
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return fallback
    return DigestSummary(
        headline=parsed.get("headline", fallback.headline),
        executive_summary=parsed.get("executive_summary", fallback.executive_summary),
        vector_breakdown=_coerce_list(parsed.get("vector_breakdown"), fallback.vector_breakdown),
        notable_incidents=_coerce_list(
            parsed.get("notable_incidents"), fallback.notable_incidents
        ),
        recommended_actions=_coerce_list(
            parsed.get("recommended_actions"), fallback.recommended_actions
        ),
        grounding_notes=fallback.grounding_notes,
        model_source=f"gemini:{response.get('modelVersion', fallback.model_source)}",
    )


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
