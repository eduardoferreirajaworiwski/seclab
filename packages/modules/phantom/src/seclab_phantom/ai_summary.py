from __future__ import annotations

import logging

from seclab.core.ai_provider import AIProviderService
from seclab.core.config import Settings

from seclab_phantom.models import AnalystSummary, ScoredAsset, TargetProfile

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a security analyst assistant. Summarize only the structured "
    "evidence provided. Do not invent evidence, confidence, attribution, or "
    "unseen infrastructure. Output a strict JSON object with keys: headline, "
    "executive_summary, analyst_notes (list of strings), recommended_actions "
    "(list of strings), grounding_notes (list of strings)."
)


class AnalystSummaryService:
    """Turns a scored list of lookalike-domain assets into an analyst-facing
    narrative. Always computes a deterministic summary first (see
    _build_deterministic_summary) and only replaces it with an AI-generated
    one when offline_mode is off, an AI provider is configured, and that
    provider actually returns something parseable - so this never blocks or
    breaks the phantom pipeline on an AI outage."""

    def __init__(self, settings: Settings, ai: AIProviderService | None = None) -> None:
        self.settings = settings
        self.ai = ai or AIProviderService(settings)

    async def build_summary(
        self, target: TargetProfile, assets: list[ScoredAsset], offline_mode: bool
    ) -> AnalystSummary:
        fallback = _build_deterministic_summary(target, assets)

        payload = _build_ai_payload(target, assets)
        result = await self.ai.generate_json(
            system_prompt=SYSTEM_PROMPT,
            user_prompt=(
                "Base the output strictly on this evidence:\n" + _dump(payload)
            ),
            offline_mode=offline_mode,
        )
        if result is None:
            return fallback

        parsed = self.ai.parse_json(result.text)
        if parsed is None:
            return fallback

        return AnalystSummary(
            headline=parsed.get("headline", fallback.headline),
            executive_summary=parsed.get("executive_summary", fallback.executive_summary),
            analyst_notes=_coerce_list(parsed.get("analyst_notes"), fallback.analyst_notes),
            recommended_actions=_coerce_list(
                parsed.get("recommended_actions"), fallback.recommended_actions
            ),
            grounding_notes=_coerce_list(parsed.get("grounding_notes"), fallback.grounding_notes),
            model_source=result.provider.value,
        )


def _dump(payload: dict[str, object]) -> str:
    import json

    return json.dumps(payload, indent=2)


def _build_ai_payload(target: TargetProfile, assets: list[ScoredAsset]) -> dict[str, object]:
    return {
        "target": target.model_dump(mode="json"),
        "top_assets": [
            {
                "domain": asset.domain,
                "technique": asset.technique,
                "score": asset.score,
                "priority": asset.priority,
                "signals": [signal.model_dump(mode="json") for signal in asset.risk_signals],
                "infrastructure": asset.infrastructure.model_dump(mode="json"),
            }
            for asset in assets[:5]
        ],
        "counts": {
            "total_assets": len(assets),
            "high_priority": sum(1 for asset in assets if asset.priority == "high"),
            "medium_priority": sum(1 for asset in assets if asset.priority == "medium"),
        },
    }


def _coerce_list(value: object, fallback: list[str]) -> list[str]:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return fallback


def _build_deterministic_summary(
    target: TargetProfile, assets: list[ScoredAsset]
) -> AnalystSummary:
    ranked = sorted(assets, key=lambda item: item.score, reverse=True)
    high = [item for item in ranked if item.priority == "high"]
    medium = [item for item in ranked if item.priority == "medium"]
    mock_count = sum(1 for item in ranked if item.infrastructure.origin.value != "live")

    headline = (
        f"{len(high)} high-priority lookalikes identified for {target.normalized_target}"
        if high
        else f"No high-priority lookalikes identified for {target.normalized_target}"
    )

    executive_summary = (
        f"PhantomScope reviewed {len(ranked)} candidate domains associated with "
        f"{target.normalized_target}. {len(high)} were classified as high priority and "
        f"{len(medium)} as medium priority based on named, rule-based signals covering "
        "lookalike technique, phishing lure language, CT log activity, registration "
        "privacy, infrastructure resolution, and provider heuristics. "
        f"{mock_count} findings include offline mock evidence for demo continuity."
    )

    analyst_notes = [
        f"{asset.domain} ranked {asset.score}/100 ({asset.priority}) because "
        f"{'; '.join(signal.reason for signal in asset.risk_signals[:2])}."
        for asset in ranked[:3]
    ] or ["No candidate reached the current alerting threshold in this run."]

    recommended_actions = [
        "Validate the highest-scoring domains for reachable login content before starting an "
        "abuse or takedown workflow.",
        "Track repeated registrar, nameserver, and ASN patterns to cluster future brand-abuse "
        "campaigns.",
        "Review domains backed only by mock evidence separately from live findings before "
        "external escalation.",
    ]
    grounding_notes = [
        "Risk scoring is deterministic and does not accept direct model overrides.",
        "AI output, when enabled, summarizes only the structured evidence included in the "
        "analysis payload.",
        "Offline fixtures are explicitly marked as mock to keep demo evidence distinct from "
        "live provider data.",
    ]

    return AnalystSummary(
        headline=headline,
        executive_summary=executive_summary,
        analyst_notes=analyst_notes,
        recommended_actions=recommended_actions,
        grounding_notes=grounding_notes,
        model_source="deterministic-fallback",
    )
