from __future__ import annotations

import json
import logging

from seclab.core.config import Settings
from seclab.core.http import HttpProvider

from seclab_phantom.models import AnalystSummary, ScoredAsset, TargetProfile

logger = logging.getLogger(__name__)


class AnalystSummaryService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.http = HttpProvider(settings)

    async def build_summary(
        self, target: TargetProfile, assets: list[ScoredAsset], offline_mode: bool
    ) -> AnalystSummary:
        fallback = _build_deterministic_summary(target, assets)
        if offline_mode or not self.settings.openai_api_key:
            return fallback

        payload = _build_ai_payload(target, assets)
        headers = {
            "Authorization": f"Bearer {self.settings.openai_api_key.get_secret_value()}",
            "Content-Type": "application/json",
        }
        try:
            response = await self.http.post_json(
                f"{self.settings.openai_base_url}/chat/completions",
                json_body={
                    "model": self.settings.openai_model,
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                "You are a security analyst assistant. Summarize only the "
                                "structured evidence provided. Do not invent evidence, "
                                "confidence, attribution, or unseen infrastructure."
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                "Produce a JSON object with keys: headline, executive_summary, "
                                "analyst_notes, recommended_actions, grounding_notes. Base the "
                                "output strictly on this evidence:\n"
                                f"{json.dumps(payload, indent=2)}"
                            ),
                        },
                    ],
                },
                headers=headers,
            )
            return _parse_ai_summary(response, fallback)
        except Exception as exc:
            logger.warning(
                "ai_summary_failed", extra={"target": target.normalized_target, "error": str(exc)}
            )
            return fallback


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


def _parse_ai_summary(response: dict[str, object], fallback: AnalystSummary) -> AnalystSummary:
    choices = response.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return fallback
    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        return fallback
    message = first_choice.get("message", {})
    if not isinstance(message, dict):
        return fallback
    content = message.get("content", "{}")
    if isinstance(content, list):
        text_parts = [item.get("text", "") for item in content if isinstance(item, dict)]
        content = "".join(part for part in text_parts if isinstance(part, str))
    if not isinstance(content, str):
        return fallback
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return fallback
    return AnalystSummary(
        headline=parsed.get("headline", fallback.headline),
        executive_summary=parsed.get("executive_summary", fallback.executive_summary),
        analyst_notes=_coerce_list(parsed.get("analyst_notes"), fallback.analyst_notes),
        recommended_actions=_coerce_list(
            parsed.get("recommended_actions"), fallback.recommended_actions
        ),
        grounding_notes=_coerce_list(parsed.get("grounding_notes"), fallback.grounding_notes),
        model_source=f"openai:{response.get('model', fallback.model_source)}",
    )


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
