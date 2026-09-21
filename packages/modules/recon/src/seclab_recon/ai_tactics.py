from __future__ import annotations

import logging

from seclab.core.ai_provider import AIProviderService
from seclab.core.config import Settings

from seclab_recon.models import Hypothesis, Target
from seclab_recon.schemas import HypothesisSuggestions, SuggestedHypothesis

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = (
    "You are a bug bounty recon assistant. Given a target and its existing "
    "hypotheses, suggest new attack techniques/vectors worth investigating. "
    "Only suggest reconnaissance and testing directions grounded in common, "
    "named bug-bounty/OWASP techniques (e.g. subdomain takeover, IDOR, SSRF, "
    "auth bypass, misconfigured CORS, exposed admin panels, JWT issues, "
    "GraphQL introspection). Never suggest destructive, illegal, or "
    "out-of-scope actions. Output strict JSON: a list under key "
    '"suggestions", each item with keys title, description, technique, '
    "suggested_next_step, severity (low|medium|high), confidence (0-1)."
)


class TacticsAdvisorService:
    """Suggests candidate bug-bounty hypotheses for a target. Always builds
    a deterministic checklist first (see _deterministic_suggestions) and
    only replaces it with an AI-generated list when offline_mode is off, a
    provider is configured, and the response actually parses into valid
    SuggestedHypothesis rows - this never creates a Hypothesis on its own,
    it only proposes candidates for the analyst to submit through the
    existing create-hypothesis endpoint, so the approval workflow is
    untouched."""

    def __init__(self, settings: Settings, ai: AIProviderService | None = None) -> None:
        self.settings = settings
        self.ai = ai or AIProviderService(settings)

    async def suggest(
        self, target: Target, existing: list[Hypothesis], offline_mode: bool
    ) -> HypothesisSuggestions:
        fallback = _deterministic_suggestions(target)

        user_prompt = (
            f"Target identifier: {target.identifier}\n"
            f"Target type: {target.target_type}\n"
            f"Existing hypothesis titles (avoid duplicating): "
            f"{[h.title for h in existing]}\n"
        )
        result = await self.ai.generate_json(
            system_prompt=SYSTEM_PROMPT, user_prompt=user_prompt, offline_mode=offline_mode
        )
        if result is None:
            return fallback

        parsed = self.ai.parse_json(result.text)
        if parsed is None:
            return fallback

        raw_suggestions = parsed.get("suggestions")
        if not isinstance(raw_suggestions, list):
            return fallback

        suggestions: list[SuggestedHypothesis] = []
        for item in raw_suggestions:
            if not isinstance(item, dict):
                continue
            try:
                suggestions.append(SuggestedHypothesis(**item))
            except Exception as exc:
                logger.debug("ai_suggestion_item_invalid", extra={"error": str(exc)})
                continue
        if not suggestions:
            return fallback

        return HypothesisSuggestions(
            target_identifier=target.identifier,
            model_source=result.provider.value,
            suggestions=suggestions,
        )


_GENERIC_TECHNIQUES_BY_TYPE: dict[str, list[dict[str, str]]] = {
    "domain": [
        {
            "title": "Check for subdomain takeover",
            "description": (
                "Enumerate subdomains and check for dangling CNAMEs pointing at "
                "unclaimed cloud resources (S3, Heroku, GitHub Pages, etc.)."
            ),
            "technique": "subdomain_takeover",
            "suggested_next_step": (
                "Run a subdomain enumeration pass and diff against known live services."
            ),
            "severity": "high",
        },
        {
            "title": "Review CORS configuration",
            "description": (
                "Check for reflected Origin headers or wildcard ACAO with credentials allowed."
            ),
            "technique": "misconfigured_cors",
            "suggested_next_step": (
                "Send requests with an attacker-controlled Origin header and inspect ACAO/ACAC."
            ),
            "severity": "medium",
        },
        {
            "title": "Probe for exposed admin/debug panels",
            "description": "Check common admin/debug paths and default credentials exposure.",
            "technique": "exposed_admin_panel",
            "suggested_next_step": "Run a targeted path wordlist against the host.",
            "severity": "medium",
        },
    ],
    "ip": [
        {
            "title": "Fingerprint exposed services",
            "description": (
                "Identify open ports/services and check for known CVEs on detected versions."
            ),
            "technique": "service_fingerprinting",
            "suggested_next_step": (
                "Run a version-detection scan and cross-check against cve_watch."
            ),
            "severity": "medium",
        },
    ],
}

_DEFAULT_TECHNIQUES = _GENERIC_TECHNIQUES_BY_TYPE["domain"]


def _deterministic_suggestions(target: Target) -> HypothesisSuggestions:
    templates = _GENERIC_TECHNIQUES_BY_TYPE.get(target.target_type, _DEFAULT_TECHNIQUES)
    suggestions = [
        SuggestedHypothesis(
            title=t["title"],
            description=t["description"],
            technique=t["technique"],
            suggested_next_step=t["suggested_next_step"],
            severity=t["severity"],
            confidence=0.4,
        )
        for t in templates
    ]
    return HypothesisSuggestions(
        target_identifier=target.identifier,
        model_source="deterministic-fallback",
        suggestions=suggestions,
    )
