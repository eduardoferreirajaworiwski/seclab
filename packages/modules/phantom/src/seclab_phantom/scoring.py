from seclab.reporting.scoring import RiskSignal, score_and_prioritize

from seclab_phantom.models import CertificateObservation, DomainInfrastructure, DomainVariation

HIGH_RISK_TECHNIQUES = {
    "homoglyph": 30,
    "character-swap": 28,
    "character-duplication": 18,
    "character-omission": 18,
}

LURE_TECHNIQUES = {
    "brand-prefix": 20,
    "security-lure": 22,
    "support-lure": 16,
    "tld-blend": 12,
}


def score_asset(
    variation: DomainVariation,
    certificates: list[CertificateObservation],
    infrastructure: DomainInfrastructure,
) -> tuple[int, str, list[RiskSignal], str]:
    """Domain-specific rule-set: decides *which* signals fire. Aggregation,
    priority thresholds, and rationale text are shared logic delegated to
    seclab.reporting.scoring.score_and_prioritize."""
    signals: list[RiskSignal] = []

    if variation.technique in HIGH_RISK_TECHNIQUES:
        weight = HIGH_RISK_TECHNIQUES[variation.technique]
        signals.append(
            RiskSignal(
                code="lookalike-technique",
                severity="high",
                reason=f"Domain uses {variation.technique} to mimic the target.",
                weight=weight,
                evidence=[variation.domain, variation.technique],
            )
        )

    if variation.technique in LURE_TECHNIQUES:
        weight = LURE_TECHNIQUES[variation.technique]
        signals.append(
            RiskSignal(
                code="credential-lure-pattern",
                severity="medium",
                reason="Domain contains wording commonly used in phishing login lures.",
                weight=weight,
                evidence=variation.risk_context_tags or [variation.technique],
            )
        )

    if certificates:
        signals.append(
            RiskSignal(
                code="certificate-observed",
                severity="high",
                reason=(
                    "Certificate Transparency data shows the domain has active "
                    "certificate activity."
                ),
                weight=25,
                evidence=[certificate.source for certificate in certificates],
            )
        )

    if "Privacy" in (infrastructure.rdap_org or ""):
        signals.append(
            RiskSignal(
                code="privacy-registrant",
                severity="medium",
                reason="Registration details suggest privacy shielding.",
                weight=10,
                evidence=[infrastructure.rdap_org or ""],
            )
        )

    if infrastructure.ip_addresses:
        signals.append(
            RiskSignal(
                code="resolves-to-ip",
                severity="medium",
                reason="Domain resolves to routable infrastructure.",
                weight=10,
                evidence=infrastructure.ip_addresses[:2],
            )
        )

    if infrastructure.reputation_tags:
        bonus = min(15, len(infrastructure.reputation_tags) * 5)
        signals.append(
            RiskSignal(
                code="reputation-tags",
                severity="medium",
                reason=(
                    "Basic reputation heuristics produced tags: "
                    f"{', '.join(infrastructure.reputation_tags)}."
                ),
                weight=bonus,
                evidence=infrastructure.reputation_tags,
            )
        )

    score, priority, rationale = score_and_prioritize(signals)
    return score, priority, signals, rationale
