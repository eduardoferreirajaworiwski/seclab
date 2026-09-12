from __future__ import annotations

from seclab.reporting.scoring import RiskSignal
from seclab_threatlens.models import AttackVector, ThreatArticle

# Deterministic keyword taxonomy: same "named, explainable signal"
# philosophy as seclab_phantom.scoring - no ML classifier, every tag is
# traceable to the exact phrase that triggered it.
VECTOR_KEYWORDS: dict[AttackVector, tuple[str, ...]] = {
    AttackVector.RANSOMWARE: ("ransomware", "encrypted files", "extortion"),
    AttackVector.PHISHING: (
        "phishing", "business email compromise", "credential harvesting", "bec",
    ),
    AttackVector.ZERO_DAY: ("zero-day", "zero day", "0-day", "unpatched"),
    AttackVector.SUPPLY_CHAIN: (
        "supply chain", "npm package", "pypi package", "compromised dependency",
    ),
    AttackVector.RCE: ("remote code execution", "rce"),
    AttackVector.DDOS: ("ddos", "denial of service"),
    AttackVector.DATA_BREACH: ("data breach", "leaked database", "exposed database"),
    AttackVector.CREDENTIAL_ATTACK: (
        "credential stuffing", "password spraying", "stolen credentials",
        "harvests credentials", "harvested credentials", "credential theft",
    ),
    AttackVector.MALWARE: ("malware", "trojan", "backdoor", "botnet"),
    AttackVector.CLOUD_MISCONFIG: (
        "misconfigured", "publicly exposed bucket", "open s3 bucket",
    ),
}


def tag_article(article: ThreatArticle) -> tuple[list[RiskSignal], list[AttackVector]]:
    haystack = f"{article.title} {article.summary}".lower()
    signals: list[RiskSignal] = []
    vectors: list[AttackVector] = []
    for vector, keywords in VECTOR_KEYWORDS.items():
        matched = [kw for kw in keywords if kw in haystack]
        if not matched:
            continue
        vectors.append(vector)
        signals.append(
            RiskSignal(
                code=f"vector:{vector.value}",
                severity="info",
                reason=f"Matched keyword(s): {', '.join(matched)}.",
                weight=len(matched),
                evidence=matched,
            )
        )
    return signals, vectors
