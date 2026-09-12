from seclab_threatlens.models import AttackVector, ThreatArticle
from seclab_threatlens.vectors import tag_article


def _article(text: str) -> ThreatArticle:
    return ThreatArticle(
        title=text, link="https://x.test/1", published_at="2026-09-08T00:00:00Z",
        source="Mock", summary="",
    )


def test_tags_ransomware_and_rce():
    signals, vectors = tag_article(_article(
        "Ransomware gang exploits zero-day RCE in VPN appliance"
    ))
    assert AttackVector.RANSOMWARE in vectors
    assert AttackVector.ZERO_DAY in vectors
    assert AttackVector.RCE in vectors
    assert all(signal.reason for signal in signals)


def test_tags_phishing_and_credential_attack():
    _, vectors = tag_article(_article(
        "Business email compromise phishing campaign harvests credentials"
    ))
    assert AttackVector.PHISHING in vectors
    assert AttackVector.CREDENTIAL_ATTACK in vectors


def test_untagged_article_returns_empty():
    signals, vectors = tag_article(_article("Company releases quarterly earnings"))
    assert vectors == []
    assert signals == []
