import pytest
from seclab.core.config import Settings
from seclab_threatlens.ai_analysis import DigestNarrativeService
from seclab_threatlens.models import ThreatArticle
from seclab_threatlens.vectors import tag_article


def _tagged_article(title: str) -> ThreatArticle:
    article = ThreatArticle(
        title=title, link="https://x.test/1", published_at="2026-09-08T00:00:00Z",
        source="Mock", summary=title,
    )
    signals, vectors = tag_article(article)
    return article.model_copy(update={"vector_signals": signals, "vectors": vectors})


@pytest.mark.asyncio
async def test_offline_mode_returns_deterministic_summary_without_calling_gemini():
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = DigestNarrativeService(settings)
    articles = [_tagged_article("Ransomware gang exploits zero-day RCE")]

    summary = await service.build_summary(articles, offline_mode=True)

    assert summary.model_source == "deterministic-fallback"
    assert summary.headline
    assert "ransomware" in summary.vector_breakdown[0].lower() or summary.vector_breakdown


@pytest.mark.asyncio
async def test_missing_api_key_falls_back_even_when_offline_mode_false():
    settings = Settings(api_key_pepper="test-pepper-not-for-prod", gemini_api_key=None)
    service = DigestNarrativeService(settings)
    articles = [_tagged_article("Phishing campaign harvests credentials")]

    summary = await service.build_summary(articles, offline_mode=False)

    assert summary.model_source == "deterministic-fallback"
