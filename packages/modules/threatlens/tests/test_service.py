import asyncio

from seclab.core.config import Settings
from seclab_threatlens.models import DigestRequest
from seclab_threatlens.service import ThreatLensService


def test_run_digest_returns_tagged_articles_and_summary(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = ThreatLensService(settings, db_session)
    request = DigestRequest(offline_mode=True)

    result = asyncio.run(service.run_digest(request))

    assert result.articles
    assert any(article.vectors for article in result.articles)
    assert result.summary.headline
    assert result.report_markdown.startswith("# ThreatLens Weekly Digest")


def test_digest_can_be_retrieved_and_listed(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = ThreatLensService(settings, db_session)
    result = asyncio.run(service.run_digest(DigestRequest(offline_mode=True)))

    fetched = service.get_digest(result.digest_id)
    assert fetched is not None
    assert fetched.digest_id == result.digest_id

    recent = service.list_recent_digests(limit=5)
    assert any(item.digest_id == result.digest_id for item in recent)
