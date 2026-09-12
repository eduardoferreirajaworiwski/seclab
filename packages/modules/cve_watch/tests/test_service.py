import asyncio

from seclab.core.config import Settings
from seclab_cve_watch.models import DigestRequest, WatchedProduct
from seclab_cve_watch.service import CveWatchService


def test_run_digest_returns_merged_and_tagged_cves(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = CveWatchService(settings, db_session)
    request = DigestRequest(offline_mode=True)

    result = asyncio.run(service.run_digest(request))

    assert result.cves
    assert any(cve.is_actively_exploited for cve in result.cves)
    assert result.summary.headline
    assert result.report_markdown.startswith("# CVE Watch Digest")


def test_run_digest_applies_watchlist_tagging(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = CveWatchService(settings, db_session)
    request = DigestRequest(
        offline_mode=True,
        watched_products=[WatchedProduct(vendor="Acme", product="VPN Gateway")],
    )

    result = asyncio.run(service.run_digest(request))

    matched = [cve for cve in result.cves if cve.matched_products]
    assert matched
    assert any(
        "Acme" in cve.matched_products or "VPN Gateway" in cve.matched_products
        for cve in matched
    )


def test_digest_can_be_retrieved_and_listed(db_session):
    settings = Settings(api_key_pepper="test-pepper-not-for-prod")
    service = CveWatchService(settings, db_session)
    result = asyncio.run(service.run_digest(DigestRequest(offline_mode=True)))

    fetched = service.get_digest(result.digest_id)
    assert fetched is not None
    assert fetched.digest_id == result.digest_id

    recent = service.list_recent_digests(limit=5)
    assert any(item.digest_id == result.digest_id for item in recent)
