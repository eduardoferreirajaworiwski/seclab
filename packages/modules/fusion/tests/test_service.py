from datetime import UTC, datetime

from seclab_cve_watch.db import CveDigestRepository
from seclab_cve_watch.models import DigestResult as CveDigestResult
from seclab_cve_watch.models import DigestSummary as CveDigestSummary
from seclab_cve_watch.models import TrackedCve
from seclab_fusion.service import FusionService
from seclab_monitor.models import MonitorMatch
from seclab_threatlens.db import DigestRepository
from seclab_threatlens.models import DigestResult as ThreatDigestResult
from seclab_threatlens.models import DigestSummary as ThreatDigestSummary
from seclab_threatlens.models import ThreatArticle


def _seed_monitor_match(db_session, *, domain="acme-login.com", keyword="acme", score=40) -> None:
    db_session.add(
        MonitorMatch(
            domain=domain,
            issuer="Let's Encrypt",
            matched_keyword=keyword,
            technique="live-ct-match",
            score=score,
            priority="medium",
            score_rationale="test",
            capture_status="skipped",
            created_at=datetime.now(UTC),
        )
    )
    db_session.commit()


def _seed_threatlens_digest(db_session, *, with_vector_article=True) -> str:
    articles = []
    if with_vector_article:
        articles.append(
            ThreatArticle(
                title="Acme phishing kit spreads",
                link="https://example.com/a",
                published_at=datetime.now(UTC),
                source="feed",
                summary="A phishing kit impersonating Acme is spreading.",
                vectors=["phishing"],
            )
        )
    result = ThreatDigestResult(
        lookback_days=7,
        articles=articles,
        summary=ThreatDigestSummary(
            headline="h",
            executive_summary="e",
            vector_breakdown=[],
            notable_incidents=[],
            recommended_actions=[],
            grounding_notes=[],
            model_source="deterministic",
        ),
        report_markdown="# report",
    )
    DigestRepository(db_session).save(result)
    return result.digest_id


def _seed_cve_digest(db_session, *, matched_product="Acme Gateway", exploited=True) -> str:
    result = CveDigestResult(
        lookback_days=7,
        cves=[
            TrackedCve(
                cve_id="CVE-2026-0001",
                published_at=datetime.now(UTC),
                is_actively_exploited=exploited,
                matched_products=[matched_product],
                source="cisa-kev" if exploited else "nvd",
            )
        ],
        summary=CveDigestSummary(
            headline="h",
            executive_summary="e",
            exploited_highlights=[],
            watchlist_matches=[],
            recommended_actions=[],
            grounding_notes=[],
            model_source="deterministic",
        ),
        report_markdown="# report",
    )
    CveDigestRepository(db_session).save(result)
    return result.digest_id


def test_get_feed_returns_correlated_finding_when_all_sources_have_data(db_session):
    _seed_monitor_match(db_session)
    threat_digest_id = _seed_threatlens_digest(db_session)
    cve_digest_id = _seed_cve_digest(db_session)

    feed = FusionService(db_session).get_feed()

    assert feed.monitor_match_count == 1
    assert feed.threatlens_digest_id == threat_digest_id
    assert feed.cve_watch_digest_id == cve_digest_id
    assert len(feed.findings) == 1
    finding = feed.findings[0]
    kinds = {s.kind for s in finding.signals}
    assert "exploited_cve" in kinds
    assert "threat_vector" in kinds


def test_get_feed_degrades_gracefully_with_no_monitor_matches(db_session):
    _seed_threatlens_digest(db_session)
    _seed_cve_digest(db_session)

    feed = FusionService(db_session).get_feed()

    assert feed.monitor_match_count == 0
    assert feed.findings == []


def test_get_feed_degrades_gracefully_with_no_threatlens_or_cve_digest(db_session):
    _seed_monitor_match(db_session)

    feed = FusionService(db_session).get_feed()

    assert feed.threatlens_digest_id is None
    assert feed.cve_watch_digest_id is None
    # no source data to correlate against -> no findings, but no error either
    assert feed.findings == []


def test_get_feed_respects_limit_and_sorts_by_score_descending(db_session):
    _seed_monitor_match(db_session, domain="acme-one.com", keyword="acme", score=90)
    _seed_monitor_match(db_session, domain="acme-two.com", keyword="acme", score=10)
    _seed_cve_digest(db_session, matched_product="Acme Gateway", exploited=True)

    feed = FusionService(db_session).get_feed(limit=1)

    assert len(feed.findings) == 1
    assert feed.findings[0].score == max(
        FusionService(db_session).get_feed().findings, key=lambda f: f.score
    ).score
