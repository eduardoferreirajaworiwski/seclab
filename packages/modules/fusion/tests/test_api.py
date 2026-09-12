from fastapi import FastAPI
from fastapi.testclient import TestClient
from seclab.core.db import get_db
from seclab_cve_watch.db import CveDigestRepository
from seclab_cve_watch.models import DigestResult as CveDigestResult
from seclab_cve_watch.models import DigestSummary as CveDigestSummary
from seclab_cve_watch.models import TrackedCve
from seclab_fusion.routes import router
from seclab_monitor.models import MonitorMatch


def build_client(db_session):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1/fusion")
    app.dependency_overrides[get_db] = lambda: db_session
    return TestClient(app)


def test_feed_returns_200_with_expected_shape_when_no_data_exists(db_session):
    client = build_client(db_session)

    response = client.get("/api/v1/fusion/feed")

    assert response.status_code == 200
    payload = response.json()
    assert payload["findings"] == []
    assert payload["monitor_match_count"] == 0
    assert payload["threatlens_digest_id"] is None
    assert payload["cve_watch_digest_id"] is None
    assert "generated_at" in payload


def test_feed_returns_correlated_finding_when_seeded(db_session):
    db_session.add(
        MonitorMatch(
            domain="acme-login.com",
            issuer="Let's Encrypt",
            matched_keyword="acme",
            technique="live-ct-match",
            score=50,
            priority="medium",
            score_rationale="test",
            capture_status="skipped",
        )
    )
    db_session.commit()

    cve_result = CveDigestResult(
        lookback_days=7,
        cves=[
            TrackedCve(
                cve_id="CVE-2026-0001",
                published_at="2026-01-01T00:00:00Z",
                is_actively_exploited=True,
                matched_products=["Acme Gateway"],
                source="cisa-kev",
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
    CveDigestRepository(db_session).save(cve_result)

    client = build_client(db_session)
    response = client.get("/api/v1/fusion/feed")

    assert response.status_code == 200
    payload = response.json()
    assert payload["monitor_match_count"] == 1
    assert payload["cve_watch_digest_id"] == cve_result.digest_id
    assert len(payload["findings"]) == 1
    assert payload["findings"][0]["score"] > 0


def test_feed_limit_query_param_is_respected(db_session):
    for i in range(3):
        db_session.add(
            MonitorMatch(
                domain=f"acme-{i}.com",
                issuer="Let's Encrypt",
                matched_keyword="acme",
                technique="live-ct-match",
                score=50,
                priority="medium",
                score_rationale="test",
                capture_status="skipped",
            )
        )
    db_session.commit()
    cve_result = CveDigestResult(
        lookback_days=7,
        cves=[
            TrackedCve(
                cve_id="CVE-2026-0002",
                published_at="2026-01-01T00:00:00Z",
                is_actively_exploited=True,
                matched_products=["Acme"],
                source="cisa-kev",
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
    CveDigestRepository(db_session).save(cve_result)

    client = build_client(db_session)
    response = client.get("/api/v1/fusion/feed?limit=1")

    assert response.status_code == 200
    assert len(response.json()["findings"]) == 1
