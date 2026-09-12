import hashlib

from seclab_cve_watch.models import TrackedCve
from seclab_fusion.models import FusionFinding, FusionSignal
from seclab_monitor.models import MonitorMatch
from seclab_threatlens.models import ThreatArticle


def test_matching_keyword_and_product_produces_finding_with_signals_and_score():
    match = MonitorMatch(
        domain="acme-login-secure.com",
        matched_keyword="acme",
        technique="live-ct-match",
        score=50,
        priority="medium",
    )
    cve = TrackedCve(
        cve_id="CVE-2026-0001",
        published_at="2026-01-01T00:00:00Z",
        is_actively_exploited=True,
        matched_products=["Acme Widget Server"],
        source="cisa-kev",
    )

    from seclab_fusion.correlation import correlate

    findings = correlate(monitor_matches=[match], threatlens_articles=[], tracked_cves=[cve])

    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, FusionFinding)
    assert any(s.kind == "exploited_cve" for s in finding.signals)
    exploited_signal = next(s for s in finding.signals if s.kind == "exploited_cve")
    assert isinstance(exploited_signal, FusionSignal)
    assert "CVE-2026-0001" in exploited_signal.detail
    # base score (round(50/10)=5) + exploited cve weight (3) = 8
    assert finding.score == 8
    assert "CVE-2026-0001" in finding.rationale


def test_non_matching_monitor_match_produces_no_finding():
    match = MonitorMatch(
        domain="totally-unrelated.com",
        matched_keyword="unrelated",
        technique="live-ct-match",
        score=10,
        priority="low",
    )
    cve = TrackedCve(
        cve_id="CVE-2026-0002",
        published_at="2026-01-01T00:00:00Z",
        is_actively_exploited=True,
        matched_products=["Some Other Product"],
        source="cisa-kev",
    )
    article = ThreatArticle(
        title="Ransomware wave hits hospitals",
        link="https://example.com/a",
        published_at="2026-01-01T00:00:00Z",
        source="feed",
        summary="Ransomware campaigns continue.",
        vectors=["ransomware"],
    )

    from seclab_fusion.correlation import correlate

    findings = correlate(
        monitor_matches=[match], threatlens_articles=[article], tracked_cves=[cve]
    )

    assert findings == []


def test_multiple_signals_stack_the_score():
    match = MonitorMatch(
        domain="acme-secure-portal.com",
        matched_keyword="acme",
        technique="live-ct-match",
        score=20,
        priority="low",
    )
    cve_exploited = TrackedCve(
        cve_id="CVE-2026-0003",
        published_at="2026-01-01T00:00:00Z",
        is_actively_exploited=True,
        matched_products=["Acme Gateway"],
        source="cisa-kev",
    )
    cve_not_exploited = TrackedCve(
        cve_id="CVE-2026-0004",
        published_at="2026-01-01T00:00:00Z",
        is_actively_exploited=False,
        matched_products=["Acme Gateway Extension"],
        source="nvd",
    )
    article = ThreatArticle(
        title="Acme phishing kit spotted in the wild",
        link="https://example.com/b",
        published_at="2026-01-01T00:00:00Z",
        source="feed",
        summary="A new phishing kit targets Acme customers.",
        vectors=["phishing"],
    )
    article_no_vector = ThreatArticle(
        title="Acme quarterly earnings call notes",
        link="https://example.com/c",
        published_at="2026-01-01T00:00:00Z",
        source="feed",
        summary="Nothing security related here.",
        vectors=[],
    )

    from seclab_fusion.correlation import correlate

    findings = correlate(
        monitor_matches=[match],
        threatlens_articles=[article, article_no_vector],
        tracked_cves=[cve_exploited, cve_not_exploited],
    )

    assert len(findings) == 1
    finding = findings[0]
    kinds = [s.kind for s in finding.signals]
    assert kinds.count("exploited_cve") == 1
    assert kinds.count("cve_match") == 1
    assert kinds.count("threat_vector") == 1
    # base round(20/10)=2 + exploited(3) + non-exploited cve match(1) + vector(1) = 7
    assert finding.score == 7


def test_finding_id_is_deterministic_slug_of_domain():
    match = MonitorMatch(
        domain="Acme-Login.COM",
        matched_keyword="acme",
        technique="live-ct-match",
        score=10,
        priority="low",
    )
    cve = TrackedCve(
        cve_id="CVE-2026-0005",
        published_at="2026-01-01T00:00:00Z",
        is_actively_exploited=False,
        matched_products=["Acme"],
        source="nvd",
    )

    from seclab_fusion.correlation import correlate

    findings = correlate(monitor_matches=[match], threatlens_articles=[], tracked_cves=[cve])

    expected_id = hashlib.sha256(b"acme-login.com").hexdigest()[:16]
    assert findings[0].id == expected_id
