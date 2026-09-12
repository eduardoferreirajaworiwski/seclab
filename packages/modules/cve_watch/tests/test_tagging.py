from seclab_cve_watch.models import TrackedCve, WatchedProduct
from seclab_cve_watch.tagging import tag_cve


def _cve(description: str, matched_products: list[str] | None = None) -> TrackedCve:
    return TrackedCve(
        cve_id="CVE-2099-0001",
        description=description,
        published_at="2099-01-01T00:00:00Z",
        source="NVD",
        matched_products=matched_products or [],
    )


def test_tags_cve_matching_watchlist_by_product_keyword():
    watchlist = [WatchedProduct(vendor="Acme", product="VPN Gateway")]
    signals, matched = tag_cve(
        _cve("An RCE vulnerability in Acme VPN Gateway allows code execution."), watchlist
    )
    assert "Acme" in matched or "VPN Gateway" in matched
    assert signals
    assert all(signal.reason for signal in signals)


def test_tags_cve_matching_watchlist_by_existing_matched_products():
    watchlist = [WatchedProduct(vendor="Contoso", product="Mail Server")]
    signals, matched = tag_cve(
        _cve("Auth bypass.", matched_products=["Contoso", "Mail Server"]), watchlist
    )
    assert matched
    assert signals


def test_untagged_cve_returns_empty_when_no_watchlist_match():
    watchlist = [WatchedProduct(vendor="Globex", product="Widget CMS")]
    signals, matched = tag_cve(_cve("Unrelated privilege escalation issue."), watchlist)
    assert matched == []
    assert signals == []


def test_empty_watchlist_tracks_only_kev_entries_regardless_of_product():
    signals, matched = tag_cve(_cve("Some vulnerability."), [])
    assert matched == []
    assert signals == []
