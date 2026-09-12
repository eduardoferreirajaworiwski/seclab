from __future__ import annotations

from seclab.reporting.scoring import RiskSignal

from seclab_cve_watch.models import TrackedCve, WatchedProduct


def tag_cve(
    cve: TrackedCve, watchlist: list[WatchedProduct]
) -> tuple[list[RiskSignal], list[str]]:
    """Deterministic keyword match against a configurable product/vendor
    watchlist - same "named, explainable signal" philosophy as
    seclab_threatlens's VECTOR_KEYWORDS. An empty watchlist means "track
    only KEV entries regardless of product" (per the plan), so it never
    matches anything here.

    A CVE matches a watched product when the vendor or product name
    appears (case-insensitively) in the CVE's description or in the
    product names already surfaced by the CISA KEV feed
    (`matched_products`).
    """
    if not watchlist:
        return [], []

    haystack = f"{cve.description} {' '.join(cve.matched_products)}".lower()
    signals: list[RiskSignal] = []
    matched_names: list[str] = []
    for watched in watchlist:
        hits = [
            keyword
            for keyword in (watched.vendor, watched.product)
            if keyword and keyword.lower() in haystack
        ]
        if not hits:
            continue
        matched_names.extend(hits)
        signals.append(
            RiskSignal(
                code=f"watchlist:{watched.vendor}/{watched.product}",
                severity="info",
                reason=f"Matched watchlist entry via keyword(s): {', '.join(hits)}.",
                weight=len(hits),
                evidence=hits,
            )
        )
    return signals, list(dict.fromkeys(matched_names))
