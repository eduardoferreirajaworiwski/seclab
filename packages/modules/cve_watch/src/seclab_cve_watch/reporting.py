from seclab.reporting.exporters import MarkdownReportBuilder

from seclab_cve_watch.models import DigestResult


def build_markdown_report(result: DigestResult) -> str:
    builder = (
        MarkdownReportBuilder("CVE Watch Digest")
        .meta(
            digest_id=result.digest_id,
            created_at=result.created_at.isoformat(),
            cves_reviewed=len(result.cves),
            lookback_days=result.lookback_days,
            summary_source=result.summary.model_source,
        )
        .section("Executive Summary")
        .paragraph(result.summary.executive_summary)
        .section("Actively Exploited (CISA KEV) Highlights")
        .bullets(result.summary.exploited_highlights)
        .section("Watchlist Matches")
        .bullets(result.summary.watchlist_matches)
        .section("Recommended Actions")
        .bullets(result.summary.recommended_actions)
        .section("Grounding Notes")
        .bullets(result.summary.grounding_notes)
        .section("CVEs Reviewed")
    )
    for cve in result.cves:
        builder.section(cve.cve_id, level=3)
        builder.bullets(
            [
                f"Source: `{cve.source}`",
                f"Published: `{cve.published_at.isoformat()}`",
                f"CVSS score: {cve.cvss_score if cve.cvss_score is not None else 'n/a'}",
                f"Actively exploited (CISA KEV): {cve.is_actively_exploited}",
                f"Matched products: {', '.join(cve.matched_products) or 'none'}",
                f"Description: {cve.description or 'n/a'}",
            ]
        )
    return builder.build()
