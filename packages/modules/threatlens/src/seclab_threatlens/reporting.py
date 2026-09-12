from seclab.reporting.exporters import MarkdownReportBuilder

from seclab_threatlens.models import DigestResult


def build_markdown_report(result: DigestResult) -> str:
    builder = (
        MarkdownReportBuilder("ThreatLens Weekly Digest")
        .meta(
            digest_id=result.digest_id,
            created_at=result.created_at.isoformat(),
            articles_reviewed=len(result.articles),
            lookback_days=result.lookback_days,
            summary_source=result.summary.model_source,
        )
        .section("Executive Summary")
        .paragraph(result.summary.executive_summary)
        .section("Vector Breakdown")
        .bullets(result.summary.vector_breakdown)
        .section("Notable Incidents")
        .bullets(result.summary.notable_incidents)
        .section("Recommended Actions")
        .bullets(result.summary.recommended_actions)
        .section("Grounding Notes")
        .bullets(result.summary.grounding_notes)
        .section("Articles Reviewed")
    )
    for article in result.articles:
        builder.section(article.title, level=3)
        builder.bullets(
            [
                f"Source: `{article.source}`",
                f"Link: {article.link}",
                f"Published: `{article.published_at.isoformat()}`",
                f"Vectors: {', '.join(v.value for v in article.vectors) or 'none'}",
            ]
        )
    return builder.build()
