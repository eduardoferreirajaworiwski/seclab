from seclab.reporting.exporters import MarkdownReportBuilder

from seclab_osint_breach.models import BreachCheckResult


def build_markdown_report(result: BreachCheckResult) -> str:
    builder = (
        MarkdownReportBuilder("OSINT Breach Check")
        .meta(
            check_id=result.check_id,
            created_at=result.created_at.isoformat(),
            identifiers_checked=len(result.identifiers_checked),
            exposures_found=len(result.exposures),
            summary_source=result.summary.model_source,
        )
        .section("Executive Summary")
        .paragraph(result.summary.executive_summary)
        .section("Exposure Breakdown")
        .bullets(result.summary.exposure_breakdown)
        .section("Notable Exposures")
        .bullets(result.summary.notable_exposures)
        .section("Recommended Actions")
        .bullets(result.summary.recommended_actions)
        .section("Grounding Notes")
        .bullets(result.summary.grounding_notes)
        .section("Exposures Found")
    )
    for exposure in result.exposures:
        builder.section(exposure.breach_name, level=3)
        builder.bullets(
            [
                f"Identifier: `{exposure.identifier}`",
                f"Breach date: `{exposure.breach_date.isoformat()}`",
                f"Data classes: {', '.join(exposure.data_classes) or 'none'}",
                f"Source: `{exposure.source}`",
                f"Origin: `{exposure.origin.value}`",
            ]
        )
    return builder.build()
