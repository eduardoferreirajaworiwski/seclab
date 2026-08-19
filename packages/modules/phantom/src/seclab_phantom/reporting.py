from seclab.reporting.exporters import MarkdownReportBuilder, build_json_report

from seclab_phantom.models import AnalysisResult

__all__ = ["build_json_report", "build_markdown_report"]


def build_markdown_report(result: AnalysisResult) -> str:
    builder = (
        MarkdownReportBuilder(f"PhantomScope Report: {result.target_profile.normalized_target}")
        .meta(
            analysis_id=result.analysis_id,
            created_at=result.created_at.isoformat(),
            assets_reviewed=len(result.assets),
            offline_mode=result.metadata.get("offline_mode", False),
            summary_source=result.summary.model_source,
        )
        .section("Executive Summary")
        .paragraph(result.summary.executive_summary)
        .section("Grounding Notes")
        .bullets(result.summary.grounding_notes)
        .section("Priority Findings")
    )

    if not result.assets:
        builder.paragraph("No suspicious assets were produced in this run.")

    for asset in result.assets:
        builder.section(asset.domain, level=3)
        builder.bullets(
            [
                f"Technique: `{asset.technique}`",
                f"Score: `{asset.score}`",
                f"Priority: `{asset.priority}`",
                f"Scoring rationale: `{asset.score_rationale}`",
                f"Evidence sources: {', '.join(asset.evidence_sources) or 'none'}",
                f"Infrastructure origin: `{asset.infrastructure.origin.value}`",
                f"Signals: {', '.join(signal.code for signal in asset.risk_signals) or 'none'}",
            ]
        )
        builder.section("Signal Breakdown", level=4)
        builder.bullets(
            [
                f"`{signal.code}` (+{signal.weight}): {signal.reason}"
                for signal in asset.risk_signals
            ]
        )

    builder.section("Analyst Notes")
    builder.bullets(result.summary.analyst_notes)
    builder.section("Recommended Actions")
    builder.bullets(result.summary.recommended_actions)

    return builder.build()
