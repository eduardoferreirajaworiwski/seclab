from __future__ import annotations

import json

from pydantic import BaseModel


def build_json_report(model: BaseModel) -> str:
    """Generic JSON exporter for any Pydantic result model. Ported from
    phantomscope/src/phantomscope/reporting/exporters.py::build_json_report,
    which was already generic (json.dumps(model_dump(mode="json"))) - no
    phantom-specific logic to strip out."""
    return json.dumps(model.model_dump(mode="json"), indent=2)


class MarkdownReportBuilder:
    """Small helper for assembling consistent Markdown reports across
    modules. Factored out of phantomscope's build_markdown_report so every
    module's report (phantom lookalike findings, recon findings, monitor
    matches...) shares the same heading/section conventions instead of each
    hand-rolling its own line-joining.
    """

    def __init__(self, title: str) -> None:
        self._lines: list[str] = [f"# {title}", ""]

    def meta(self, **fields: object) -> MarkdownReportBuilder:
        for key, value in fields.items():
            self._lines.append(f"- {key}: `{value}`")
        self._lines.append("")
        return self

    def section(self, heading: str, *, level: int = 2) -> MarkdownReportBuilder:
        self._lines.append(f"{'#' * level} {heading}")
        self._lines.append("")
        return self

    def paragraph(self, text: str) -> MarkdownReportBuilder:
        self._lines.append(text)
        self._lines.append("")
        return self

    def bullets(self, items: list[str]) -> MarkdownReportBuilder:
        if not items:
            return self
        self._lines.extend(f"- {item}" for item in items)
        self._lines.append("")
        return self

    def raw(self, text: str) -> MarkdownReportBuilder:
        self._lines.append(text)
        return self

    def build(self) -> str:
        return "\n".join(self._lines)
