from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, Field


class FusionSignal(BaseModel):
    """A single named, explainable contribution to a fusion finding's
    score - mirrors seclab.reporting.scoring.RiskSignal's philosophy
    (named/weighted/explainable) but is deliberately lighter-weight since
    fusion signals reference *other modules'* data, not a local rule-set."""

    source_module: str
    kind: str
    label: str
    detail: str
    severity: str


class FusionFinding(BaseModel):
    id: str
    title: str
    score: int
    signals: list[FusionSignal] = Field(default_factory=list)
    rationale: str


class FusionFeedResponse(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    findings: list[FusionFinding] = Field(default_factory=list)
    monitor_match_count: int = 0
    threatlens_digest_id: str | None = None
    cve_watch_digest_id: str | None = None
