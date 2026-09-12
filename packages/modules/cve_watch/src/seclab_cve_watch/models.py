from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
from seclab.reporting.scoring import RiskSignal

__all__ = ["RiskSignal"]


class WatchedProduct(BaseModel):
    vendor: str
    product: str


class TrackedCve(BaseModel):
    cve_id: str
    description: str = ""
    cvss_score: float | None = None
    published_at: datetime
    is_actively_exploited: bool = False
    matched_products: list[str] = Field(default_factory=list)
    source: str
    match_signals: list[RiskSignal] = Field(default_factory=list)


class DigestSummary(BaseModel):
    headline: str
    executive_summary: str
    exploited_highlights: list[str]
    watchlist_matches: list[str]
    recommended_actions: list[str]
    grounding_notes: list[str]
    model_source: str


class DigestRequest(BaseModel):
    lookback_days: int = Field(default=7, ge=1, le=90)
    watched_products: list[WatchedProduct] = Field(default_factory=list)
    offline_mode: bool | None = None


class DigestResult(BaseModel):
    digest_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    lookback_days: int
    cves: list[TrackedCve]
    summary: DigestSummary
    report_markdown: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DigestListItem(BaseModel):
    digest_id: str
    created_at: datetime
    cve_count: int
    actively_exploited_count: int
    summary_headline: str
    offline_mode: bool


class DigestListResponse(BaseModel):
    digests: list[DigestListItem]
