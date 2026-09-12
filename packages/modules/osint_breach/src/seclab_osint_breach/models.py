from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
from seclab.core.origin import DataOrigin

__all__ = ["DataOrigin"]  # re-exported for convenience


class WatchedIdentifier(BaseModel):
    identifier: str
    identifier_type: str  # "email" | "domain"


class BreachExposure(BaseModel):
    identifier: str
    breach_name: str
    breach_date: datetime
    data_classes: list[str] = Field(default_factory=list)
    source: str
    origin: DataOrigin = DataOrigin.MOCK


class BreachSummary(BaseModel):
    headline: str
    executive_summary: str
    exposure_breakdown: list[str]
    notable_exposures: list[str]
    recommended_actions: list[str]
    grounding_notes: list[str]
    model_source: str


class BreachCheckRequest(BaseModel):
    identifiers: list[WatchedIdentifier] = Field(default_factory=list)
    offline_mode: bool | None = None


class BreachCheckResult(BaseModel):
    check_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    identifiers_checked: list[WatchedIdentifier]
    exposures: list[BreachExposure]
    summary: BreachSummary
    report_markdown: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BreachCheckListItem(BaseModel):
    check_id: str
    created_at: datetime
    identifier_count: int
    exposure_count: int
    summary_headline: str
    offline_mode: bool


class BreachCheckListResponse(BaseModel):
    checks: list[BreachCheckListItem]
