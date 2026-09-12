from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
from seclab.reporting.scoring import RiskSignal

__all__ = ["RiskSignal"]


class AttackVector(StrEnum):
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    ZERO_DAY = "zero_day"
    SUPPLY_CHAIN = "supply_chain"
    RCE = "remote_code_execution"
    DDOS = "ddos"
    DATA_BREACH = "data_breach"
    CREDENTIAL_ATTACK = "credential_attack"
    MALWARE = "malware"
    CLOUD_MISCONFIG = "cloud_misconfiguration"


class FeedSource(BaseModel):
    name: str
    url: str


class ThreatArticle(BaseModel):
    title: str
    link: str
    published_at: datetime
    source: str
    summary: str = ""
    vectors: list[AttackVector] = Field(default_factory=list)
    vector_signals: list[RiskSignal] = Field(default_factory=list)


class DigestSummary(BaseModel):
    headline: str
    executive_summary: str
    vector_breakdown: list[str]
    notable_incidents: list[str]
    recommended_actions: list[str]
    grounding_notes: list[str]
    model_source: str


class DigestRequest(BaseModel):
    lookback_days: int = Field(default=7, ge=1, le=30)
    max_articles_per_feed: int = Field(default=15, ge=1, le=50)
    offline_mode: bool | None = None


class DigestResult(BaseModel):
    digest_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    lookback_days: int
    articles: list[ThreatArticle]
    summary: DigestSummary
    report_markdown: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class DigestListItem(BaseModel):
    digest_id: str
    created_at: datetime
    article_count: int
    top_vectors: list[str]
    summary_headline: str
    offline_mode: bool


class DigestListResponse(BaseModel):
    digests: list[DigestListItem]
