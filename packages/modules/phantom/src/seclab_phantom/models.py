from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator
from seclab.reporting.scoring import RiskSignal

__all__ = ["RiskSignal"]  # re-exported for convenience: seclab_phantom.models.RiskSignal


class TargetType(StrEnum):
    BRAND = "brand"
    DOMAIN = "domain"


class DataOrigin(StrEnum):
    LIVE = "live"
    MOCK = "mock"
    FALLBACK = "fallback"


class TargetRequest(BaseModel):
    target: str = Field(min_length=2, max_length=255)
    target_type: TargetType
    offline_mode: bool | None = None
    max_variants: int = Field(default=10, ge=1, le=50)

    @field_validator("target")
    @classmethod
    def sanitize_target(cls, value: str) -> str:
        # Restrict to ASCII alphanumerics plus a small punctuation set. str.isalnum
        # is Unicode-aware, so an ASCII guard is required to keep non-ASCII characters
        # (e.g. homoglyphs) from flowing into DNS resolution and outbound provider URLs.
        sanitized = "".join(
            ch for ch in value.strip().lower() if (ch.isascii() and ch.isalnum()) or ch in ".- "
        )
        if not sanitized:
            raise ValueError("target is empty after sanitization")
        return sanitized


class TargetProfile(BaseModel):
    original_input: str
    normalized_target: str
    brand_keyword: str
    root_domain: str | None = None
    apex_domain: str | None = None


class DomainVariation(BaseModel):
    domain: str
    technique: str
    source_target: str
    risk_context_tags: list[str] = Field(default_factory=list)


class CertificateObservation(BaseModel):
    logged_at: datetime
    issuer_name: str
    common_name: str
    matching_identities: list[str] = Field(default_factory=list)
    source: str = "crt.sh"
    origin: DataOrigin = DataOrigin.LIVE


class DomainInfrastructure(BaseModel):
    ip_addresses: list[str] = Field(default_factory=list)
    name_servers: list[str] = Field(default_factory=list)
    rdap_org: str | None = None
    registrar: str | None = None
    asn: str | None = None
    asn_org: str | None = None
    hosted_country: str | None = None
    reputation_tags: list[str] = Field(default_factory=list)
    source: str = "composite-enrichment"
    origin: DataOrigin = DataOrigin.LIVE


class ScoredAsset(BaseModel):
    domain: str
    technique: str
    score: int
    priority: str
    certificate_observations: list[CertificateObservation] = Field(default_factory=list)
    infrastructure: DomainInfrastructure = Field(default_factory=DomainInfrastructure)
    risk_signals: list[RiskSignal] = Field(default_factory=list)
    score_rationale: str
    evidence_sources: list[str] = Field(default_factory=list)


class AnalystSummary(BaseModel):
    headline: str
    executive_summary: str
    analyst_notes: list[str]
    recommended_actions: list[str]
    grounding_notes: list[str]
    model_source: str


class AnalysisResult(BaseModel):
    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target_profile: TargetProfile
    assets: list[ScoredAsset]
    summary: AnalystSummary
    report_markdown: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalysisListItem(BaseModel):
    analysis_id: str
    created_at: datetime
    target: str
    high_priority_count: int
    medium_priority_count: int
    total_assets: int
    summary_headline: str
    offline_mode: bool


class AnalysisListResponse(BaseModel):
    analyses: list[AnalysisListItem]
