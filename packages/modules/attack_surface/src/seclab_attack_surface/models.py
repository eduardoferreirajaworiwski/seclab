from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field
from seclab.security.scope_guard import ProgramPolicy


class AssetTarget(BaseModel):
    """The domain the caller owns/operates and wants mapped - distinct from
    phantom's "lookalike of a brand" use case."""

    domain: str = Field(min_length=2, max_length=255)


class DiscoveredHost(BaseModel):
    hostname: str
    ip_addresses: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    unexpected_exposure_tags: list[str] = Field(default_factory=list)


class SurfaceScanRequest(BaseModel):
    """Carries the ProgramPolicy allowlist inline in the request itself,
    since this module (unlike recon) has no separate Program registration
    step - the caller supplies the scope policy directly with every scan."""

    target: AssetTarget
    scope_policy: ProgramPolicy = Field(default_factory=ProgramPolicy)


class SurfaceScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    target: AssetTarget
    in_scope: bool
    hosts: list[DiscoveredHost] = Field(default_factory=list)
    report_markdown: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class SurfaceScanListItem(BaseModel):
    scan_id: str
    created_at: datetime
    domain: str
    in_scope: bool
    host_count: int
    exposure_tag_count: int


class SurfaceScanListResponse(BaseModel):
    scans: list[SurfaceScanListItem]
