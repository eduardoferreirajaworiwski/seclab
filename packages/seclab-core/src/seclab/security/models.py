from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from seclab.core.db import Base


class Role(StrEnum):
    ANALYST = "analyst"
    SECURITY_LEAD = "security_lead"


_ROLE_RANK = {Role.ANALYST.value: 1, Role.SECURITY_LEAD.value: 2}


def role_rank(role: str) -> int:
    return _ROLE_RANK.get(role, 0)


class User(Base):
    """Any module's authz depends on the identity/role coming from this
    authenticated row - never from a request body. Ported from
    scopepilot/app/db/models.py::User; api_key_hash now stores an
    HMAC-SHA256(pepper) digest instead of unsalted SHA-256 (see
    seclab.security.keys)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(40), nullable=False, default=Role.ANALYST.value)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class AuditLog(Base):
    """Fail-closed, append-only audit trail. Generalized from scopepilot's
    DecisionLog (app/db/models.py) so any module can write to the same
    table - entity_type/entity_id stay module-namespaced free text
    (e.g. "recon.hypothesis", "sensor_chimera.hit")."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    event_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    decision: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )


class EvidenceArtifact(Base):
    """Generic chain-of-custody store: any module can persist an artifact
    (text, JSON, screenshot path, HTML dump...) with a content hash.
    Consolidates scopepilot's Evidence table and hydra-mapper's loose
    .hash sidecar files into one auditable place."""

    __tablename__ = "evidence_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    source_module: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(60), nullable=False)
    subject_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_format: Mapped[str] = mapped_column(String(30), nullable=False, default="text")
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalRequest(Base):
    """Human-in-the-loop gate, generalized from scopepilot's
    Approval/Hypothesis pairing (app/db/models.py) to reference any
    module's subject instead of hardcoding hypothesis_id, so `recon`,
    `monitor` and future modules can all gate active actions behind the
    same approval state machine."""

    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    subject_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    subject_id: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    required_role: Mapped[str] = mapped_column(
        String(40), nullable=False, default=Role.ANALYST.value
    )
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    request_rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    approver: Mapped[str | None] = mapped_column(String(120), nullable=True)
    approver_role: Mapped[str | None] = mapped_column(String(40), nullable=True)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=ApprovalStatus.PENDING.value
    )
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
