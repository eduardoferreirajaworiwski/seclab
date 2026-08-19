from datetime import UTC, datetime

from seclab.core.db import Base
from seclab.security.models import Role
from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from seclab_recon.enums import ExecutionStatus, FindingStatus, HypothesisStatus


class Program(Base):
    __tablename__ = "recon_programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(150), unique=True, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner: Mapped[str] = mapped_column(String(120), nullable=False)
    scope_policy: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class Target(Base):
    __tablename__ = "recon_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    program_id: Mapped[int] = mapped_column(
        ForeignKey("recon_programs.id"), index=True, nullable=False
    )
    identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    in_scope: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    scope_reason: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )


class Hypothesis(Base):
    __tablename__ = "recon_hypotheses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    program_id: Mapped[int] = mapped_column(
        ForeignKey("recon_programs.id"), index=True, nullable=False
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("recon_targets.id"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    suggested_next_step: Mapped[str] = mapped_column(Text, nullable=False, default="")
    required_role: Mapped[str] = mapped_column(
        String(40), nullable=False, default=Role.ANALYST.value
    )
    severity: Mapped[str] = mapped_column(String(30), nullable=False, default="medium")
    created_by: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(
        String(40), nullable=False, default=HypothesisStatus.DRAFT.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )


class Execution(Base):
    __tablename__ = "recon_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("recon_hypotheses.id"), index=True, nullable=False
    )
    requested_by: Mapped[str] = mapped_column(String(120), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    status: Mapped[str] = mapped_column(
        String(30), nullable=False, default=ExecutionStatus.QUEUED.value
    )
    action_plan: Mapped[str] = mapped_column(Text, nullable=False)
    output_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "recon_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    program_id: Mapped[int] = mapped_column(
        ForeignKey("recon_programs.id"), index=True, nullable=False
    )
    target_id: Mapped[int] = mapped_column(
        ForeignKey("recon_targets.id"), index=True, nullable=False
    )
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("recon_hypotheses.id"), index=True, nullable=False
    )
    execution_id: Mapped[int] = mapped_column(
        ForeignKey("recon_executions.id"), index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default=FindingStatus.NEW.value)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False
    )
