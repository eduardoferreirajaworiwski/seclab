from datetime import UTC, datetime

from seclab.core.db import Base
from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column


class MonitorMatch(Base):
    __tablename__ = "monitor_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    issuer: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    matched_keyword: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    technique: Mapped[str] = mapped_column(String(50), nullable=False, default="live-ct-match")
    score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    score_rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    capture_status: Mapped[str] = mapped_column(String(30), nullable=False, default="skipped")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
