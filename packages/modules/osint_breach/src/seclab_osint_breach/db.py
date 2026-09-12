from datetime import UTC, datetime

from seclab.core.db import Base
from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from seclab_osint_breach.models import BreachCheckListItem, BreachCheckResult


class BreachCheckRun(Base):
    __tablename__ = "osint_breach_checks"

    check_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    identifier_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exposure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    offline_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class BreachCheckRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, result: BreachCheckResult) -> None:
        payload = result.model_dump_json()
        existing = self.db.get(BreachCheckRun, result.check_id)
        if existing is not None:
            existing.payload_json = payload
            existing.identifier_count = len(result.identifiers_checked)
            existing.exposure_count = len(result.exposures)
        else:
            self.db.add(
                BreachCheckRun(
                    check_id=result.check_id,
                    created_at=result.created_at,
                    identifier_count=len(result.identifiers_checked),
                    exposure_count=len(result.exposures),
                    offline_mode=bool(result.metadata.get("offline_mode", False)),
                    payload_json=payload,
                )
            )
        self.db.commit()

    def get(self, check_id: str) -> BreachCheckResult | None:
        row = self.db.get(BreachCheckRun, check_id)
        if row is None:
            return None
        return BreachCheckResult.model_validate_json(row.payload_json)

    def list_recent(self, limit: int = 10) -> list[BreachCheckListItem]:
        rows = self.db.scalars(
            select(BreachCheckRun).order_by(BreachCheckRun.created_at.desc()).limit(limit)
        )
        items: list[BreachCheckListItem] = []
        for row in rows:
            result = BreachCheckResult.model_validate_json(row.payload_json)
            items.append(
                BreachCheckListItem(
                    check_id=result.check_id,
                    created_at=result.created_at,
                    identifier_count=len(result.identifiers_checked),
                    exposure_count=len(result.exposures),
                    summary_headline=result.summary.headline,
                    offline_mode=row.offline_mode,
                )
            )
        return items
