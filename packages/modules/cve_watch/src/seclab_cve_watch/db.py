from datetime import UTC, datetime

from seclab.core.db import Base
from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from seclab_cve_watch.models import DigestListItem, DigestResult


class CveDigestRun(Base):
    __tablename__ = "cve_watch_digest_runs"

    digest_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    cve_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    actively_exploited_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    offline_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class CveDigestRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, result: DigestResult) -> None:
        payload = result.model_dump_json()
        exploited_count = sum(1 for cve in result.cves if cve.is_actively_exploited)
        existing = self.db.get(CveDigestRun, result.digest_id)
        if existing is not None:
            existing.payload_json = payload
            existing.cve_count = len(result.cves)
            existing.actively_exploited_count = exploited_count
        else:
            self.db.add(
                CveDigestRun(
                    digest_id=result.digest_id,
                    created_at=result.created_at,
                    cve_count=len(result.cves),
                    actively_exploited_count=exploited_count,
                    offline_mode=bool(result.metadata.get("offline_mode", False)),
                    payload_json=payload,
                )
            )
        self.db.commit()

    def get(self, digest_id: str) -> DigestResult | None:
        row = self.db.get(CveDigestRun, digest_id)
        if row is None:
            return None
        return DigestResult.model_validate_json(row.payload_json)

    def list_recent(self, limit: int = 10) -> list[DigestListItem]:
        rows = self.db.scalars(
            select(CveDigestRun).order_by(CveDigestRun.created_at.desc()).limit(limit)
        )
        items: list[DigestListItem] = []
        for row in rows:
            result = DigestResult.model_validate_json(row.payload_json)
            items.append(
                DigestListItem(
                    digest_id=result.digest_id,
                    created_at=result.created_at,
                    cve_count=len(result.cves),
                    actively_exploited_count=row.actively_exploited_count,
                    summary_headline=result.summary.headline,
                    offline_mode=row.offline_mode,
                )
            )
        return items
