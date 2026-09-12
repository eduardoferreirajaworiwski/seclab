from datetime import UTC, datetime

from seclab.core.db import Base
from sqlalchemy import DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from seclab_threatlens.models import DigestListItem, DigestResult


class DigestRun(Base):
    __tablename__ = "threatlens_digest_runs"

    digest_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    article_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class DigestRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, result: DigestResult) -> None:
        payload = result.model_dump_json()
        existing = self.db.get(DigestRun, result.digest_id)
        if existing is not None:
            existing.payload_json = payload
            existing.article_count = len(result.articles)
        else:
            self.db.add(
                DigestRun(
                    digest_id=result.digest_id,
                    created_at=result.created_at,
                    article_count=len(result.articles),
                    payload_json=payload,
                )
            )
        self.db.commit()

    def get(self, digest_id: str) -> DigestResult | None:
        row = self.db.get(DigestRun, digest_id)
        if row is None:
            return None
        return DigestResult.model_validate_json(row.payload_json)

    def list_recent(self, limit: int = 10) -> list[DigestListItem]:
        rows = self.db.scalars(
            select(DigestRun).order_by(DigestRun.created_at.desc()).limit(limit)
        )
        items: list[DigestListItem] = []
        for row in rows:
            result = DigestResult.model_validate_json(row.payload_json)
            vector_counts: dict[str, int] = {}
            for article in result.articles:
                for vector in article.vectors:
                    vector_counts[vector.value] = vector_counts.get(vector.value, 0) + 1
            top_vectors = sorted(vector_counts, key=vector_counts.get, reverse=True)[:3]
            items.append(
                DigestListItem(
                    digest_id=result.digest_id,
                    created_at=result.created_at,
                    article_count=len(result.articles),
                    top_vectors=top_vectors,
                    summary_headline=result.summary.headline,
                    offline_mode=bool(result.metadata.get("offline_mode", False)),
                )
            )
        return items
