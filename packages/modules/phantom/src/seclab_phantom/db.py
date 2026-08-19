from datetime import UTC, datetime

from seclab.core.db import Base
from sqlalchemy import DateTime, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from seclab_phantom.models import AnalysisListItem, AnalysisResult


class AnalysisRun(Base):
    """Replaces phantomscope's raw sqlite3 AnalysisRepository (db/repository.py)
    with an ORM-backed table on the shared seclab Base, per the migration
    plan. Still stores the full AnalysisResult as a JSON blob - acceptable
    for a personal-lab MVP - but now shares the engine/session/migrations
    story with every other module instead of opening its own sqlite3
    connection."""

    __tablename__ = "phantom_analysis_runs"

    analysis_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    target: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class AnalysisRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, result: AnalysisResult) -> None:
        payload = result.model_dump_json()
        existing = self.db.get(AnalysisRun, result.analysis_id)
        if existing is not None:
            existing.payload_json = payload
            existing.target = result.target_profile.normalized_target
        else:
            self.db.add(
                AnalysisRun(
                    analysis_id=result.analysis_id,
                    created_at=result.created_at,
                    target=result.target_profile.normalized_target,
                    payload_json=payload,
                )
            )
        self.db.commit()

    def get(self, analysis_id: str) -> AnalysisResult | None:
        row = self.db.get(AnalysisRun, analysis_id)
        if row is None:
            return None
        return AnalysisResult.model_validate_json(row.payload_json)

    def list_recent(self, limit: int = 10) -> list[AnalysisListItem]:
        rows = self.db.scalars(
            select(AnalysisRun).order_by(AnalysisRun.created_at.desc()).limit(limit)
        )
        analyses: list[AnalysisListItem] = []
        for row in rows:
            result = AnalysisResult.model_validate_json(row.payload_json)
            analyses.append(
                AnalysisListItem(
                    analysis_id=result.analysis_id,
                    created_at=result.created_at,
                    target=result.target_profile.normalized_target,
                    high_priority_count=sum(
                        1 for asset in result.assets if asset.priority == "high"
                    ),
                    medium_priority_count=sum(
                        1 for asset in result.assets if asset.priority == "medium"
                    ),
                    total_assets=len(result.assets),
                    summary_headline=result.summary.headline,
                    offline_mode=bool(result.metadata.get("offline_mode", False)),
                )
            )
        return analyses
