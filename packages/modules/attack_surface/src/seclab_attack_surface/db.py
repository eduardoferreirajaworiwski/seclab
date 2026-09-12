from datetime import UTC, datetime

from seclab.core.db import Base
from sqlalchemy import Boolean, DateTime, Integer, String, Text, select
from sqlalchemy.orm import Mapped, Session, mapped_column

from seclab_attack_surface.models import SurfaceScanListItem, SurfaceScanResult


class SurfaceScanRun(Base):
    __tablename__ = "attack_surface_scan_runs"

    scan_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    host_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    exposure_tag_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)


class SurfaceScanRepository:
    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, result: SurfaceScanResult) -> None:
        payload = result.model_dump_json()
        exposure_tag_count = sum(len(host.unexpected_exposure_tags) for host in result.hosts)
        existing = self.db.get(SurfaceScanRun, result.scan_id)
        if existing is not None:
            existing.payload_json = payload
            existing.in_scope = result.in_scope
            existing.host_count = len(result.hosts)
            existing.exposure_tag_count = exposure_tag_count
        else:
            self.db.add(
                SurfaceScanRun(
                    scan_id=result.scan_id,
                    created_at=result.created_at,
                    domain=result.target.domain,
                    in_scope=result.in_scope,
                    host_count=len(result.hosts),
                    exposure_tag_count=exposure_tag_count,
                    payload_json=payload,
                )
            )
        self.db.commit()

    def get(self, scan_id: str) -> SurfaceScanResult | None:
        row = self.db.get(SurfaceScanRun, scan_id)
        if row is None:
            return None
        return SurfaceScanResult.model_validate_json(row.payload_json)

    def list_recent(self, limit: int = 10) -> list[SurfaceScanListItem]:
        rows = self.db.scalars(
            select(SurfaceScanRun).order_by(SurfaceScanRun.created_at.desc()).limit(limit)
        )
        items: list[SurfaceScanListItem] = []
        for row in rows:
            items.append(
                SurfaceScanListItem(
                    scan_id=row.scan_id,
                    created_at=row.created_at,
                    domain=row.domain,
                    in_scope=row.in_scope,
                    host_count=row.host_count,
                    exposure_tag_count=row.exposure_tag_count,
                )
            )
        return items
