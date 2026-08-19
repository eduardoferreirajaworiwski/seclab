from fastapi import APIRouter, Depends, Query
from seclab.core.db import get_db
from sqlalchemy import select
from sqlalchemy.orm import Session

from seclab_monitor.models import MonitorMatch
from seclab_monitor.schemas import MonitorMatchRead

router = APIRouter(tags=["monitor"])


@router.get("/matches", response_model=list[MonitorMatchRead])
def list_matches(
    limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)
) -> list[MonitorMatchRead]:
    rows = db.scalars(select(MonitorMatch).order_by(MonitorMatch.created_at.desc()).limit(limit))
    return [MonitorMatchRead.model_validate(row) for row in rows]
