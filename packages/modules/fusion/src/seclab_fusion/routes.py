from fastapi import APIRouter, Depends, Query
from seclab.core.db import get_db
from sqlalchemy.orm import Session

from seclab_fusion.models import FusionFeedResponse
from seclab_fusion.service import DEFAULT_FEED_LIMIT, FusionService

router = APIRouter(tags=["fusion"])


def get_fusion_service(db: Session = Depends(get_db)) -> FusionService:
    return FusionService(db)


@router.get("/feed", response_model=FusionFeedResponse)
def get_feed(
    limit: int = Query(default=DEFAULT_FEED_LIMIT, ge=1, le=200),
    service: FusionService = Depends(get_fusion_service),
) -> FusionFeedResponse:
    return service.get_feed(limit=limit)
