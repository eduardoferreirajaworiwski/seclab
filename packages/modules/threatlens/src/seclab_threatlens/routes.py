from fastapi import APIRouter, Depends, HTTPException, Query
from seclab.core.config import Settings, get_settings
from seclab.core.db import get_db
from sqlalchemy.orm import Session

from seclab_threatlens.models import DigestListResponse, DigestRequest, DigestResult
from seclab_threatlens.service import ThreatLensService

router = APIRouter(tags=["threatlens"])


def get_threatlens_service(
    settings: Settings = Depends(get_settings), db: Session = Depends(get_db)
) -> ThreatLensService:
    return ThreatLensService(settings, db)


@router.post("/digests", response_model=DigestResult)
async def create_digest(
    request: DigestRequest = DigestRequest(),
    service: ThreatLensService = Depends(get_threatlens_service),
) -> DigestResult:
    return await service.run_digest(request)


@router.get("/digests", response_model=DigestListResponse)
async def list_digests(
    limit: int = Query(default=10, ge=1, le=50),
    service: ThreatLensService = Depends(get_threatlens_service),
) -> DigestListResponse:
    return DigestListResponse(digests=service.list_recent_digests(limit))


@router.get("/digests/{digest_id}", response_model=DigestResult)
async def get_digest(
    digest_id: str, service: ThreatLensService = Depends(get_threatlens_service)
) -> DigestResult:
    result = service.get_digest(digest_id)
    if result is None:
        raise HTTPException(status_code=404, detail="digest not found")
    return result
