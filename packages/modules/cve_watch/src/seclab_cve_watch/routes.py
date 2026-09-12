from fastapi import APIRouter, Depends, HTTPException, Query
from seclab.core.config import Settings, get_settings
from seclab.core.db import get_db
from sqlalchemy.orm import Session

from seclab_cve_watch.models import DigestListResponse, DigestRequest, DigestResult
from seclab_cve_watch.service import CveWatchService

router = APIRouter(tags=["cve_watch"])


def get_cve_watch_service(
    settings: Settings = Depends(get_settings), db: Session = Depends(get_db)
) -> CveWatchService:
    return CveWatchService(settings, db)


@router.post("/digests", response_model=DigestResult)
async def create_digest(
    request: DigestRequest = DigestRequest(),
    service: CveWatchService = Depends(get_cve_watch_service),
) -> DigestResult:
    return await service.run_digest(request)


@router.get("/digests", response_model=DigestListResponse)
async def list_digests(
    limit: int = Query(default=10, ge=1, le=50),
    service: CveWatchService = Depends(get_cve_watch_service),
) -> DigestListResponse:
    return DigestListResponse(digests=service.list_recent_digests(limit))


@router.get("/digests/{digest_id}", response_model=DigestResult)
async def get_digest(
    digest_id: str, service: CveWatchService = Depends(get_cve_watch_service)
) -> DigestResult:
    result = service.get_digest(digest_id)
    if result is None:
        raise HTTPException(status_code=404, detail="digest not found")
    return result
