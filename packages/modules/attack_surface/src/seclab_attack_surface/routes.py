from fastapi import APIRouter, Depends, HTTPException, Query
from seclab.core.config import Settings, get_settings
from seclab.core.db import get_db
from seclab_phantom.providers import CrtShProvider
from sqlalchemy.orm import Session

from seclab_attack_surface.models import (
    SurfaceScanListResponse,
    SurfaceScanRequest,
    SurfaceScanResult,
)
from seclab_attack_surface.service import AttackSurfaceService

router = APIRouter(tags=["attack_surface"])


def get_attack_surface_service(
    settings: Settings = Depends(get_settings), db: Session = Depends(get_db)
) -> AttackSurfaceService:
    ct_provider = CrtShProvider(settings, offline_mode=settings.offline_mode)
    return AttackSurfaceService(ct_provider=ct_provider, db=db)


@router.post("/scans", response_model=SurfaceScanResult)
async def create_scan(
    request: SurfaceScanRequest,
    service: AttackSurfaceService = Depends(get_attack_surface_service),
) -> SurfaceScanResult:
    return await service.run_scan(request)


@router.get("/scans", response_model=SurfaceScanListResponse)
async def list_scans(
    limit: int = Query(default=10, ge=1, le=50),
    service: AttackSurfaceService = Depends(get_attack_surface_service),
) -> SurfaceScanListResponse:
    return SurfaceScanListResponse(scans=service.list_recent_scans(limit))


@router.get("/scans/{scan_id}", response_model=SurfaceScanResult)
async def get_scan(
    scan_id: str, service: AttackSurfaceService = Depends(get_attack_surface_service)
) -> SurfaceScanResult:
    result = service.get_scan(scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return result
