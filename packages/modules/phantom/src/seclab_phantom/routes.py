from fastapi import APIRouter, Depends, HTTPException, Query
from seclab.core.config import Settings, get_settings
from seclab.core.db import get_db
from sqlalchemy.orm import Session

from seclab_phantom.models import AnalysisListResponse, AnalysisResult, TargetRequest
from seclab_phantom.service import AnalysisService

router = APIRouter(tags=["phantom"])


def get_analysis_service(
    settings: Settings = Depends(get_settings), db: Session = Depends(get_db)
) -> AnalysisService:
    return AnalysisService(settings, db)


@router.post("/analyses", response_model=AnalysisResult)
async def create_analysis(
    request: TargetRequest, service: AnalysisService = Depends(get_analysis_service)
) -> AnalysisResult:
    return await service.analyze(request)


@router.get("/analyses", response_model=AnalysisListResponse)
async def list_analyses(
    limit: int = Query(default=10, ge=1, le=50),
    service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisListResponse:
    return AnalysisListResponse(analyses=service.list_recent_analyses(limit))


@router.get("/analyses/{analysis_id}", response_model=AnalysisResult)
async def get_analysis(
    analysis_id: str, service: AnalysisService = Depends(get_analysis_service)
) -> AnalysisResult:
    result = service.get_analysis(analysis_id)
    if result is None:
        raise HTTPException(status_code=404, detail="analysis not found")
    return result
