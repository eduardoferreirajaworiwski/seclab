from fastapi import APIRouter, Depends, HTTPException, Query
from seclab.core.config import Settings, get_settings
from seclab.core.db import get_db
from sqlalchemy.orm import Session

from seclab_osint_breach.models import (
    BreachCheckListResponse,
    BreachCheckRequest,
    BreachCheckResult,
)
from seclab_osint_breach.service import BreachCheckService

router = APIRouter(tags=["osint_breach"])


def get_breach_check_service(
    settings: Settings = Depends(get_settings), db: Session = Depends(get_db)
) -> BreachCheckService:
    return BreachCheckService(settings, db)


@router.post("/checks", response_model=BreachCheckResult)
async def create_check(
    request: BreachCheckRequest = BreachCheckRequest(),
    service: BreachCheckService = Depends(get_breach_check_service),
) -> BreachCheckResult:
    return await service.run_check(request)


@router.get("/checks", response_model=BreachCheckListResponse)
async def list_checks(
    limit: int = Query(default=10, ge=1, le=50),
    service: BreachCheckService = Depends(get_breach_check_service),
) -> BreachCheckListResponse:
    return BreachCheckListResponse(checks=service.list_recent_checks(limit))


@router.get("/checks/{check_id}", response_model=BreachCheckResult)
async def get_check(
    check_id: str, service: BreachCheckService = Depends(get_breach_check_service)
) -> BreachCheckResult:
    result = service.get_check(check_id)
    if result is None:
        raise HTTPException(status_code=404, detail="check not found")
    return result
