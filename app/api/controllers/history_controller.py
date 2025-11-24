from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.domain.enums import AnalysisType, RiskLabel
from app.domain.user_model import User
from app.schemas.history import HistoryDetailOut, HistoryPageOut
from app.services.history_service import HistoryService

router = APIRouter(prefix="/v1/user/history", tags=["History"])


@router.get("", response_model=HistoryPageOut)
async def list_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(6, ge=1, le=50),
    q: Optional[str] = Query(None, description="Busca livre"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    status_filter: Optional[RiskLabel] = Query(None, alias="status"),
    analysis_type: Optional[AnalysisType] = Query(None),
    origin: Optional[str] = Query(None, regex="^(token|user)$"),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data final não pode ser anterior à data inicial.",
        )

    svc = HistoryService(session)
    return await svc.list_for_user(
        user_id=str(user.id),
        page=page,
        page_size=page_size,
        q=q,
        date_from=date_from,
        date_to=date_to,
        status=status_filter,
        analysis_type=analysis_type,
        origin=origin,
    )


@router.get("/{analysis_id}", response_model=HistoryDetailOut)
async def history_detail(
    analysis_id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    svc = HistoryService(session)
    detail = await svc.detail_for_user(
        analysis_id=analysis_id,
        user_id=str(user.id),
    )
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Análise não encontrada",
        )
    return detail