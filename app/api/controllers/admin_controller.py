from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.database import get_session as get_db
from app.services.admin_service import AdminDashboardService

router = APIRouter(prefix="/administration", tags=["admin"])


def _validate_year_month(year: int | None, month: int | None) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    y = year or now.year
    m = month or now.month
    if not (2000 <= y <= 2100):
        raise HTTPException(status_code=400, detail="Parâmetro 'year' inválido")
    if not (1 <= m <= 12):
        raise HTTPException(status_code=400, detail="Parâmetro 'month' inválido")
    return y, m


@router.get("/metrics/month")
async def metrics_month(
    _: str = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
    year: int | None = Query(default=None, description="Ano (YYYY)"),
    month: int | None = Query(default=None, description="Mês (1-12)"),
) -> Dict[str, Any]:
    y, m = _validate_year_month(year, month)
    service = AdminDashboardService(session)
    return await service.get_monthly_metrics(year=y, month=m)
