from __future__ import annotations

import calendar
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin, get_current_user, get_db
from app.core.database import get_session
from app.domain.enums import ApiTokenRequestStatus, ApiTokenStatus
from app.domain.user_model import User
from app.domain.api_token_model import ApiToken
from app.schemas.api_token import ApiTokenRead, ApiTokenPageOut, ApiTokenListItem
from app.schemas.api_token_request import (
    ApiTokenRequestRead,
    ApiTokenRequestPageOut,
    ApiTokenRequestListItem,
    RejectBody,
)
from app.services.admin_service import AdminDashboardService
from app.services.api_token_service import ApiTokenService

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
    session: AsyncSession = Depends(get_session),
    year: int | None = Query(default=None, description="Ano (YYYY)"),
    month: int | None = Query(default=None, description="Mês (1-12)"),
) -> Dict[str, Any]:
    y, m = _validate_year_month(year, month)
    service = AdminDashboardService(session)
    
    metrics = await service.get_monthly_metrics(year=y, month=m)
    
    last_day = calendar.monthrange(y, m)[1]
    end_of_month = datetime(y, m, last_day, 23, 59, 59, tzinfo=timezone.utc)
    
    stmt = select(ApiToken).where(ApiToken.created_at <= end_of_month)
    result = await session.execute(stmt)
    tokens = result.scalars().all()
    
    active_count = 0
    expired_count = 0
    revoked_count = 0
    
    for t in tokens:
        if t.revoked_at and t.revoked_at <= end_of_month:
            revoked_count += 1
        elif t.expires_at and t.expires_at <= end_of_month:
            expired_count += 1
        else:
            active_count += 1

    metrics["tokens"] = {
        "bars": {
            "active": active_count,
            "expired": expired_count,
            "revoked": revoked_count,
        },
        "totals": {
            "total": active_count + expired_count + revoked_count,
            "active": active_count,
            "expired": expired_count,
            "revoked": revoked_count
        }
    }

    return metrics


@router.get("/api/token-requests", response_model=ApiTokenRequestPageOut)
async def list_token_requests(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status: Optional[ApiTokenRequestStatus] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    email: Optional[str] = Query(None),
    _: User = Depends(get_current_user), 
    session: AsyncSession = Depends(get_db),
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(status_code=400, detail="Data final inválida.")

    svc = ApiTokenService(session)
    total, total_pages, rows = await svc.list_requests(
        page=page, page_size=page_size, status=status,
        date_from=date_from, date_to=date_to, email=email
    )
    items = [
        ApiTokenRequestListItem(
            id=row.id, email=row.email, message_preview=row.message[:120],
            status=row.status, created_at=row.created_at
        ) for row in rows
    ]
    return ApiTokenRequestPageOut(items=items, page=page, page_size=page_size, total=total, total_pages=total_pages)


@router.get("/api/token-requests/{request_id}", response_model=ApiTokenRequestRead)
async def get_token_request(
    request_id: UUID, _: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)
):
    svc = ApiTokenService(session)
    req = await svc.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return req


@router.post("/api/token-requests/{request_id}/approve", response_model=ApiTokenRead)
async def approve_token_request(
    request_id: UUID, admin: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)
):
    svc = ApiTokenService(session)
    try:
        _, token, _ = await svc.approve_request(request_id=request_id, admin_id=admin.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return token


@router.post("/api/token-requests/{request_id}/reject", response_model=ApiTokenRequestRead)
async def reject_token_request(
    request_id: UUID, body: RejectBody, admin: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)
):
    if not body.reason.strip():
        raise HTTPException(status_code=400, detail="Motivo obrigatório.")
    svc = ApiTokenService(session)
    try:
        req = await svc.reject_request(request_id=request_id, admin_id=admin.id, reason=body.reason.strip())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return req


@router.get("/api/tokens", response_model=ApiTokenPageOut)
async def list_tokens(
    page: int = Query(1, ge=1), page_size: int = Query(10, ge=1, le=100),
    status: Optional[ApiTokenStatus] = Query(None),
    date_from: Optional[datetime] = Query(None), date_to: Optional[datetime] = Query(None),
    email: Optional[str] = Query(None),
    _: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(status_code=400, detail="Data final inválida.")
    svc = ApiTokenService(session)
    total, total_pages, rows = await svc.list_tokens(
        page=page, page_size=page_size, status=status,
        date_from=date_from, date_to=date_to, email=email
    )
    items = [
        ApiTokenListItem(
            id=row.id, token_prefix=row.token_prefix, status=row.status,
            created_at=row.created_at, expires_at=row.expires_at,
            last_used_at=row.last_used_at, user_email=row.user.email
        ) for row in rows
    ]
    return ApiTokenPageOut(items=items, page=page, page_size=page_size, total=total, total_pages=total_pages)


@router.post("/api/tokens/{token_id}/revoke", response_model=ApiTokenRead)
async def revoke_token(
    token_id: UUID, body: RejectBody | None = None,
    admin: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)
):
    reason = body.reason.strip() if body and body.reason else None
    svc = ApiTokenService(session)
    try:
        token = await svc.revoke_token(token_id=token_id, admin_id=admin.id, reason=reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return token

@router.get("/api/tokens/{token_id}")
async def get_token_detail(
    token_id: UUID,
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    svc = ApiTokenService(session)
    token_data = await svc.get_token_details(token_id)
    if not token_data:
        raise HTTPException(status_code=404, detail="Token não encontrado.")
    return token_data