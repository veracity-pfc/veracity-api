from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db, require_admin
from app.domain.enums import ApiTokenRequestStatus, ApiTokenStatus
from app.domain.user_model import User
from app.schemas.api_token import ApiTokenListItem, ApiTokenPageOut, ApiTokenRead
from app.schemas.api_token_request import (
    ApiTokenRequestListItem,
    ApiTokenRequestPageOut,
    ApiTokenRequestRead,
    RejectBody,
)
from app.schemas.contact import (
    ContactRequestReplyBody,
    UnifiedRequestDetail,
    UnifiedRequestPageOut,
)
from app.services.admin_service import AdminDashboardService
from app.services.api_token_service import ApiTokenService
from app.services.contact_service import ContactService

router = APIRouter(prefix="/v1/administration", tags=["admin"])


@router.get("/metrics/month")
async def metrics_month(
    _: str = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
    year: int | None = Query(default=None, description="Ano (YYYY)"),
    month: int | None = Query(default=None, description="Mês (1-12)"),
) -> Dict[str, Any]:
    service = AdminDashboardService(session)
    try:
        return await service.get_monthly_metrics(year=year, month=month)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/contact-requests", response_model=UnifiedRequestPageOut)
async def list_unified_requests(
    status_filter: Optional[str] = Query(None, alias="status"),
    category: Optional[str] = None,
    email: Optional[str] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    service = AdminDashboardService(session)
    return await service.list_unified_requests(
        status=status_filter,
        category=category,
        email=email,
        page=page,
        page_size=page_size,
    )


@router.get("/contact-requests/{request_id}", response_model=UnifiedRequestDetail)
async def get_unified_request_detail(
    request_id: UUID,
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    service = AdminDashboardService(session)
    detail = await service.get_unified_request_detail(request_id)
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação não encontrada.",
        )
    return detail


@router.post("/contact-requests/{request_id}/reply")
async def reply_contact_request(
    request_id: UUID,
    body: ContactRequestReplyBody,
    admin: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    svc = ContactService(session)
    try:
        await svc.reply_request(request_id, admin, body.reply_message)
        return {"ok": True}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get("/api/token-requests", response_model=ApiTokenRequestPageOut)
async def list_token_requests(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status_filter: Optional[ApiTokenRequestStatus] = Query(None, alias="status"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    email: Optional[str] = Query(None),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data final inválida.",
        )

    svc = ApiTokenService(session)
    total, total_pages, rows = await svc.list_requests(
        page=page,
        page_size=page_size,
        status=status_filter,
        date_from=date_from,
        date_to=date_to,
        email=email,
    )
    items = [
        ApiTokenRequestListItem(
            id=row.id,
            email=row.email,
            message_preview=row.message[:120],
            status=row.status,
            created_at=row.created_at,
        )
        for row in rows
    ]
    return ApiTokenRequestPageOut(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.get("/api/token-requests/{request_id}", response_model=ApiTokenRequestRead)
async def get_token_request(
    request_id: UUID,
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    svc = ApiTokenService(session)
    req = await svc.get_request(request_id)
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Solicitação não encontrada.",
        )
    return req


@router.post("/api/token-requests/{request_id}/approve", response_model=ApiTokenRead)
async def approve_token_request(
    request_id: UUID,
    admin: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    svc = ApiTokenService(session)
    try:
        _, token, _ = await svc.approve_request(
            request_id=request_id,
            admin_id=admin.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return token


@router.post(
    "/api/token-requests/{request_id}/reject",
    response_model=ApiTokenRequestRead,
)
async def reject_token_request(
    request_id: UUID,
    body: RejectBody,
    admin: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    if not body.reason.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Motivo obrigatório.",
        )
    svc = ApiTokenService(session)
    try:
        req = await svc.reject_request(
            request_id=request_id,
            admin_id=admin.id,
            reason=body.reason.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return req


@router.get("/api/tokens", response_model=ApiTokenPageOut)
async def list_tokens(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status_filter: Optional[ApiTokenStatus] = Query(None, alias="status"),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    email: Optional[str] = Query(None),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data final inválida.",
        )
    svc = ApiTokenService(session)
    total, total_pages, rows = await svc.list_tokens(
        page=page,
        page_size=page_size,
        status=status_filter,
        date_from=date_from,
        date_to=date_to,
        email=email,
    )
    items = [
        ApiTokenListItem(
            id=row.id,
            token_prefix=row.token_prefix,
            status=row.status,
            created_at=row.created_at,
            expires_at=row.expires_at,
            last_used_at=row.last_used_at,
            user_email=row.user.email,
        )
        for row in rows
    ]
    return ApiTokenPageOut(
        items=items,
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )


@router.post("/api/tokens/{token_id}/revoke", response_model=ApiTokenRead)
async def revoke_token(
    token_id: UUID,
    body: RejectBody | None = None,
    admin: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    reason = body.reason.strip() if body and body.reason else None
    svc = ApiTokenService(session)
    try:
        token = await svc.revoke_token(
            token_id=token_id,
            admin_id=admin.id,
            reason=reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
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
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token não encontrado.",
        )
    return token_data