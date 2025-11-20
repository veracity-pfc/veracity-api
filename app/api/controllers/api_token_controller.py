from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.api.deps import get_current_user, get_db
from app.domain.enums import ApiTokenRequestStatus, ApiTokenStatus
from app.domain.user_model import User
from app.schemas.api_token import ApiTokenRead, ApiTokenPageOut, ApiTokenListItem
from app.schemas.api_token_request import (
    ApiTokenRequestRead,
    ApiTokenRequestPageOut,
    ApiTokenRequestListItem,
    RejectBody,
)
from app.services.api_token_service import ApiTokenService
from app.services.url_analysis_service import UrlAnalysisService
from app.services.image_analysis_service import ImageAnalysisService


router = APIRouter(prefix="/administration/api", tags=["API Tokens"])


@router.get(
    "/token-requests",
    response_model=ApiTokenRequestPageOut,
)
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
        raise HTTPException(
            status_code=400,
            detail="Data final não pode ser anterior à data inicial.",
        )

    svc = ApiTokenService(session)
    total, total_pages, rows = await svc.list_requests(
        page=page,
        page_size=page_size,
        status=status,
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


@router.get(
    "/token-requests/{request_id}",
    response_model=ApiTokenRequestRead,
)
async def get_token_request(
    request_id: UUID,
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    svc = ApiTokenService(session)
    req = await svc.get_request(request_id)
    if not req:
        raise HTTPException(status_code=404, detail="Solicitação não encontrada.")
    return req


@router.post(
    "/token-requests/{request_id}/approve",
    response_model=ApiTokenRead,
)
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
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return token


@router.post(
    "/token-requests/{request_id}/reject",
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
            status_code=400,
            detail="O motivo da rejeição deve ser informado.",
        )

    svc = ApiTokenService(session)
    try:
        req = await svc.reject_request(
            request_id=request_id,
            admin_id=admin.id,
            reason=body.reason.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return req


@router.get(
    "/tokens",
    response_model=ApiTokenPageOut,
)
async def list_tokens(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status: Optional[ApiTokenStatus] = Query(None),
    date_from: Optional[datetime] = Query(None),
    date_to: Optional[datetime] = Query(None),
    email: Optional[str] = Query(None),
    _: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    if date_from and date_to and date_to < date_from:
        raise HTTPException(
            status_code=400,
            detail="Data final não pode ser anterior à data inicial.",
        )

    svc = ApiTokenService(session)
    total, total_pages, rows = await svc.list_tokens(
        page=page,
        page_size=page_size,
        status=status,
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


@router.post(
    "/tokens/{token_id}/revoke",
    response_model=ApiTokenRead,
)
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
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return token


@router.post("/auth")
async def token_auth(
    token: str = Body(...),
    session: AsyncSession = Depends(get_session),
):
    svc = ApiTokenService(session)
    t = await svc.validate_token(token)
    return {"ok": True, "user_id": str(t.user_id), "expires_at": t.expires_at}


@router.post("/refresh")
async def token_refresh(
    token: str = Body(...),
    session: AsyncSession = Depends(get_session),
):
    svc = ApiTokenService(session)
    new_token = await svc.refresh_token(token)
    return {"token": new_token}


@router.post("/url-analysis")
async def token_url_analysis(
    token: str = Body(...),
    url: str = Body(...),
    session: AsyncSession = Depends(get_session),
):
    svc = ApiTokenService(session)
    token_obj = await svc.validate_token(token)
    analysis = UrlAnalysisService(session)
    result = await analysis.run_analysis(token_obj.user_id, url)
    return result


@router.post("/image-analysis")
async def token_image_analysis(
    token: str = Body(...),
    image_url: str = Body(...),
    session: AsyncSession = Depends(get_session),
):
    svc = ApiTokenService(session)
    token_obj = await svc.validate_token(token)
    analysis = ImageAnalysisService(session)
    result = await analysis.run_analysis(token_obj.user_id, image_url)
    return result
