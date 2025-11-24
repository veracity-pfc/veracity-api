from __future__ import annotations

from datetime import datetime, timezone
from typing import List
from zoneinfo import ZoneInfo

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    HTTPException,
    Request,
    Security,
    UploadFile,
    status,
)
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_session
from app.domain.api_token_model import ApiToken
from app.domain.analysis_model import Analysis
from app.domain.enums import AnalysisType, AnalysisStatus
from app.services.api_token_service import ApiTokenService
from app.services.image_analysis_service import ImageAnalysisService
from app.services.url_analysis_service import UrlAnalysisService

router = APIRouter(prefix="/v1/api", tags=["Public API"])

security = HTTPBearer()


async def get_api_token_header(
    creds: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session),
) -> ApiToken:
    svc = ApiTokenService(session)
    try:
        return await svc.validate_token(creds.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )


async def _token_usage_today(
    session: AsyncSession,
    token_id: str,
    analysis_type: AnalysisType,
) -> int:
    tz = ZoneInfo("America/Sao_Paulo")
    now = datetime.now(tz)
    start_local = datetime(now.year, now.month, now.day, tzinfo=tz)
    start_utc = start_local.astimezone(timezone.utc)

    stmt = (
        select(func.count(Analysis.id))
        .where(
            Analysis.api_token_id == token_id,
            Analysis.analysis_type == analysis_type,
            Analysis.created_at >= start_utc,
            Analysis.status != AnalysisStatus.error,
        )
    )
    res = await session.execute(stmt)
    return int(res.scalar_one() or 0)


@router.post("/auth")
async def token_auth(
    token: str = Body(..., embed=True),
    session: AsyncSession = Depends(get_session),
):
    svc = ApiTokenService(session)
    try:
        t = await svc.validate_token(token)

        url_used = await _token_usage_today(
            session,
            str(t.id),
            AnalysisType.url,
        )
        img_used = await _token_usage_today(
            session,
            str(t.id),
            AnalysisType.image,
        )

        url_limit = int(getattr(settings, "user_url_limit", 0) or 0)
        img_limit = int(getattr(settings, "user_image_limit", 0) or 0)

        url_remaining = max(url_limit - url_used, 0) if url_limit else 0
        img_remaining = max(img_limit - img_used, 0) if img_limit else 0

        return {
            "status": "active",
            "expires_at": t.expires_at,
            "quota": {
                "urls": {
                    "limit": url_limit,
                    "used_today": url_used,
                    "remaining_today": url_remaining,
                },
                "images": {
                    "limit": img_limit,
                    "used_today": img_used,
                    "remaining_today": img_remaining,
                },
            },
        }
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        )


@router.post("/url-analysis")
async def token_url_analysis(
    request: Request,
    url: str = Body(..., embed=True),
    token_obj: ApiToken = Depends(get_api_token_header),
    session: AsyncSession = Depends(get_session),
):
    analysis_svc = UrlAnalysisService(session)
    try:
        an, url_row, ai_data = await analysis_svc.run_analysis_with_validation(
            token_obj.user_id,
            url,
            request,
            token_id=token_obj.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return [
        {
            "analysis_type": an.analysis_type,
            "status": an.status,
            "label": an.label,
            "created_at": an.created_at,
            "completed_at": an.completed_at,
        },
        {
            "analysis_id": str(an.id),
            "url": url_row.url,
            "dns_ok": url_row.dns_ok,
            "gsb_json": url_row.gsb_json,
            "risk_label": url_row.risk_label,
        },
        {
            "classification": ai_data.get("classification"),
            "explanation": ai_data.get("explanation"),
            "recommendations": ai_data.get("recommendations"),
            "quota": ai_data.get("quota"),
        },
    ]


@router.post("/image-analysis")
async def token_image_analysis(
    request: Request,
    file: List[UploadFile] = File(...),
    token_obj: ApiToken = Depends(get_api_token_header),
    session: AsyncSession = Depends(get_session),
):
    if not file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nenhum arquivo enviado.",
        )

    uploaded_file = file[0]
    file_content = await uploaded_file.read()

    analysis_svc = ImageAnalysisService(session)
    try:
        an, img_row, ai_data = await analysis_svc.run_analysis_with_validation(
            token_obj.user_id,
            file_content,
            len(file),
            request,
            token_id=token_obj.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    return [
        {
            "analysis_type": an.analysis_type,
            "status": an.status,
            "label": an.label,
            "created_at": an.created_at,
            "completed_at": an.completed_at,
        },
        {
            "analysis_id": str(an.id),
            "filename": img_row.meta.get("filename"),
            "size": img_row.meta.get("size"),
            "mime": img_row.meta.get("mime"),
        },
        {
            "classification": ai_data.get("classification"),
            "explanation": ai_data.get("explanation"),
            "recommendations": ai_data.get("recommendations"),
            "quota": ai_data.get("quota"),
        },
    ]
