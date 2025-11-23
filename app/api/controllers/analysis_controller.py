from __future__ import annotations

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_optional_user
from app.domain.user_model import User
from app.schemas.image_analysis import ImageAnalysisOut, ImageIn
from app.schemas.url_analysis import UrlAnalysisIn, UrlAnalysisOut
from app.services.image_analysis_service import ImageAnalysisService
from app.services.url_analysis_service import UrlAnalysisService

router = APIRouter(prefix="/v1/analyses", tags=["analyses"])


@router.post("/url", response_model=UrlAnalysisOut)
async def analyze_url(
    payload: UrlAnalysisIn,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    svc = UrlAnalysisService(session)
    try:
        analysis, _row, ai_json = await svc.analyze(
            url_in=payload.url,
            request=request,
            user_id=str(user.id) if user else None,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )

    return {
        "analysis_id": str(analysis.id),
        "url": payload.url,
        "explanation": ai_json.get("explanation"),
        "recommendations": ai_json.get("recommendations", []),
        "label": analysis.label.value,
        "quota": ai_json.get("quota"),
    }


@router.post("/image", response_model=ImageAnalysisOut)
async def analyze_image(
    request: Request,
    file: UploadFile = File(..., description="Imagem PNG/JPEG até 1MB"),
    session: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    raw = await file.read()

    try:
        payload = ImageIn(
            filename=file.filename or "upload",
            content_type=file.content_type or "",
            size_bytes=len(raw),
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Parâmetros de imagem inválidos.",
        )

    svc = ImageAnalysisService(session)
    try:
        analysis, _img_row, ai_json = await svc.analyze(
            upload_bytes=raw,
            filename=payload.filename,
            content_type=payload.content_type,
            request=request,
            user_id=str(user.id) if user else None,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )

    return {
        "analysis_id": str(analysis.id),
        "label": analysis.label,
        "explanation": ai_json.get("explanation", ""),
        "recommendations": list(ai_json.get("recommendations") or []),
        "quota": ai_json.get("quota"),
    }