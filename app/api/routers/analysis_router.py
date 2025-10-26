from fastapi import APIRouter, UploadFile, File, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_db
from app.schemas.url_analysis import UrlAnalysisIn, UrlAnalysisOut
from app.services.url_analysis_service import UrlAnalysisService
from app.domain.enums import RiskLabel
from app.schemas.imgae_analysis import ImageIn, ImageAnalysisOut
from app.services.image_analysis_service import ImageAnalysisService


router = APIRouter(prefix="/analyses", tags=["analyses"])

@router.post("/url", response_model=UrlAnalysisOut)
async def analyze_url(
    payload: UrlAnalysisIn,
    request: Request,
    session: AsyncSession = Depends(get_db),
    user = Depends(lambda: None),
):
    service = UrlAnalysisService(session)
    analysis, url_row, ai_json = await service.analyze(
        url_in=payload.url,
        request=request,
        user_id=str(user.id) if user else None,
    )

    explanation = ai_json.get("explanation", "")
    recommendations = ai_json.get("recommendations", []) or []
    label = RiskLabel(url_row.risk_label) if url_row.risk_label in {e.value for e in RiskLabel} else RiskLabel.unknown

    return UrlAnalysisOut(
        analysis_id=str(analysis.id),
        url=url_row.url,
        explanation=explanation,
        recommendations=recommendations,
        label=label,
    )

@router.post("/image", response_model=ImageAnalysisOut)
async def analyze_image(
    request: Request,
    file: UploadFile = File(..., description="Uma imagem PNG ou JPEG até 1MB"),
    session: AsyncSession = Depends(get_db),
    user = Depends(lambda: None)
):
    raw = await file.read()
    payload = ImageIn(filename=file.filename, content_type=file.content_type or "", size_bytes=len(raw))

    svc = ImageAnalysisService(session)
    analysis, img_row, ai_json = await svc.analyze(
        upload_bytes=raw,
        filename=payload.filename,
        content_type=payload.content_type,
        request=request,
        user_id=str(user.id) if user else None,
    )

    return ImageAnalysisOut(
        analysis_id=str(analysis.id),
        label=analysis.label,
        explanation=str(ai_json.get("explanation","")),
        recommendations=list(ai_json.get("recommendations") or []),
    )