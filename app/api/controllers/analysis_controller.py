from fastapi import APIRouter, UploadFile, File, Depends, Request, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_db
from app.schemas.url_analysis import UrlAnalysisIn, UrlAnalysisOut
from app.services.url_analysis_service import UrlAnalysisService
from app.domain.enums import RiskLabel
from app.schemas.image_analysis import ImageIn, ImageAnalysisOut
from app.services.image_analysis_service import ImageAnalysisService
from app.domain.user_model import User
from app.api.deps import get_db, get_optional_user

router = APIRouter(prefix="/analyses", tags=["analyses"])

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
            user_id=(str(user.id) if user else None),
        )
    except ValueError as e:
        raise HTTPException(status_code=429, detail=str(e))

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
    file: UploadFile = File(..., description="Uma imagem PNG ou JPEG até 1MB"),
    session: AsyncSession = Depends(get_db),
    user: User | None = Depends(get_optional_user), 
):
    raw = await file.read()
    payload = ImageIn(
        filename=file.filename or "upload",
        content_type=file.content_type or "",
        size_bytes=len(raw),
    )

    svc = ImageAnalysisService(session)
    try:
        analysis, img_row, ai_json = await svc.analyze(
            upload_bytes=raw,
            filename=payload.filename,
            content_type=payload.content_type,
            request=request,
            user_id=(str(user.id) if user else None),  
        )
    except ValueError as e:
        raise HTTPException(status_code=429, detail=str(e))

    return {
        "analysis_id": str(analysis.id),
        "label": analysis.label,                        
        "explanation": ai_json.get("explanation", ""),
        "recommendations": list(ai_json.get("recommendations") or []),
        "quota": ai_json.get("quota"),                   
    }