from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.schemas.analysis import UrlAnalysisIn, UrlAnalysisOut
from app.services.url_analysis_service import UrlAnalysisService
from app.domain.enums import RiskLabel

router = APIRouter(prefix="/analysis", tags=["analysis"])

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
