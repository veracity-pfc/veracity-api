from fastapi import APIRouter, HTTPException
from app.utils.validators import is_valid_url
from app.services.link_analysis_service import analyze_link
from app.schemas.analysis_schema import LinkAnalysisRequest, LinkAnalysisResponse
from app.utils.error_message import ERROR_MESSAGE_INVALID_URL

router = APIRouter(prefix="/v1/analysis", tags=["Análise de Links"])

@router.post("/links", response_model=LinkAnalysisResponse, name="AnalyzeLinks")
async def analyze_link_endpoint(payload: LinkAnalysisRequest):
    if not is_valid_url(str(payload.url)):
        raise HTTPException(status_code=400, detail=ERROR_MESSAGE_INVALID_URL)
    return await analyze_link(str(payload.url))