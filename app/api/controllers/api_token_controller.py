from __future__ import annotations

from typing import List

import filetype
from fastapi import APIRouter, Depends, Body, UploadFile, File, Security, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from tld import get_tld  

from app.core.database import get_session
from app.core.constants import ALLOWED_MIMES
from app.domain.api_token_model import ApiToken
from app.services.api_token_service import ApiTokenService
from app.services.url_analysis_service import UrlAnalysisService
from app.services.image_analysis_service import ImageAnalysisService


router = APIRouter(prefix="/api", tags=["Public API"])

security = HTTPBearer()

def _validate_url_rules(url: str):
    if not url or not url.strip():
        raise HTTPException(status_code=400, detail="A URL não pode estar vazia.")

    if len(url) > 200:
        raise HTTPException(status_code=400, detail="A URL excede o limite máximo de 200 caracteres.")

    if not (url.lower().startswith("http://") or url.lower().startswith("https://")):
        raise HTTPException(status_code=400, detail="A URL deve começar com 'http://' ou 'https://'.")

    try:
        get_tld(url, fix_protocol=True)
    except Exception:
        raise HTTPException(status_code=400, detail="A URL não possui um domínio (TLD) válido.")

def _validate_image_rules(content: bytes, count: int):
    if count > 1:
        raise HTTPException(status_code=400, detail="Apenas uma imagem é permitida por requisição.")

    if len(content) == 0:
        raise HTTPException(status_code=400, detail="O arquivo de imagem está vazio.")

    if len(content) > 1_000_000:
        raise HTTPException(status_code=400, detail="A imagem excede o limite de 1MB.")

    kind = filetype.guess(content)
    if not kind or kind.mime not in ALLOWED_MIMES:
        raise HTTPException(
            status_code=400, 
            detail="Formato de arquivo inválido. Apenas PNG, JPEG ou JPG são aceitos."
        )


async def get_api_token_header(
    creds: HTTPAuthorizationCredentials = Security(security),
    session: AsyncSession = Depends(get_session)
) -> ApiToken:
    svc = ApiTokenService(session)
    return await svc.validate_token(creds.credentials)


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
    url: str = Body(..., embed=True), 
    token_obj: ApiToken = Depends(get_api_token_header),
    session: AsyncSession = Depends(get_session),
):
    _validate_url_rules(url)

    analysis_svc = UrlAnalysisService(session)
    an, url_row, ai_data = await analysis_svc.run_analysis(token_obj.user_id, url)

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
        }
    ]


@router.post("/image-analysis")
async def token_image_analysis(
    file: List[UploadFile] = File(...), 
    token_obj: ApiToken = Depends(get_api_token_header), 
    session: AsyncSession = Depends(get_session),
):
    if not file:
        raise HTTPException(status_code=400, detail="Nenhum arquivo enviado.")
    
    uploaded_file = file[0]
    file_content = await uploaded_file.read()
    
    _validate_image_rules(file_content, len(file))
    
    analysis_svc = ImageAnalysisService(session)
    an, img_row, ai_data = await analysis_svc.run_analysis(token_obj.user_id, file_content)
    
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
        }
    ]