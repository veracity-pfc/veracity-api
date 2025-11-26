from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_optional_user, get_session
from app.domain.user_model import User
from app.schemas.contact_request import ContactMessageIn, ContactOkOut
from app.services.contact_service import ContactService
from app.services.api_token_service import ApiTokenService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/contact", tags=["contact"])


@router.post("", response_model=ContactOkOut)
async def send_contact(
    data: ContactMessageIn,
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    session: AsyncSession = Depends(get_session),
):
    is_token_req = (
        data.category == "token_request" or 
        data.subject.lower().strip() == "solicitação de token de api"
    )

    if is_token_req and not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Para solicitar um token de API, faça login.",
        )

    svc = ContactService(session)
    api_token_svc = ApiTokenService(session)
    try:
        if is_token_req and user:
            await api_token_svc.create_token_request_from_contact(
                user_id=user.id,
                email=data.email,
                message=data.message,
                request_obj=request,
            )
        else:            
            await svc.process_contact_request(
                user=user,
                email=data.email,
                category=data.category, 
                subject=data.subject,
                message=data.message,
                request_obj=request,
            )
        return ContactOkOut()
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error(f"Erro inesperado ao processar contato: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Falha ao processar solicitação.",
        )