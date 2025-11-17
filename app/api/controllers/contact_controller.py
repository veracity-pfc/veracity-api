from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_session
from app.schemas.contact import ContactMessageIn, ContactOkOut
from app.services.contact_service import ContactService

router = APIRouter(prefix="/contact-us", tags=["contact-us"])


@router.post("", response_model=ContactOkOut)
async def send_contact(
    data: ContactMessageIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    svc = ContactService(session)
    try:
        await svc.send_contact_message(
            email=data.email,
            subject=data.subject,
            message=data.message,
            request=request,
        )
        return ContactOkOut()
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Falha ao enviar sua mensagem.",
        )
