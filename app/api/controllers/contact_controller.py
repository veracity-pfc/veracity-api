from __future__ import annotations

from jose import jwt
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_session
from app.core.config import settings
from app.domain.user_model import User
from app.schemas.contact import ContactMessageIn, ContactOkOut
from app.services.contact_service import ContactService

router = APIRouter(prefix="/contact-us", tags=["contact-us"])

security = HTTPBearer(auto_error=False)

async def get_optional_user(
    creds: Optional[HTTPAuthorizationCredentials] = Security(security),
    session: AsyncSession = Depends(get_session),
) -> Optional[User]:
    
    if not creds:
        return None
    
    try:
        payload = jwt.decode(
            creds.credentials,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
        )
        user_id = payload.get("sub")
        if not user_id:
            return None
            
        stmt = select(User).where(User.id == user_id)
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
    except Exception:
        return None

@router.post("", response_model=ContactOkOut)
async def send_contact(
    data: ContactMessageIn,
    request: Request,
    user: Optional[User] = Depends(get_optional_user),
    session: AsyncSession = Depends(get_session),
):
    
    final_user = user

    if not final_user and data.email:
        stmt = select(User).where(func.lower(User.email) == data.email.strip().lower())
        result = await session.execute(stmt)
        final_user = result.scalar_one_or_none()

    if data.subject.lower() == "solicitação de token de api":
         if not user: 
             raise HTTPException(
                 status_code=401, 
                 detail="Para solicitar um token de API, você precisa realizar o login na plataforma."
             )
         pass 

    svc = ContactService(session)
    try:
        await svc.create_request(
            user=final_user, 
            email=data.email,
            category=data.category,
            subject=data.subject,
            message=data.message,
            request_obj=request
        )
        return ContactOkOut()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Falha ao processar solicitação.")