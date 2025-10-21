from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_session
from app.schemas.auth import LogIn, TokenOut, RegisterIn, VerifyEmailIn
from app.schemas.common import OkOut
from jose import jwt
from app.core.config import settings
from app.services.auth_service import AuthService
from app.domain.user_model import UserRole 

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login", response_model=TokenOut)
async def login(data: LogIn, request: Request, session: AsyncSession = Depends(get_session)):
    svc = AuthService(session)
    try:
        token = await svc.login(data.email, data.password, request)
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
        role = payload.get("role", "user")
        return TokenOut(access_token=token, role=role)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Falha interna no login")

@router.post("/register", response_model=OkOut)
async def register(data: RegisterIn, request: Request, session: AsyncSession = Depends(get_session)):
    svc = AuthService(session)
    try:
        await svc.register(data.name, data.email, data.password, data.accepted_terms, request)
        return OkOut()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/verify-email", response_model=TokenOut)
async def verify_email(data: VerifyEmailIn, request: Request, session: AsyncSession = Depends(get_session)):
    svc = AuthService(session)
    try:
        token = await svc.verify_email(data.email, data.code, request)
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
        role = payload.get("role", "user")
        return TokenOut(access_token=token, role=role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/resend-code", response_model=OkOut)
async def resend_code(data: VerifyEmailIn, request: Request, session: AsyncSession = Depends(get_session)):
    svc = AuthService(session)
    try:
        await svc.resend_code(data.email, request)
        return OkOut()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
