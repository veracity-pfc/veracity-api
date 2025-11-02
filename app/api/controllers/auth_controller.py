from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.database import get_session
from app.schemas.auth import LogIn, TokenOut, RegisterIn, VerifyEmailIn
from app.schemas.common import OkOut
from jose import jwt
from app.schemas.auth import ForgotPasswordIn, ResetPasswordIn
from app.core.config import settings
from app.services.auth_service import AuthService
from app.domain.user_model import User
from app.domain.enums import UserStatus

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login", response_model=TokenOut)
async def login(data: LogIn, request: Request, session: AsyncSession = Depends(get_session)):
    q = await session.execute(
        select(User).where(func.lower(User.email) == data.email.strip().lower())
    )
    user = q.scalar_one_or_none()
    if user and user.status == UserStatus.inactive:
        raise HTTPException(
            status_code=403,
            detail={"code": "ACCOUNT_INACTIVE", "message": "A conta está desativada. Entre em contato para recuperar o acesso."}
        )
    service = AuthService(session)
    try:
        token = await service.login(data.email, data.password, request)
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
        role = payload.get("role", "user")
        return TokenOut(access_token=token, role=role)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception:
        raise HTTPException(status_code=500, detail="Falha interna no login")

@router.post("/register", response_model=OkOut)
async def register(data: RegisterIn, request: Request, session: AsyncSession = Depends(get_session)):
    service = AuthService(session)
    try:
        await service.register(data.name, data.email, data.password, data.accepted_terms, request)
        return OkOut()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/verify-email", response_model=TokenOut)
async def verify_email(data: VerifyEmailIn, request: Request, session: AsyncSession = Depends(get_session)):
    service = AuthService(session)
    try:
        token = await service.verify_email(data.email, data.code, request)
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
        role = payload.get("role", "user")
        return TokenOut(access_token=token, role=role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/resend-code", response_model=OkOut)
async def resend_code(data: VerifyEmailIn, request: Request, session: AsyncSession = Depends(get_session)):
    service = AuthService(session)
    try:
        await service.resend_code(data.email, request)
        return OkOut()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
@router.post("/forgot-password", response_model=OkOut)
async def forgot_password(data: ForgotPasswordIn, request: Request, session: AsyncSession = Depends(get_session)):
    service = AuthService(session)
    try:
        await service.forgot_password(data.email, request)
        return OkOut()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/reset-password/{token}", response_model=OkOut)
async def reset_password(token: str, data: ResetPasswordIn, request: Request, session: AsyncSession = Depends(get_session)):
    service = AuthService(session)
    try:
        await service.reset_password(token, data.password, data.confirm_password, request)
        return OkOut()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/logout", response_model=OkOut)
async def logout(request: Request, session: AsyncSession = Depends(get_session)):
    service = AuthService(session)
    await service.logout(request)
    return OkOut()
