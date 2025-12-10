from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any
import hashlib

from fastapi import Depends, HTTPException, status, Request, Response
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_session
from app.domain.enums import UserRole, UserStatus
from app.domain.user_model import User


async def get_db(session: AsyncSession = Depends(get_session)) -> AsyncSession:
    return session


def ip_hash_from_request(req: Request) -> str | None:
    forwarded = req.headers.get("x-forwarded-for", "")
    ip = forwarded.split(",")[0].strip() if forwarded else ""
    if not ip and req.client:
        ip = req.client.host

    if not ip:
        return None

    value = f"{ip}|{settings.salt_ip_hash}"
    return sha256(value.encode()).hexdigest()


def _decode_token_payload(token: str) -> dict[str, Any] | None:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_alg],
        )
    except JWTError:
        return None


def get_actor_identifier(request: Request) -> str | None:
    if not request:
        return None
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")
    raw = f"{ip}|{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def oauth2_scheme(request: Request) -> str | None:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
    return token


async def get_current_user(
    request: Request,
    response: Response, 
    token: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise cred_exc

    payload = _decode_token_payload(token)
    if payload is None:
        raise cred_exc

    uid = payload.get("sub")
    if not isinstance(uid, str):
        raise cred_exc

    exp = payload.get("exp")
    if exp:
        now = datetime.now(timezone.utc)
        remaining_seconds = exp - now.timestamp()

        if remaining_seconds < 300:
            new_exp = now + timedelta(minutes=10)
            
            new_payload = payload.copy()
            new_payload.update({
                "exp": new_exp,
                "iat": now
            })
            
            new_token = jwt.encode(
                new_payload, 
                settings.jwt_secret, 
                algorithm=settings.jwt_alg
            )
            
            response.set_cookie(
                key="access_token",
                value=new_token,
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=600  
            )

    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()

    if not user or user.status != UserStatus.active:
        raise cred_exc

    try:
        request.state.user = user
        request.state.user_id = str(user.id)
    except Exception:
        pass

    return user


async def get_optional_user(
    request: Request,
    token: str | None = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db),
) -> User | None:
    if not token:
        return None

    payload = _decode_token_payload(token)
    if payload is None:
        return None
    
    uid = payload.get("sub")
    if not isinstance(uid, str):
        return None

    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()

    if not user or user.status != UserStatus.active:
        return None

    try:
        request.state.user = user
        request.state.user_id = str(user.id)
    except Exception:
        pass

    return user


async def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != UserRole.admin:
        raise HTTPException(
            status_code=403,
            detail="Acesso restrito a administradores",
        )
    return user