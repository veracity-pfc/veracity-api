from hashlib import sha256
from typing import Any

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.database import get_session
from app.domain.enums import UserRole, UserStatus
from app.domain.user_model import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


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


def _decode_token(token: str) -> str | None:
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_alg],
        )
    except JWTError:
        return None

    uid = payload.get("sub")
    if not isinstance(uid, str):
        return None
    return uid


async def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )

    uid = _decode_token(token)
    if uid is None:
        raise cred_exc

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


oauth2_optional = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


async def get_optional_user(
    request: Request,
    token: str | None = Depends(oauth2_optional),
    session: AsyncSession = Depends(get_db),
) -> User | None:
    if not token:
        return None

    uid = _decode_token(token)
    if uid is None:
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
