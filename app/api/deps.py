from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from hashlib import sha256

from app.core.config import settings
from app.core.database import get_session
from app.domain.user_model import User, UserStatus, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

async def get_db(session: AsyncSession = Depends(get_session)):
    return session

def ip_hash_from_request(req: Request) -> str | None:
    ip = req.headers.get("x-forwarded-for", "").split(",")[0].strip() or (req.client.host if req.client else "")
    if not ip:
        return None
    value = f"{ip}|{settings.salt_ip_hash}"
    return sha256(value.encode()).hexdigest()

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    session: AsyncSession = Depends(get_db),
):
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
        uid: str | None = payload.get("sub")
        if uid is None:
            raise cred_exc
    except JWTError:
        raise cred_exc

    result = await session.execute(select(User).where(User.id == uid))
    user = result.scalar_one_or_none()
    if not user or user.status != UserStatus.active:
        raise cred_exc
    return user

async def require_admin(user: User = Depends(get_current_user)):
    if user.role != UserRole.admin:
        raise HTTPException(status_code=403, detail="Acesso restrito a administradores")
    return user
