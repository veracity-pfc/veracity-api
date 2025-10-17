from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert

from ..schemas import LogIn, TokenOut
from ..database import get_session
from ..models import User, AuditLog, UserStatus
from ..security import verify_password, create_access_token
from ..deps import ip_hash_from_request, get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login", response_model=TokenOut)
async def login(
    data: LogIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        result = await session.execute(select(User).where(User.email == data.email))
        user = result.scalar_one_or_none()
        actor_hash = ip_hash_from_request(request)

        ok = False
        if user and user.status == UserStatus.active:
            ok = verify_password(data.password, user.password_hash)

        await session.execute(
            insert(AuditLog).values(
                user_id=user.id if user else None,
                actor_ip_hash=actor_hash,
                action="auth.login",
                resource="/auth/login",
                success=ok,
                details={"email": data.email},
            )
        )
        await session.commit()

        if not ok:
            raise HTTPException(status_code=401, detail="E-mail ou senha inválidos")

        token = create_access_token({"sub": str(user.id), "role": user.role.value})
        return TokenOut(access_token=token, role=user.role)

    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Falha interna no login")

@router.post("/logout")
async def logout(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user=Depends(get_current_user),
):
    actor_hash = ip_hash_from_request(request)
    await session.execute(
        insert(AuditLog).values(
            user_id=str(user.id),
            actor_ip_hash=actor_hash,
            action="auth.logout",
            resource="/auth/logout",
            success=True,
            details={},
        )
    )
    await session.commit()
    return {"ok": True}
