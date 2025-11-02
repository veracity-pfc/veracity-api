import re
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Body, HTTPException, Query
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Literal
from secrets import randbelow
from app.api.deps import get_current_user
from app.core.database import get_session as get_db
from app.domain.user_model import User
from app.domain.enums import UserStatus
from app.domain.url_analysis_model import UrlAnalysis
from app.domain.password_reset import PasswordReset
from app.domain.audit_model import AuditLog
from app.domain.analysis_model import Analysis
from app.domain.enums import AnalysisType
from app.domain.pending_email_change_model import PendingEmailChange

router = APIRouter(prefix="/user", tags=["user"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _quotas():
    return {"urls": 25, "images": 25}

@router.get("/profile")
async def get_profile(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    q_today = await session.execute(
        select(Analysis.analysis_type, func.count(Analysis.id))
        .where(Analysis.user_id == user.id, Analysis.created_at >= start, Analysis.created_at <= end)
        .group_by(Analysis.analysis_type)
    )
    today_map = {r[0]: r[1] for r in q_today.all()}

    q_all = await session.execute(
        select(Analysis.analysis_type, func.count(Analysis.id))
        .where(Analysis.user_id == user.id)
        .group_by(Analysis.analysis_type)
    )
    total_map = {r[0]: r[1] for r in q_all.all()}

    quotas = _quotas()
    remaining = {
        "urls": max(quotas["urls"] - int(today_map.get(AnalysisType.url, 0)), 0),
        "images": max(quotas["images"] - int(today_map.get(AnalysisType.image, 0)), 0),
    }

    return {
        "id": str(user.id),
        "name": user.name,
        "email": user.email,
        "stats": {
            "remaining": remaining,
            "performed": {
                "urls": int(total_map.get(AnalysisType.url, 0)),
                "images": int(total_map.get(AnalysisType.image, 0)),
            },
        },
    }

@router.patch("/profile/name")
async def update_name(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    new_name = (payload.get("name") or "").strip()
    if len(new_name) < 3 or len(new_name) > 30:
        raise HTTPException(status_code=400, detail="Nome deve ter entre 3 e 30 caracteres.")
    await session.execute(update(User).where(User.id == user.id).values(name=new_name))
    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action="user.update_name",
            resource="/user/profile/name",
            success=True,
            details={"name": new_name},
        )
    )
    await session.commit()
    return {"ok": True, "name": new_name}

@router.patch("/profile/name", name="validate_name")
async def validate_name_only(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    validate_only: bool = Query(False),
):
    if not validate_only:
        raise HTTPException(status_code=404, detail="Not found")
    new_name = (payload.get("name") or "").strip()
    if len(new_name) < 3 or len(new_name) > 30:
        raise HTTPException(status_code=400, detail="Nome deve ter entre 3 e 30 caracteres.")
    return {"ok": True}

@router.post("/profile/email-change/request")
async def request_email_change(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    new_email = (payload.get("email") or "").strip().lower()
    if not EMAIL_RE.fullmatch(new_email):
        raise HTTPException(status_code=400, detail="E-mail inválido.")
    exists = await session.execute(select(User.id).where(func.lower(User.email) == new_email))
    if exists.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado.")
    prev = await session.execute(select(PendingEmailChange).where(PendingEmailChange.user_id == user.id))
    old = prev.scalar_one_or_none()
    if old:
        await session.execute(delete(PendingEmailChange).where(PendingEmailChange.id == old.id))

    code = f"{randbelow(1000000):06d}"
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)
    rec = PendingEmailChange(user_id=user.id, new_email=new_email, code=code, expires_at=expires_at)
    session.add(rec)
    await session.flush()

    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action="user.request_email_change",
            resource="/user/profile/email-change/request",
            success=True,
            details={"new_email": new_email},
        )
    )
    await session.commit()
    return {"ok": True, "requires_verification": True}

@router.post("/profile/email-change/confirm")
async def confirm_email_change(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    code = (payload.get("code") or "").strip()
    email = (payload.get("email") or "").strip().lower()

    q = await session.execute(
        select(PendingEmailChange).where(
            and_(PendingEmailChange.user_id == user.id, func.lower(PendingEmailChange.new_email) == email)
        )
    )
    pending = q.scalar_one_or_none()
    if not pending:
        raise HTTPException(status_code=400, detail="Solicitação não encontrada.")
    now = datetime.now(timezone.utc)
    if pending.expires_at < now:
        await session.execute(delete(PendingEmailChange).where(PendingEmailChange.id == pending.id))
        await session.commit()
        raise HTTPException(status_code=400, detail="Código expirado.")

    if pending.code != code:
        raise HTTPException(status_code=400, detail="Código inválido.")

    await session.execute(update(User).where(User.id == user.id).values(email=pending.new_email))
    await session.execute(delete(PendingEmailChange).where(PendingEmailChange.id == pending.id))
    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action="user.confirm_email_change",
            resource="/user/profile/email-change/confirm",
            success=True,
            details={"new_email": pending.new_email},
        )
    )
    await session.commit()
    return {"ok": True, "email": pending.new_email}

@router.delete("/account")
async def delete_or_inactivate_account(
    mode: Literal["delete", "inactivate"] = Query(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    if mode == "inactivate":
        await session.execute(update(User).where(User.id == user.id).values(status=UserStatus.inactive))
        action = "user.inactivate"
    else:
        await session.execute(update(AuditLog).where(AuditLog.user_id == user.id).values(user_id=None))
        await session.execute(delete(PasswordReset).where(PasswordReset.user_id == user.id))
        await session.execute(delete(UrlAnalysis).where(UrlAnalysis.user_id == user.id))
        await session.execute(delete(Analysis).where(Analysis.user_id == user.id))
        await session.execute(delete(PendingEmailChange).where(PendingEmailChange.user_id == user.id))
        await session.execute(delete(User).where(User.id == user.id))
        action = "user.delete"

    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=None if mode == "delete" else user.id,
            action=action,
            resource="/user/account",
            success=True,
        )
    )
    await session.commit()
    return {"ok": True}
