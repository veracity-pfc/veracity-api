import re
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Body, HTTPException, Request, Query
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Literal
from secrets import randbelow

from app.api.deps import get_current_user
from app.core.database import get_session as get_db
from app.core.config import settings
from app.domain.user_model import User
from app.domain.audit_model import AuditLog
from app.domain.analysis_model import Analysis
from app.domain.enums import AnalysisType
from app.domain.pending_email_change_model import PendingEmailChange
from app.services.email_service import send_email, verification_email_html

router = APIRouter(prefix="/user", tags=["user"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _today_range():
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    end = datetime(now.year, now.month, now.day, 23, 59, 59, 999000, tzinfo=timezone.utc)
    return start, end


def _quotas():
    return {"urls": getattr(settings, "daily_url_quota", 25),
            "images": getattr(settings, "daily_image_quota", 25)}


@router.get("/profile")
async def profile(user: User = Depends(get_current_user), session: AsyncSession = Depends(get_db)):
    start, end = _today_range()
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
    validate_only: bool = Query(False),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    new_name = (payload.get("name") or "").strip()

    if not new_name:
        raise HTTPException(status_code=400, detail="Informe um nome.")
    if new_name == (user.name or "").strip():
        raise HTTPException(status_code=400, detail="O nome precisa ser diferente do atual.")
    if len(new_name) < 3 or len(new_name) > 60:
        raise HTTPException(status_code=400, detail="Nome deve ter entre 3 e 60 caracteres.")

    if validate_only:
        return {"ok": True}

    await session.execute(update(User).where(User.id == user.id).values(name=new_name))
    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action="user.update_name",
            resource="/user/profile/name",
            success=True,
            details={"from": user.name, "to": new_name},
        )
    )
    await session.commit()
    return {"ok": True, "name": new_name}


@router.post("/profile/email-change/request")
async def request_email_change(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    new_email = (payload.get("email") or "").strip().lower()
    if not EMAIL_RE.fullmatch(new_email):
        raise HTTPException(status_code=400, detail="E-mail inválido.")
    if new_email == (user.email or "").lower():
        raise HTTPException(status_code=400, detail="Informe um e-mail diferente do atual.")
    exists = await session.scalar(select(User.id).where(func.lower(User.email) == new_email))
    if exists:
        raise HTTPException(status_code=400, detail="E-mail já está em uso por outra conta.")

    await session.execute(delete(PendingEmailChange).where(PendingEmailChange.user_id == user.id))

    code = f"{randbelow(1_000_000):06d}"
    rec = PendingEmailChange(
        user_id=user.id,
        new_email=new_email,
        token=code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    session.add(rec)
    await session.flush()

    await send_email(
        to=new_email,
        subject="Confirmação de e-mail - Veracity",
        html_body=verification_email_html(user.name or "Usuário", code),
    )

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
    return {"ok": True, "requires_verification": True, "email": new_email}

@router.post("/profile/email-change/confirm")
async def confirm_email_change(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    email_in = (payload.get("email") or "").strip().lower()
    code = (payload.get("code") or "").strip()

    if not code or len(code) != 6 or not code.isdigit():
        raise HTTPException(status_code=400, detail="Código inválido.")

    if email_in:
        q = await session.execute(
            select(PendingEmailChange).where(
                PendingEmailChange.user_id == user.id,
                func.lower(PendingEmailChange.new_email) == email_in,
            )
        )
    else:
        q = await session.execute(
            select(PendingEmailChange)
            .where(PendingEmailChange.user_id == user.id)
            .order_by(PendingEmailChange.created_at.desc())
            .limit(1)
        )

    pending = q.scalar_one_or_none()
    if not pending:
        raise HTTPException(status_code=400, detail="Solicitação não encontrada.")

    now = datetime.now(timezone.utc)
    if now > pending.expires_at:
        await session.execute(delete(PendingEmailChange).where(PendingEmailChange.id == pending.id))
        await session.commit()
        raise HTTPException(status_code=400, detail="Código expirado. Solicite novamente.")

    if pending.token != code:
        raise HTTPException(status_code=400, detail="Código inválido. Tente novamente.")

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
        await session.execute(update(User).where(User.id == user.id).values(status="inactive"))
        action = "user.inactivate"
    else:
        await session.execute(delete(User).where(User.id == user.id))
        action = "user.delete"

    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action=action,
            resource="/user/account",
            success=True,
        )
    )
    await session.commit()
    return {"ok": True}
