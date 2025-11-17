from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from secrets import randbelow
from typing import Dict

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy import select, update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_session
from app.core.constants import EMAIL_RE
from app.domain.enums import AnalysisType, UserStatus
from app.domain.user_model import User
from app.domain.audit_model import AuditLog
from app.domain.url_analysis_model import UrlAnalysis
from app.domain.image_analysis_model import ImageAnalysis
from app.domain.password_reset import PasswordReset
from app.domain.pending_email_change_model import PendingEmailChange
from app.domain.analysis_model import Analysis
from app.repositories.analysis_repo import AnalysisRepository
from app.repositories.audit_repo import AuditRepository
from app.services.user_service import UserService

router = APIRouter(prefix="/user", tags=["user"])
class ReactivateAccountPayload(BaseModel):
    email: str

class ReactivateConfirmPayload(BaseModel):
    email: str
    code: str


def _quotas() -> Dict[str, int]:
    return {
        "urls": settings.user_url_limit,
        "images": settings.user_image_limit,
    }


def _hash_ip(ip: str | None) -> str | None:
    if not ip:
        return None
    secret = settings.jwt_secret.encode("utf-8")
    return hashlib.sha256(secret + ip.encode("utf-8")).hexdigest()


@router.get("/profile")
async def get_profile(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    repo = AnalysisRepository(session)
    today_map, total_map = await repo.user_counts(
        user_id=str(user.id),
        day_start=start,
        day_end=end,
    )

    quotas = _quotas()
    remaining = {
        "urls": max(int(quotas["urls"]) - int(today_map.get(AnalysisType.url, 0)), 0),
        "images": max(
            int(quotas["images"]) - int(today_map.get(AnalysisType.image, 0)),
            0,
        ),
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
    session: AsyncSession = Depends(get_session),
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
    session: AsyncSession = Depends(get_session),
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
    session: AsyncSession = Depends(get_session),
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
    session: AsyncSession = Depends(get_session),
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

@router.patch("/account")
async def inactivate_account(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    await session.execute(update(User).where(User.id == user.id).values(status=UserStatus.inactive))
    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=user.id,
            action="user.inactivate",
            resource="/user/account",
            success=True,
        )
    )
    await session.commit()
    return {"ok": True, "status": "inactive"}

@router.delete("/account")
async def delete_account(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    await session.execute(update(AuditLog).where(AuditLog.user_id == user.id).values(user_id=None))
    await session.execute(delete(PasswordReset).where(PasswordReset.user_id == user.id))
    await session.execute(update(UrlAnalysis).where(UrlAnalysis.user_id == user.id).values(user_id=None))
    await session.execute(update(ImageAnalysis).where(ImageAnalysis.user_id == user.id).values(user_id=None))
    await session.execute(update(Analysis).where(Analysis.user_id == user.id).values(user_id=None))
    await session.execute(delete(PendingEmailChange).where(PendingEmailChange.user_id == user.id))
    await session.execute(delete(User).where(User.id == user.id))
    await session.execute(
        AuditLog.__table__.insert().values(
            user_id=None,
            action="user.delete",
            resource="/user/account",
            success=True,
        )
    )
    await session.commit()
    return {"ok": True}



@router.post("/reactivate-account/validate")
async def validate_reactivate_account(
    payload: ReactivateAccountPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    audit = AuditRepository(session)
    ip = request.client.host if request.client else None
    ip_hash = _hash_ip(ip)

    try:
        email, user_id = await service.validate_email(payload.email)
    except HTTPException as exc:
        await audit.insert(
            AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash,
            action="user.reactivate.validate",
            resource="user",
            success=False,
            details={
                "email": payload.email,
                "error": exc.detail,
            },
        )
        raise

    await audit.insert(
        AuditLog,
        user_id=user_id,
        actor_ip_hash=ip_hash,
        action="user.reactivate.validate",
        resource="user",
        success=True,
        details={"email": email},
    )

    return {"ok": True}


@router.post("/reactivate-account/send-code")
async def send_reactivate_code(
    payload: ReactivateAccountPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    audit = AuditRepository(session)
    ip = request.client.host if request.client else None
    ip_hash = _hash_ip(ip)

    try:
        email, user_id = await service.validate_email(payload.email)
    except HTTPException as exc:
        await audit.insert(
            AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash,
            action="user.reactivate.send_code",
            resource="user",
            success=False,
            details={
                "email": payload.email,
                "error": exc.detail,
            },
        )
        raise

    try:
        await service.send_reactivation_code(email)
    except HTTPException as exc:
        await audit.insert(
            AuditLog,
            user_id=user_id,
            actor_ip_hash=ip_hash,
            action="user.reactivate.send_code",
            resource="user",
            success=False,
            details={
                "email": email,
                "error": exc.detail,
            },
        )
        raise

    await audit.insert(
        AuditLog,
        user_id=user_id,
        actor_ip_hash=ip_hash,
        action="user.reactivate.send_code",
        resource="user",
        success=True,
        details={"email": email},
    )

    return {"detail": "Código de reativação enviado com sucesso."}


@router.post("/reactivate-account/confirm-code")
async def confirm_reactivate_code(
    payload: ReactivateConfirmPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    audit = AuditRepository(session)
    ip = request.client.host if request.client else None
    ip_hash = _hash_ip(ip)

    try:
        email, user_id = await service.validate_email(payload.email)
    except HTTPException as exc:
        await audit.insert(
            AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash,
            action="user.reactivate.confirm_code",
            resource="user",
            success=False,
            details={
                "email": payload.email,
                "code": payload.code,
                "error": exc.detail,
            },
        )
        raise

    try:
        await service.confirm_reactivation_code(email, payload.code)
    except HTTPException as exc:
        await audit.insert(
            AuditLog,
            user_id=user_id,
            actor_ip_hash=ip_hash,
            action="user.reactivate.confirm_code",
            resource="user",
            success=False,
            details={
                "email": email,
                "code": payload.code,
                "error": exc.detail,
            },
        )
        raise

    await audit.insert(
        AuditLog,
        user_id=user_id,
        actor_ip_hash=ip_hash,
        action="user.reactivate.confirm_code",
        resource="/user/reactivate-account",
        success=True,
        details={
            "email": email,
            "code": payload.code,
        },
    )

    return {"detail": "Conta reativada com sucesso."}

