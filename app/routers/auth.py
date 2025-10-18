from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, insert, delete, update, func
from datetime import datetime, timedelta, timezone
import re
from typing import Optional
from ..schemas import LogIn, TokenOut, RegisterIn, VerifyEmailIn, OkOut
from ..database import get_session
from ..models import User, AuditLog, UserStatus, PendingRegistration, UserRole
from ..security import verify_password, create_access_token, hash_password
from ..deps import ip_hash_from_request, get_current_user
from app.services.emails import send_email, verification_email_html, EmailError

router = APIRouter(prefix="/auth", tags=["auth"])

def sanitize_text(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[\u0000-\u001F<>]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s

def validate_password_policy(pw: str) -> Optional[str]:
    if not 8 <= len(pw) <= 30:
        return "A senha deve ter entre 8 e 30 caracteres."
    if not re.search(r"[A-Z]", pw):
        return "A senha precisa ter pelo menos 1 letra maiúscula."
    if not re.search(r"[a-z]", pw):
        return "A senha precisa ter pelo menos 1 letra minúscula."
    if not re.search(r"\d", pw):
        return "A senha precisa ter pelo menos 1 número."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return "A senha precisa ter pelo menos 1 símbolo."
    return None

def six_digit_code() -> str:
    from secrets import randbelow
    return f"{randbelow(1000000):06d}"

@router.post("/login", response_model=TokenOut)
async def login(
    data: LogIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        email = (data.email or "").strip().lower()
        result = await session.execute(select(User).where(func.lower(User.email) == email))
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
                details={"email": email},
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

@router.post("/register", response_model=OkOut)
async def register(
    data: RegisterIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    name = sanitize_text(data.name)[:30]
    email = sanitize_text(data.email).lower()[:255]

    if not data.accepted_terms:
        raise HTTPException(
            status_code=400,
            detail="É necessário aceitar os Termos de Uso e a Política de Privacidade."
        )

    dup_user = await session.execute(select(User.id).where(func.lower(User.email) == email))
    if dup_user.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="E-mail já cadastrado.")

    pwd_hash = hash_password(data.password)
    code = f"{__import__('random').randint(0, 999999):06d}"
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)

    accepted_at = datetime.now(timezone.utc)

    pending = PendingRegistration(
        name=name,
        email=email,
        password_hash=pwd_hash,
        code=code,
        expires_at=expires,
        accepted_terms_at=accepted_at,  
    )
    session.add(pending)
    await session.flush()  

    await send_email(
            to=email,
            subject="Verificação de e-mail - Veracity",
            html_body=verification_email_html(pending.name, code),
    )

    await session.execute(
        insert(AuditLog).values(
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.register",
            resource="/auth/register",
            success=True,
            details={
                "email": email,
                "registration_id": str(pending.id),
                "accepted_terms": True,
                "accepted_terms_at": accepted_at.isoformat(),
            },
        )
    )
    await session.commit()
    return OkOut()

@router.post("/verify-email", response_model=TokenOut)
async def verify_email(
    data: VerifyEmailIn,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    email = sanitize_text(data.email).lower()

    result = await session.execute(
        select(PendingRegistration).where(func.lower(PendingRegistration.email) == email)
    )
    pending = result.scalar_one_or_none()
    if not pending:
        raise HTTPException(status_code=404, detail="Cadastro não encontrado ou já confirmado.")

    now = datetime.now(timezone.utc)
    if now > pending.expires_at:
        await session.execute(delete(PendingRegistration).where(PendingRegistration.id == pending.id))
        await session.commit()
        raise HTTPException(status_code=410, detail="Código expirado. Inicie o cadastro novamente.")

    if pending.attempts >= 5 or pending.code != data.code:
        await session.execute(
            update(PendingRegistration)
            .where(PendingRegistration.id == pending.id)
            .values(attempts=pending.attempts + 1)
        )
        await session.commit()
        raise HTTPException(status_code=400, detail="O código inserido está inválido. Tente novamente")

    user = User(
        name=pending.name,
        email=pending.email,
        password_hash=pending.password_hash,
        role=UserRole.user,
        status=UserStatus.active,
        accepted_terms_at=pending.accepted_terms_at or now, 
    )
    session.add(user)
    await session.flush()

    res = await session.execute(
        update(AuditLog)
        .where(
            AuditLog.user_id.is_(None),
            AuditLog.details["registration_id"].as_string() == str(pending.id),
            AuditLog.action.in_(["auth.register", "auth.resend_code"]),
        )
        .values(user_id=user.id)
    )
    if (res.rowcount or 0) == 0:
        await session.execute(
            update(AuditLog)
            .where(
                AuditLog.user_id.is_(None),
                AuditLog.details["email"].as_string() == email,
                AuditLog.action.in_(["auth.register", "auth.resend_code"]),
            )
            .values(user_id=user.id)
        )

    await session.execute(delete(PendingRegistration).where(PendingRegistration.id == pending.id))

    await session.execute(
        insert(AuditLog).values(
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.verify_email",
            resource="/auth/verify-email",
            success=True,
            details={"email": email},
        )
    )

    token = create_access_token({"sub": str(user.id), "role": user.role.value})
    
    await session.execute(
        insert(AuditLog).values(
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.auto_login",
            resource="/auth/verify-email",
            success=True,
            details={"email": email},
        )
    )

    await session.commit()
    return TokenOut(access_token=token, role=user.role)


@router.post("/resend-code", response_model=OkOut)
async def resend_code(
    data: VerifyEmailIn, 
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    email = sanitize_text(data.email)[:30].lower()

    result = await session.execute(
        select(PendingRegistration).where(func.lower(PendingRegistration.email) == email)
    )
    pending = result.scalar_one_or_none()
    if not pending:
        raise HTTPException(status_code=404, detail="Cadastro não encontrado ou já confirmou.")

    now = datetime.now(timezone.utc)
    if (now - pending.last_sent_at).total_seconds() < 30:
        raise HTTPException(status_code=429, detail="Aguarde 30 segundos para reenviar o código.")

    new_code = six_digit_code()
    expiry_minutes = 10
    await session.execute(
        update(PendingRegistration)
        .where(PendingRegistration.id == pending.id)
        .values(code=new_code, expires_at=now + timedelta(minutes=expiry_minutes), last_sent_at=now)
    )

    actor_hash = ip_hash_from_request(request)
    await session.execute(
        insert(AuditLog).values(
            user_id=None,
            actor_ip_hash=actor_hash,
            action="auth.resend_code",
            resource="/auth/resend-code",
            success=True,
            details={"email": email, "registration_id": str(pending.id)},  
        )
    )
    await session.commit()

    try:
        await send_email(
            to=email,
            subject="Verificação de e-mail - Veracity",
            html_body=verification_email_html(pending.name, new_code),
        )
    except EmailError:
        raise HTTPException(status_code=502, detail="Falha ao reenviar e-mail. Tente novamente em instantes.")

    return OkOut()
