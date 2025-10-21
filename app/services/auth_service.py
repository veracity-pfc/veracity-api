import re
from datetime import datetime, timedelta, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, func
from typing import Optional

from app.core.security import verify_password, create_access_token, hash_password
from app.domain.enums import UserStatus, UserRole
from app.domain.user_model import User
from app.domain.pending_registration_model import PendingRegistration
from app.domain.audit_model import AuditLog
from app.api.deps import ip_hash_from_request
from app.services.emails import send_email, verification_email_html, EmailError

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_PASSWORD_POLICY = re.compile(r"^(?=.{8,30}$)(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*\W).+$")

def sanitize_text(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[\u0000-\u001F<>]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s

def validate_password_policy(pw: str) -> Optional[str]:
    return None if _PASSWORD_POLICY.match(pw) else "A senha não atende aos requisitos mínimos."


def six_digit_code() -> str:
    from secrets import randbelow
    return f"{randbelow(1000000):06d}"

class AuthService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def login(self, email: str, password: str, request) -> str:
        email = (email or "").strip().lower()
        result = await self.session.execute(select(User).where(func.lower(User.email) == email))
        user = result.scalar_one_or_none()
        actor_hash = ip_hash_from_request(request)

        ok = False
        if user and user.status == UserStatus.active:
            ok = verify_password(password, user.password_hash)

        await self.session.execute(
            AuditLog.__table__.insert().values(
                user_id=user.id if user else None,
                actor_ip_hash=actor_hash,
                action="auth.login",
                resource="/auth/login",
                success=ok,
                details={"email": email},
            )
        )
        await self.session.commit()

        if not ok:
            raise ValueError("E-mail ou senha inválidos")

        token = create_access_token({"sub": str(user.id), "role": user.role.value})
        return token

    async def register(self, name: str, email: str, password: str, accepted_terms: bool, request) -> None:
        name = sanitize_text(name)[:30]
        email = sanitize_text(email).lower()[:60]

        if not accepted_terms:
            raise ValueError("É necessário aceitar os Termos de Uso e a Política de Privacidade.")

        if not EMAIL_RE.match(email):
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")

        res = await self.session.execute(select(User.id).where(func.lower(User.email) == email))
        if res.scalar_one_or_none():
            raise ValueError("E-mail já cadastrado.")

        pw_err = validate_password_policy(password)
        if pw_err:
            raise ValueError(pw_err)

        pwd_hash = hash_password(password)
        code = six_digit_code()
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
        self.session.add(pending)
        await self.session.flush()

        await send_email(
            to=email,
            subject="Verificação de e-mail - Veracity",
            html_body=verification_email_html(pending.name, code),
        )

        await self.session.execute(
            AuditLog.__table__.insert().values(
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
        await self.session.commit()

    async def verify_email(self, email: str, code: str, request) -> str:
        email = sanitize_text(email).lower()

        result = await self.session.execute(
            select(PendingRegistration).where(func.lower(PendingRegistration.email) == email)
        )
        pending = result.scalar_one_or_none()
        if not pending:
            raise ValueError("Cadastro não encontrado ou já confirmado.")

        now = datetime.now(timezone.utc)
        if now > pending.expires_at:
            await self.session.execute(delete(PendingRegistration).where(PendingRegistration.id == pending.id))
            await self.session.commit()
            raise ValueError("Código expirado. Inicie o cadastro novamente.")

        if pending.attempts >= 5 or pending.code != code:
            await self.session.execute(
                update(PendingRegistration)
                .where(PendingRegistration.id == pending.id)
                .values(attempts=pending.attempts + 1)
            )
            await self.session.commit()
            raise ValueError("O código inserido está inválido. Tente novamente")

        user = User(
            name=pending.name,
            email=pending.email,
            password_hash=pending.password_hash,
            role=UserRole.user,
            status=UserStatus.active,
            accepted_terms_at=pending.accepted_terms_at or now,
        )
        self.session.add(user)
        await self.session.flush()

        await self.session.execute(
            update(AuditLog)
            .where(
                AuditLog.user_id.is_(None),
                AuditLog.details["registration_id"].as_string() == str(pending.id),
                AuditLog.action.in_(["auth.register", "auth.resend_code"]),
            )
            .values(user_id=user.id)
        )

        await self.session.execute(delete(PendingRegistration).where(PendingRegistration.id == pending.id))

        await self.session.execute(
            AuditLog.__table__.insert().values(
                user_id=str(user.id),
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.verify_email",
                resource="/auth/verify-email",
                success=True,
                details={"email": email},
            )
        )

        token = create_access_token({"sub": str(user.id), "role": user.role.value})

        await self.session.execute(
            AuditLog.__table__.insert().values(
                user_id=str(user.id),
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.auto_login",
                resource="/auth/verify-email",
                success=True,
                details={"email": email},
            )
        )
        await self.session.commit()
        return token

    async def resend_code(self, email: str, request) -> None:
        email = sanitize_text(email).lower()
        result = await self.session.execute(
            select(PendingRegistration).where(func.lower(PendingRegistration.email) == email)
        )
        pending = result.scalar_one_or_none()
        if not pending:
            raise ValueError("Cadastro não encontrado ou já confirmou.")

        now = datetime.now(timezone.utc)
        if (now - pending.last_sent_at).total_seconds() < 30:
            raise ValueError("Aguarde 30 segundos para reenviar o código.")

        new_code = six_digit_code()
        expiry_minutes = 10
        await self.session.execute(
            update(PendingRegistration)
            .where(PendingRegistration.id == pending.id)
            .values(code=new_code, expires_at=now + timedelta(minutes=expiry_minutes), last_sent_at=now)
        )

        await self.session.execute(
            AuditLog.__table__.insert().values(
                user_id=None,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.resend_code",
                resource="/auth/resend-code",
                success=True,
                details={"email": email, "registration_id": str(pending.id)},
            )
        )
        await self.session.commit()

        try:
            await send_email(
                to=email,
                subject="Verificação de e-mail - Veracity",
                html_body=verification_email_html(pending.name, new_code),
            )
        except EmailError:
            raise ValueError("Falha ao reenviar e-mail. Tente novamente em instantes.")
