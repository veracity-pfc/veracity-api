from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.core.constants import EMAIL_RE, PASSWORD_POLICY
from app.core.security import create_access_token, hash_password, verify_password
from app.domain.audit_model import AuditLog
from app.domain.enums import UserRole, UserStatus
from app.domain.user_model import User
from app.repositories.audit_repository import AuditRepository
from app.repositories.password_reset_repository import PasswordResetRepository
from app.repositories.pending_registration_repository import PendingRegistrationRepository
from app.repositories.user_repository import UserRepository
from app.services.email_service import (
    EmailError,
    reset_password_email_html,
    send_email,
    verification_email_html,
)


def sanitize_text(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"[\u0000-\u001F<>]", "", s)
    s = re.sub(r"\s+", " ", s)
    return s


def validate_password_policy(pw: str) -> Optional[str]:
    return None if PASSWORD_POLICY.match(pw) else "A senha não atende aos requisitos mínimos."


def six_digit_code() -> str:
    from secrets import randbelow
    return f"{randbelow(1000000):06d}"


class AuthService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.user_repo = UserRepository(session)
        self.pending_repo = PendingRegistrationRepository(session)
        self.password_reset_repo = PasswordResetRepository(session)
        self.audit_repo = AuditRepository(session)

    async def login(self, email: str, password: str, request) -> str:
        email = (email or "").strip().lower()
        user = await self.user_repo.get_by_email(email)
        actor_hash = ip_hash_from_request(request)

        ok = False
        if user and user.status == UserStatus.active:
            ok = verify_password(password, user.password_hash)

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=user.id if user else None,
            actor_ip_hash=actor_hash,
            action="auth.login",
            resource="/auth/login",
            success=ok,
            details={"email": email},
        )
        await self.session.commit()

        if not ok:
            raise ValueError("E-mail ou senha inválidos")

        return create_access_token({"sub": str(user.id), "role": user.role.value})

    async def register(
        self,
        name: str,
        email: str,
        password: str,
        accepted_terms: bool,
        request,
    ) -> None:
        name = sanitize_text(name)[:30]
        email = sanitize_text(email).lower()[:60]

        if not accepted_terms:
            raise ValueError("É necessário aceitar os Termos de Uso e a Política de Privacidade.")

        if not EMAIL_RE.match(email):
            raise ValueError("O e-mail digitado não é válido.")

        existing = await self.user_repo.get_by_email(email)
        if existing:
            raise ValueError("E-mail já cadastrado.")

        pw_err = validate_password_policy(password)
        if pw_err:
            raise ValueError(pw_err)

        pwd_hash = hash_password(password)
        code = six_digit_code()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(minutes=10)
        accepted_at = now

        pending = await self.pending_repo.create(
            name=name,
            email=email,
            password_hash=pwd_hash,
            code=code,
            expires_at=expires,
            accepted_terms_at=accepted_at,
        )

        try:
            await send_email(
                to=email,
                subject="Verificação de e-mail - Veracity",
                html_body=verification_email_html(pending.name, code),
            )
        except EmailError:
            await self.session.rollback()
            raise ValueError("Não foi possível enviar o e-mail agora.")

        await self.audit_repo.insert(
            table=AuditLog,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.register",
            resource="/auth/register",
            success=True,
            details={
                "email": email,
                "registration_id": str(pending.id),
                "accepted_terms": True,
            },
        )
        await self.session.commit()

    async def verify_email(self, email: str, code: str, request) -> str:
        email = sanitize_text(email).lower()
        pending = await self.pending_repo.get_by_email(email)
        if not pending:
            raise ValueError("Cadastro não encontrado ou já confirmado.")

        now = datetime.now(timezone.utc)
        if now > pending.expires_at:
            await self.pending_repo.delete_by_id(str(pending.id))
            await self.session.commit()
            raise ValueError("Código expirado. Inicie o cadastro novamente.")

        if pending.attempts >= 5 or pending.code != code:
            await self.pending_repo.increment_attempts(str(pending.id), pending.attempts)
            await self.session.commit()
            raise ValueError("O código inserido está inválido.")

        user = User(
            name=pending.name,
            email=pending.email,
            password_hash=pending.password_hash,
            role=UserRole.user,
            status=UserStatus.active,
            accepted_terms_at=pending.accepted_terms_at or now,
        )
        await self.user_repo.add(user)
        await self.audit_repo.link_registration_to_user(str(pending.id), str(user.id))
        await self.pending_repo.delete_by_id(str(pending.id))

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.verify_email",
            resource="/auth/verify-email",
            success=True,
            details={"email": email},
        )

        token = create_access_token({"sub": str(user.id), "role": user.role.value})
        await self.session.commit()
        return token

    async def resend_code(self, email: str, request) -> None:
        email = sanitize_text(email).lower()
        pending = await self.pending_repo.get_by_email(email)
        if not pending:
            raise ValueError("Cadastro não encontrado ou já confirmou.")

        now = datetime.now(timezone.utc)
        if (now - pending.last_sent_at).total_seconds() < 30:
            raise ValueError("Aguarde 30 segundos para reenviar o código.")

        new_code = six_digit_code()
        expires_at = now + timedelta(minutes=10)

        await self.pending_repo.update_code(
            str(pending.id),
            code=new_code,
            expires_at=expires_at,
            last_sent_at=now,
        )

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.resend_code",
            resource="/auth/resend-code",
            success=True,
            details={"email": email},
        )
        await self.session.commit()

        try:
            await send_email(
                to=email,
                subject="Verificação de e-mail - Veracity",
                html_body=verification_email_html(pending.name, new_code),
            )
        except EmailError:
            raise ValueError("Falha ao reenviar e-mail.")

    async def forgot_password(self, email: str, request) -> None:
        email = (email or "").strip().lower()
        user = await self.user_repo.get_by_email(email)
        if not user:
            raise ValueError("E-mail não encontrado.")

        now = datetime.now(timezone.utc)
        token = await self.password_reset_repo.create(
            user_id=str(user.id),
            expires_at=now + timedelta(minutes=30),
            actor_ip_hash=ip_hash_from_request(request),
        )

        base = getattr(settings, "frontend_url", None)
        link = f"{base}/reset-password/{token.id}"

        try:
            await send_email(
                to=user.email,
                subject="Redefinir sua senha - Veracity",
                html_body=reset_password_email_html(user.name, link),
            )
        except EmailError:
            await self.session.rollback()
            raise ValueError("Não foi possível enviar o e-mail agora.")

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=user.id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.forgot_password",
            resource="/auth/forgot-password",
            success=True,
            details={"email": email},
        )
        await self.session.commit()

    async def reset_password(
        self, token_id: str, password: str, confirm_password: str, request
    ) -> None:
        if password != confirm_password:
            raise ValueError("A senha deve ser igual nos dois campos.")

        err = validate_password_policy(password)
        if err:
            raise ValueError(err)

        token = await self.password_reset_repo.get_by_id(token_id)
        now = datetime.now(timezone.utc)

        if not token or token.used_at is not None or token.expires_at < now:
            raise ValueError("Link inválido ou expirado.")

        user = await self.user_repo.get_by_id(str(token.user_id))
        if not user:
            raise ValueError("Usuário não encontrado.")

        if verify_password(password, user.password_hash):
            raise ValueError("A nova senha deve ser diferente da senha atual.")

        user.password_hash = hash_password(password)
        await self.password_reset_repo.mark_used(str(token.id), now)

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=user.id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.reset_password",
            resource=f"/auth/reset-password/{token_id}",
            success=True,
        )
        await self.session.commit()

    async def logout(self, request) -> None:
        auth = (request.headers.get("authorization") or "").strip()
        user_id = None
        if auth.lower().startswith("bearer "):
            try:
                token = auth.split(" ", 1)[1].strip()
                payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
                user_id = payload.get("sub")
            except Exception:
                pass

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=user_id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.logout",
            resource="/auth/logout",
            success=True,
        )
        await self.session.commit()