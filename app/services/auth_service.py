from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from jose import jwt
from passlib.hash import bcrypt

from app.core.config import settings
from app.domain.audit_model import AuditLog
from app.domain.enums import UserStatus
from app.core.constants import EMAIL_RE
from app.domain.user_model import User
from app.repositories.audit_repository import AuditRepository
from app.repositories.password_reset_repository import PasswordResetRepository
from app.repositories.pending_registration_repository import PendingRegistrationRepository
from app.repositories.user_repository import UserRepository
from app.services.utils.email_utils import (
    reset_password_email_html,
    send_email,
    verification_email_html,
)
from app.api.deps import ip_hash_from_request


class AuthService:
    def __init__(self, session):
        self.session = session
        self.user_repo = UserRepository(session)
        self.pending_repo = PendingRegistrationRepository(session)
        self.pwd_repo = PasswordResetRepository(session)
        self.audit_repo = AuditRepository(session)

    def _hash_password(self, password: str) -> str:
        return bcrypt.hash(password)

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        if stored_hash.startswith("$2"):
            try:
                return bcrypt.verify(password, stored_hash)
            except Exception:
                return False
        expected = hashlib.sha256(
            (password + settings.jwt_secret).encode("utf-8")
        ).hexdigest()
        return stored_hash == expected

    def _create_token(self, user: User) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": str(user.id),
            "role": user.role.value,
            "exp": now + timedelta(hours=24),
            "iat": now,
        }
        return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_alg)

    async def login(self, email: str, password: str, request: Request) -> str:
        email = (email or "").strip().lower()
        user = await self.user_repo.get_by_email(email)

        if not user:
            await self.audit_repo.insert(
                AuditLog,
                user_id=None,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": email, "reason": "user_not_found"},
            )
            raise ValueError("Credenciais inválidas.")

        status_value = getattr(user, "status", None)
        if isinstance(status_value, UserStatus):
            is_active = status_value == UserStatus.active
        elif isinstance(status_value, str):
            is_active = status_value.lower() == UserStatus.active.value
        else:
            is_active = True

        if not is_active:
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": email, "reason": "account_inactive"},
            )
            raise ValueError(
                "A conta vinculada ao e-mail informado está inativa. Reative a conta para poder acessar a plataforma."
            )

        if not self._verify_password(password, user.password_hash):
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": email, "reason": "credentials_invalid"},
            )
            raise ValueError("Credenciais inválidas.")

        token = self._create_token(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=user.id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.login",
            resource="/auth/login",
            success=True,
        )
        return token

    async def register(
        self,
        name: str,
        email: str,
        password: str,
        accepted_terms: bool,
        request: Request,
    ) -> None:
        if not accepted_terms:
            raise ValueError("Termos de uso obrigatórios.")

        email = email.strip().lower()
        if await self.user_repo.get_by_email(email):
            raise ValueError("E-mail já cadastrado.")

        await self.pending_repo.delete_by_email(email)

        code = f"{int(hashlib.sha256((email + str(datetime.now().timestamp())).encode()).hexdigest(), 16) % 1000000:06d}"
        pwd_hash = self._hash_password(password)
        expires = datetime.now(timezone.utc) + timedelta(minutes=10)

        pending = await self.pending_repo.create(
            name=name,
            email=email,
            password_hash=pwd_hash,
            code=code,
            expires_at=expires,
            accepted_terms_at=datetime.now(timezone.utc),
        )
        await self.session.commit()

        try:
            html = verification_email_html(name, code)
            await send_email(email, "Confirme seu e-mail", html)
        except Exception as exc:
            raise ValueError(f"Falha ao enviar e-mail: {exc}")

        await self.audit_repo.insert(
            AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.register",
            resource="/auth/register",
            success=True,
            details={"email": email, "registration_id": str(pending.id)},
        )
        await self.session.commit()

    async def verify_email(self, email: str, code: str, request: Request) -> str:
        email = (email or "").strip().lower()
        pending = await self.pending_repo.get_by_email(email)

        if not pending:
            raise ValueError("Solicitação não encontrada.")
        if pending.attempts >= 3:
            await self.pending_repo.delete(pending)
            await self.session.commit()
            raise ValueError("Muitas tentativas. Registre-se novamente.")
        if pending.expires_at < datetime.now(timezone.utc):
            raise ValueError("Código expirado.")
        if pending.code != code:
            await self.pending_repo.increment_attempts(pending.id, pending.attempts)
            await self.session.commit()
            raise ValueError("Código inválido.")

        user = User(
            name=pending.name,
            email=pending.email,
            password_hash=pending.password_hash,
            status=UserStatus.active,
            accepted_terms_at=pending.accepted_terms_at,
        )

        user = await self.user_repo.create(user)
        await self.pending_repo.delete(pending)

        await self.session.commit()

        await self.audit_repo.link_registration_to_user(
            registration_id=str(pending.id),
            user_id=str(user.id),
        )

        await self.audit_repo.insert(
            AuditLog,
            user_id=user.id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.verify_email",
            resource="/auth/verify-email",
            success=True,
        )

        return self._create_token(user)

    async def resend_code(self, email: str, request: Request) -> None:
        email = (email or "").strip().lower()
        pending = await self.pending_repo.get_by_email(email)
        if not pending:
            raise ValueError("Solicitação não encontrada.")

        now = datetime.now(timezone.utc)
        if pending.last_sent_at and (now - pending.last_sent_at).total_seconds() < 60:
            raise ValueError("Aguarde 1 minuto para reenviar.")

        new_code = f"{int(hashlib.sha256((email + str(now.timestamp())).encode()).hexdigest(), 16) % 1000000:06d}"
        expires = now + timedelta(minutes=10)

        await self.pending_repo.update_code(
            pending.id,
            code=new_code,
            expires_at=expires,
            last_sent_at=now,
        )
        await self.session.commit()

        html = verification_email_html(pending.name, new_code)
        await send_email(email, "Confirme seu e-mail", html)

        await self.audit_repo.insert(
            AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.resend_code",
            resource="/auth/resend-code",
            success=True,
            details={"email": email, "registration_id": str(pending.id)},
        )
        await self.session.commit()

    async def forgot_password(self, email: str, request: Request) -> None:
        email = (email or "").strip().lower()
        if not EMAIL_RE.match(email) or len(email) > 60:
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")

        user = await self.user_repo.get_by_email(email)
        if not user:
            raise ValueError("O e-mail informado não está vinculado a nenhuma conta.")
        if user.status != UserStatus.active:
            raise ValueError(
                "A conta vinculada ao e-mail informado está inativa. Reative a conta para poder realizar a troca de senha"
            )

        reset = await self.pwd_repo.create(
            user_id=str(user.id),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            actor_ip_hash=ip_hash_from_request(request),
        )

        link = f"{settings.frontend_url}/reset-password/{reset.id}"
        html = reset_password_email_html(user.name, link)
        await send_email(email, "Redefinir senha", html)

        await self.audit_repo.insert(
            AuditLog,
            user_id=user.id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.forgot_password",
            resource="/auth/forgot-password",
            success=True,
        )
        await self.session.commit()

    async def reset_password(
        self, token: str, password: str, confirm: str, request: Request
    ) -> None:
        password = password or ""
        confirm = confirm or ""

        if password != confirm:
            raise ValueError("Senhas não conferem.")

        if len(password) < 8:
            raise ValueError("A nova senha deve ter pelo menos 8 caracteres.")

        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)

        if not (has_upper and has_digit and has_symbol):
            raise ValueError(
                "A senha deve conter pelo menos 1 letra maiúscula, 1 número e 1 símbolo."
            )

        reset = await self.pwd_repo.get_by_id(token)
        if not reset or reset.used_at or reset.expires_at < datetime.now(timezone.utc):
            raise ValueError("Link inválido ou expirado.")

        user = await self.user_repo.get_by_id(reset.user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")

        if self._verify_password(password, user.password_hash):
            raise ValueError("A nova senha deve ser diferente da senha atual.")

        user.password_hash = self._hash_password(password)
        await self.user_repo.update(user)

        await self.pwd_repo.mark_used(token, datetime.now(timezone.utc))

        await self.audit_repo.insert(
            AuditLog,
            user_id=user.id,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.reset_password",
            resource="/auth/reset-password",
            success=True,
        )
        await self.session.commit()

    async def logout(self, request: Request) -> None:
        user_id = None
        try:
            if hasattr(request.state, "user_id"):
                user_id = request.state.user_id
        except Exception:
            pass

        if user_id:
            await self.audit_repo.insert(
                AuditLog,
                user_id=user_id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.logout",
                resource="/auth/logout",
                success=True,
            )
            await self.session.commit()
