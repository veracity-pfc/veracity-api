from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone

from fastapi import Request
from jose import jwt
from passlib.hash import bcrypt

from app.core.config import settings
from app.domain.audit_model import AuditLog
from app.domain.enums import UserStatus
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
from app.services.utils.validation_utils import normalize_email, validate_password_complexity, anonymize_email
from app.core.constants import EMAIL_RE

logger = logging.getLogger("veracity.auth_service")


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
        anonymized_email = anonymize_email(email)
        logger.info(f"Login attempt for email: {anonymized_email}")

        user = await self.user_repo.get_by_email(email)

        if not user:
            logger.warning(f"Login failed: User not found for email {anonymized_email}")
            await self.audit_repo.insert(
                AuditLog,
                user_id=None,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": anonymized_email, "reason": "user_not_found"},
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
            logger.warning(f"Login failed: Account inactive for email {anonymized_email}")
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": anonymized_email, "reason": "account_inactive"},
            )
            raise ValueError(
                "A conta vinculada ao e-mail informado está inativa. Reative a conta para poder acessar a plataforma."
            )

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            logger.warning(f"Login failed: Account locked for email {anonymized_email}")
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": anonymized_email, "reason": "account_locked"},
            )
            raise ValueError("Conta bloqueada temporariamente. Tente novamente em 3 minutos.")

        if not self._verify_password(password, user.password_hash):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 3:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=3)
            
            await self.user_repo.update(user)
            await self.session.commit()

            logger.warning(f"Login failed: Invalid password for email {anonymized_email}")
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.login",
                resource="/auth/login",
                success=False,
                details={"email": anonymized_email, "reason": "credentials_invalid"},
            )
            raise ValueError("Credenciais inválidas.")

        if (user.failed_login_attempts or 0) > 0 or user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            await self.user_repo.update(user)
            await self.session.commit()

        token = self._create_token(user)
        logger.info(f"Login successful for user ID: {user.id}")
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

        email = (email or "").strip().lower()
        anonymized_email = anonymize_email(email)
        logger.info(f"Register attempt for email: {anonymized_email}")

        if await self.user_repo.get_by_email(email):
            logger.info(f"Register failed: Email {anonymized_email} already exists")
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
            logger.error(
                f"Failed to send registration email to {anonymized_email}: {exc}"
            )
            raise ValueError(f"Falha ao enviar e-mail: {exc}")

        logger.info(f"Registration pending created for {anonymized_email}, ID: {pending.id}")
        await self.audit_repo.insert(
            AuditLog,
            user_id=None,
            actor_ip_hash=ip_hash_from_request(request),
            action="auth.register",
            resource="/auth/register",
            success=True,
            details={"email": anonymized_email, "registration_id": str(pending.id)},
        )
        await self.session.commit()

    async def verify_email(self, email: str, code: str, request: Request) -> str:
        email = (email or "").strip().lower()
        anonymized_email = anonymize_email(email)
        logger.info(f"Verifying email: {anonymized_email}")
        pending = await self.pending_repo.get_by_email(email)

        if not pending:
            logger.warning(f"Verify failed: No pending registration for {anonymized_email}")
            raise ValueError("Solicitação não encontrada.")
        if pending.attempts >= 3:
            logger.warning(f"Verify failed: Too many attempts for {anonymized_email}")
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
        logger.info(f"User created successfully: {user.id}")

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
        anonymized_email = anonymize_email(email)
        logger.info(f"Resend code requested for {anonymized_email}")
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
            details={"email": anonymized_email, "registration_id": str(pending.id)},
        )
        await self.session.commit()

    async def forgot_password(self, email: str, request: Request) -> None:
        email = (email or "").strip().lower()
        anonymized_email = anonymize_email(email)
        logger.info(f"Forgot password requested for {anonymized_email}")
        if not EMAIL_RE.match(email) or len(email) > 60:
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")

        user = await self.user_repo.get_by_email(email)
        if not user:
            logger.info(f"Forgot password: User not found for {anonymized_email}")
            raise ValueError("O e-mail informado não está vinculado a nenhuma conta.")

        role_val = getattr(user.role, "value", str(user.role))
        if str(role_val).lower() == "admin":
            raise ValueError("Administradores não podem realizar a troca de senha.")

        if user.status != UserStatus.active:
            raise ValueError(
                "A conta vinculada ao e-mail informado está inativa. Reative a conta para poder realizar a troca de senha"
            )

        reset = await self.pwd_repo.create(
            user_id=str(user.id),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
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
        logger.info(f"Password reset attempt with token: {token}")
        password = password or ""
        confirm = confirm or ""

        if password != confirm:
            raise ValueError("Senhas não conferem.")

        validate_password_complexity(password)

        reset = await self.pwd_repo.get_by_id(token)
        if not reset or reset.used_at or reset.expires_at < datetime.now(timezone.utc):
            logger.warning("Password reset failed: Invalid or expired token")
            raise ValueError("Link inválido ou expirado.")

        user = await self.user_repo.get_by_id(reset.user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")

        if self._verify_password(password, user.password_hash):
            raise ValueError("A nova senha deve ser diferente da senha atual.")

        user.password_hash = self._hash_password(password)
        await self.user_repo.update(user)

        await self.pwd_repo.mark_used(token, datetime.now(timezone.utc))

        logger.info(f"Password reset successful for user ID: {user.id}")
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
            logger.info(f"User logout: {user_id}")
            await self.audit_repo.insert(
                AuditLog,
                user_id=user_id,
                actor_ip_hash=ip_hash_from_request(request),
                action="auth.logout",
                resource="/auth/logout",
                success=True,
            )
            await self.session.commit()