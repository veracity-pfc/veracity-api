from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Tuple
from zoneinfo import ZoneInfo
from fastapi import Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.domain.audit_model import AuditLog
from app.domain.enums import UserStatus, AnalysisType, AnalysisStatus, ContactStatus, ApiTokenRequestStatus
from app.domain.user_model import User
from app.domain.analysis_model import Analysis
from app.domain.contact_request_model import ContactRequest
from app.domain.api_token_request_model import ApiTokenRequest
from app.repositories.audit_repository import AuditRepository
from app.repositories.user_repository import UserRepository
from app.repositories.api_token_repository import ApiTokenRepository
from app.services.utils.email_utils import (
    send_email,
    reactivate_account_email_html,
    email_change_email_html,
)
from app.core.constants import CODE_RE, EMAIL_RE


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.audit_repo = AuditRepository(session)
        self.tokens = ApiTokenRepository(session)

    async def _count_web_analyses(
        self,
        user_id: str,
        analysis_type: str,
        start_date: datetime | None = None,
        end_date: datetime | None = None
    ) -> int:
        stmt = select(func.count(Analysis.id)).where(
            Analysis.user_id == user_id,
            Analysis.api_token_id.is_(None),
            Analysis.analysis_type == analysis_type,
            Analysis.status != AnalysisStatus.error
        )

        if start_date:
            stmt = stmt.where(Analysis.created_at >= start_date)
        if end_date:
            stmt = stmt.where(Analysis.created_at < end_date)

        result = await self.session.execute(stmt)
        return result.scalar_one() or 0

    async def get_user_profile(self, user: Any) -> dict:
        user_id = getattr(user, "id", None)
        if not user_id:
            raise ValueError("Usuário não encontrado.")

        db_user = await self.users.get_by_id(user_id)
        if not db_user:
            raise ValueError("Usuário não encontrado.")

        role_value = getattr(db_user, "role", None)
        if hasattr(role_value, "value"):
            role_value = role_value.value

        status_value = getattr(db_user, "status", None)
        if hasattr(status_value, "value"):
            status_value = status_value.value

        is_admin = str(role_value).lower() == "admin"

        if is_admin:
            stmt_doubts = select(
                func.count(ContactRequest.id),
                ContactRequest.status,
            ).where(
                ContactRequest.category == "doubt"
            ).group_by(ContactRequest.status)

            stmt_suggestions = select(
                func.count(ContactRequest.id),
                ContactRequest.status,
            ).where(
                ContactRequest.category == "suggestion"
            ).group_by(ContactRequest.status)

            stmt_complaints = select(
                func.count(ContactRequest.id),
                ContactRequest.status,
            ).where(
                ContactRequest.category == "complaint"
            ).group_by(ContactRequest.status)

            stmt_tokens = select(
                func.count(ApiTokenRequest.id),
                ApiTokenRequest.status,
            ).group_by(ApiTokenRequest.status)

            res_doubts = (await self.session.execute(stmt_doubts)).all()
            res_suggestions = (await self.session.execute(stmt_suggestions)).all()
            res_complaints = (await self.session.execute(stmt_complaints)).all()
            res_tokens = (await self.session.execute(stmt_tokens)).all()

            def build_counts(rows):
                responded = 0
                rejected = 0
                for total, st in rows:
                    val = st.value if hasattr(st, "value") else str(st)
                    if val in ("finished", "approved"):
                        responded += int(total)
                    if val in ("rejected",):
                        rejected += int(total)
                return {"responded": responded, "rejected": rejected}

            admin_stats = {
                "doubt": build_counts(res_doubts),
                "suggestion": build_counts(res_suggestions),
                "complaint": build_counts(res_complaints),
                "token_request": build_counts(res_tokens),
            }

            return {
                "id": str(db_user.id),
                "name": db_user.name,
                "email": db_user.email,
                "role": role_value,
                "status": status_value,
                "admin_stats": admin_stats,
            }

        user_key = str(db_user.id)

        tz = ZoneInfo("America/Sao_Paulo")
        now_local = datetime.now(tz)
        start_local = datetime(now_local.year, now_local.month, now_local.day, tzinfo=tz)
        end_local = start_local + timedelta(days=1)
        start_today = start_local.astimezone(timezone.utc)
        end_today = end_local.astimezone(timezone.utc)

        total_urls = await self._count_web_analyses(user_key, AnalysisType.url)
        total_images = await self._count_web_analyses(user_key, AnalysisType.image)

        today_urls = await self._count_web_analyses(user_key, AnalysisType.url, start_today, end_today)
        today_images = await self._count_web_analyses(user_key, AnalysisType.image, start_today, end_today)

        url_daily_limit = int(getattr(settings, "user_url_limit", 0) or 0)
        image_daily_limit = int(getattr(settings, "user_image_limit", 0) or 0)

        remaining_urls = max(url_daily_limit - today_urls, 0) if url_daily_limit else 0
        remaining_images = max(image_daily_limit - today_images, 0) if image_daily_limit else 0

        api_token_info = None
        active_token = await self.tokens.get_active_by_user(db_user.id)
        if active_token:
            api_token_info = {
                "prefix": active_token.token_prefix,
                "status": active_token.status.value,
                "expires_at": active_token.expires_at,
                "revealed": bool(active_token.revealed_at),
            }

        return {
            "id": str(db_user.id),
            "name": db_user.name,
            "email": db_user.email,
            "role": role_value,
            "status": status_value,
            "api_token_info": api_token_info,
            "stats": {
                "limits": {
                    "urls": url_daily_limit,
                    "images": image_daily_limit,
                },
                "today": {
                    "urls": today_urls,
                    "images": today_images,
                },
                "remaining": {
                    "urls": remaining_urls,
                    "images": remaining_images,
                },
                "performed": {
                    "urls": total_urls,
                    "images": total_images,
                },
            },
        }

    def _hash_password(self, password: str) -> str:
        salt = settings.password_salt.encode("utf-8")
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100_000,
        ).hex()

    def _verify_password(self, password: str, hashed: str) -> bool:
        salt = settings.password_salt.encode("utf-8")
        check_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100_000,
        ).hex()
        return hmac.compare_digest(check_hash, hashed)

    def _normalize_email(self, email: str) -> str:
        email = html.unescape(email or "").strip().lower()
        if not EMAIL_RE.fullmatch(email):
            raise ValueError("E-mail inválido.")
        return email

    def _validate_password(self, password: str) -> None:
        if len(password) < 8:
            raise ValueError("Senha deve ter pelo menos 8 caracteres.")
        if not any(c.islower() for c in password):
            raise ValueError("Senha deve conter pelo menos uma letra minúscula.")
        if not any(c.isupper() for c in password):
            raise ValueError("Senha deve conter pelo menos uma letra maiúscula.")
        if not any(c.isdigit() for c in password):
            raise ValueError("Senha deve conter pelo menos um dígito numérico.")
        special = "!@#$%^&*()-_=+[]{};:,.<>/?"
        if not any(c in special for c in password):
            raise ValueError(
                "Senha deve conter pelo menos um caractere especial: " + special
            )

    async def _ensure_unique_email(self, email: str) -> None:
        existing = await self.users.get_by_email(email)
        if existing:
            raise ValueError("E-mail já está em uso.")

    async def register_user(self, name: str, email: str, password: str, request: Request) -> User:
        name = (name or "").strip()
        if len(name) < 3 or len(name) > 30:
            raise ValueError("Nome deve ter entre 3 e 30 caracteres.")

        email = self._normalize_email(email)
        await self._ensure_unique_email(email)
        self._validate_password(password)

        hashed = self._hash_password(password)
        user = await self.users.create_user(name=name, email=email, password_hash=hashed)

        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.register",
            resource="/auth/register",
            success=True,
            details={"email": email},
        )
        await self.session.commit()
        return user

    async def authenticate_user(self, email: str, password: str, request: Request) -> User:
        email = self._normalize_email(email)
        user = await self.users.get_by_email(email)
        if not user:
            raise ValueError("Credenciais inválidas.")
        if not self._verify_password(password, user.password_hash):
            raise ValueError("Credenciais inválidas.")
        if user.status != UserStatus.active:
            raise ValueError("Conta inativa. Verifique seu e-mail para reativação.")

        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.login",
            resource="/auth/login",
            success=True,
        )
        await self.session.commit()
        return user

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        request: Request,
    ) -> None:
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        if not self._verify_password(current_password, user.password_hash):
            raise ValueError("Senha atual incorreta.")
        self._validate_password(new_password)
        user.password_hash = self._hash_password(new_password)
        await self.users.update(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.password.change",
            resource="/v1/user/change-password",
            success=True,
        )
        await self.session.commit()

    async def update_name(self, user_id: str, new_name: str) -> str:
        name = (new_name or "").strip()
        if len(name) < 3 or len(name) > 30:
            raise ValueError("Nome deve ter entre 3 e 30 caracteres.")
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        if user.name == name:
            return user.name
        user.name = name
        await self.users.update(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=None,
            action="user.name.update",
            resource="/v1/user/profile",
            success=True,
        )
        await self.session.commit()
        return user.name

    async def update_email(self, user_id: str, new_email: str) -> str:
        email = self._normalize_email(new_email)
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        if user.email == email:
            return user.email
        await self._ensure_unique_email(email)
        user.email = email
        await self.users.update(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=None,
            action="user.email.update",
            resource="/v1/user/profile",
            success=True,
        )
        await self.session.commit()
        return user.email

    async def _normalize_and_validate_email(self, raw_email: str) -> str:
        email = self._normalize_email(raw_email)
        return email

    async def _normalize_and_validate_new_email_for_change(self, user_id: str, raw_email: str) -> str:
        email = self._normalize_email(raw_email)
        existing = await self.users.get_by_email(email)
        if existing and str(existing.id) != user_id:
            raise ValueError("E-mail já está em uso por outra conta.")
        return email

    def _time_step(self) -> int:
        return int(time.time() // 300)

    def _build_code_secret(self, email: str, step: int) -> bytes:
        return f"{email}:{step}".encode("utf-8")

    def _generate_code(self, email: str) -> str:
        step = self._time_step()
        secret = settings.jwt_secret.encode("utf-8")
        msg = self._build_code_secret(email, step)
        digest = hmac.new(secret, msg, hashlib.sha256).digest()
        value = int.from_bytes(digest[:4], "big")
        value = value % 1_000_000
        return f"{value:06d}"

    def _validate_code(self, email: str, code: str) -> bool:
        if not CODE_RE.fullmatch(code):
            return False
        secret = settings.jwt_secret.encode("utf-8")
        now_step = self._time_step()
        for step in (now_step, now_step - 1, now_step + 1):
            msg = self._build_code_secret(email, step)
            digest = hmac.new(secret, msg, hashlib.sha256).digest()
            value = int.from_bytes(digest[:4], "big")
            value = value % 1_000_000
            expected = f"{value:06d}"
            if hmac.compare_digest(expected, code):
                return True
        return False

    async def request_reactivation_code(self, raw_email: str, request: Request) -> None:
        email = await self._normalize_and_validate_email(raw_email)
        user = await self.users.get_by_email(email)
        if not user:
            raise ValueError("E-mail não encontrado.")
        if user.status == UserStatus.active:
            raise ValueError("Conta já está ativa.")

        code = self._generate_code(email)
        html_body = reactivate_account_email_html(code)
        await send_email(email, "Código de reativação de conta", html_body)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.reactivate.request_code",
            resource="/user/reactivate-account",
            success=True,
            details={"email": email},
        )
        await self.session.commit()

    async def confirm_reactivation_code(
        self,
        raw_email: str,
        code: str,
        request: Request,
    ) -> None:
        email = await self._normalize_and_validate_email(raw_email)
        user = await self.users.get_by_email(email)
        if not user:
            raise ValueError("E-mail não encontrado.")

        try:
            if not self._validate_code(email, code):
                raise ValueError("Código inválido ou expirado.")
            user.status = UserStatus.active
            await self.users.update(user)
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.confirm_code",
                resource="/user/reactivate-account",
                success=True,
                details={"email": email, "code": code},
            )
            await self.session.commit()
        except ValueError as exc:
            await self.audit_repo.insert(
                AuditLog,
                user_id=user.id,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.confirm_code",
                resource="user",
                success=False,
                details={"email": raw_email, "code": code, "error": str(exc)},
            )
            await self.session.commit()
            raise

    def _generate_random_code(self) -> str:
        value = secrets.randbelow(1_000_000)
        return f"{value:06d}"

    async def request_email_change(
        self,
        user_id: str,
        raw_email: str,
        request: Request,
    ) -> None:
        email = await self._normalize_and_validate_new_email_for_change(user_id, raw_email)
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        code = self._generate_random_code()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        await self.users.set_email_change_code(user.id, email, code, expires_at)
        html_body = email_change_email_html(code, email)
        await send_email(email, "Confirmação de alteração de e-mail", html_body)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.email_change.request",
            resource="/v1/user/profile/email-change/request",
            success=True,
            details={"new_email": email},
        )
        await self.session.commit()

    async def confirm_email_change(
        self,
        user_id: str,
        code: str,
        request: Request,
    ) -> None:
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        if not user.pending_email or not user.pending_email_code or not user.pending_email_expires_at:
            raise ValueError("Nenhuma alteração de e-mail pendente.")
        if user.pending_email_expires_at < datetime.now(timezone.utc):
            raise ValueError("Código expirado.")
        if user.pending_email_code != code:
            raise ValueError("Código inválido.")

        new_email = user.pending_email
        await self._ensure_unique_email(new_email)
        user.email = new_email
        user.pending_email = None
        user.pending_email_code = None
        user.pending_email_expires_at = None
        await self.users.update(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.email_change.confirm",
            resource="/v1/user/profile/email-change/confirm",
            success=True,
            details={"new_email": new_email},
        )
        await self.session.commit()

    def _is_active_user(self, user: User) -> bool:
        status_value = getattr(user, "status", None)
        if hasattr(status_value, "value"):
            status_value = status_value.value
        if isinstance(status_value, UserStatus):
            return status_value == UserStatus.active
        if isinstance(status_value, str):
            return status_value.lower() == UserStatus.active.value
        return getattr(user, "is_active", True)

    async def validate_email(self, raw_email: str) -> Tuple[str, str]:
        email = await self._normalize_and_validate_email(raw_email)
        user = await self.users.get_by_email(email)
        if not user:
            raise ValueError("O e-mail fornecido não foi encontrado.")
        if self._is_active_user(user):
            raise ValueError("A conta vinculada ao e-mail fornecido já está ativa.")
        return email, str(user.id)

    async def validate_email_change(self, user_id: str, raw_email: str) -> None:
        await self._normalize_and_validate_new_email_for_change(user_id, raw_email)

    async def inactivate_account(self, user_id: str) -> None:
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        user.status = UserStatus.inactive
        await self.users.update(user)
        await self._revoke_active_token_for_user_auto(
            user_id=str(user.id),
            reason="Conta inativada pelo usuário",
        )
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=None,
            action="user.account.inactivate",
            resource="/v1/user/account",
            success=True,
        )
        await self.session.commit()

    async def _revoke_active_token_for_user_auto(self, user_id: str, reason: str) -> None:
        token = await self.tokens.get_active_by_user(user_id)
        if not token:
            return
        now = datetime.now(timezone.utc)
        await self.tokens.revoke(token, reason=reason, admin_id=None, now=now)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user_id),
            actor_ip_hash=None,
            action="api_token.revoke_user_auto",
            resource="/v1/user/account",
            success=True,
            details={"reason": reason, "token_id": str(token.id)},
        )

    async def _close_requests_for_deleted_user(self, user: User, closed_at: datetime) -> None:
        message = "Solicitação encerrada pois a conta do usuário foi excluída."
        result_contacts = await self.session.execute(
            select(ContactRequest).where(
                ContactRequest.user_id == user.id,
                ContactRequest.status == ContactStatus.open,
            )
        )
        contact_requests = result_contacts.scalars().all()
        for req in contact_requests:
            req.status = ContactStatus.finished
            req.admin_reply = message
            req.replied_at = closed_at
            req.replied_by_admin_id = None
        result_tokens = await self.session.execute(
            select(ApiTokenRequest).where(
                ApiTokenRequest.user_id == user.id,
                ApiTokenRequest.status == ApiTokenRequestStatus.open,
            )
        )
        token_requests = result_tokens.scalars().all()
        for req in token_requests:
            req.status = ApiTokenRequestStatus.rejected
            req.rejection_reason = message
            req.decided_at = closed_at
            req.decided_by_admin_id = None

    async def inactivate_account(self, user_id: str) -> None:
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        user.status = UserStatus.inactive
        await self.users.update(user)
        await self._revoke_active_token_for_user_auto(
            user_id=str(user.id),
            reason="Conta inativada pelo usuário",
        )
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=None,
            action="user.account.inactivate",
            resource="/v1/user/account",
            success=True,
        )
        await self.session.commit()

    async def delete_account(self, user_id: str) -> None:
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        now = datetime.now(timezone.utc)
        user.status = UserStatus.inactive
        suffix = str(user.id)
        user.email = f"deleted+{suffix}@.deleted.local.com"
        user.name = "Conta excluída"
        await self.users.update(user)
        await self._close_requests_for_deleted_user(user=user, closed_at=now)
        await self._revoke_active_token_for_user_auto(
            user_id=str(user.id),
            reason="Conta excluída pelo usuário",
        )
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=None,
            action="user.account.delete",
            resource="/v1/user/account",
            success=True,
        )
        await self.session.commit()
