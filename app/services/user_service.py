from __future__ import annotations

import hashlib
import hmac
import html
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Tuple

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.domain.audit_model import AuditLog
from app.domain.enums import UserStatus
from app.domain.user_model import User
from app.repositories.audit_repository import AuditRepository
from app.repositories.user_repository import UserRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.services.email_service import (
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

        repo = AnalysisRepository(self.session)
        user_key = str(db_user.id)

        total_urls, _ = await repo.paginated_for_user(
            user_id=user_key,
            page=1,
            page_size=1,
            q=None,
            date_from=None,
            date_to=None,
            status=None,
            analysis_type="url",
            exclude_errors=True,
        )

        total_images, _ = await repo.paginated_for_user(
            user_id=user_key,
            page=1,
            page_size=1,
            q=None,
            date_from=None,
            date_to=None,
            status=None,
            analysis_type="image",
            exclude_errors=True,
        )

        now = datetime.now(timezone.utc)
        start_today = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        end_today = start_today + timedelta(days=1)

        today_urls, _ = await repo.paginated_for_user(
            user_id=user_key,
            page=1,
            page_size=1,
            q=None,
            date_from=start_today,
            date_to=end_today,
            status=None,
            analysis_type="url",
            exclude_errors=True,
        )

        today_images, _ = await repo.paginated_for_user(
            user_id=user_key,
            page=1,
            page_size=1,
            q=None,
            date_from=start_today,
            date_to=end_today,
            status=None,
            analysis_type="image",
            exclude_errors=True,
        )

        url_daily_limit = int(getattr(settings, "user_url_limit", 0) or 0)
        image_daily_limit = int(getattr(settings, "user_image_limit", 0) or 0)

        remaining_urls = max(url_daily_limit - today_urls, 0) if url_daily_limit else 0
        remaining_images = max(image_daily_limit - today_images, 0) if image_daily_limit else 0

        return {
            "id": str(db_user.id),
            "name": db_user.name,
            "email": db_user.email,
            "role": role_value,
            "status": status_value,
            "stats": {
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
            action="user.profile.update_name",
            resource="/v1/user/profile/name",
            success=True,
            details={"name": name},
        )
        await self.session.commit()
        return user.name

    async def _normalize_and_validate_email(self, raw: str) -> str:
        email = (raw or "").strip().lower()
        if not email or len(email) > 255 or not EMAIL_RE.match(email):
            raise ValueError("O e-mail informado não é válido.")
        return email

    async def _normalize_and_validate_new_email_for_change(
        self,
        user_id: str,
        raw_email: str,
    ) -> str:
        email = await self._normalize_and_validate_email(raw_email)
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        if user.email and user.email.lower() == email:
            raise ValueError("O novo e-mail deve ser diferente do atual.")
        existing = await self.users.get_by_email(email)
        if existing and str(existing.id) != str(user_id):
            raise ValueError("O e-mail informado já está vinculado a outra conta.")
        return email

    def _is_active_user(self, user: Any) -> bool:
        status_value = getattr(user, "status", None)
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

    def _time_step(self) -> int:
        return int(time.time() // 900)

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
        await self.users.save_reactivation_code(user, code, expires_at)
        body = email_change_email_html(user.name or "", email, code)
        await send_email(email, "Confirmar alteração de e-mail", body)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.email_change.request",
            resource="/v1/user/profile/email-change/request",
            success=True,
            details={"email": email},
        )
        await self.session.commit()

    async def confirm_email_change(
        self,
        raw_email: str,
        code: str,
        request: Request,
    ) -> str:
        email = await self._normalize_and_validate_email(raw_email)
        if not CODE_RE.fullmatch(code or ""):
            raise ValueError("O código inserido está inválido ou expirado.")
        result = await self.session.execute(
            select(User).where(User.reactivation_code == code)
        )
        user = result.scalar_one_or_none()
        if not user:
            raise ValueError("O código inserido está inválido ou expirado.")
        now = datetime.now(timezone.utc)
        if not user.reactivation_code_expires_at or user.reactivation_code_expires_at < now:
            raise ValueError("O código inserido está inválido ou expirado.")
        email = await self._normalize_and_validate_new_email_for_change(str(user.id), email)
        user.email = email
        await self.users.clear_reactivation_code(user)
        await self.users.update(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=ip_hash_from_request(request),
            action="user.email_change.confirm",
            resource="/v1/user/profile/email-change/confirm",
            success=True,
            details={"email": email},
        )
        await self.session.commit()
        return user.email

    def _generate_for_step(self, email: str, step: int) -> str:
        key = settings.jwt_secret.encode("utf-8")
        msg = f"reactivate:{email.lower()}:{step}".encode("utf-8")
        digest = hmac.new(key, msg, hashlib.sha256).digest()
        num = int.from_bytes(digest[:4], "big") % 1_000_000
        return f"{num:06d}"

    def generate_reactivation_code(self, email: str) -> str:
        step = self._time_step()
        return self._generate_for_step(email, step)

    def validate_reactivation_code_value(self, email: str, code: str) -> bool:
        if not CODE_RE.fullmatch(code):
            return False
        now_step = self._time_step()
        for delta in (0, -1):
            step = now_step + delta
            if step < 0:
                continue
            if self._generate_for_step(email, step) == code:
                return True
        return False

    async def validate_reactivation_email(self, raw_email: str, request: Request) -> None:
        try:
            email, user_id = await self.validate_email(raw_email)
            await self.audit_repo.insert(
                AuditLog,
                user_id=user_id,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.validate",
                resource="user",
                success=True,
                details={"email": email},
            )
            await self.session.commit()
        except ValueError as exc:
            await self.audit_repo.insert(
                AuditLog,
                user_id=None,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.validate",
                resource="user",
                success=False,
                details={"email": raw_email, "error": str(exc)},
            )
            await self.session.commit()
            raise

    async def send_reactivation_code_flow(self, raw_email: str, request: Request) -> None:
        try:
            email, user_id = await self.validate_email(raw_email)
            user = await self.users.get_by_email(email)
            code = self._generate_random_code()
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
            await self.users.save_reactivation_code(user, code, expires_at)
            body = reactivate_account_email_html(html.escape(user.name or ""), code)
            await send_email(email, "Reativar conta", body)
            await self.audit_repo.insert(
                AuditLog,
                user_id=user_id,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.send_code",
                resource="user",
                success=True,
                details={"email": email},
            )
            await self.session.commit()
        except ValueError as exc:
            await self.audit_repo.insert(
                AuditLog,
                user_id=None,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.send_code",
                resource="user",
                success=False,
                details={"email": raw_email, "error": str(exc)},
            )
            await self.session.commit()
            raise

    async def confirm_reactivation_code_flow(
        self,
        raw_email: str,
        code: str,
        request: Request,
    ) -> None:
        user_id: str | None = None
        try:
            email, user_id = await self.validate_email(raw_email)
            if not CODE_RE.fullmatch(code or ""):
                raise ValueError("O código inserido está inválido ou expirado.")
            user = await self.users.get_by_email(email)
            if not user:
                raise ValueError("Usuário não encontrado.")
            now = datetime.now(timezone.utc)
            if (
                not user.reactivation_code
                or user.reactivation_code != code
                or not user.reactivation_code_expires_at
                or user.reactivation_code_expires_at < now
            ):
                raise ValueError("O código inserido está inválido ou expirado.")
            if not self._is_active_user(user):
                await self.users.reactivate(user)
            await self.users.clear_reactivation_code(user)
            await self.audit_repo.insert(
                AuditLog,
                user_id=user_id,
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
                user_id=user_id,
                actor_ip_hash=ip_hash_from_request(request),
                action="user.reactivate.confirm_code",
                resource="user",
                success=False,
                details={"email": raw_email, "code": code, "error": str(exc)},
            )
            await self.session.commit()
            raise

    async def inactivate_account(self, user_id: str) -> None:
        user = await self.users.get_by_id(user_id)
        if not user:
            raise ValueError("Usuário não encontrado.")
        user.status = UserStatus.inactive
        await self.users.update(user)
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
        user.status = UserStatus.inactive
        suffix = str(user.id)
        user.email = f"deleted+{suffix}@deleted.local"
        user.name = "Conta excluída"
        await self.users.update(user)
        await self.audit_repo.insert(
            AuditLog,
            user_id=str(user.id),
            actor_ip_hash=None,
            action="user.account.delete",
            resource="/v1/user/account",
            success=True,
        )
        await self.session.commit()
