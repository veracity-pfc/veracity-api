from __future__ import annotations

import hashlib
import hmac
import html
import time
from typing import Any, Tuple

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.domain.audit_model import AuditLog
from app.domain.enums import UserStatus
from app.repositories.audit_repository import AuditRepository
from app.repositories.user_repository import UserRepository
from app.services.email_service import send_email, reactivate_account_email_html
from app.core.constants import CODE_RE, EMAIL_RE
class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.audit_repo = AuditRepository(session)

    async def _normalize_and_validate_email(self, raw: str) -> str:
        email = (raw or "").strip().lower()
        if not email or len(email) > 255 or not EMAIL_RE.match(email):
            raise ValueError("O e-mail informado não é válido.")
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

    def _time_step(self) -> int:
        return int(time.time() // 900)

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
            raise

    async def send_reactivation_code_flow(self, raw_email: str, request: Request) -> None:
        try:
            email, user_id = await self.validate_email(raw_email)
            user = await self.users.get_by_email(email) 
            
            code = self.generate_reactivation_code(email)
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
            raise

    async def confirm_reactivation_code_flow(self, raw_email: str, code: str, request: Request) -> None:
        user_id = None
        email = raw_email
        try:
            email, user_id = await self.validate_email(raw_email)

            if not self.validate_reactivation_code_value(email, code):
                raise ValueError("O código inserido está inválido ou expirado.")

            user = await self.users.get_by_email(email)
            
            if not self._is_active_user(user):
                await self.users.reactivate(user)
                await self.session.commit()

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