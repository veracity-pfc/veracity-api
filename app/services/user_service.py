from __future__ import annotations

import hashlib
import hmac
import html
import re
import time
from typing import Any, Tuple

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.domain.enums import UserStatus
from app.repositories.user_repo import UserRepository
from app.services.email_service import send_email, reactivate_account_email_html


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CODE_RE = re.compile(r"^\d{6}$")


class UserService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.users = UserRepository(session)

    async def _normalize_and_validate_email(self, raw: str) -> str:
        email = (raw or "").strip().lower()
        if not email or len(email) > 255 or not EMAIL_RE.match(email):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O e-mail informado não é válido. Tente novamente.",
            )
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
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="O e-mail fornecido não foi encontrado. Verifique e tente novamente.",
            )
        if self._is_active_user(user):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A conta vinculada ao e-mail fornecido já está ativa.",
            )
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

    async def send_reactivation_code(self, raw_email: str) -> str:
        email, _ = await self.validate_email(raw_email)
        user = await self.users.get_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="O e-mail fornecido não foi encontrado. Verifique e tente novamente.",
            )

        code = self.generate_reactivation_code(email)
        body = reactivate_account_email_html(html.escape(user.name or ""), code)
        await send_email(email, "Reativar conta", body)
        return email

    async def confirm_reactivation_code(self, raw_email: str, code: str) -> str:
        email, _ = await self.validate_email(raw_email)
        if not self.validate_reactivation_code_value(email, code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="O código inserido está inválido ou expirado. Tente novamente.",
            )

        user = await self.users.get_by_email(email)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="O e-mail fornecido não foi encontrado. Verifique e tente novamente.",
            )

        if not self._is_active_user(user):
            await self.users.reactivate(user)
            await self.session.commit()

        return email
