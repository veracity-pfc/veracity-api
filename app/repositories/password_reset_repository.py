from __future__ import annotations

from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.password_reset import PasswordReset


class PasswordResetRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        *,
        user_id: str,
        expires_at: datetime,
        actor_ip_hash: str,
    ) -> PasswordReset:
        token = PasswordReset(
            user_id=user_id,
            expires_at=expires_at,
            actor_ip_hash=actor_ip_hash,
        )
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_by_id(self, token_id: str) -> PasswordReset | None:
        result = await self.session.execute(
            select(PasswordReset).where(PasswordReset.id == token_id)
        )
        return result.scalar_one_or_none()

    async def mark_used(self, token_id: str, used_at: datetime) -> None:
        await self.session.execute(
            update(PasswordReset)
            .where(PasswordReset.id == token_id)
            .values(used_at=used_at)
        )
