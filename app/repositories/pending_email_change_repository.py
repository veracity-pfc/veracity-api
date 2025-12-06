from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.pending_email_change_model import PendingEmailChange


class PendingEmailChangeRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_user_id(self, user_id: str | UUID) -> Optional[PendingEmailChange]:
        stmt = select(PendingEmailChange).where(PendingEmailChange.user_id == user_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_by_new_email(self, email: str) -> Optional[PendingEmailChange]:
        stmt = select(PendingEmailChange).where(PendingEmailChange.new_email == email.lower())
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create_or_update(
        self,
        user_id: str | UUID,
        new_email: str,
        token: str,
        expires_at,
    ) -> PendingEmailChange:
        pending = await self.get_by_user_id(user_id)
        if pending:
            pending.new_email = new_email
            pending.token = token
            pending.expires_at = expires_at
            self.session.add(pending)
        else:
            pending = PendingEmailChange(
                user_id=user_id,
                new_email=new_email,
                token=token,
                expires_at=expires_at,
            )
            self.session.add(pending)
        await self.session.flush()
        return pending

    async def delete_for_user(self, user_id: str | UUID) -> None:
        pending = await self.get_by_user_id(user_id)
        if not pending:
            return
        await self.session.delete(pending)
        await self.session.flush()
