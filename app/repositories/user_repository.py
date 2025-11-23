from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import UserStatus
from app.domain.user_model import User


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_id(self, user_id: str | UUID) -> Optional[User]:
        return await self.session.get(User, user_id)

    async def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email.lower())
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def reactivate(self, user: User) -> User:
        user.status = UserStatus.active
        self.session.add(user)
        await self.session.flush()
        return user

    async def save_reactivation_code(
        self,
        user: User,
        code: str,
        expires_at,
    ) -> None:
        user.reactivation_code = code
        user.reactivation_code_expires_at = expires_at
        self.session.add(user)
        await self.session.flush()

    async def clear_reactivation_code(self, user: User) -> None:
        user.reactivation_code = None
        user.reactivation_code_expires_at = None
        self.session.add(user)
        await self.session.flush()

    async def update(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        return user