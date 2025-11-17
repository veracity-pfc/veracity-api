from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import UserStatus
from app.domain.user_model import User


class UserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_by_email(self, email: str) -> Optional[User]:
        stmt = select(User).where(User.email == email.lower())
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def reactivate(self, user: User) -> User:
        if hasattr(user, "status"):
            user.status = UserStatus.active
        await self.session.flush()
        return user

    async def save_reactivation_code(
        self,
        user: User,
        code: str,
        expires_at,
    ) -> None:
        if hasattr(user, "reactivation_code"):
            user.reactivation_code = code
        if hasattr(user, "reactivation_code_expires_at"):
            user.reactivation_code_expires_at = expires_at
        await self.session.flush()

    async def clear_reactivation_code(self, user: User) -> None:
        if hasattr(user, "reactivation_code"):
            user.reactivation_code = None
        if hasattr(user, "reactivation_code_expires_at"):
            user.reactivation_code_expires_at = None
        await self.session.flush()
