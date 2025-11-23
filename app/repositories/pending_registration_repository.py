from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.pending_registration_model import PendingRegistration


class PendingRegistrationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_email(self, email: str) -> PendingRegistration | None:
        normalized = (email or "").strip().lower()
        stmt = (
            select(PendingRegistration)
            .where(func.lower(PendingRegistration.email) == normalized)
            .order_by(PendingRegistration.created_at.desc())
            .limit(1)
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create(
        self,
        *,
        name: str,
        email: str,
        password_hash: str,
        code: str,
        expires_at: datetime,
        accepted_terms_at: datetime,
    ) -> PendingRegistration:
        pending = PendingRegistration(
            name=name,
            email=email,
            password_hash=password_hash,
            code=code,
            expires_at=expires_at,
            accepted_terms_at=accepted_terms_at,
        )
        self.session.add(pending)
        await self.session.flush()
        return pending

    async def delete_by_email(self, email: str) -> None:
        normalized = (email or "").strip().lower()
        await self.session.execute(
            delete(PendingRegistration).where(
                func.lower(PendingRegistration.email) == normalized
            )
        )

    async def delete_by_id(self, pending_id: str) -> None:
        await self.session.execute(
            delete(PendingRegistration).where(PendingRegistration.id == pending_id)
        )

    async def update_attempts(self, pending_id: str, new_attempts: int) -> None:
        await self.session.execute(
            update(PendingRegistration)
            .where(PendingRegistration.id == pending_id)
            .values(attempts=new_attempts)
        )

    async def update_code(
        self,
        pending_id: str,
        *,
        code: str,
        expires_at: datetime,
        last_sent_at: datetime,
    ) -> None:
        await self.session.execute(
            update(PendingRegistration)
            .where(PendingRegistration.id == pending_id)
            .values(
                code=code,
                expires_at=expires_at,
                last_sent_at=last_sent_at,
            )
        )