from __future__ import annotations

from typing import Any

from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.audit_model import AuditLog


class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def insert(self, table, **values: Any) -> None:
        await self.session.execute(insert(table).values(**values))

    async def link_registration_to_user(
        self,
        *,
        registration_id: str,
        user_id: str,
    ) -> None:
        await self.session.execute(
            update(AuditLog)
            .where(
                AuditLog.user_id.is_(None),
                AuditLog.details["registration_id"].as_string() == registration_id,
                AuditLog.action.in_(["auth.register", "auth.resend_code"]),
            )
            .values(user_id=user_id)
        )
