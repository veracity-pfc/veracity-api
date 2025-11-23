from __future__ import annotations

from typing import Any

from sqlalchemy import insert, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.domain.audit_model import AuditLog


class AuditRepository:
    def __init__(self, session: AsyncSession):
        engine = session.bind
        if engine is None:
            raise RuntimeError("AuditRepository requires a bound session")
        self._sessionmaker = async_sessionmaker(engine, expire_on_commit=False)

    async def insert(self, table, **values: Any) -> None:
        async with self._sessionmaker() as session:
            await session.execute(insert(table).values(**values))
            await session.commit()

    async def link_registration_to_user(
        self,
        *,
        registration_id: str,
        user_id: str,
    ) -> None:
        async with self._sessionmaker() as session:
            await session.execute(
                update(AuditLog)
                .where(
                    AuditLog.user_id.is_(None),
                    AuditLog.details["registration_id"].as_string() == registration_id,
                    AuditLog.action.in_(["auth.register", "auth.resend_code"]),
                )
                .values(user_id=user_id)
            )
            await session.commit()