from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import insert
from typing import Any

class AuditRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def insert(self, table, **values: Any) -> None:
        await self.session.execute(insert(table).values(**values))
