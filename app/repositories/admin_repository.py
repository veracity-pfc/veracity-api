from __future__ import annotations

from datetime import date
from typing import Dict

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


class AdminRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def user_status_metrics(self, year: int, month: int) -> Dict[str, int]:
        start = date(year, month, 1)
        if month == 12:
            end = date(year + 1, 1, 1)
        else:
            end = date(year, month + 1, 1)

        query = text(
            """
            SELECT status, COUNT(*) AS total
            FROM users
            WHERE created_at < :end_date
            GROUP BY status
            """
        )

        result = await self._session.execute(
            query,
            {"end_date": end},
        )
        rows = result.all()

        active = 0
        inactive = 0

        for status, total in rows:
            if status == "active":
                active += int(total)
            elif status == "inactive":
                inactive += int(total)

        return {"active": active, "inactive": inactive}
