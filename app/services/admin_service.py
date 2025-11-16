from __future__ import annotations

from typing import Any, Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.analysis_repo import AnalysisRepository
from app.repositories.admin_repo import AdminRepository


class AdminDashboardService:
    def __init__(self, session: AsyncSession) -> None:
        self._analysis_repo = AnalysisRepository(session)
        self._admin_repo = AdminRepository(session)

    async def get_monthly_metrics(self, year: int, month: int) -> Dict[str, Any]:
        analysis = await self._analysis_repo.monthly_metrics(year=year, month=month)
        user_status = await self._admin_repo.user_status_metrics(year=year, month=month)

        active = int(user_status.get("active", 0))
        inactive = int(user_status.get("inactive", 0))
        total_users = active + inactive

        return {
            "year": year,
            "month": month,
            "reference": f"{year:04d}-{month:02d}",
            "bars": analysis["bars"],
            "totals": analysis["totals"],
            "users": {
                "bars": {
                    "active_users": active,
                    "inactive_users": inactive,
                },
                "totals": {
                    "total_users": total_users,
                    "active_users": active,
                    "inactive_users": inactive,
                },
            },
        }
