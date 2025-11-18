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
        analysis_raw = await self._analysis_repo.monthly_metrics(year=year, month=month)
        user_status = await self._admin_repo.user_status_metrics(year=year, month=month)

        bars = dict(analysis_raw.get("bars") or {})
        totals_raw = dict(analysis_raw.get("totals") or {})

        urls_month = int(totals_raw.get("urls_month", 0))
        images_month = int(totals_raw.get("images_month", 0))
        total_month = urls_month + images_month

        analyses_totals = {
            "total_month": total_month,
            "urls_month": urls_month,
            "images_month": images_month,
        }

        active = int(user_status.get("active", 0))
        inactive = int(user_status.get("inactive", 0))
        total_users = active + inactive

        users_payload = {
            "bars": {
                "active_users": active,
                "inactive_users": inactive,
            },
            "totals": {
                "total_users": total_users,
                "active_users": active,
                "inactive_users": inactive,
            },
        }

        return {
            "year": year,
            "month": month,
            "reference": f"{year:04d}-{month:02d}",
            "analyses": {
                "bars": bars,
                "totals": analyses_totals,
            },
            "users": users_payload,
            "bars": bars,
            "totals": analyses_totals,
        }
