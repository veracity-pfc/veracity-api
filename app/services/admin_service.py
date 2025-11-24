from __future__ import annotations

from math import ceil
from typing import Any, Dict, Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.repositories.admin_repository import AdminRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.repositories.contact_repository import ContactRepository


class AdminDashboardService:
    def __init__(self, session: AsyncSession) -> None:
        self._analysis_repo = AnalysisRepository(session)
        self._admin_repo = AdminRepository(session)
        self._contact_repo = ContactRepository(session)

    async def get_monthly_metrics(self, year: int, month: int) -> Dict[str, Any]:
        analysis_raw = await self._analysis_repo.monthly_metrics(year=year, month=month)
        user_status = await self._admin_repo.user_status_metrics(year=year, month=month)
        token_data = await self._admin_repo.token_metrics(year=year, month=month)
        request_data = await self._admin_repo.request_metrics(year=year, month=month)

        analysis_bars = dict(analysis_raw.get("bars") or {})
        analysis_totals_raw = dict(analysis_raw.get("totals") or {})
        
        urls_month = int(analysis_totals_raw.get("urls_month", 0))
        images_month = int(analysis_totals_raw.get("images_month", 0))
        total_month = urls_month + images_month

        analyses_payload = {
            "bars": analysis_bars,
            "totals": {
                "total_month": total_month,
                "urls_month": urls_month,
                "images_month": images_month,
            },
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

        t_active = int(token_data.get("active", 0))
        t_expired = int(token_data.get("expired", 0))
        t_revoked = int(token_data.get("revoked", 0))
        total_tokens = t_active + t_expired + t_revoked

        tokens_payload = {
            "bars": {
                "active": t_active,
                "expired": t_expired,
                "revoked": t_revoked,
            },
            "totals": {
                "total_tokens": total_tokens,
                "active": t_active,
                "revoked": t_revoked,
            }
        }

        r_doubt = int(request_data.get("doubt", 0))
        r_suggestion = int(request_data.get("suggestion", 0))
        r_complaint = int(request_data.get("complaint", 0))
        r_token = int(request_data.get("token_request", 0))
        total_requests = r_doubt + r_suggestion + r_complaint + r_token

        requests_payload = {
            "bars": {
                "doubt": r_doubt,
                "suggestion": r_suggestion,
                "complaint": r_complaint,
                "token_request": r_token,
            },
            "totals": {
                "total_requests": total_requests,
                "doubt": r_doubt,
                "suggestion": r_suggestion,
                "complaint": r_complaint,
                "token_request": r_token,
            }
        }

        return {
            "year": year,
            "month": month,
            "reference": f"{year:04d}-{month:02d}",
            "analyses": analyses_payload,
            "users": users_payload,
            "tokens": tokens_payload,
            "requests": requests_payload,
        }

    async def list_unified_requests(
        self,
        status: Optional[str],
        category: Optional[str],
        email: Optional[str],
        page: int,
        page_size: int,
    ) -> Dict[str, Any]:

        status_enum = None
        if status:
            try:
                status_enum = status
            except ValueError:
                pass

        category_enum = None
        if category:
            try:
                category_enum = category
            except ValueError:
                pass

        total, rows = await self._admin_repo.list_unified_requests(
            page=page,
            page_size=page_size,
            status=status,
            category=category,
            email=email,
        )

        for idx, row in enumerate(rows):
            if isinstance(row, dict):
                user_email = row.get("user_email")
                if user_email and "deleted.local" in user_email:
                    row["email"] = user_email
            else:
                user_email = getattr(row, "user_email", None)
                if user_email and "deleted.local" in user_email:
                    setattr(row, "email", user_email)

        total_pages = ceil(total / page_size) if page_size > 0 else 1

        return {
            "items": rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    async def get_unified_request_detail(self, request_id: UUID) -> Optional[Any]:
        detail = await self._admin_repo.get_unified_detail(request_id)
        if detail and isinstance(detail, dict):
            user_email = detail.get("user_email")
            if user_email and "deleted.local" in user_email:
                detail["email"] = user_email
        return detail
