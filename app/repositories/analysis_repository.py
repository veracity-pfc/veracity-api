from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple, Any

from sqlalchemy import bindparam, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.ai_model import AIResponse
from app.domain.analysis_model import Analysis
from app.domain.enums import AnalysisType, RiskLabel
from app.domain.image_analysis_model import ImageAnalysis


class AnalysisRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def paginated_for_user(
        self,
        *,
        user_id: str,
        page: int,
        page_size: int,
        q: Optional[str],
        date_from: Optional[object],
        date_to: Optional[object],
        status: Optional[RiskLabel],
        analysis_type: Optional[AnalysisType],
        exclude_errors: bool = False,
    ) -> Tuple[int, list]:
        filters = [Analysis.user_id == user_id]

        if exclude_errors:
            filters.append(Analysis.status == "done")

        if date_from:
            filters.append(Analysis.created_at >= date_from)
        if date_to:
            filters.append(Analysis.created_at < date_to)
        if analysis_type:
            filters.append(Analysis.analysis_type == analysis_type)
        if status:
            filters.append(Analysis.label == status)
        if q:
            filters.append(Analysis.source_url.ilike(f"%{q}%"))

        stmt_count = select(func.count(Analysis.id)).where(*filters)
        total = (await self.session.execute(stmt_count)).scalar_one()

        stmt = (
            select(
                Analysis.id,
                Analysis.created_at,
                Analysis.analysis_type,
                Analysis.label,
                Analysis.status,
                Analysis.source_url,
            )
            .where(*filters)
            .order_by(Analysis.created_at.desc())
            .limit(page_size)
            .offset((page - 1) * page_size)
        )
        rows = (await self.session.execute(stmt)).all()

        return total, rows

    async def find_one_for_user(
        self,
        *,
        analysis_id: str,
        user_id: str,
        exclude_errors: bool = False,
    ) -> Optional[Analysis]:
        filters = [Analysis.id == analysis_id, Analysis.user_id == user_id]

        if exclude_errors:
            filters.append(Analysis.status == "done")

        stmt = select(Analysis).where(*filters)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def get_image_analysis_by_analysis_id(
        self, analysis_id: str
    ) -> Optional[ImageAnalysis]:
        stmt = select(ImageAnalysis).where(ImageAnalysis.analysis_id == analysis_id)
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def get_ai_response(self, ai_response_id: str) -> Optional[AIResponse]:
        return await self.session.get(AIResponse, ai_response_id)

    async def user_counts(
        self,
        *,
        user_id: str,
        day_start: datetime,
        day_end: datetime,
    ) -> Tuple[dict[str, int], dict[str, int]]:
        stmt_today = (
            select(Analysis.analysis_type, func.count(Analysis.id))
            .where(
                Analysis.user_id == user_id,
                Analysis.created_at >= day_start,
                Analysis.created_at < day_end,
            )
            .group_by(Analysis.analysis_type)
        )
        today_rows = (await self.session.execute(stmt_today)).all()
        today_map = {row[0]: int(row[1]) for row in today_rows}

        stmt_all = (
            select(Analysis.analysis_type, func.count(Analysis.id))
            .where(Analysis.user_id == user_id)
            .group_by(Analysis.analysis_type)
        )
        all_rows = (await self.session.execute(stmt_all)).all()
        total_map = {row[0]: int(row[1]) for row in all_rows}

        return today_map, total_map

    async def monthly_metrics(
        self, *, year: int, month: int
    ) -> dict[str, dict[str, int]]:
        sql = text(
            """
            WITH month_range AS (
                SELECT
                    make_timestamptz(:y, :m, 1, 0, 0, 0) AS start_dt,
                    (make_timestamptz(:y, :m, 1, 0, 0, 0) + INTERVAL '1 month') AS end_dt
            )
            SELECT
                COUNT(*) FILTER (
                    WHERE a.analysis_type = 'url'
                      AND a.label = 'suspicious'
                      AND a.created_at >= mr.start_dt
                      AND a.created_at <  mr.end_dt
                ) AS url_suspicious,
                COUNT(*) FILTER (
                    WHERE a.analysis_type = 'url'
                      AND a.label = 'safe'
                      AND a.created_at >= mr.start_dt
                      AND a.created_at <  mr.end_dt
                ) AS url_safe,
                COUNT(*) FILTER (
                    WHERE a.analysis_type = 'image'
                      AND a.label = 'fake'
                      AND a.created_at >= mr.start_dt
                      AND a.created_at <  mr.end_dt
                ) AS image_fake,
                COUNT(*) FILTER (
                    WHERE a.analysis_type = 'image'
                      AND a.label = 'safe'
                      AND a.created_at >= mr.start_dt
                      AND a.created_at <  mr.end_dt
                ) AS image_safe,
                COUNT(*) FILTER (
                    WHERE a.created_at >= mr.start_dt
                      AND a.created_at <  mr.end_dt
                ) AS total_month
            FROM analyses a
            CROSS JOIN month_range mr
        """
        ).bindparams(bindparam("y", year), bindparam("m", month))

        res = await self.session.execute(sql)
        row = res.first() or (0, 0, 0, 0, 0)

        url_suspicious = int(row[0] or 0)
        url_safe = int(row[1] or 0)
        image_fake = int(row[2] or 0)
        image_safe = int(row[3] or 0)
        total_month = int(row[4] or 0)

        return {
            "bars": {
                "url_suspicious": url_suspicious,
                "url_safe": url_safe,
                "image_fake": image_fake,
                "image_safe": image_safe,
            },
            "totals": {
                "total_month": total_month,
                "urls_month": url_suspicious + url_safe,
                "images_month": image_fake + image_safe,
            },
        }