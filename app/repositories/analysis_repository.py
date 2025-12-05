from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple

from sqlalchemy import and_, func, select
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
                Analysis.api_token_id,
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
        start_dt = datetime(year, month, 1)
        if month == 12:
            end_dt = datetime(year + 1, 1, 1)
        else:
            end_dt = datetime(year, month + 1, 1)

        stmt = (
            select(
                func.count()
                .filter(
                    and_(
                        Analysis.analysis_type == AnalysisType.url,
                        Analysis.label == RiskLabel.suspicious,
                    )
                )
                .label("url_suspicious"),
                func.count()
                .filter(
                    and_(
                        Analysis.analysis_type == AnalysisType.url,
                        Analysis.label == RiskLabel.malicious,
                    )
                )
                .label("url_malicious"),
                func.count()
                .filter(
                    and_(
                        Analysis.analysis_type == AnalysisType.url,
                        Analysis.label == RiskLabel.safe,
                    )
                )
                .label("url_safe"),
                func.count()
                .filter(
                    and_(
                        Analysis.analysis_type == AnalysisType.image,
                        Analysis.label == RiskLabel.fake,
                    )
                )
                .label("image_fake"),
                func.count()
                .filter(
                    and_(
                        Analysis.analysis_type == AnalysisType.image,
                        Analysis.label == RiskLabel.safe,
                    )
                )
                .label("image_safe"),
                func.count().label("total_month"),
            )
            .where(
                Analysis.created_at >= start_dt,
                Analysis.created_at < end_dt,
            )
        )

        res = await self.session.execute(stmt)
        row = res.first() or (0, 0, 0, 0, 0, 0)

        url_suspicious = int(row[0] or 0)
        url_malicious = int(row[1] or 0)
        url_safe = int(row[2] or 0)
        image_fake = int(row[3] or 0)
        image_safe = int(row[4] or 0)
        total_month = int(row[5] or 0)

        return {
            "bars": {
                "url_malicious": url_malicious,
                "url_suspicious": url_suspicious,
                "url_safe": url_safe,
                "image_fake": image_fake,
                "image_safe": image_safe,
            },
            "totals": {
                "total_month": total_month,
                "urls_month": url_malicious + url_suspicious + url_safe,
                "images_month": image_fake + image_safe,
            },
        }
