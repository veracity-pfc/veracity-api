from __future__ import annotations
from typing import Optional, Sequence
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, cast, String
from app.domain.analysis_model import Analysis
from app.domain.image_analysis_model import ImageAnalysis
from app.domain.ai_model import AIResponse
from app.domain.enums import RiskLabel, AnalysisType


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
        date_from: Optional[str],
        date_to: Optional[str],
        status: Optional[RiskLabel],
        analysis_type: Optional[AnalysisType],
    ) -> tuple[int, Sequence[tuple]]:
        filters = [Analysis.user_id == user_id]

        if status:
            filters.append(Analysis.label == status)
        if analysis_type:
            filters.append(Analysis.analysis_type == analysis_type)
        if date_from:
            filters.append(Analysis.created_at >= date_from)
        if date_to:
            filters.append(Analysis.created_at < date_to)
        if q:
            like = f"%{q.lower()}%"
            filters.append(
                or_(
                    func.lower(Analysis.source_url).like(like),
                    func.lower(cast(ImageAnalysis.meta["filename"], String)).like(like),
                    func.lower(Analysis.label.cast(String)).like(like),
                )
            )

        image_filename = cast(ImageAnalysis.meta["filename"], String)
        source_expr = func.coalesce(image_filename, Analysis.source_url)

        base_q = (
            select(
                Analysis.id,
                Analysis.created_at,
                Analysis.analysis_type,
                Analysis.label,
                Analysis.status,
                source_expr.label("source"),
            )
            .join(ImageAnalysis, ImageAnalysis.analysis_id == Analysis.id, isouter=True)
            .where(and_(*filters))
            .order_by(Analysis.created_at.desc(), Analysis.id.desc())
        )

        total_q = select(func.count()).select_from(base_q.subquery())
        total = (await self.session.execute(total_q)).scalar_one()

        offset = (page - 1) * page_size
        rows = (await self.session.execute(base_q.limit(page_size).offset(offset))).all()
        return total, rows

    async def find_one_for_user(self, *, analysis_id: str, user_id: str):
        image_filename = cast(ImageAnalysis.meta["filename"], String)
        source_expr = func.coalesce(image_filename, Analysis.source_url)

        q = (
            select(
                Analysis.id,
                Analysis.created_at,
                Analysis.analysis_type,
                Analysis.label,
                Analysis.status,
                source_expr.label("source"),
                AIResponse.content.label("ai_content"),
            )
            .join(ImageAnalysis, ImageAnalysis.analysis_id == Analysis.id, isouter=True)
            .join(AIResponse, AIResponse.analysis_id == Analysis.id, isouter=True)
            .where(Analysis.id == analysis_id, Analysis.user_id == user_id)
        )
        res = (await self.session.execute(q)).first()
        return res
