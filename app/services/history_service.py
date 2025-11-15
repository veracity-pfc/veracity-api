from __future__ import annotations

import json
from math import ceil
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import AnalysisType, RiskLabel
from app.repositories.analysis_repo import AnalysisRepository
from app.schemas.history import HistoryDetailOut, HistoryItemOut, HistoryPageOut


class HistoryService:
    def __init__(self, session: AsyncSession):
        self.repo = AnalysisRepository(session)

    async def list_for_user(
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
    ) -> HistoryPageOut:
        total, rows = await self.repo.paginated_for_user(
            user_id=user_id,
            page=page,
            page_size=page_size,
            q=q,
            date_from=date_from,
            date_to=date_to,
            status=status,
            analysis_type=analysis_type,
        )
        items = [
            HistoryItemOut(
                id=str(r.id),
                created_at=r.created_at,
                analysis_type=r.analysis_type,
                label=r.label,
                status=r.status.value if hasattr(r.status, "value") else str(r.status),
                source=r.source,
            )
            for r in rows
        ]
        total_pages = ceil(total / page_size) if page_size else 1
        return HistoryPageOut(
            items=items,
            page=page,
            page_size=page_size,
            total=total,
            total_pages=total_pages,
        )

    @staticmethod
    def _parse_ai(content: Optional[str]) -> tuple[Optional[str], list[str], Optional[str]]:
        if not content:
            return None, [], None
        try:
            data = json.loads(content)
            summary = data.get("explanation") or data.get("summary") or None
            recs = data.get("recommendations") or data.get("recomendacoes") or []
            if isinstance(recs, str):
                recs = [recs]
            return summary, recs, content
        except Exception:
            return None, [], content

    async def detail_for_user(
        self,
        *,
        analysis_id: str,
        user_id: str,
    ) -> Optional[HistoryDetailOut]:
        row = await self.repo.find_one_for_user(
            analysis_id=analysis_id,
            user_id=user_id,
        )
        if not row:
            return None
        summary, recs, raw = self._parse_ai(row.ai_content)
        return HistoryDetailOut(
            id=str(row.id),
            created_at=row.created_at,
            analysis_type=row.analysis_type,
            label=row.label,
            status=row.status.value if hasattr(row.status, "value") else str(row.status),
            source=row.source,
            ai_summary=summary,
            ai_recommendations=recs,
            ai_raw=raw,
        )
