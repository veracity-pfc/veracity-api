from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import RiskLabel
from app.repositories.analysis_repo import AnalysisRepository
from app.schemas.history import HistoryDetailOut, HistoryItemOut, HistoryPageOut


def _normalize_range(
    date_from: Optional[datetime],
    date_to: Optional[datetime],
) -> tuple[Optional[datetime], Optional[datetime]]:
    start = None
    end = None

    if date_from:
        d = date_from
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        start = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)

    if date_to:
        d = date_to
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        base = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
        end = base + timedelta(days=1)

    return start, end


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
        date_from: Optional[datetime],
        date_to: Optional[datetime],
        status: Optional[RiskLabel],
        analysis_type,
    ) -> HistoryPageOut:
        start, end = _normalize_range(date_from, date_to)

        total, rows = await self.repo.paginated_for_user(
            user_id=user_id,
            page=page,
            page_size=page_size,
            q=q,
            date_from=start,
            date_to=end,
            status=status,
            analysis_type=analysis_type,
        )

        items = [
            HistoryItemOut(
                id=str(r[0]),
                created_at=r[1],
                analysis_type=r[2],
                label=r[3],
                status=r[4].value if hasattr(r[4], "value") else str(r[4]),
                source=r[5],
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
        except Exception:
            return None, [], content

        summary = data.get("explanation") or data.get("summary") or None
        recs = data.get("recommendations") or data.get("recomendacoes") or []
        if isinstance(recs, str):
            recs = [recs]
        return summary, recs, content

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
