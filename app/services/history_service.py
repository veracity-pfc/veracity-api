from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import RiskLabel
from app.repositories.analysis_repo import AnalysisRepository
from app.schemas.history import HistoryDetailOut, HistoryItemOut, HistoryPageOut
from app.domain.ai_model import AIResponse
from app.domain.image_analysis_model import ImageAnalysis


def normalize_date_range(
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
        self.session = session
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
        start, end = normalize_date_range(date_from, date_to)

        total, rows = await self.repo.paginated_for_user(
            user_id=user_id,
            page=page,
            page_size=page_size,
            q=q,
            date_from=start,
            date_to=end,
            status=status,
            analysis_type=analysis_type,
            exclude_errors=True,
        )

        items: list[HistoryItemOut] = []
        for r in rows:
            analysis_id = str(r[0])
            created_at = r[1]
            a_type = r[2]
            label = r[3]
            status_val = r[4].value if hasattr(r[4], "value") else str(r[4])
            source_url = r[5]

            if a_type == "image":
                img = await self.session.get(ImageAnalysis, analysis_id)
                filename = img.meta.get("filename") if img else "—"
                source = filename
            else:
                source = source_url or "—"

            items.append(
                HistoryItemOut(
                    id=analysis_id,
                    created_at=created_at,
                    analysis_type=a_type,
                    label=label,
                    status=status_val,
                    source=source,
                )
            )

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
            exclude_errors=True,
        )
        if not row:
            return None

        ai_resp = None
        if row.ai_response_id:
            ai_resp = await self.session.get(AIResponse, row.ai_response_id)

        summary, recs, raw = self._parse_ai(ai_resp.content if ai_resp else None)

        if row.analysis_type == "image":
            img = await self.session.get(ImageAnalysis, analysis_id)
            source = img.meta.get("filename") if img else "—"
        else:
            source = row.source_url or "—"

        return HistoryDetailOut(
            id=str(row.id),
            created_at=row.created_at,
            analysis_type=row.analysis_type,
            label=row.label,
            status=row.status.value if hasattr(row.status, "value") else str(row.status),
            source=source,
            ai_summary=summary,
            ai_recommendations=recs,
            ai_raw=raw,
        )
