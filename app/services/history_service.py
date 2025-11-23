from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.enums import RiskLabel
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.history import HistoryDetailOut, HistoryItemOut, HistoryPageOut
from app.domain.ai_model import AIResponse


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

        if not q:
            total, rows = await self.repo.paginated_for_user(
                user_id=user_id,
                page=page,
                page_size=page_size,
                q=None,
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

                source = source_url or "—"
                if a_type == "image":
                    img = await self.repo.get_image_analysis_by_analysis_id(analysis_id)
                    filename = img.meta.get("filename") if img and img.meta else "—"
                    source = filename

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

        q_normalized = q.strip().lower()
        internal_page_size = 50 if page_size <= 0 else page_size

        total, rows = await self.repo.paginated_for_user(
            user_id=user_id,
            page=1,
            page_size=internal_page_size,
            q=None,
            date_from=start,
            date_to=end,
            status=status,
            analysis_type=analysis_type,
            exclude_errors=True,
        )

        all_rows = list(rows)
        total_db_pages = ceil(total / internal_page_size) if internal_page_size else 1

        current_page = 1
        while current_page < total_db_pages:
            current_page += 1
            _, more_rows = await self.repo.paginated_for_user(
                user_id=user_id,
                page=current_page,
                page_size=internal_page_size,
                q=None,
                date_from=start,
                date_to=end,
                status=status,
                analysis_type=analysis_type,
                exclude_errors=True,
            )
            all_rows.extend(more_rows)

        filtered_raw = []
        for r in all_rows:
            analysis_id = str(r[0])
            created_at = r[1]
            a_type = r[2]
            label = r[3]
            status_enum = r[4]
            source_url = r[5]

            status_val = status_enum.value if hasattr(status_enum, "value") else str(status_enum)
            source = source_url or "—"
            filename = None

            if a_type == "image":
                img = await self.repo.get_image_analysis_by_analysis_id(analysis_id)
                if img and img.meta:
                    filename = img.meta.get("filename")
                if filename:
                    source_for_search = filename
                else:
                    source_for_search = source
            else:
                source_for_search = source

            if source_for_search and q_normalized in source_for_search.lower():
                filtered_raw.append(
                    (analysis_id, created_at, a_type, label, status_val, filename, source)
                )

        total_filtered = len(filtered_raw)
        total_pages = ceil(total_filtered / page_size) if page_size else 1

        start_index = (page - 1) * page_size
        end_index = start_index + page_size
        page_slice = filtered_raw[start_index:end_index]

        items: list[HistoryItemOut] = []
        for analysis_id, created_at, a_type, label, status_val, filename, source in page_slice:
            display_source = filename or source or "—"
            items.append(
                HistoryItemOut(
                    id=analysis_id,
                    created_at=created_at,
                    analysis_type=a_type,
                    label=label,
                    status=status_val,
                    source=display_source,
                )
            )

        return HistoryPageOut(
            items=items,
            page=page,
            page_size=page_size,
            total=total_filtered,
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
            ai_resp = await self.repo.get_ai_response(row.ai_response_id)

        summary, recs, raw = self._parse_ai(ai_resp.content if ai_resp else None)

        source = row.source_url or "—"
        if row.analysis_type == "image":
            img = await self.repo.get_image_analysis_by_analysis_id(analysis_id)
            source = img.meta.get("filename") if img and img.meta else "—"

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
