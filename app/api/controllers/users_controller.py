from __future__ import annotations

from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Dict, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_session as get_db
from app.domain.enums import AnalysisType, RiskLabel
from app.domain.user_model import User
from app.repositories.analysis_repo import AnalysisRepository

router = APIRouter(prefix="/user", tags=["user"])


def _quotas() -> Dict[str, int]:
    return {
        "urls": settings.user_url_limit,
        "images": settings.user_image_limit,
    }


def _parse_date_only(s: str) -> datetime:
    s = s.strip()
    try:
        d = datetime.fromisoformat(s.replace("Z", ""))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    except Exception:
        try:
            d2 = datetime.strptime(s[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return d2
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Parâmetro de data inválido.",
            )


@router.get("/profile")
async def get_profile(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)

    repo = AnalysisRepository(session)
    today_map, total_map = await repo.user_counts(
        user_id=str(user.id),
        day_start=start,
        day_end=end,
    )

    quotas = _quotas()
    remaining = {
        "urls": max(int(quotas["urls"]) - int(today_map.get(AnalysisType.url, 0)), 0),
        "images": max(
            int(quotas["images"]) - int(today_map.get(AnalysisType.image, 0)),
            0,
        ),
    }

    return {
        "id": str(user.id),
        "name": user.name,
        "email": user.email,
        "stats": {
            "remaining": remaining,
            "performed": {
                "urls": int(total_map.get(AnalysisType.url, 0)),
                "images": int(total_map.get(AnalysisType.image, 0)),
            },
        },
    }


@router.get("/history")
async def user_history(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(6, ge=1, le=100),
    q: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    analysis_type: Optional[Literal["url", "image"]] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
):
    start = None
    end = None
    if date_from and not date_to:
        start = _parse_date_only(date_from)
        end = start + timedelta(days=1)
    elif date_to and not date_from:
        start = _parse_date_only(date_to)
        end = start + timedelta(days=1)
    elif date_from and date_to:
        start = _parse_date_only(date_from)
        end_day = _parse_date_only(date_to)
        if end_day < start:
            raise HTTPException(
                status_code=400,
                detail="Data final não pode ser anterior à data inicial.",
            )
        end = end_day + timedelta(days=1)

    status_enum = None
    if status:
        try:
            status_enum = RiskLabel(status)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Parâmetro de status inválido.",
            )

    analysis_enum = AnalysisType(analysis_type) if analysis_type else None

    repo = AnalysisRepository(session)
    total, rows = await repo.paginated_for_user(
        user_id=str(user.id),
        page=page,
        page_size=page_size,
        q=q,
        date_from=start.isoformat() if start else None,
        date_to=end.isoformat() if end else None,
        status=status_enum,
        analysis_type=analysis_enum,
    )

    total_pages = max(ceil(total / page_size), 1) if page_size else 1

    items = []
    for row in rows:
        analysis_id = str(row[0])
        created_at = row[1]
        analysis_type_value = row[2]
        label = row[3]
        source = row[5]

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        items.append(
            {
                "id": analysis_id,
                "created_at": created_at.astimezone(timezone.utc).isoformat(),
                "analysis_type": analysis_type_value,
                "source": source,
                "label": label,
            }
        )

    return {"items": items, "total_pages": total_pages}
