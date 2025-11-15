from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.database import get_session as get_db
from app.domain.enums import AnalysisType
from app.domain.user_model import User
from app.repositories.analysis_repo import AnalysisRepository

router = APIRouter(prefix="/user", tags=["user"])


def _quotas() -> Dict[str, int]:
    return {
        "urls": settings.user_url_limit,
        "images": settings.user_image_limit,
    }

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
