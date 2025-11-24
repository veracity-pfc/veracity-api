from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.domain.analysis_model import Analysis
from app.domain.enums import AnalysisType, AnalysisStatus


async def _count_today(
    session: AsyncSession,
    analysis_type: AnalysisType,
    *,
    user_id: Optional[str],
    actor_hash: Optional[str],
    api_token_id: Optional[str],
) -> int:
    tz = ZoneInfo("America/Sao_Paulo")
    now = datetime.now(tz)
    start_local = datetime(now.year, now.month, now.day, tzinfo=tz)
    start_utc = start_local.astimezone(timezone.utc)

    stmt = select(func.count(Analysis.id)).where(
        Analysis.analysis_type == analysis_type,
        Analysis.created_at >= start_utc,
        Analysis.status != AnalysisStatus.error,
    )

    if api_token_id:
        stmt = stmt.where(Analysis.api_token_id == api_token_id)
    elif user_id:
        stmt = stmt.where(Analysis.user_id == user_id, Analysis.api_token_id.is_(None))
    else:
        stmt = stmt.where(
            Analysis.user_id.is_(None),
            Analysis.actor_ip_hash == actor_hash,
            Analysis.api_token_id.is_(None),
        )

    result = await session.execute(stmt)
    return int(result.scalar_one() or 0)


async def check_daily_limit(
    session: AsyncSession,
    analysis_type: AnalysisType,
    *,
    user_id: Optional[str],
    actor_hash: Optional[str],
    api_token_id: Optional[str] = None,
) -> Tuple[int, int, str]:
    if getattr(settings, "disable_limits", False):
        return 0, 0, "disabled"

    used = await _count_today(
        session,
        analysis_type,
        user_id=user_id,
        actor_hash=actor_hash,
        api_token_id=api_token_id,
    )

    if analysis_type == AnalysisType.image:
        limit_user = settings.user_image_limit
        limit_anon = settings.anon_image_limit
        limit_token = settings.user_image_limit
        msg = "Limite diário de análises de imagem atingido."
    else:
        limit_user = settings.user_url_limit
        limit_anon = settings.anon_url_limit
        limit_token = settings.user_url_limit
        msg = "Limite diário de análises de URLs atingido."

    if api_token_id:
        limit = limit_token
        scope = "token"
    elif user_id:
        limit = limit_user
        scope = "user"
    else:
        limit = limit_anon
        scope = "anon"

    if used >= limit:
        raise ValueError(msg)

    return used, limit, scope
