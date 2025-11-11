import re
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, Body, HTTPException, Query
from sqlalchemy import select, update, delete, func, and_, or_, desc
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Literal, Optional, Dict, Any, List, Tuple
from secrets import randbelow
from app.api.deps import get_current_user
from app.core.database import get_session as get_db
from app.core.config import settings
from app.domain.user_model import User
from app.domain.enums import UserStatus
from app.domain.url_analysis_model import UrlAnalysis
from app.domain.image_analysis_model import ImageAnalysis
from app.domain.password_reset import PasswordReset
from app.domain.audit_model import AuditLog
from app.domain.analysis_model import Analysis
from app.domain.enums import AnalysisType

router = APIRouter(prefix="/user", tags=["user"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def _quotas():
  return {"urls": settings.user_url_limit, "images": settings.user_image_limit}

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
      raise HTTPException(status_code=400, detail="Parâmetro de data inválido.")

@router.get("/profile")
async def get_profile(
  user: User = Depends(get_current_user),
  session: AsyncSession = Depends(get_db),
):
  now = datetime.now(timezone.utc)
  start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
  end = start + timedelta(days=1)

  q_today = await session.execute(
    select(Analysis.analysis_type, func.count(Analysis.id))
    .where(Analysis.user_id == user.id, Analysis.created_at >= start, Analysis.created_at < end)
    .group_by(Analysis.analysis_type)
  )
  today_map = {r[0]: r[1] for r in q_today.all()}

  q_all = await session.execute(
    select(Analysis.analysis_type, func.count(Analysis.id))
    .where(Analysis.user_id == user.id)
    .group_by(Analysis.analysis_type)
  )
  total_map = {r[0]: r[1] for r in q_all.all()}

  quotas = _quotas()
  remaining = {
    "urls": max(int(quotas["urls"]) - int(today_map.get(AnalysisType.url, 0)), 0),
    "images": max(int(quotas["images"]) - int(today_map.get(AnalysisType.image, 0)), 0),
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
      raise HTTPException(status_code=400, detail="Data final não pode ser anterior à data inicial.")
    end = end_day + timedelta(days=1)

  stmt = select(
    Analysis.id,
    Analysis.created_at,
    Analysis.analysis_type,
    Analysis.label,
  ).where(Analysis.user_id == user.id)

  if analysis_type:
    stmt = stmt.where(Analysis.analysis_type == analysis_type)  # type: ignore
  if status:
    stmt = stmt.where(func.lower(Analysis.label) == func.lower(status))
  if q:
    like = f"%{q}%"
    stmt = stmt.where(func.lower(Analysis.label).like(func.lower(like)))
  if start and end:
    stmt = stmt.where(Analysis.created_at >= start, Analysis.created_at < end)

  total = await session.execute(stmt.with_only_columns(func.count()).order_by(None))
  total_count = int(total.scalar_one() or 0)
  pages = max((total_count + page_size - 1) // page_size, 1)

  rows = await session.execute(
    stmt.order_by(desc(Analysis.created_at)).limit(page_size).offset((page - 1) * page_size)
  )
  base: List[Tuple[Any, ...]] = rows.all()

  ids: List[str] = [str(r[0]) for r in base]
  type_map: Dict[str, str] = {str(r[0]): r[2] for r in base}

  url_sources: Dict[str, str] = {}
  if ids:
    q_urls = await session.execute(
      select(UrlAnalysis.analysis_id, UrlAnalysis.url).where(UrlAnalysis.analysis_id.in_(ids))
    )
    for aid, url in q_urls.all():
      if url:
        url_sources[str(aid)] = url

  image_sources: Dict[str, str] = {}
  if ids:
    q_imgs = await session.execute(
      select(
        ImageAnalysis.analysis_id,
        ImageAnalysis.meta["filename"].astext
      ).where(ImageAnalysis.analysis_id.in_(ids))
    )
    for aid, name in q_imgs.all():
      if name:
        image_sources[str(aid)] = name

  items = []
  for r in base:
    aid = str(r[0])
    atype = type_map[aid]
    if atype == AnalysisType.url:
      source = url_sources.get(aid)
    elif atype == AnalysisType.image:
      source = image_sources.get(aid)
    else:
      source = None
    items.append(
      {
        "id": aid,
        "created_at": r[1].astimezone(timezone.utc).isoformat(),
        "analysis_type": atype,
        "source": source,
        "label": r[3],
      }
    )

  return {"items": items, "total_pages": pages}
