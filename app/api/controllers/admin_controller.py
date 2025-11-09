from __future__ import annotations

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, bindparam

from app.api.deps import require_admin
from app.core.database import get_session as get_db

router = APIRouter(prefix="/administration", tags=["admin"])

def _validate_year_month(year: int | None, month: int | None) -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    y = year or now.year
    m = month or now.month
    if not (2000 <= y <= 2100):
        raise HTTPException(status_code=400, detail="Parâmetro 'year' inválido")
    if not (1 <= m <= 12):
        raise HTTPException(status_code=400, detail="Parâmetro 'month' inválido")
    return y, m

@router.get("/metrics/month")
async def metrics_month(
    _: str = Depends(require_admin),
    session: AsyncSession = Depends(get_db),
    year: int | None = Query(default=None, description="Ano (YYYY)"),
    month: int | None = Query(default=None, description="Mês (1-12)"),
):
    y, m = _validate_year_month(year, month)

    sql = text("""
        WITH month_range AS (
            SELECT
                make_timestamptz(:y, :m, 1, 0, 0, 0) AS start_dt,
                (make_timestamptz(:y, :m, 1, 0, 0, 0) + INTERVAL '1 month') AS end_dt
        )
        SELECT
            COUNT(*) FILTER (WHERE a.analysis_type = 'url'
                             AND a.label = 'suspicious'
                             AND a.created_at >= mr.start_dt
                             AND a.created_at <  mr.end_dt) AS url_suspicious,
            COUNT(*) FILTER (WHERE a.analysis_type = 'url'
                             AND a.label = 'safe'
                             AND a.created_at >= mr.start_dt
                             AND a.created_at <  mr.end_dt) AS url_safe,
            COUNT(*) FILTER (WHERE a.analysis_type = 'image'
                             AND a.label = 'fake'
                             AND a.created_at >= mr.start_dt
                             AND a.created_at <  mr.end_dt) AS image_fake,
            COUNT(*) FILTER (WHERE a.analysis_type = 'image'
                             AND a.label = 'safe'
                             AND a.created_at >= mr.start_dt
                             AND a.created_at <  mr.end_dt) AS image_safe,
            COUNT(*) FILTER (WHERE a.created_at >= mr.start_dt
                             AND a.created_at <  mr.end_dt) AS total_month
        FROM analyses a
        CROSS JOIN month_range mr
    """).bindparams(bindparam("y", y), bindparam("m", m))

    res = await session.execute(sql)
    row = res.first()
    data = {
        "year": y,
        "month": m,
        "reference": f"{y:04d}-{m:02d}",
        "bars": {
            "url_suspicious": int(row[0] or 0),
            "url_safe": int(row[1] or 0),
            "image_fake": int(row[2] or 0),
            "image_safe": int(row[3] or 0),
        },
        "totals": {
            "total_month": int(row[4] or 0),
            "urls_month": int((row[0] or 0) + (row[1] or 0)),
            "images_month": int((row[2] or 0) + (row[3] or 0)),
        },
    }
    return data
