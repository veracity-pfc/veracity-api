from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from datetime import datetime
from app.api.deps import require_admin
from app.core.database import get_session as get_db

router = APIRouter(prefix="/administration", tags=["admin"])

@router.get("/metrics")
async def metrics(_: str = Depends(require_admin), session: AsyncSession = Depends(get_db)):
    sql = text("""
      SELECT
        COUNT(*) FILTER (WHERE date_trunc('month', created_at)=date_trunc('month', now())) AS total_month,
        COUNT(*) FILTER (WHERE analysis_type='url'  AND date_trunc('month', created_at)=date_trunc('month', now())) AS urls_month,
        COUNT(*) FILTER (WHERE analysis_type='image' AND date_trunc('month', created_at)=date_trunc('month', now())) AS images_month
      FROM analyses
    """)
    res = await session.execute(sql)
    row = res.first()
    return {
        "reference_month": datetime.utcnow().strftime("%Y-%m"),
        "total_month": row[0] or 0,
        "urls_month": row[1] or 0,
        "images_month": row[2] or 0,
    }
