from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..deps import get_current_user, get_db
from ..schemas import UserOut
from ..models import Analysis

router = APIRouter(prefix="/user", tags=["user"])

@router.get("/profile", response_model=UserOut)
async def profile(user=Depends(get_current_user)):
    return {
        "id": str(user.id),
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "status": user.status.value,
        "created_at": user.created_at,
    }

@router.get("/history")
async def history(user=Depends(get_current_user), session: AsyncSession = Depends(get_db)):
    q = await session.execute(select(Analysis).where(Analysis.user_id == user.id).order_by(Analysis.created_at.desc()).limit(50))
    rows = q.scalars().all()
    return [
        {"id": str(a.id), "type": a.analysis_type.value, "label": a.label.value, "created_at": a.created_at}
        for a in rows
    ]
