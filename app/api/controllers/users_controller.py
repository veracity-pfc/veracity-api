from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.api.deps import get_current_user
from app.core.database import get_session as get_db
from app.schemas.user import UserOut
from app.domain.analysis_model import Analysis

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
