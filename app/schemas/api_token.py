from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.enums import ApiTokenStatus


class ApiTokenBase(BaseModel):
    user_id: UUID
    token_prefix: str = Field(max_length=16)
    status: ApiTokenStatus
    created_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_reason: Optional[str] = None
    revoked_by_admin_id: Optional[UUID] = None


class ApiTokenCreate(BaseModel):
    user_id: UUID
    expires_at: datetime


class ApiTokenRead(ApiTokenBase):
    id: UUID

    model_config = ConfigDict(from_attributes=True)


class ApiTokenWithPlainValue(ApiTokenRead):
    token: str
