from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.domain.enums import ApiTokenRequestStatus


class ApiTokenRequestBase(BaseModel):
    user_id: UUID
    email: EmailStr = Field(max_length=60)
    message: str = Field(max_length=4000)
    status: ApiTokenRequestStatus


class ApiTokenRequestCreate(BaseModel):
    email: EmailStr = Field(max_length=60)
    message: str = Field(max_length=4000)


class ApiTokenRequestUpdateStatus(BaseModel):
    status: ApiTokenRequestStatus
    rejection_reason: Optional[str] = None
    related_token_id: Optional[UUID] = None


class ApiTokenRequestRead(ApiTokenRequestBase):
    id: UUID
    created_at: datetime
    decided_at: Optional[datetime] = None
    decided_by_admin_id: Optional[UUID] = None
    rejection_reason: Optional[str] = None
    related_token_id: Optional[UUID] = None

    model_config = ConfigDict(from_attributes=True)
