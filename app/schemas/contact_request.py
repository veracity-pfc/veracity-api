from __future__ import annotations
from datetime import datetime
from typing import Optional, List, Union, Literal
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from app.domain.enums import ContactCategory, ContactStatus

class ContactMessageIn(BaseModel):
    email: EmailStr = Field(max_length=60)
    subject: str = Field(min_length=3, max_length=100)
    message: str = Field(min_length=10, max_length=4000)
    category: Union[ContactCategory, Literal['token_request']]

class ContactRequestRead(BaseModel):
    id: UUID
    email: EmailStr
    category: ContactCategory
    subject: str
    message: str
    status: ContactStatus
    created_at: datetime
    admin_reply: Optional[str] = None
    replied_at: Optional[datetime] = None
    replied_by_admin_id: Optional[UUID] = None

    model_config = ConfigDict(from_attributes=True)

class ContactRequestReplyBody(BaseModel):
    reply_message: str = Field(min_length=5, max_length=4000)

class ContactOkOut(BaseModel):
    ok: bool = True
    detail: str = "Mensagem enviada com sucesso."

class ContactRequestPageOut(BaseModel):
    items: List[ContactRequestRead]
    page: int
    page_size: int
    total: int
    total_pages: int

class UnifiedRequestListItem(BaseModel):
    id: UUID
    email: EmailStr
    seq_id: int
    category: str
    subject: str
    message: str
    status: str
    created_at: datetime
    admin_reply: Optional[str] = None
    replied_at: Optional[datetime] = None

class UnifiedRequestPageOut(BaseModel):
    items: List[UnifiedRequestListItem]
    page: int
    page_size: int
    total: int
    total_pages: int

class UnifiedRequestDetail(BaseModel):
    id: UUID
    seq_id: int
    email: EmailStr
    category: str         
    subject: str
    message: str
    status: str
    created_at: datetime
    
    admin_reply: Optional[str] = None
    replied_at: Optional[datetime] = None
    
    rejection_reason: Optional[str] = None
    token_prefix: Optional[str] = None
    
    model_config = ConfigDict(from_attributes=True)