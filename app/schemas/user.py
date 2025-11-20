from datetime import datetime
from pydantic import BaseModel, EmailStr
from app.domain.user_model import UserRole

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: UserRole
    status: str
    created_at: datetime

class ReactivateAccountPayload(BaseModel):
  email: str

class ReactivateConfirmPayload(BaseModel):
  email: str
  code: str