from pydantic import BaseModel, EmailStr, field_validator
from datetime import datetime
from .models import UserRole, RiskLabel

class LogIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole

class UserOut(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: UserRole
    status: str
    created_at: datetime

class LinkAnalysisIn(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str):
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("URL deve começar com http(s)://")
        return v

class LinkAnalysisOut(BaseModel):
    id: str
    url: str
    label: RiskLabel
    summary: str
