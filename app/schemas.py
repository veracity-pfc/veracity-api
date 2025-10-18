from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, EmailStr, field_validator
from pydantic.types import StringConstraints

from .models import UserRole, RiskLabel

NameStr = Annotated[str, StringConstraints(min_length=1, max_length=30, strip_whitespace=True)]
EmailLimited = Annotated[str, StringConstraints(max_length=30, strip_whitespace=True)]
PasswordStr = Annotated[str, StringConstraints(min_length=8, max_length=30)]
SixDigitCode = Annotated[str, StringConstraints(min_length=6, max_length=6, pattern=r"^\d{6}$")]

class RegisterIn(BaseModel):
    name: NameStr
    email: EmailLimited
    password: PasswordStr
    confirm_password: PasswordStr

class VerifyEmailIn(BaseModel):
    email: EmailLimited
    code: SixDigitCode

class OkOut(BaseModel):
    ok: Literal[True] = True

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
