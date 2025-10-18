from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, EmailStr, field_validator, Field
from pydantic.types import StringConstraints
import re

from .models import UserRole, RiskLabel

NameStr = Annotated[str, StringConstraints(min_length=1, max_length=30, strip_whitespace=True)]
EmailLimited = Annotated[str, StringConstraints(max_length=30, strip_whitespace=True)]
PasswordStr = Annotated[str, StringConstraints(min_length=8, max_length=30)]
SixDigitCode = Annotated[str, StringConstraints(min_length=6, max_length=6, pattern=r"^\d{6}$")]

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=30)
    email: str = Field(min_length=3, max_length=60)
    password: str = Field(min_length=8, max_length=30)
    confirm_password: str = Field(min_length=8, max_length=30)
    accepted_terms: bool = Field(
        ..., description="Usuário marcou o checkbox de Termos de Uso"
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if len(v) > 60:
            raise ValueError("Máximo de 60 caracteres.")
        if not EMAIL_RE.match(v):
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")
        return v

    @field_validator("confirm_password")
    @classmethod
    def confirm_matches(cls, v: str, info):
        password = info.data.get("password")
        if password and v != password:
            raise ValueError("A senha deve ser igual nos dois campos")
        return v

    @field_validator("confirm_password")
    @classmethod
    def confirm_matches(cls, v: str, info):
        password = info.data.get("password")
        if password and v != password:
            raise ValueError("A senha deve ser igual nos dois campos")
        return v

class VerifyEmailIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    code: str = Field(min_length=6, max_length=6)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if not EMAIL_RE.match(v):
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")
        return v

class OkOut(BaseModel):
    ok: Literal[True] = True

class LogIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=30)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if len(v) > 255:
            raise ValueError("Máximo de 255 caracteres.")
        if not EMAIL_RE.match(v):
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")
        return v

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
