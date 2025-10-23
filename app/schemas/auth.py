import re
from pydantic import BaseModel, Field
from pydantic import EmailStr
from app.domain.user_model import UserRole

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

class RegisterIn(BaseModel):
    name: str = Field(min_length=1, max_length=30)
    email: str = Field(min_length=3, max_length=60)
    password: str = Field(min_length=8, max_length=30)
    confirm_password: str = Field(min_length=8, max_length=30)
    accepted_terms: bool = Field(..., description="Usuário aceitou Termos de Uso/Política de Privacidade")

    @classmethod
    def validate_email(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if len(v) > 60:
            raise ValueError("Máximo de 60 caracteres.")
        if not EMAIL_RE.match(v):
            raise ValueError("O e-mail digitado não é válido. Tente novamente.")
        return v

    @classmethod
    def field_validators(cls):
        return {
            "email": cls.validate_email,
            "confirm_password": cls.validate_confirm_password,
        }

    @staticmethod
    def validate_confirm_password(v: str, info):
        password = info.data.get("password")
        if password and v != password:
            raise ValueError("A senha deve ser igual nos dois campos")
        return v

class VerifyEmailIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    code: str = Field(min_length=6, max_length=6)

class LogIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=30)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: UserRole
    
class ForgotPasswordIn(BaseModel):
    email: str = Field(min_length=3, max_length=255)

class ResetPasswordIn(BaseModel):
    password: str = Field(min_length=8, max_length=30)
    confirm_password: str = Field(min_length=8, max_length=30)

