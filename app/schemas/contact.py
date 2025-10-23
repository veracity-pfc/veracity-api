from pydantic import BaseModel, Field, EmailStr, field_validator

ALLOWED_SUBJECTS = {"Dúvida", "Sugestão", "Solicitação", "Reclamação"}

class ContactMessageIn(BaseModel):
    email: EmailStr
    subject: str = Field(min_length=3, max_length=20)
    message: str = Field(min_length=3, max_length=4000)

    @field_validator("subject")
    @classmethod
    def valid_subject(cls, v: str):
        if v not in ALLOWED_SUBJECTS:
            raise ValueError("Assunto inválido.")
        return v

class ContactOkOut(BaseModel):
    ok: bool = True
