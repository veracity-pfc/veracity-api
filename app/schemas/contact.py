from pydantic import BaseModel, field_validator, Field

ALLOWED_SUBJECTS = {"Dúvida", "Sugestão", "Solicitação", "Reclamação"}

class ContactMessageIn(BaseModel):
    email: str = ""
    subject: str = ""
    message: str = ""

    @field_validator("subject")
    @classmethod
    def valid_subject(cls, v: str):
        if v not in ALLOWED_SUBJECTS:
            raise ValueError("Assunto inválido.")
        return v

class ContactOkOut(BaseModel):
    ok: bool = True
