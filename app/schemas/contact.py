from pydantic import BaseModel

ALLOWED_SUBJECTS = {
    "Dúvida",
    "Sugestão",
    "Solicitação de token de API",
    "Reclamação",
}

class ContactMessageIn(BaseModel):
    email: str = ""
    subject: str = ""
    message: str = ""

class ContactOkOut(BaseModel):
    ok: bool = True
