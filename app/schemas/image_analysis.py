from __future__ import annotations
from pydantic import BaseModel, field_validator
from app.domain.enums import RiskLabel

ALLOWED = {"image/png", "image/jpeg", "image/jpg"}

class ImageIn(BaseModel):
    filename: str
    content_type: str
    size_bytes: int

    @field_validator("content_type")
    @classmethod
    def check_mime(cls, v: str):
        if v not in ALLOWED:
            raise ValueError("Formato inválido. Aceitos: png, jpeg ou jpg.")
        return v

    @field_validator("size_bytes")
    @classmethod
    def check_size(cls, v: int):
        if v > 1_000_000:
            raise ValueError("A imagem não pode ultrapassar 1MB.")
        if v <= 0:
            raise ValueError("Arquivo vazio ou inválido.")
        return v

class ImageAnalysisOut(BaseModel):
    analysis_id: str
    label: RiskLabel
    explanation: str
    recommendations: list[str]
