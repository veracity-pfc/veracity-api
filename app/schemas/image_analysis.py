from __future__ import annotations
from typing import Optional
from pydantic import BaseModel, field_validator
from pydantic_core import PydanticCustomError  
from app.domain.enums import RiskLabel
from app.schemas.common import QuotaOut

ALLOWED = {"image/png", "image/jpeg", "image/jpg"}

class ImageIn(BaseModel):
    filename: str
    content_type: str
    size_bytes: int

    @field_validator("content_type")
    @classmethod
    def check_mime(cls, v: str):
        if v not in ALLOWED:
            raise PydanticCustomError(
                "invalid_mime",
                "Formato inválido. Aceitos: png, jpeg ou jpg."
            )
        return v

    @field_validator("size_bytes")
    @classmethod
    def check_size(cls, v: int):
        if v > 1_000_000:
            raise PydanticCustomError(
                "file_too_large",
                "A imagem deve ter no máximo 1MB."
            )
        if v <= 0:
            raise PydanticCustomError(
                "empty_file",
                "Arquivo vazio ou inválido."
            )
        return v

class ImageAnalysisOut(BaseModel):
    analysis_id: str
    label: RiskLabel
    explanation: str
    recommendations: list[str]
    quota: Optional[QuotaOut] = None
