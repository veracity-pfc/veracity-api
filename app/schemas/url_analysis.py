from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, field_validator
from pydantic_core import PydanticCustomError
from tld import get_tld


def has_valid_tld(host: str) -> bool:
    host = (host or "").lower().strip()
    if not host or "." not in host:
        return False
    try:
        res = get_tld("http://" + host, as_object=True, fix_protocol=True)
        tld = str(res.tld or "").strip()
        return bool(tld)
    except Exception:
        return False


class UrlAnalysisIn(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_tld(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise PydanticCustomError(
                "url_missing",
                "A URL é obrigatória",
                {"reason": "empty"},
            )
        parts = urlsplit(v)
        host = (parts.hostname or "").lower()
        if not has_valid_tld(host):
            raise PydanticCustomError(
                "url_tld",
                "A URL deve possuir um TLD válido (.com, .com.br, .gov.br...)",
                {"reason": "invalid_tld"},
            )
        return v


class UrlAnalysisOut(BaseModel):
    analysis_id: str
    url: str
    explanation: Optional[str] = None
    recommendations: List[str] = []
    label: str
    quota: Optional[dict] = None
