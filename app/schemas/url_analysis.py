from typing import List, Optional
from pydantic import BaseModel, field_validator
from urllib.parse import urlsplit
import re
from app.domain.enums import RiskLabel
from app.schemas.common import QuotaOut

_TLD_RE = re.compile(r"^[A-Za-z]{2,24}$")

def has_valid_tld(host: str) -> bool:
    if "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    return bool(_TLD_RE.match(tld))

class UrlAnalysisIn(BaseModel):
    url: str 

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str):
        if len(v) > 120:
            raise ValueError("A URL não pode exceder 120 caracteres")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("A URL deve começar com http:// ou https://")
        parts = urlsplit(v)
        if not parts.netloc:
            raise ValueError("A URL não pode estar vazia")
        host = parts.hostname or ""
        if not has_valid_tld(host):
            raise ValueError("A URL deve possuir um TLD válido")
        return v

class UrlAnalysisOut(BaseModel):
    analysis_id: str
    url: str
    explanation: str
    recommendations: List[str]
    label: RiskLabel
    quota: Optional[QuotaOut] = None
