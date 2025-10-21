from pydantic import BaseModel, field_validator
from app.domain.enums import RiskLabel

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
