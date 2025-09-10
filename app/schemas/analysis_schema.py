from pydantic import BaseModel, field_validator
from app.utils.validators import is_valid_url

class LinkAnalysisRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        ok, error_msg = is_valid_url(value)
        if not ok:
            raise ValueError(error_msg)
        return value

class LinkAnalysisResponse(BaseModel):
    classification: str
    explanation: str
    sources: list[str]
    recommendations: list[str]
