from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    database_url: str = Field(..., alias="DATABASE_URL")
    jwt_secret: str = Field(..., alias="JWT_SECRET")
    jwt_alg: str = Field(default="HS256", alias="JWT_ALG")
    access_token_expire_seg: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_SEG")
    salt_ip_hash: str = Field(..., alias="SALT_IP_HASH")
    frontend_url: str = Field(..., alias="FRONTEND_URL")
    disable_limits: bool = Field(default=False, alias="DISABLE_LIMITS")

    resend_api_key: Optional[str] = Field(default=None, alias="RESEND_API_KEY")
    resend_from: Optional[str] = Field(default=None, alias="RESEND_FROM")

    gsb_api_key: str = Field(..., alias="GSB_API_KEY")

    hf_token: str = Field(..., alias="HF_TOKEN")
    hf_openai_model: str = Field(..., alias="HF_OPENAI_MODEL")
    hf_base_url: str = Field(..., alias="HF_BASE_URL")
    
    sight_engine_api_user: str = Field(..., alias="SIGHT_ENGINE_API_USER")
    sight_engine_api_secret: str = Field(..., alias="SIGHT_ENGINE_API_SECRET")

    anon_url_limit: int = Field(..., alias="ANON_URL_ANALYSIS_LIMIT")
    anon_image_limit: int = Field(..., alias="ANON_IMAGE_ANALYSIS_LIMIT")
    user_url_limit: int = Field(..., alias="USER_URL_ANALYSIS_LIMIT")
    user_image_limit: int = Field(..., alias="USER_IMAGE_ANALYSIS_LIMIT")

    http_timeout: float = 6.0
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
