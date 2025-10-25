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
    hf_model: str = Field(default="openai/gpt-oss-20b", alias="HF_MODEL")
    hf_base_url: str = Field(default="https://router.huggingface.co/v1", alias="HF_BASE_URL")

    anon_url_limit: int = 2
    anon_image_limit: int = 1
    user_url_limit: int = 5
    user_image_limit: int = 3

    http_timeout: float = 6.0
    
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
