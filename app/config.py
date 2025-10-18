from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import Optional

class Settings(BaseSettings):
    database_url: str = Field(..., alias="DATABASE_URL")
    jwt_secret: str = Field(..., alias="JWT_SECRET")
    jwt_alg: str = Field(default="HS256", alias="JWT_ALG")
    resend_api_key: Optional[str] = Field(default=None, alias="RESEND_API_KEY")
    resend_from: Optional[str] = Field(default=None, alias="RESEND_FROM")
    access_token_expire_min: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MIN")

    salt_ip_hash: str = Field(..., alias="SALT_IP_HASH")

    gsb_api_key: str = Field(..., alias="GSB_API_KEY")
    ipqs_key: str = Field(..., alias="IPQS_API_KEY")

    anon_link_limit: int = 2
    anon_image_limit: int = 1
    user_link_limit: int = 5
    user_image_limit: int = 3

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
