from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./security_system.db"
    redis_url: str = "redis://localhost:6379/0"
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480
    osv_api_url: str = "https://api.osv.dev/v1"
    osv_batch_size: int = 100
    ci_api_token: str = "change-me-in-production"

    class Config:
        env_prefix = "SEC_"
        env_file = ".env"


settings = Settings()
