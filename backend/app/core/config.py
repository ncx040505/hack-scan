"""Application configuration"""
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""
    
    # API Settings
    app_name: str = "Shelling"
    debug: bool = False
    api_prefix: str = "/api/v1"
    
    # Database
    postgres_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/vulnscanner"
    mongodb_url: str = "mongodb://localhost:27017"
    mongodb_db: str = "vulnscanner_raw"
    redis_url: str = "redis://localhost:6379/0"
    
    # LLM Configuration
    openai_api_key: str = ""
    openai_base_url: str | None = None  # 支持自定义 API 端点
    llm_model: str = "gpt-4o"
    llm_temperature: float = 0.1
    
    # Scanning Configuration
    max_concurrent_scans: int = 5
    scan_timeout: int = 3600  # 1 hour
    rate_limit_per_target: int = 10  # requests per second
    
    # Security
    secret_key: str = "change-me-in-production"
    allowed_origins: list[str] = ["http://localhost:3000", "http://0.0.0.0:3000", "*"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
