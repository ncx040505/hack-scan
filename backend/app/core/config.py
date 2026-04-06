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
    
    # LLM Configuration (已弃用 - 请使用 Web 界面管理)
    # 以下配置仅作为后备默认值，建议通过数据库配置管理
    openai_api_key: str = ""
    openai_base_url: str | None = None
    llm_model: str = "gpt-4o"
    llm_temperature: float = 0.1
    
    # Kali Scanner
    kali_scanner_url: str = "http://kali_scanner:8888"
    
    # Scanning Configuration
    max_concurrent_scans: int = 5
    scan_timeout: int = 3600  # 1 hour
    rate_limit_per_target: int = 10  # requests per second
    scan_temp_dir: str = "/tmp/shelling_scans"  # 扫描结果临时目录
    
    # Security
    secret_key: str = "change-me-in-production"
    allowed_origins: list[str] = ["http://localhost:3000", "http://0.0.0.0:3000", "*"]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
