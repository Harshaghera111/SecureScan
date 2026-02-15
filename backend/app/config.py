"""
SecureScan Backend — Application Configuration
Pydantic Settings for environment variable management
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # ── Application ──
    APP_NAME: str = "SecureScan"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SECRET_KEY: str = "change-me-to-a-random-64-char-string"
    ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:5500"

    # ── Database ──
    DATABASE_URL: str = "sqlite+aiosqlite:///./securescan.db"  # SQLite for local dev; override in .env for PostgreSQL

    # ── Redis ──
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT ──
    JWT_SECRET_KEY: str = "change-me-to-another-random-64-char-string"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ALGORITHM: str = "HS256"

    # ── AI Providers ──
    OPENAI_API_KEY: str = ""
    GEMINI_API_KEY: str = ""
    LLM_PROVIDER: str = "mock"  # "openai", "gemini", "mock"

    # ── File Storage ──
    UPLOAD_DIR: str = "./uploads"
    MAX_FILE_SIZE_MB: int = 50

    # ── Rate Limiting ──
    RATE_LIMIT_PER_MINUTE: int = 30

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",")]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
