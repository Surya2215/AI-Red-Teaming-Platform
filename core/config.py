"""Application configuration loaded from environment and .env files."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


class Settings(BaseSettings):
    """Runtime settings shared by API, engine, and Streamlit UI."""

    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "AI Red Teaming and LLM Security Assessment Platform"
    environment: str = "local"
    database_url: str = "sqlite+aiosqlite:///./database/redteam.db"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_dir: Path = ROOT_DIR / "logs"
    report_dir: Path = ROOT_DIR / "reports"

    azure_openai_endpoint: str | None = Field(default=None, alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_api_key: SecretStr | None = Field(default=None, alias="AZURE_OPENAI_API_KEY")
    azure_openai_deployment: str | None = Field(default=None, alias="AZURE_OPENAI_DEPLOYMENT")
    azure_openai_api_version: str = Field(default="2024-12-01-preview", alias="AZURE_OPENAI_API_VERSION")

    default_temperature: float = 0.2
    default_timeout_seconds: float = 30.0
    default_retry_count: int = 2
    safe_prompt_log_chars: int = 600

    @property
    def azure_ready(self) -> bool:
        """Return whether Azure OpenAI credentials are configured."""

        return bool(self.azure_openai_endpoint and self.azure_openai_api_key and self.azure_openai_deployment)


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""

    settings = Settings()
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    return settings

