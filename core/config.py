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
    database_url: str = "postgresql+asyncpg://redteam:redteam@localhost:5432/redteam"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_dir: Path = ROOT_DIR / "logs"
    report_dir: Path = ROOT_DIR / "reports"
    celery_broker_url: str = Field(default="amqp://redteam:redteam@localhost:5672//", alias="CELERY_BROKER_URL")
    celery_result_backend: str = Field(default="redis://localhost:6379/0", alias="CELERY_RESULT_BACKEND")
    celery_task_default_queue: str = Field(default="tool-scans", alias="CELERY_TASK_DEFAULT_QUEUE")
    tool_worker_enabled: bool = Field(default=True, alias="TOOL_WORKER_ENABLED")

    llm_provider: Literal["azure_openai", "aws_bedrock", "ollama", "openai", "huggingface", "anthropic"] = Field(
        default="azure_openai",
        alias="LLM_PROVIDER",
    )

    azure_openai_endpoint: str | None = Field(default=None, alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_api_key: SecretStr | None = Field(default=None, alias="AZURE_OPENAI_API_KEY")
    azure_openai_deployment: str | None = Field(default=None, alias="AZURE_OPENAI_DEPLOYMENT")
    azure_openai_api_version: str = Field(default="2024-12-01-preview", alias="AZURE_OPENAI_API_VERSION")

    openai_api_key: SecretStr | None = Field(default=None, alias="OPENAI_API_KEY")
    openai_model: str = Field(default="gpt-4o-mini", alias="OPENAI_MODEL")
    openai_base_url: str = Field(default="https://api.openai.com/v1", alias="OPENAI_BASE_URL")

    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    anthropic_model: str = Field(default="claude-3-5-sonnet-latest", alias="ANTHROPIC_MODEL")
    anthropic_base_url: str = Field(default="https://api.anthropic.com/v1", alias="ANTHROPIC_BASE_URL")
    anthropic_version: str = Field(default="2023-06-01", alias="ANTHROPIC_VERSION")

    huggingface_api_key: SecretStr | None = Field(default=None, alias="HUGGINGFACE_API_KEY")
    huggingface_model: str = Field(default="mistralai/Mistral-7B-Instruct-v0.3", alias="HUGGINGFACE_MODEL")
    huggingface_base_url: str = Field(default="https://api-inference.huggingface.co/models", alias="HUGGINGFACE_BASE_URL")

    ollama_base_url: str = Field(default="http://localhost:11434", alias="OLLAMA_BASE_URL")
    ollama_model: str = Field(default="llama3.1", alias="OLLAMA_MODEL")

    aws_region: str = Field(default="us-east-1", alias="AWS_REGION")
    aws_bedrock_model_id: str = Field(default="anthropic.claude-3-haiku-20240307-v1:0", alias="AWS_BEDROCK_MODEL_ID")

    default_temperature: float = 0.2
    default_timeout_seconds: float = 30.0
    default_retry_count: int = 2
    safe_prompt_log_chars: int = 600

    @property
    def azure_ready(self) -> bool:
        """Return whether Azure OpenAI credentials are configured."""

        return bool(self.azure_openai_endpoint and self.azure_openai_api_key and self.azure_openai_deployment)

    @property
    def openai_ready(self) -> bool:
        return bool(self.openai_api_key and self.openai_model)

    @property
    def anthropic_ready(self) -> bool:
        return bool(self.anthropic_api_key and self.anthropic_model)

    @property
    def huggingface_ready(self) -> bool:
        return bool(self.huggingface_api_key and self.huggingface_model)

    @property
    def ollama_ready(self) -> bool:
        return bool(self.ollama_base_url and self.ollama_model)

    @property
    def aws_bedrock_ready(self) -> bool:
        return bool(self.aws_region and self.aws_bedrock_model_id)

    @property
    def llm_ready(self) -> bool:
        readiness = {
            "azure_openai": self.azure_ready,
            "openai": self.openai_ready,
            "anthropic": self.anthropic_ready,
            "huggingface": self.huggingface_ready,
            "ollama": self.ollama_ready,
            "aws_bedrock": self.aws_bedrock_ready,
        }
        return readiness.get(self.llm_provider, False)


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""

    settings = Settings()
    settings.log_dir.mkdir(parents=True, exist_ok=True)
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    return settings

