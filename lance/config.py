"""
LANCE — Core Settings
lance.iosec.in
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # App
    app_name: str = "LANCE"
    app_version: str = "0.5.0"
    app_url: str = "https://lance.iosec.in"
    debug: bool = False

    # Database
    database_url: str = Field(
        default="sqlite:///./lance.db",
        description="SQLite for local, postgresql://... for cloud",
    )

    # LLM Provider API Keys
    openai_api_key: str = Field(default="", description="OpenAI API key")
    anthropic_api_key: str = Field(default="", description="Anthropic API key")
    ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama endpoint")

    # Judge LLM — used to score attack responses
    judge_model: str = Field(
        default="ollama/llama3",
        description="LLM used to judge if attack succeeded. Use ollama/llama3 for free local scoring.",
    )
    judge_temperature: float = 0.0

    # Attack engine
    max_concurrent_probes: int = Field(default=5, description="Async concurrency limit")
    probe_timeout_seconds: int = 30
    max_retries: int = 3

    # Paths
    attacks_dir: Path = Path(__file__).parent / "attacks"
    reports_dir: Path = Path(__file__).parent.parent / "reports"
    templates_dir: Path = Path(__file__).parent.parent / "reports" / "templates"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Reporting
    org_name: str = "iosec.in"
    assessor_name: str = "Shekhar Suman"


settings = Settings()
