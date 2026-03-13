from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    wazuh_url: str = "https://localhost:9200"
    wazuh_username: str = "admin"
    wazuh_password: str = ""
    wazuh_verify_ssl: bool = False
    wazuh_timeout: int = 30
    min_rule_level: int = 12
    excluded_rule_ids: str = ""

    azure_openai_endpoint: str = ""
    azure_openai_key: str = ""
    azure_openai_deployment: str = "gpt-4.1"
    azure_openai_api_version: str = "2025-01-01-preview"

    max_alerts_per_sync: int = 500
    ai_batch_size: int = 5
    database_url: str = "sqlite+aiosqlite:///./wazuh_alerts.db"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
