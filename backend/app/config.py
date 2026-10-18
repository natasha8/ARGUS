"""Argus configuration loaded from the environment."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./argus.db"
    allowed_target_hosts: str = "localhost,127.0.0.1,vulnerable-api,host.docker.internal"
    collaborator_base_url: str = "http://127.0.0.1:8090"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
