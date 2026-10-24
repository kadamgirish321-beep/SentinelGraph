"""
AttackGraphX Analysis Service — Application Configuration
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Service Bindings
    app_name: str = "AttackGraphX Analysis Service"
    app_version: str = "1.0.0"
    service_host: str = "0.0.0.0"
    service_port: int = 9000
    log_level: str = "INFO"

    # Redis
    redis_url: str = Field(default="redis://localhost:6379/0")
    redis_stream_topic: str = Field(default="scan_results")
    redis_consumer_group: str = Field(default="analysis_group")
    redis_consumer_name: str = Field(default="analysis_worker_1")
    redis_connect_timeout: int = Field(default=5)

    # Neo4j Graph Database
    neo4j_uri: str = Field(default="bolt://localhost:7687")
    neo4j_user: str = Field(default="neo4j")
    neo4j_password: str = Field(default="attackgraphx123")
    neo4j_database: str = Field(default="neo4j")
    use_neo4j: bool = Field(default=True, description="Attempt Neo4j connection; fallback to native in-memory if offline")

    # Upstream Recon Service (for scan triggers)
    recon_service_url: str = Field(default="http://localhost:8001")

    # Risk Model Parameters
    weight_exploitability: float = 0.4
    weight_criticality: float = 0.4
    weight_exposure: float = 0.2

    # Graph Analysis Defaults
    max_alternative_paths: int = 5
    max_path_hops: int = 8

    # Optional AI Assistant
    openai_api_key: str | None = Field(default=None)
    anthropic_api_key: str | None = Field(default=None)


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
