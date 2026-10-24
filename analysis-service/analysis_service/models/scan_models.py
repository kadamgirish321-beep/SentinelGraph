"""
AttackGraphX Analysis Service — Ingested Scan Data Models
Directly matches the canonical contract published by Person 1 (recon-service).
"""
from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


class IngestedService(BaseModel):
    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None


class IngestedHost(BaseModel):
    ip: str
    hostname: str | None = None
    state: str = "up"
    segment: str | None = None
    services: list[IngestedService] = Field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    credentials: list[dict[str, Any]] = Field(default_factory=list)


class IngestedScanResult(BaseModel):
    scan_id: str
    timestamp: datetime
    scanner: Literal["nmap"] = "nmap"
    target_scope: str
    hosts: list[IngestedHost] = Field(default_factory=list)
