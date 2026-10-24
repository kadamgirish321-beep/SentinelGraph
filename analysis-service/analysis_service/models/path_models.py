"""
AttackGraphX Analysis Service — Canonical Path & Simulation Data Models
Follows the exact contract consumed by the API Gateway (Person 3) and Frontend.
"""
from typing import Optional, Literal
from pydantic import BaseModel, Field


class HopModel(BaseModel):
    host: str = Field(..., description="Hostname or node identifier")
    ip: Optional[str] = Field(default=None, description="IP address if applicable")
    vulnerability: Optional[str] = Field(default=None, description="CVE or weakness ID")
    attack_technique: Optional[str] = Field(default=None, description="MITRE ATT&CK technique e.g. T1190")
    description: Optional[str] = Field(default=None, description="Human readable description of the transition")


class PathModel(BaseModel):
    id: str = Field(..., description="Unique path identifier, e.g. PATH-001")
    target: str = Field(..., description="Target asset identifier, e.g. db-01")
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score (0-100)")
    severity: Literal["low", "medium", "high", "critical"] = Field(..., description="Severity classification")
    detectability: Optional[Literal["low", "medium", "high"]] = Field(default="medium", description="Attacker detectability")
    hops: list[HopModel] = Field(default_factory=list, description="Ordered hops from ingress to target")
    cost: Optional[float] = Field(default=None, description="Dijkstra cumulative path cost")
    rationale: Optional[str] = Field(default=None, description="Explainable risk rationale")


class PatchModel(BaseModel):
    id: str = Field(..., description="Patch identifier, e.g. PATCH-001")
    vulnerability_id: str = Field(..., description="Vulnerability ID mitigated, e.g. CVE-2023-34362")
    host: str = Field(..., description="Host on which the patch applies")
    description: Optional[str] = Field(default=None, description="Remediation guidance description")
    paths_closed: int = Field(default=0, ge=0, description="Number of attack paths severed by this patch")
    risk_reduction: int = Field(default=0, description="Calculated decrease in average or total risk")


class SimulateStats(BaseModel):
    path_count: int = Field(..., ge=0)
    avg_risk: int = Field(..., ge=0, le=100)
    critical_paths: int = Field(..., ge=0)


class SimulateResponse(BaseModel):
    before: SimulateStats
    after: SimulateStats
    vulnerability_id: str
    status: str = "live"
    paths_eliminated: list[str] = Field(default_factory=list)
    remaining_paths: list[str] = Field(default_factory=list)
    risk_reduction: int = Field(default=0)


class ScanStatusResponse(BaseModel):
    status: str = "idle"
    last_scan: str
    hosts_discovered: int = 0
    services_discovered: int = 0
