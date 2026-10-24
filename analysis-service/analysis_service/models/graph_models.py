"""
AttackGraphX Analysis Service — Graph Entity Data Models
Defines internal representations of nodes and edges in the attack graph.
"""
from typing import Optional, Literal, Any
from pydantic import BaseModel, Field


class HostNode(BaseModel):
    id: str = Field(..., description="Unique host key, e.g. 'web-01' or '172.20.0.10'")
    ip: str = Field(..., description="IPv4 address")
    hostname: Optional[str] = Field(default=None)
    segment: str = Field(default="internal", description="Network segment: dmz, internal, secure, lab")
    state: str = Field(default="up")
    os: Optional[str] = Field(default=None)
    is_compromised: bool = Field(default=False)
    is_critical_asset: bool = Field(default=False)


class ServiceNode(BaseModel):
    id: str = Field(..., description="Unique service key e.g. 'web-01:80'")
    host_id: str
    port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(default="tcp")
    name: Optional[str] = Field(default=None)
    product: Optional[str] = Field(default=None)
    version: Optional[str] = Field(default=None)
    state: str = Field(default="open")


class VulnerabilityNode(BaseModel):
    id: str = Field(..., description="CVE ID or weakness identifier, e.g. 'CVE-2023-34362'")
    cve: str
    cvss: float = Field(default=7.5, ge=0.0, le=10.0)
    exploitability: int = Field(default=70, ge=0, le=100, description="Normalized exploitability (0-100)")
    attack_technique: str = Field(default="T1190", description="MITRE ATT&CK technique")
    description: str = Field(default="")
    is_patched: bool = Field(default=False)


class CredentialNode(BaseModel):
    id: str = Field(..., description="Unique credential key, e.g. 'cred-dba'")
    username: str
    privilege_level: Literal["user", "admin", "system", "root"] = "user"
    scope: str = "local"
    is_revoked: bool = Field(default=False)


class AssetNode(BaseModel):
    id: str = Field(..., description="Asset identifier, e.g. 'db-01' or 'vault-01'")
    name: str
    criticality: int = Field(default=80, ge=0, le=100, description="Asset business criticality (0-100)")
    asset_type: str = Field(default="database", description="database, vault, k8s_control_plane, pci_records")
    data_classification: str = Field(default="confidential")


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: Literal[
        "HOSTS",
        "EXPOSES",
        "HAS_VULNERABILITY",
        "CAN_REACH",
        "HAS_CREDENTIAL",
        "CAN_ACCESS",
        "CAN_COMPROMISE",
        "MITIGATES"
    ]
    weight: float = Field(default=1.0, ge=0.0, description="Edge cost for shortest-path routing")
    properties: dict[str, Any] = Field(default_factory=dict)
