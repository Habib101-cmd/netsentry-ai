from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class RefreshIn(BaseModel):
    refresh_token: str = Field(max_length=256)


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    must_change_password: bool


class ChangePasswordIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(max_length=256)
    role: Literal["admin", "analyst"]


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    role: str
    is_active: bool
    must_change_password: bool
    last_login: datetime | None


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    username: str | None
    action: str
    target: str | None
    source_ip: str | None
    result: str


class ScopeCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    cidr: str = Field(max_length=43)
    description: str = Field("", max_length=500)
    allow_public: bool = False
    authorization_confirmed: bool


class ScopeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    cidr: str
    description: str
    allow_public: bool
    is_active: bool
    created_at: datetime


class ScanCreate(BaseModel):
    target: str = Field(max_length=64)
    profile: Literal["discovery", "standard", "deep"]


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scope_id: int
    target: str
    profile: str
    status: str
    cancel_requested: bool
    error: str | None
    created_by: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    nmap_version: str | None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    cve: str
    cvss: float | None
    source: str


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    port: int
    protocol: str
    state: str
    name: str | None
    product: str | None
    version: str | None
    confidence: int
    vulnerabilities: list[VulnerabilityOut]


class HostOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    ip: str
    mac: str | None
    hostname: str | None
    os_guess: str | None
    state: str
    criticality: str
    services: list[ServiceOut]


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    host_id: int
    host_ip: str
    service_id: int | None
    rule_id: str
    rule_version: int
    title: str
    level: str
    score: int
    factors: list[dict]
    justification: str
    evidence: str
    recommendation: str
    status: str
    accepted_comment: str | None
    accepted_by: int | None
    first_seen: datetime
    last_seen: datetime


class FindingUpdate(BaseModel):
    status: Literal["new", "in_progress", "fixed", "accepted"]
    comment: str | None = Field(None, max_length=1000)


class HostUpdate(BaseModel):
    criticality: Literal["low", "normal", "high"]


class ReportCreate(BaseModel):
    scan_id: int


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    generated_by: int
    created_at: datetime
    size_bytes: int


class AnomalyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    host_id: int
    host_ip: str
    score: float
    is_anomaly: bool
    features: dict
    explanation: dict
    model_version: str
