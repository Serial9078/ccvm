from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.job import JobOut


class NetworkScanCreate(BaseModel):
    customer_id: int = Field(gt=0)
    target: str = Field(min_length=1, max_length=100)
    name: str | None = Field(default=None, max_length=255)
    exclusions: list[str] = Field(default_factory=list, max_length=256)
    profile: Literal["fast", "standard", "full", "custom"] = "standard"
    ports: str | None = Field(default=None, max_length=2000)
    rate: int = Field(default=100, ge=10, le=1000)
    timeout_seconds: int = Field(default=28800, ge=60, le=86400)


class ScopePreview(BaseModel):
    target: str
    address_count: int
    sample: list[str]
    exclusions: list[str]
    ports_per_host: int
    minimum_portscan_seconds: int
    ip_version: int


class NetworkScanOut(BaseModel):
    id: int
    customer_id: int
    asset_id: int
    pipeline_id: str
    target: str
    exclusions: list[str]
    profile: str
    ports: str | None
    rate: int
    timeout_seconds: int
    address_count: int
    status: str
    cancel_requested: bool
    hosts_checked: int
    open_services: int
    findings_created: int
    findings_updated: int
    scanner_version: str | None
    created_at: datetime
    jobs: list[JobOut]


class ServiceOut(BaseModel):
    audit_coverage: str | None = None
    port: int
    protocol: str
    state: str
    service: str | None = None
    product: str | None = None
    version: str | None = None
    tunnel: str | None = None
    extra_info: str | None = None
    cpe: list[str] = Field(default_factory=list)
    method: str | None = None
    confidence: int | None = None
    checks: list[dict] = Field(default_factory=list)


class NetworkObservationOut(BaseModel):
    id: int
    host_id: int
    asset_id: int
    ip_address: str
    services: list[ServiceOut]
    model_config = {"from_attributes": True}


class NetworkScanDetail(NetworkScanOut):
    observations: list[NetworkObservationOut]
