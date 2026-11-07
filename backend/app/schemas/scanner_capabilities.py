"""Private implementation coverage and positively observed network devices."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class CapabilityStage(BaseModel):
    status: Literal["available", "limited", "unavailable"]
    provider: str | None
    scope: str
    prerequisites: list[str]
    limitations: list[str]


class CapabilityPlatform(BaseModel):
    id: str
    name: str
    stages: dict[str, CapabilityStage]


class CapabilityLabel(BaseModel):
    id: str
    name: str


class ScannerCapabilitiesOut(BaseModel):
    version: str
    stage_labels: list[CapabilityLabel]
    platforms: list[CapabilityPlatform]
    limitations: list[str]


class DiscoveredServiceOut(BaseModel):
    port: int
    protocol: Literal["tcp"]
    state: Literal["open"]
    service: str | None
    product: str | None
    version: str | None
    audit_coverage: str


class DiscoveredDeviceOut(BaseModel):
    asset_id: int
    ip_address: str
    last_seen: datetime
    scan_id: int
    discovery_status: str
    services: list[DiscoveredServiceOut]
    services_total: int
    services_truncated: bool
    inventory_status: Literal["not_inventoried", "pending", "failed", "inventoried", "partial"]
    host_audit_id: int | None
    inventory_collected_at: datetime | None


class DiscoveredDevicesOut(BaseModel):
    customer_id: int
    total: int
    limit: int
    offset: int
    has_more: bool
    items: list[DiscoveredDeviceOut]
    limitations: list[str]
