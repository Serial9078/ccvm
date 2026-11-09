"""Compact operator-only host status; detailed evidence stays on its own routes."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class OverviewRun(BaseModel):
    id: int
    credential_id: int
    port: int
    winrm_transport: str
    ssh_fingerprint: str | None
    mode: str
    status: str
    message: str
    created_at: datetime | None
    completed_at: datetime | None


class OverviewInventory(BaseModel):
    id: int
    completed_at: datetime
    os: dict
    package_count: int
    package_status: str
    hotfix_count: int
    hotfix_status: str
    mode: str = "inventory"
    collection_method: Literal["cim"] | None = None
    windows_updates: dict | None = None


class OverviewAssessment(BaseModel):
    id: int
    status: str
    expired: bool
    current_catalog: bool
    evidence_matches: bool
    engine_current: bool
    evaluated_at: datetime
    result: dict
    provider: str | None = None
    source: str | None = None
    catalog_applicable: bool = True


class OverviewHost(BaseModel):
    asset_id: int
    target: str
    platform: Literal["windows_server", "windows_client", "linux", "vmware", "unclassified"]
    latest_run: OverviewRun
    inventory: OverviewInventory | None
    windows_assessment: OverviewAssessment | None
    software_assessment: OverviewAssessment | None
    issues: list[str]


class OverviewCatalog(BaseModel):
    id: int
    retrieved_at: datetime
    expired: bool


class OverviewCatalogs(BaseModel):
    windows: OverviewCatalog | None
    software: OverviewCatalog | None


class HostOverviewOut(BaseModel):
    customer_id: int
    generated_at: datetime
    hosts: list[OverviewHost]
    catalogs: OverviewCatalogs
    issues: list[str]
    limit: int
    hosts_total: int
    hosts_truncated: bool
