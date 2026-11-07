from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SoftwareAssessmentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class SoftwareCatalogOut(BaseModel):
    id: int
    source: str
    sha256: str
    retrieved_at: datetime
    created_at: datetime
    coverage_start: str
    coverage_end: str
    document_ids: list[str]
    coverage: list[dict]
    entry_count: int
    expired: bool


class SoftwareAssessmentOut(BaseModel):
    id: int
    customer_id: int
    asset_id: int
    host_audit_id: int
    catalog_id: int | None
    engine_version: str
    evidence_sha256: str
    status: str
    result: dict
    evaluated_at: datetime
    expired: bool
