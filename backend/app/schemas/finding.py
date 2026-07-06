from pydantic import BaseModel


class FindingOut(BaseModel):
    id: int
    asset_id: int
    job_id: int | None = None
    scanner: str
    template_id: str | None = None
    name: str
    severity: str
    host: str | None = None
    matched_at: str | None = None
    description: str | None = None
    remediation: str | None = None
    reference: str | None = None
    cve: str | None = None
    cvss_score: str | None = None
    status: str

    model_config = {"from_attributes": True}
