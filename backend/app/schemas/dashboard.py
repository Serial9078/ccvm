from pydantic import BaseModel


class DashboardSummary(BaseModel):
    customers: int
    domains: int
    assets: int
    jobs: int
    running_jobs: int

    findings: int

    critical: int
    high: int
    medium: int
    low: int
    info: int

    open: int
    fixed: int
