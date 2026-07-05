from pydantic import BaseModel


class DashboardStats(BaseModel):
    customers: int
    assets: int
    scans: int
    findings: int
    critical: int
    high: int
    medium: int
    low: int
