from pydantic import BaseModel


class DashboardFinding(BaseModel):
    id: int
    severity: str
    name: str
    host: str | None = None
    scanner: str
    status: str


class DashboardJob(BaseModel):
    id: int
    plugin: str
    status: str
    progress: int
    message: str | None = None
    worker: str | None = None


class ChartPoint(BaseModel):
    label: str
    value: int


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

    latest_findings: list[DashboardFinding]
    active_jobs: list[DashboardJob]

    severity_chart: list[ChartPoint]
    scanner_chart: list[ChartPoint]
