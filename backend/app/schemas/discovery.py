from pydantic import BaseModel


class DiscoveryCreate(BaseModel):
    domain_id: int


class DiscoveryJobOut(BaseModel):
    id: int
    uuid: str

    domain_id: int | None = None
    parent_job_id: int | None = None
    pipeline_id: str | None = None

    plugin: str
    status: str
    progress: int
    message: str | None = None
    worker: str | None = None

    model_config = {
        "from_attributes": True,
    }


class DiscoveryOut(BaseModel):
    pipeline_id: str
    domain_id: int
    jobs: list[DiscoveryJobOut]
