from pydantic import BaseModel


class JobCreate(BaseModel):
    asset_id: int | None = None
    domain_id: int | None = None
    plugin: str
    parent_job_id: int | None = None
    pipeline_id: str | None = None


class JobOut(BaseModel):
    id: int
    uuid: str

    asset_id: int | None = None
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
