from pydantic import BaseModel


class PipelineJobOut(BaseModel):
    id: int
    uuid: str
    parent_job_id: int | None = None

    plugin: str
    status: str
    progress: int

    message: str | None = None
    worker: str | None = None

    model_config = {
        "from_attributes": True,
    }


class PipelineOut(BaseModel):
    pipeline_id: str
    domain_id: int | None = None
    domain_name: str | None = None
    asset_id: int | None = None
    asset_name: str | None = None
    asset_target: str | None = None

    status: str
    progress: int

    total_jobs: int
    finished_jobs: int
    failed_jobs: int
    skipped_jobs: int
    running_jobs: int
    queued_jobs: int

    jobs: list[PipelineJobOut]
