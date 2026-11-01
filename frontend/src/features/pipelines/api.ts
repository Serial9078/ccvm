import { api } from "../../shared/api/api";

export interface PipelineJob {
  id: number;
  uuid: string;
  parent_job_id?: number | null;

  plugin: string;
  status: string;
  progress: number;

  message?: string | null;
  worker?: string | null;
}

export interface Pipeline {
  pipeline_id: string;

  domain_id?: number | null;
  domain_name?: string | null;

  status: string;
  progress: number;

  total_jobs: number;
  finished_jobs: number;
  failed_jobs: number;
  skipped_jobs: number;
  running_jobs: number;
  queued_jobs: number;

  jobs: PipelineJob[];
}

export async function getPipelines(): Promise<Pipeline[]> {
  const { data } = await api.get<Pipeline[]>(
    "/pipelines",
  );

  return data;
}

export async function getPipeline(
  pipelineId: string,
): Promise<Pipeline> {
  const { data } = await api.get<Pipeline>(
    `/pipelines/${pipelineId}`,
  );

  return data;
}
