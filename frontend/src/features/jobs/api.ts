import { api } from "../../shared/api/api";

export interface Job {
  id: number;
  uuid: string;
  asset_id: number;
  plugin: string;
  status: string;
  progress: number;
  message?: string | null;
  worker?: string | null;
}

export interface JobCreate {
  asset_id: number;
  plugin: string;
}

export async function getJobs(): Promise<Job[]> {
  const { data } = await api.get("/jobs");
  return data;
}

export async function createJob(payload: JobCreate): Promise<Job> {
  const { data } = await api.post("/jobs", payload);
  return data;
}
