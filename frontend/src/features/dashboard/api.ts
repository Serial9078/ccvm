import { api } from "../../shared/api/api";

export interface DashboardSummary {
  customers: number;
  domains: number;
  assets: number;
  jobs: number;
  running_jobs: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  open: number;
  fixed: number;
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const { data } = await api.get("/dashboard");
  return data;
}
