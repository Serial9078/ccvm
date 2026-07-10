import { api } from "../../shared/api/api";

export interface DashboardFinding {
  id: number;
  severity: string;
  name: string;
  host?: string | null;
  scanner: string;
  status: string;
}

export interface DashboardJob {
  id: number;
  plugin: string;
  status: string;
  progress: number;
  message?: string | null;
  worker?: string | null;
}

export interface ChartPoint {
  label: string;
  value: number;
}

export interface DashboardSummary {
  customers: number;
  domains: number;
  subdomains: number;
  hosts: number;
  ports: number;
  technologies: number;
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
  latest_findings: DashboardFinding[];
  active_jobs: DashboardJob[];
  severity_chart: ChartPoint[];
  scanner_chart: ChartPoint[];
}

export async function getDashboardSummary(): Promise<DashboardSummary> {
  const { data } = await api.get("/dashboard");
  return data;
}
