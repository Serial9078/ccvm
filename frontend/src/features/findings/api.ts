import { api } from "../../shared/api/api";

export interface Finding {
  id: number;
  asset_id: number;
  job_id?: number | null;
  scanner: string;
  template_id?: string | null;
  name: string;
  severity: string;
  host?: string | null;
  matched_at?: string | null;
  description?: string | null;
  remediation?: string | null;
  reference?: string | null;
  cve?: string | null;
  cvss_score?: string | null;
  status: string;
}

export async function getFindings(): Promise<Finding[]> {
  const { data } = await api.get("/findings");
  return data;
}
