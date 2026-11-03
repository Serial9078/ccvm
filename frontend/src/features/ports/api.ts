import { api } from "../../shared/api/api";

export interface Port {
  id: number;
  host_id: number;
  port: number;
  protocol: string;
  service?: string | null;
  banner?: string | null;
  source?: string | null;
  state?: string;
  product?: string | null;
  version?: string | null;
  tunnel?: string | null;
  cpe?: string[] | null;
}

export async function getPorts(): Promise<Port[]> {
  const { data } = await api.get("/ports");
  return data;
}
