import { api } from "../../shared/api/api";

export interface Port {
  id: number;
  host_id: number;
  port: number;
  protocol: string;
  service?: string | null;
  banner?: string | null;
  source?: string | null;
}

export async function getPorts(): Promise<Port[]> {
  const { data } = await api.get("/ports");
  return data;
}
