import { api } from "../../shared/api/api";

export interface Host {
  id: number;
  customer_id: number;
  domain_id?: number | null;
  subdomain_id?: number | null;
  hostname: string;
  ip_address?: string | null;
  alive: boolean;
  source?: string | null;
}

export async function getHosts(): Promise<Host[]> {
  const { data } = await api.get("/hosts");
  return data;
}
