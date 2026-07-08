import { api } from "../../shared/api/api";

export interface Subdomain {
  id: number;
  customer_id: number;
  domain_id: number;
  name: string;
  source?: string | null;
}

export async function getSubdomains(): Promise<Subdomain[]> {
  const { data } = await api.get("/subdomains");
  return data;
}
