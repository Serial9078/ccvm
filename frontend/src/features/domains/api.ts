import { api } from "../../shared/api/api";

export interface Domain {
  id: number;
  customer_id: number;
  name: string;
  description?: string | null;
}

export interface DomainCreate {
  customer_id: number;
  name: string;
  description?: string;
}

export async function getDomains(): Promise<Domain[]> {
  const { data } = await api.get("/domains");
  return data;
}

export async function createDomain(payload: DomainCreate): Promise<Domain> {
  const { data } = await api.post("/domains", payload);
  return data;
}
