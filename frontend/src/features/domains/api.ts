import { api } from "../../shared/api/api";

export interface Domain {
  id: number;
  customer_id: number;
  name: string;
  description?: string | null;
}

export interface DiscoveryJob {
  id: number;
  uuid: string;
  domain_id?: number | null;
  plugin: string;
  status: string;
  progress: number;
  message?: string | null;
}

export interface DiscoveryResponse {
  domain_id: number;
  jobs: DiscoveryJob[];
}

export async function getDomains(): Promise<Domain[]> {
  const { data } = await api.get<Domain[]>("/domains");
  return data;
}

export async function startDiscovery(
  domainId: number,
): Promise<DiscoveryResponse> {
  const { data } = await api.post<DiscoveryResponse>("/discover", {
    domain_id: domainId,
  });

  return data;
}
