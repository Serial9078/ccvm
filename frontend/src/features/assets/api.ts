import { api } from "../../shared/api/api";

export interface Asset {
  id: number;
  customer_id: number;
  target: string;
  name?: string | null;
  hostname?: string | null;
  fqdn?: string | null;
  ip_address?: string | null;
  type: string;
  exposure: string;
  environment: string;
  criticality: string;
  owner?: string | null;
  description?: string | null;
  tags?: string | null;
}

export interface AssetCreate {
  customer_id: number;
  target: string;
  name?: string;
  hostname?: string;
  fqdn?: string;
  ip_address?: string;
  type: string;
  exposure: string;
  environment: string;
  criticality: string;
  owner?: string;
  description?: string;
  tags?: string;
}

export async function getAssets(): Promise<Asset[]> {
  const { data } = await api.get("/assets");
  return data;
}

export async function createAsset(payload: AssetCreate): Promise<Asset> {
  const { data } = await api.post("/assets", payload);
  return data;
}
