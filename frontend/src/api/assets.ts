import { api } from "./api";

export interface Asset {
  id: number;
  customer_id: number;
  target: string;
  type: string;
  exposure: string;
}

export interface AssetCreate {
  customer_id: number;
  target: string;
  type: string;
  exposure: string;
}

export async function getAssets(): Promise<Asset[]> {
  const { data } = await api.get("/assets");
  return data;
}

export async function createAsset(payload: AssetCreate): Promise<Asset> {
  const { data } = await api.post("/assets", payload);
  return data;
}
