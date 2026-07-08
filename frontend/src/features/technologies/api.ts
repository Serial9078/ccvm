import { api } from "../../shared/api/api";

export interface Technology {
  id: number;
  host_id: number;
  name: string;
  version?: string | null;
  category?: string | null;
  source?: string | null;
}

export async function getTechnologies(): Promise<Technology[]> {
  const { data } = await api.get("/technologies");
  return data;
}
