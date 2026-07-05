import { api } from "./api";

export interface Customer {
  id: number;
  uuid: string;
  name: string;
  company?: string;
  city?: string;
  contact_email?: string;
}

export async function getCustomers(): Promise<Customer[]> {
  const { data } = await api.get("/customers");
  return data;
}
