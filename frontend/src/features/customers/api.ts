import { api } from "../../shared/api/api";

export interface Customer {
  id: number;
  uuid: string;
  name: string;
  company?: string;
  city?: string;
  contact_email?: string;
}

export interface CustomerCreate {
  name: string;
  company?: string;
  city?: string;
  contact_email?: string;
}

export async function getCustomers(): Promise<Customer[]> {
  const { data } = await api.get("/customers");
  return data;
}

export async function createCustomer(payload: CustomerCreate): Promise<Customer> {
  const { data } = await api.post("/customers", payload);
  return data;
}
