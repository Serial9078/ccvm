import { api } from './client';
import type { Asset, Customer, DashboardStats } from './types';

export async function getDashboardStats(): Promise<DashboardStats> {
  const { data } = await api.get('/dashboard/stats');
  return data;
}

export async function getCustomers(): Promise<Customer[]> {
  const { data } = await api.get('/customers');
  return data;
}

export async function createCustomer(payload: { name: string; email?: string }) {
  const { data } = await api.post('/customers', payload);
  return data;
}

export async function getAssets(): Promise<Asset[]> {
  const { data } = await api.get('/assets');
  return data;
}

export async function createAsset(payload: { customer_id: number; target: string; type: string; exposure: string }) {
  const { data } = await api.post('/assets', payload);
  return data;
}
