export interface DashboardStats {
  customers: number;
  assets: number;
  scans: number;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Customer {
  id: number;
  name: string;
  email?: string | null;
}

export interface Asset {
  id: number;
  customer_id: number;
  target: string;
  type: string;
  exposure: string;
}
