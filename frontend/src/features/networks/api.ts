import { api } from "../../shared/api/api";
import type { PipelineJob } from "../pipelines/api";

export interface NetworkRequest {
  customer_id: number;
  target: string;
  name?: string;
  exclusions: string[];
  profile: "fast" | "standard" | "full" | "custom";
  ports?: string;
  rate: number;
  timeout_seconds: number;
}

export interface NetworkPreview {
  target: string;
  address_count: number;
  sample: string[];
  exclusions: string[];
  ports_per_host: number;
  minimum_portscan_seconds: number;
  ip_version: number;
}

export interface NetworkScan {
  id: number;
  customer_id: number;
  asset_id: number;
  pipeline_id: string;
  target: string;
  exclusions: string[];
  profile: string;
  ports?: string | null;
  rate: number;
  timeout_seconds: number;
  address_count: number;
  status: string;
  cancel_requested: boolean;
  hosts_checked: number;
  open_services: number;
  findings_created: number;
  findings_updated: number;
  scanner_version?: string | null;
  created_at: string;
  jobs: PipelineJob[];
}

export interface NetworkService {
  port: number;
  protocol: string;
  state: string;
  service?: string | null;
  product?: string | null;
  version?: string | null;
  tunnel?: string | null;
  cpe: string[];
  method?: string | null;
  checks: { check: string; status: string; output?: string }[];
}

export interface NetworkDetail extends NetworkScan {
  observations: { id: number; ip_address: string; asset_id: number; services: NetworkService[] }[];
}

export interface ScannerCapabilities {
  enabled: boolean;
  allowed_cidrs: string[];
  max_addresses: number;
  tcp: boolean;
  udp: boolean;
  credentialed: boolean;
}

export async function listNetworkScans(): Promise<NetworkScan[]> {
  return (await api.get("/network-scans")).data;
}
export async function networkCapabilities(): Promise<ScannerCapabilities> {
  return (await api.get("/network-scans/capabilities")).data;
}
export async function previewNetwork(payload: NetworkRequest): Promise<NetworkPreview> {
  return (await api.post("/network-scans/preview", payload)).data;
}
export async function startNetwork(payload: NetworkRequest): Promise<NetworkScan> {
  return (await api.post("/network-scans", payload)).data;
}
export async function cancelNetwork(id: number): Promise<NetworkScan> {
  return (await api.post(`/network-scans/${id}/cancel`)).data;
}
export async function networkDetail(id: number): Promise<NetworkDetail> {
  return (await api.get(`/network-scans/${id}`)).data;
}
