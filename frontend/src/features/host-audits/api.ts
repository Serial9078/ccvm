import { apiBaseUrl } from "../../shared/api/config";
import type { PipelineJob } from "../pipelines/api";
import { secureAuditAccess } from "./security";
export { secureAuditAccess } from "./security";

export function canUseAuditApi(): boolean {
  return secureAuditAccess(window.location, apiBaseUrl);
}

export interface Credential {
  id: number;
  customer_id: number;
  name: string;
  kind: "ssh_password" | "ssh_key" | "winrm";
  username: string;
  allowed_cidrs: string[];
  enabled: boolean;
}
export interface InventorySection {
  status: string;
  source: string;
  items: Record<string, string>[];
}
export interface Inventory {
  os: Record<string, string>;
  packages: InventorySection;
  hotfixes: InventorySection;
}
export interface HostAudit {
  id: number;
  customer_id: number;
  credential_id: number;
  target: string;
  port: number;
  mode: "connection" | "inventory";
  cancel_requested: boolean;
  created_at: string;
  completed_at: string | null;
  job: PipelineJob;
  inventory?: Inventory | null;
}

// Use transient component state, not query/mutation caches, localStorage or
// sessionStorage. No token or credential appears in a URL or request log.
export async function auditRequest<T>(
  token: string,
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  if (!secureAuditAccess(window.location, apiBaseUrl))
    throw new Error("Use HTTPS and the same-origin API proxy for host audits.");
  const response = await fetch(`${apiBaseUrl}/host-audits${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    cache: "no-store",
    redirect: "error",
    credentials: "omit",
    signal: signal
      ? AbortSignal.any([signal, AbortSignal.timeout(30000)])
      : AbortSignal.timeout(30000),
  });
  const result = await response.json();
  if (!response.ok) {
    const detail = result.detail;
    throw new Error(
      typeof detail === "string"
        ? detail
        : "Invalid host audit request. Check the fields and access configuration.",
    );
  }
  return result;
}
