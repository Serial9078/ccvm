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
  windows_updates?: WindowsUpdateEvidence | null;
}
export type WinrmTransport = "https" | "http_ntlm";
export type AuditMode = "connection" | "inventory" | "windows_updates";

export type WindowsUpdateClassification =
  "security" | "quality" | "feature" | "definition" | "other";
export interface WindowsUpdateOffer {
  update_id: string;
  revision: number;
  title: string;
  kbs: string[];
  categories: { id: string; name: string; type?: string }[];
  classification?: WindowsUpdateClassification;
  is_optional?: boolean | null;
  is_mandatory?: boolean | null;
  actionable?: boolean;
}
export interface WindowsUpdateEvidence {
  queried_at: string | null;
  mode: string;
  server_selection: string;
  status: string;
  result_code?: number | null;
  total: number;
  items: WindowsUpdateOffer[];
  items_truncated?: boolean;
  truncated?: boolean;
  summary?: Record<
    WindowsUpdateClassification | "offers" | "optional" | "optional_unknown" | "actionable",
    number
  >;
  reboot_required: boolean | null;
  hidden_updates?: string;
  drivers?: string;
  superseded?: string;
}

export interface HostAudit {
  id: number;
  customer_id: number;
  credential_id: number;
  target: string;
  port: number;
  mode: AuditMode;
  winrm_transport?: WinrmTransport;
  cancel_requested: boolean;
  created_at: string;
  completed_at: string | null;
  job: PipelineJob;
  inventory?: Inventory | null;
}

export interface PatchCatalog {
  id: number;
  source: string;
  sha256: string;
  retrieved_at: string;
  created_at: string;
  coverage_start: string;
  coverage_end: string;
  document_ids: string[];
  entry_count: number;
  expired: boolean;
}

export interface PatchAssessmentResult {
  schema_version: number;
  engine_version: string;
  status: string;
  reason: string;
  evaluated_at: string;
  valid_until: string | null;
  evidence_collected_at: string | null;
  catalog_retrieved_at: string | null;
  provider?: never;
  installed_build: string | null;
  product: {
    id: string;
    name: string;
    year: string;
    installation_type: string;
    edition_id: string;
  } | null;
  baseline_build: string | null;
  baseline_kbs: string[];
  cve_references: {
    cve: string;
    title: string;
    severity: string;
    cvss_score?: number | null;
    kbs: string[];
    source_urls: string[];
    document_ids: string[];
  }[];
  cve_references_total: number;
  cve_references_truncated: boolean;
  coverage: {
    scope: string;
    status: string;
    catalog_start: string | null;
    catalog_end: string | null;
    component_applicability: string;
    third_party_software: string;
    linux: string;
    hotpatch: string;
  };
  limitations: string[];
  sources: {
    document_id: string;
    url: string;
    sha256: string;
    current_release_date: string;
    initial_release_date: string;
  }[];
}

export interface WindowsUpdateAssessmentResult {
  schema_version: number;
  engine_version: string;
  provider: "windows-update-agent";
  source: string;
  catalog_applicable: false;
  status: string;
  reason: string;
  evaluated_at: string;
  valid_until: string | null;
  evidence_collected_at: string | null;
  windows_updates: WindowsUpdateEvidence | null;
  limitations: string[];
}

export interface HostAssessment {
  id: number;
  customer_id: number;
  asset_id: number;
  host_audit_id: number;
  catalog_id: number | null;
  engine_version: string;
  evidence_sha256: string;
  status: string;
  result: PatchAssessmentResult | WindowsUpdateAssessmentResult;
  evaluated_at: string;
  expired: boolean;
  provider?: string;
  source?: string;
  catalog_applicable?: boolean;
}

export interface SoftwareCatalogCoverage {
  product_key: string;
  discovered: number;
  parsed: number;
  unavailable_cves: string[];
  scope: string;
}

export interface SoftwareCatalog {
  id: number;
  source: string;
  sha256: string;
  retrieved_at: string;
  created_at: string;
  coverage_start: string;
  coverage_end: string;
  entry_count: number;
  coverage: SoftwareCatalogCoverage[];
  expired: boolean;
}

export interface SoftwareAssessmentResult {
  schema_version: number;
  engine_version: string;
  status: string;
  reason: string;
  evaluated_at: string;
  valid_until: string | null;
  evidence_collected_at: string | null;
  catalog_retrieved_at: string | null;
  summary: {
    inventory_entries: number;
    identified_entries: number;
    assessed_entries: number;
    unassessed_entries: number;
    product_versions: number;
    matched_product_versions: number;
    cve_matches: number;
  };
  coverage: {
    scope: string;
    status: string;
    package_status: string;
    catalog_start: string | null;
    catalog_end: string | null;
    vendor_catalog: SoftwareCatalogCoverage[];
    exploitability: string;
    per_user: string;
  };
  products: {
    product_key: string;
    name: string;
    version: string;
    publisher: string;
    evidence_basis: string;
    evidence_count: number;
    status: string;
    reason: string;
    checked_cves: number;
    matches: {
      cve: string;
      title: string;
      severity: string;
      source_product: string;
      affected_ranges: { introduced: string; fixed: string }[];
      source_urls: string[];
      document_ids: string[];
    }[];
    matches_total: number;
    matches_truncated: boolean;
    catalog_scope: string;
  }[];
  unassessed: {
    name: string;
    version: string;
    publisher: string;
    reason: string;
    evidence_count: number;
  }[];
  products_total: number;
  products_truncated: boolean;
  unassessed_total: number;
  unassessed_truncated: boolean;
  limitations: string[];
  sources: { id: string; url: string; sha256: string }[];
}

export interface SoftwareAssessment extends Omit<HostAssessment, "result"> {
  result: SoftwareAssessmentResult;
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
