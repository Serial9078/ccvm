import type { SoftwareAssessmentResult, WindowsUpdateEvidence } from "./api";

export type HostPlatformFilter = "all" | "windows-server" | "windows-client" | "linux" | "vmware";
export interface OverviewAssessment {
  id: number;
  status: string;
  expired: boolean;
  current_catalog: boolean;
  provider?: string;
  catalog_applicable?: boolean;
  evidence_matches: boolean;
  engine_current: boolean;
  evaluated_at: string;
}
export interface OverviewHost {
  asset_id: number;
  target: string;
  platform: "windows_server" | "windows_client" | "linux" | "vmware" | "unclassified";
  latest_run: {
    id: number;
    credential_id: number;
    port: number;
    winrm_transport: "https" | "http_ntlm";
    ssh_fingerprint: string | null;
    mode: string;
    status: string;
    message: string;
    created_at: string;
    completed_at: string | null;
  };
  inventory: {
    id: number;
    completed_at: string;
    os: Record<string, string>;
    package_count: number;
    package_status: string;
    hotfix_count: number;
    hotfix_status: string;
    mode?: string;
    collection_method?: string;
    windows_updates?:
      | (Pick<
          WindowsUpdateEvidence,
          "queried_at" | "status" | "result_code" | "total" | "reboot_required" | "truncated"
        > & { has_evidence: boolean })
      | null;
  } | null;
  windows_assessment:
    | (OverviewAssessment & {
        result: {
          reason: string;
          valid_until: string | null;
          installed_build?: string | null;
          baseline_build?: string | null;
          baseline_kbs?: string[];
          product?: { name: string } | null;
          provider?: string;
          source?: string;
          windows_updates?: WindowsUpdateEvidence | null;
          limitations?: string[];
        };
      })
    | null;
  software_assessment:
    | (OverviewAssessment & {
        result: Pick<
          SoftwareAssessmentResult,
          "reason" | "valid_until" | "summary" | "products_total" | "products_truncated"
        > & {
          products: (SoftwareAssessmentResult["products"][number] & {
            reference_fix: string | null;
            reference_fix_complete: boolean;
          })[];
          coverage: Omit<SoftwareAssessmentResult["coverage"], "vendor_catalog"> & {
            vendor_catalog: {
              product_key: string;
              scope: string;
              discovered: number;
              parsed: number;
              unavailable_count: number;
            }[];
          };
        };
      })
    | null;
  issues: string[];
}
export interface HostOverview {
  customer_id: number;
  generated_at: string;
  hosts: OverviewHost[];
  catalogs: {
    windows: { id: number; retrieved_at: string; expired: boolean } | null;
    software: { id: number; retrieved_at: string; expired: boolean } | null;
  };
  limit: number;
  hosts_total: number;
  hosts_truncated: boolean;
  issues: string[];
}
export const platformNames: Record<HostPlatformFilter, string> = {
  all: "Host-Übersicht",
  "windows-server": "Windows Server",
  "windows-client": "Windows Clients",
  linux: "Linux",
  vmware: "VMware",
};
export const updateStatusLabels: Record<string, string> = {
  updates_offered: "Updates angeboten",
  no_update_offers: "Keine Updateangebote",
  update_query_required: "Updateabfrage erforderlich",
  update_query_incomplete: "Updateabfrage unvollständig",
  stale_evidence: "Updateabfrage veraltet",
};
export function date(value?: string | null) {
  if (!value || !Number.isFinite(new Date(value).valueOf())) return "Noch keine";
  return new Date(value).toLocaleString();
}
export function current(
  assessment: (OverviewAssessment & { result: { valid_until: string | null } }) | null,
) {
  return Boolean(
    assessment &&
    !assessment.expired &&
    (assessment.current_catalog ||
      (assessment.provider === "windows-update-agent" &&
        assessment.catalog_applicable === false)) &&
    assessment.evidence_matches &&
    assessment.engine_current &&
    assessment.result.valid_until &&
    new Date(assessment.result.valid_until).valueOf() > Date.now(),
  );
}
export function matchesPlatform(host: OverviewHost, platform: HostPlatformFilter) {
  return platform === "all" || host.platform === platform.replaceAll("-", "_");
}
export function hostState(host: OverviewHost) {
  const windows = host.windows_assessment;
  const software = host.software_assessment;
  const needsWindows =
    current(windows) &&
    ((host.platform === "windows_server" && windows?.status === "build_gap") ||
      (host.platform === "windows_client" &&
        windows?.status === "updates_offered" &&
        Boolean(windows.result.windows_updates?.summary?.actionable)));
  const needsSoftware = current(software) && Boolean(software?.result.summary.cve_matches);
  const baselineMatch =
    host.platform === "windows_server" &&
    current(windows) &&
    windows?.status === "meets_catalog_baseline";
  const collectionIssue = host.issues.some((issue) =>
    [
      "latest_collection_failed",
      "latest_connection_failed",
      "collection_pending",
      "inventory_partial",
      "inventory_stale",
    ].includes(issue),
  );
  const baseline = baselineMatch && !collectionIssue && !hasCimInventory(host);
  const windowsUnknown =
    !current(windows) ||
    !(
      host.platform === "windows_client"
        ? ["updates_offered", "no_update_offers"]
        : ["build_gap", "meets_catalog_baseline"]
    ).includes(windows?.status ?? "");
  const softwareIncomplete =
    !current(software) ||
    !["version_matches_found", "no_matches_in_checked_ranges"].includes(software?.status ?? "") ||
    software?.result.coverage.package_status !== "complete" ||
    Boolean(software?.result.products_truncated) ||
    Boolean(software?.result.summary.unassessed_entries) ||
    Boolean(software?.result.coverage.vendor_catalog.some((scope) => scope.unavailable_count));
  return {
    needsWindows,
    needsSoftware,
    baseline,
    attention: Boolean(needsWindows || needsSoftware),
    unknown:
      !host.inventory ||
      hasCimInventory(host) ||
      collectionIssue ||
      windowsUnknown ||
      softwareIncomplete,
    collectionIssue,
  };
}

export function hasCimInventory(host: OverviewHost | null | undefined) {
  return Boolean(
    host?.inventory &&
    (host.inventory.mode === "cim_inventory" || host.inventory.collection_method === "cim"),
  );
}
export function assessmentWarning(
  assessment: OverviewHost["windows_assessment"] | OverviewHost["software_assessment"],
) {
  if (!assessment) return "Noch nicht bewertet";
  if (!assessment.engine_current) return "Prüfregeln erneuert · neu bewerten";
  if (!assessment.evidence_matches) return "Evidenz geändert · neu bewerten";
  if (
    !assessment.current_catalog &&
    !(assessment.provider === "windows-update-agent" && assessment.catalog_applicable === false)
  )
    return "Katalog erneuert · neu bewerten";
  if (!current(assessment)) return "Bewertung nicht aktuell";
  return "";
}

export function freshWindowsUpdateQuery(host: OverviewHost) {
  const query = host.inventory?.windows_updates;
  if (
    host.inventory?.mode !== "windows_updates" ||
    !query?.queried_at ||
    query.status !== "complete"
  )
    return false;
  const timestamp = new Date(query.queried_at).valueOf();
  const collected = new Date(host.inventory.completed_at).valueOf();
  return (
    Number.isFinite(timestamp) &&
    Number.isFinite(collected) &&
    timestamp <= collected &&
    collected <= Date.now() &&
    collected + 24 * 60 * 60 * 1000 > Date.now() &&
    timestamp <= Date.now() &&
    timestamp + 24 * 60 * 60 * 1000 > Date.now() &&
    query.has_evidence &&
    query.result_code === 2 &&
    query.truncated === false
  );
}

export function softwareFix(
  product: NonNullable<OverviewHost["software_assessment"]>["result"]["products"][number],
) {
  return product.reference_fix_complete && product.reference_fix ? product.reference_fix : null;
}
