import type { AuditMode, Credential } from "./api";

export type WindowsCollectionMethod = "cim" | "winrs";
export type CollectionPurpose = "inventory" | "windows_updates";

export function isCimMode(mode?: string) {
  return mode === "cim_connection" || mode === "cim_inventory";
}

/** Restore a saved run explicitly; never turn a denied shell into a fallback. */
export function savedWindowsMethod(mode?: string): WindowsCollectionMethod {
  return isCimMode(mode) ? "cim" : "winrs";
}

export function collectionAuditMode(
  kind: Credential["kind"] | undefined,
  method: WindowsCollectionMethod,
  action: "connection" | "inventory",
): AuditMode {
  if (kind === "winrm" && method === "cim")
    return action === "connection" ? "cim_connection" : "cim_inventory";
  return action;
}

export function auditModeLabel(mode: AuditMode) {
  if (mode === "cim_connection") return "CIM-Verbindungstest · ohne Remote-Shell";
  if (mode === "cim_inventory") return "CIM-Basisinventur · ohne Remote-Shell";
  if (mode === "windows_updates") return "Windows-Updateabfrage mit Inventur · WinRS";
  return mode === "connection" ? "Connection test" : "Host inventory";
}
