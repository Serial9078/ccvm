import { current, freshWindowsUpdateQuery, hostState } from "./overview-state.ts";
import type { OverviewHost } from "./overview-state";

export type HostAction =
  "collect" | "queryWindows" | "assessWindows" | "assessSoftware" | "openWindows" | "openSoftware";

export interface HostPresentation {
  status: "updates" | "collection" | "assessment" | "checked" | "unsupported";
  label: string;
  description: string;
  action: HostAction | null;
  actionLabel: string;
  tone: "error" | "warning" | "success" | "info" | "default";
}

/** One next step for the work queue. Individual assessment facts remain separate. */
export function hostPresentation(host: OverviewHost): HostPresentation {
  const state = hostState(host);
  const running = ["queued", "running"].includes(host.latest_run.status);
  const failed = host.latest_run.status === "failed";
  const windows = host.windows_assessment;
  const software = host.software_assessment;
  const collectionCaveat = running
    ? " Eine neue Prüfung läuft; die angezeigten Befunde stammen aus gespeicherten Daten."
    : failed
      ? " Der neueste Lauf ist fehlgeschlagen; gespeicherte Befunde bleiben sichtbar."
      : state.collectionIssue
        ? " Die Inventur muss zusätzlich erneuert werden."
        : "";

  // Never hide a current positive finding behind a second problem with collection.
  if (host.inventory && state.attention) {
    const softwareCount = software?.result.summary.matched_product_versions ?? 0;
    return {
      status: "updates",
      label: "Updatebedarf prüfen",
      description:
        (state.needsWindows
          ? host.platform === "windows_client"
            ? "Die Geräte-Updatequelle bietet Sicherheits- oder Qualitätsupdates an."
            : "Der gespeicherte Windows-Build liegt unter der geprüften OS-Baseline."
          : `${softwareCount} Software-Versionen passen zu geprüften CVE-Meldungen.`) +
        (state.needsWindows && state.needsSoftware
          ? ` Zusätzlich ${softwareCount} Software-Versionen mit CVE-Zuordnungen.`
          : "") +
        collectionCaveat,
      action: state.needsWindows ? "openWindows" : "openSoftware",
      actionLabel: state.needsWindows ? "Updates ansehen" : "Software-Befunde ansehen",
      tone: "error",
    };
  }

  if (running) {
    return {
      status: "collection",
      label: host.latest_run.status === "queued" ? "Prüfung wartet" : "Prüfung läuft",
      description:
        "Der laufende Auftrag wird automatisch aktualisiert. Anschließend den neuen Stand prüfen.",
      action: null,
      actionLabel: "",
      tone: "info",
    };
  }

  if (host.platform === "vmware") {
    return {
      status: "unsupported",
      label: "VMware-Prüfung noch nicht verfügbar",
      description:
        "Netzwerkdaten ersetzen keine authentifizierte ESXi- oder vCenter-Inventur. Ein Patchstatus ist nicht bestimmt.",
      action: null,
      actionLabel: "",
      tone: "default",
    };
  }

  if (
    !host.inventory ||
    failed ||
    state.collectionIssue ||
    host.inventory.package_status !== "complete"
  ) {
    const partial =
      host.inventory &&
      (host.issues.includes("inventory_partial") || host.inventory.package_status !== "complete");
    return {
      status: "collection",
      label: failed
        ? "Verbindung prüfen"
        : !host.inventory
          ? "Inventur fehlt"
          : partial
            ? "Inventur unvollständig"
            : "Inventur erneuern",
      description: failed
        ? host.inventory
          ? host.latest_run.id === host.inventory.id
            ? "Der neueste Versuch hat nur unvollständige Inventurdaten geliefert. Verbindung und Zugang prüfen, danach erneut erfassen."
            : "Der neueste Versuch ist fehlgeschlagen. Verbindung und Zugang prüfen; gespeichert ist ein älterer Inventurstand."
          : "Es liegen keine Inventurdaten vor. Verbindung und Zugang prüfen, danach die Inventur starten."
        : !host.inventory
          ? "Zuerst Betriebssystem und Software erfassen. Ohne Inventur lässt sich der Patchbedarf nicht bewerten."
          : partial
            ? "Die Softwareliste ist unvollständig. Eine neue Inventur wird für einen belastbaren Abgleich benötigt."
            : "Die gespeicherte Inventur ist nicht aktuell. Vor einer neuen Bewertung den Host erneut erfassen.",
      action: "collect",
      actionLabel: failed ? "Verbindung & Inventur prüfen" : "Inventur starten",
      tone: "warning",
    };
  }

  if (host.platform === "unclassified") {
    return {
      status: "collection",
      label: "Betriebssystem nicht bestimmt",
      description:
        "Die vorhandenen Daten reichen für die Plattformzuordnung nicht aus. Verbindungseinstellungen prüfen und die Inventur erneuern.",
      action: "collect",
      actionLabel: "Inventur prüfen",
      tone: "warning",
    };
  }

  if (host.platform === "linux") {
    return {
      status: "unsupported",
      label: "Inventar erfasst · Patchstatus offen",
      description:
        "OS, Kernel und Paketstände sind erfasst. Ein Abgleich mit Sicherheitsupdates der Distribution ist noch nicht verfügbar.",
      action: "collect",
      actionLabel: "Inventur aktualisieren",
      tone: "default",
    };
  }

  if (host.platform === "windows_client" && !freshWindowsUpdateQuery(host)) {
    return {
      status: "assessment",
      label: "Windows-Updateabfrage nötig",
      description:
        "Die Updateangebote der konfigurierten Windows Update- oder WSUS-Quelle fehlen, sind unvollständig oder älter als 24 Stunden.",
      action: "queryWindows",
      actionLabel: "Windows-Updates abfragen",
      tone: "info",
    };
  }

  if (!current(windows)) {
    return {
      status: "assessment",
      label: "Windows-Bewertung offen",
      description:
        "Inventurdaten sind vorhanden. Der Windows-Stand muss mit den aktuellen Prüfdaten bewertet werden.",
      action: "assessWindows",
      actionLabel: "Windows jetzt bewerten",
      tone: "info",
    };
  }

  if (
    !(
      host.platform === "windows_client"
        ? ["updates_offered", "no_update_offers"]
        : ["build_gap", "meets_catalog_baseline"]
    ).includes(windows?.status ?? "")
  ) {
    return {
      status: "unsupported",
      label: "Windows-Stand nicht bewertbar",
      description:
        "Die vorhandenen Prüfdaten liefern für diesen Windows-Stand keinen belastbaren Patchstatus. Den Prüfumfang in der Bewertung ansehen.",
      action: "openWindows",
      actionLabel: "Prüfumfang ansehen",
      tone: "default",
    };
  }

  if (!current(software)) {
    return {
      status: "assessment",
      label: "Software-Bewertung offen",
      description:
        "Der Windows-Stand ist geprüft. Die installierte Software muss noch mit dem aktuellen unterstützten Regelbestand abgeglichen werden.",
      action: "assessSoftware",
      actionLabel: "Software jetzt bewerten",
      tone: "info",
    };
  }

  if (
    software?.status !== "no_matches_in_checked_ranges" ||
    software.result.products_truncated ||
    software.result.coverage.package_status !== "complete" ||
    software.result.coverage.vendor_catalog.some((scope) => scope.unavailable_count > 0)
  ) {
    return {
      status: "assessment",
      label: "Software-Prüfung unvollständig",
      description:
        "Ein Teil der Software-Prüfung ist nicht auswertbar. Verfügbare Ergebnisse und fehlende Abdeckung getrennt ansehen.",
      action: "openSoftware",
      actionLabel: "Prüfumfang ansehen",
      tone: "info",
    };
  }

  const unassessed = software.result.summary.unassessed_entries;
  const optionalOffers =
    host.platform === "windows_client" &&
    (windows?.result.windows_updates?.summary?.offers ?? 0) > 0;
  return {
    status: "checked",
    label: optionalOffers ? "Weitere Updateangebote prüfen" : "Geprüfter Stand ohne Treffer",
    description:
      (host.platform === "windows_server"
        ? "Die geprüfte Windows-OS-Baseline ist erfüllt; unterstützte Software-Regeln zeigen keinen Treffer."
        : optionalOffers
          ? "Die Updatequelle bietet derzeit keine als erforderlich eingestuften Sicherheits- oder Qualitätsupdates an. Andere Updateangebote bleiben separat zu prüfen."
          : "Die konfigurierte Updatequelle bietet derzeit keine Updates an; unterstützte Software-Regeln zeigen keinen Treffer.") +
      (unassessed > 0 ? ` ${unassessed} Software-Einträge sind nicht abgedeckt.` : "") +
      (windows?.result.windows_updates?.reboot_required
        ? " Das Gerät meldet einen ausstehenden Neustart."
        : "") +
      " Das ist keine vollständige Sicherheitsfreigabe.",
    action: "openWindows",
    actionLabel: "Geprüften Stand ansehen",
    tone: "info",
  };
}
