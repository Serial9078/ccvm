import assert from "node:assert/strict";
import { test } from "node:test";
import {
  hostPresentation,
  collectionFailure,
} from "../src/features/host-audits/host-presentation.ts";

test("fixed transport failures show a specific next step without guessing unknown failures", () => {
  assert.equal(
    collectionFailure("The target rejected authentication").label,
    "Zugangsdaten prüfen",
  );
  assert.equal(
    collectionFailure("The network operation timed out; verify the service, firewall and VPN route")
      .label,
    "VPN & Firewall prüfen",
  );
  assert.equal(
    collectionFailure("WinRM denied access; verify account permissions and endpoint policy").label,
    "Berechtigungen prüfen",
  );
  assert.equal(collectionFailure("Unclassified failure"), null);
});

test("CIM response and service faults retain distinct neutral diagnostics", () => {
  const cases = [
    ["The CIM provider returned invalid or mismatched read-only evidence", "CIM-Antwort prüfen"],
    ["The CIM provider could not complete the bounded OS query", "CIM-Abfrage unvollständig"],
    [
      "WinRM returned a service fault; verify endpoint policy and service limits",
      "WinRM-Dienstfehler prüfen",
    ],
  ];
  for (const [message, label] of cases) {
    const failure = collectionFailure(message);
    assert.equal(failure.label, label);
    assert.doesNotMatch(failure.description, /VPN|Firewall|aktivieren|freigeben/);
  }
  assert.match(collectionFailure(cases[1][0]).description, /Zeitbudget/);
  assert.match(collectionFailure(cases[2][0]).description, /genaue Ursache ist noch offen/);
});

function assessment(status) {
  return {
    id: 1,
    status,
    expired: false,
    current_catalog: true,
    evidence_matches: true,
    engine_current: true,
    evaluated_at: new Date().toISOString(),
    result: {
      valid_until: "2099-01-01T00:00:00Z",
      summary: { cve_matches: 0, matched_product_versions: 0, unassessed_entries: 0 },
      coverage: { package_status: "complete", vendor_catalog: [] },
      products_truncated: false,
    },
  };
}
function host() {
  return {
    asset_id: 1,
    target: "192.0.2.10",
    platform: "windows_server",
    inventory: { id: 1, package_status: "complete" },
    latest_run: { status: "finished", mode: "inventory" },
    issues: [],
    windows_assessment: assessment("meets_catalog_baseline"),
    software_assessment: assessment("no_matches_in_checked_ranges"),
  };
}
function client() {
  const value = host();
  value.platform = "windows_client";
  value.inventory = {
    ...value.inventory,
    mode: "windows_updates",
    completed_at: new Date().toISOString(),
    windows_updates: {
      has_evidence: true,
      queried_at: new Date(Date.now() - 1000).toISOString(),
      status: "complete",
      result_code: 2,
      truncated: false,
    },
  };
  value.windows_assessment.status = "no_update_offers";
  value.windows_assessment.provider = "windows-update-agent";
  value.windows_assessment.catalog_applicable = false;
  value.windows_assessment.current_catalog = false;
  value.windows_assessment.result.windows_updates = {
    summary: { offers: 0, actionable: 0 },
  };
  return value;
}

test("a failed first attempt gives one connection action, never an assessment or safe label", () => {
  const value = host();
  value.platform = "unclassified";
  value.inventory = null;
  value.latest_run.status = "failed";
  value.issues = ["latest_collection_failed", "inventory_missing"];
  const result = hostPresentation(value);
  assert.equal(result.status, "collection");
  assert.equal(result.action, "collect");
  assert.equal(result.label, "Verbindung prüfen");
  assert.match(result.description, /keine Inventurdaten/);
});

test("a failed run distinguishes retained partial evidence from an older successful inventory", () => {
  const value = host();
  value.latest_run = { ...value.latest_run, id: 1, status: "failed" };
  assert.match(hostPresentation(value).description, /unvollständige Inventurdaten/);
  assert.doesNotMatch(hostPresentation(value).description, /älterer Inventurstand/);
  value.latest_run.id = 2;
  assert.match(hostPresentation(value).description, /älterer Inventurstand/);
});

test("failed, partial or stale new collection suppresses a prior clean headline", () => {
  for (const issue of [
    "latest_collection_failed",
    "latest_connection_failed",
    "inventory_partial",
    "inventory_stale",
  ]) {
    const value = host();
    value.issues = [issue];
    const result = hostPresentation(value);
    assert.equal(result.status, "collection", issue);
    assert.equal(result.action, "collect", issue);
  }
  const failed = host();
  failed.latest_run.status = "failed";
  assert.equal(hostPresentation(failed).status, "collection");
});

test("an active request does not offer another collection or assessment", () => {
  for (const status of ["queued", "running"]) {
    const value = host();
    value.latest_run.status = status;
    assert.equal(hostPresentation(value).status, "collection");
    assert.equal(hostPresentation(value).action, null);
  }
});

test("known actionable findings remain first and retain a newer failure caveat", () => {
  const value = host();
  value.windows_assessment.status = "build_gap";
  value.latest_run.status = "failed";
  value.issues = ["latest_collection_failed"];
  const result = hostPresentation(value);
  assert.equal(result.status, "updates");
  assert.equal(result.action, "openWindows");
  assert.match(result.description, /neueste Lauf ist fehlgeschlagen/);
  value.latest_run.status = "running";
  assert.match(hostPresentation(value).description, /neue Prüfung läuft/);
  assert.equal(hostPresentation(value).action, "openWindows");
});

test("a software finding has priority over a passing OS baseline", () => {
  const value = host();
  value.software_assessment.status = "version_matches_found";
  value.software_assessment.result.summary.cve_matches = 5;
  value.software_assessment.result.summary.matched_product_versions = 2;
  const result = hostPresentation(value);
  assert.equal(result.status, "updates");
  assert.equal(result.action, "openSoftware");
  assert.match(result.description, /2 Software-Versionen/);
  value.software_assessment.expired = true;
  assert.equal(hostPresentation(value).status, "assessment");
  assert.equal(hostPresentation(value).action, "assessSoftware");
});

test("clients require a fresh complete online query before offering assessment", () => {
  for (const mutate of [
    (value) => {
      value.inventory.mode = "inventory";
    },
    (value) => {
      value.inventory.windows_updates.result_code = 3;
    },
    (value) => {
      value.inventory.windows_updates.queried_at = "2020-01-01T00:00:00Z";
    },
    (value) => {
      value.inventory.windows_updates.truncated = true;
    },
  ]) {
    const value = client();
    mutate(value);
    const result = hostPresentation(value);
    assert.equal(result.status, "assessment");
    assert.equal(result.action, "queryWindows");
  }
  const value = client();
  value.windows_assessment = null;
  assert.equal(hostPresentation(value).action, "assessWindows");
});

test("expired rules or changed evidence produce an assessment action rather than a clean result", () => {
  for (const field of ["expired", "evidence_matches", "engine_current", "current_catalog"]) {
    const value = host();
    value.windows_assessment[field] = field === "expired";
    assert.equal(hostPresentation(value).status, "assessment", field);
    assert.equal(hostPresentation(value).action, "assessWindows", field);
  }
});

test("unsupported platforms are explicit and VMware never offers an unavailable collection", () => {
  const value = host();
  value.platform = "vmware";
  value.inventory = null;
  value.latest_run.status = "failed";
  const vmware = hostPresentation(value);
  assert.equal(vmware.status, "unsupported");
  assert.equal(vmware.action, null);
  value.platform = "linux";
  assert.equal(hostPresentation(value).action, "collect");
  value.inventory = { id: 1, package_status: "complete" };
  value.latest_run.status = "finished";
  const linux = hostPresentation(value);
  assert.equal(linux.status, "unsupported");
  assert.match(linux.description, /noch nicht verfügbar/);
});

test("out of scope software remains visible without creating an endless re-assessment task", () => {
  const value = host();
  value.software_assessment.result.summary.unassessed_entries = 29;
  const result = hostPresentation(value);
  assert.equal(result.status, "checked");
  assert.equal(result.tone, "info");
  assert.match(result.description, /29 Software-Einträge sind nicht abgedeckt/);
  assert.match(result.description, /keine vollständige Sicherheitsfreigabe/);
  assert.equal(result.action, "openWindows");
});

test("unavailable catalog evidence and truncated results remain incomplete", () => {
  for (const mutate of [
    (value) => {
      value.software_assessment.result.products_truncated = true;
    },
    (value) => {
      value.software_assessment.result.coverage.vendor_catalog = [{ unavailable_count: 1 }];
    },
  ]) {
    const value = host();
    mutate(value);
    assert.equal(hostPresentation(value).status, "assessment");
    assert.equal(hostPresentation(value).action, "openSoftware");
  }
});

test("zero client offers stays neutral and optional offers are not called required patches", () => {
  const value = client();
  assert.equal(hostPresentation(value).status, "checked");
  assert.equal(hostPresentation(value).tone, "info");
  assert.match(hostPresentation(value).description, /keine vollständige Sicherheitsfreigabe/);
  value.windows_assessment.status = "updates_offered";
  value.windows_assessment.result.windows_updates.summary = { offers: 3, actionable: 0 };
  assert.equal(hostPresentation(value).status, "checked");
  assert.equal(hostPresentation(value).label, "Weitere Updateangebote prüfen");
  assert.match(hostPresentation(value).description, /Andere Updateangebote bleiben separat/);
  value.windows_assessment.result.windows_updates.summary.actionable = 2;
  assert.equal(hostPresentation(value).status, "updates");
});

test("CIM basis evidence remains unknown without a repeated shell or update query loop", () => {
  for (const platform of ["windows_server", "windows_client"]) {
    const value = host();
    value.platform = platform;
    value.latest_run.mode = "cim_inventory";
    value.inventory = { id: 1, mode: "cim_inventory", package_status: "not_requested" };
    value.windows_assessment = null;
    value.software_assessment = null;
    value.issues = ["cim_inventory_limited"];
    const result = hostPresentation(value);
    assert.equal(result.status, "unsupported");
    assert.match(result.label, /CIM-Basisinventur erfasst.*Patchstatus offen/);
    assert.match(
      result.description,
      /Installierte Software und fehlende Updates bleiben ungeprüft/,
    );
    assert.equal(result.action, null);
    assert.notEqual(result.tone, "success");
  }
});
