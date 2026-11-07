import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assessmentWarning,
  current,
  freshWindowsUpdateQuery,
  hostState,
  matchesPlatform,
} from "../src/features/host-audits/overview-state.ts";

function assessment(status = "meets_catalog_baseline") {
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
      summary: { cve_matches: 0, unassessed_entries: 0 },
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
    inventory: { id: 1 },
    issues: [],
    windows_assessment: assessment(),
    software_assessment: assessment("no_matches_in_checked_ranges"),
  };
}

test("current status requires matching inventory, current rules, current catalog and a future validity", () => {
  assert.equal(current(assessment()), true);
  for (const field of ["expired", "current_catalog", "evidence_matches", "engine_current"]) {
    const value = assessment();
    value[field] = field === "expired";
    assert.equal(current(value), false, field);
  }
  for (const value of [null, "", "invalid", "2020-01-01T00:00:00Z"]) {
    const row = assessment();
    row.result.valid_until = value;
    assert.equal(current(row), false, String(value));
  }
  assert.equal(current(null), false);
});

test("a fully checked build gap is actionable rather than unknown", () => {
  const value = host();
  value.windows_assessment.status = "build_gap";
  assert.deepEqual(hostState(value), {
    needsWindows: true,
    needsSoftware: false,
    baseline: false,
    attention: true,
    unknown: false,
    collectionIssue: false,
  });
});

test("a scoped baseline match is separate from known software remediation", () => {
  const value = host();
  value.software_assessment.status = "version_matches_found";
  value.software_assessment.result.summary.cve_matches = 3;
  assert.equal(hostState(value).baseline, true);
  assert.equal(hostState(value).attention, true);
  assert.equal(hostState(value).needsSoftware, true);
});

test("a newer failed or incomplete inventory never inherits a green prior baseline", () => {
  for (const issue of [
    "latest_collection_failed",
    "latest_connection_failed",
    "collection_pending",
    "inventory_partial",
    "inventory_stale",
  ]) {
    const value = host();
    value.issues = [issue];
    assert.equal(hostState(value).baseline, false, issue);
    assert.equal(hostState(value).unknown, true, issue);
  }
});

test("unknown or expired software coverage remains distinct from no matches", () => {
  for (const mutation of [
    (value) => {
      value.software_assessment = null;
    },
    (value) => {
      value.software_assessment.expired = true;
    },
    (value) => {
      value.software_assessment.current_catalog = false;
    },
    (value) => {
      value.software_assessment.engine_current = false;
    },
    (value) => {
      value.software_assessment.result.summary.unassessed_entries = 29;
    },
    (value) => {
      value.software_assessment.result.coverage.vendor_catalog = [{ unavailable_count: 1 }];
    },
    (value) => {
      value.software_assessment.status = "coverage_unavailable";
    },
    (value) => {
      value.software_assessment.result.coverage.package_status = "truncated";
    },
    (value) => {
      value.software_assessment.result.products_truncated = true;
    },
  ]) {
    const value = host();
    mutation(value);
    assert.equal(hostState(value).unknown, true);
    assert.equal(hostState(value).attention, false);
  }
});

test("stale catalog, altered evidence, and new rules state why an assessment must be repeated", () => {
  assert.equal(assessmentWarning(null), "Noch nicht bewertet");
  for (const [field, text] of [
    ["engine_current", "Prüfregeln erneuert"],
    ["evidence_matches", "Evidenz geändert"],
    ["current_catalog", "Katalog erneuert"],
  ]) {
    const value = assessment();
    value[field] = false;
    assert.equal(assessmentWarning(value).includes(text), true);
  }
});

test("platform routes filter saved classification exactly and leave unknown hosts unclassified", () => {
  for (const [platform, filter] of [
    ["windows_server", "windows-server"],
    ["windows_client", "windows-client"],
    ["linux", "linux"],
    ["vmware", "vmware"],
  ]) {
    assert.equal(matchesPlatform({ platform }, filter), true);
    assert.equal(matchesPlatform({ platform }, "all"), true);
    assert.equal(matchesPlatform({ platform: "unclassified" }, filter), false);
  }
  assert.equal(matchesPlatform({ platform: "windows_client" }, "windows-server"), false);
  assert.equal(matchesPlatform({ platform: "windows_server" }, "windows-client"), false);
});

function clientQueryHost(status = "updates_offered") {
  const value = host();
  value.platform = "windows_client";
  const queriedAt = new Date(Date.now() - 1000).toISOString();
  value.inventory = {
    id: 20,
    mode: "windows_updates",
    completed_at: new Date().toISOString(),
    os: { family: "Windows", product_type: "1", name: "Synthetic Windows client" },
    windows_updates: {
      has_evidence: true,
      queried_at: queriedAt,
      status: "complete",
      result_code: 2,
      truncated: false,
      total: 2,
    },
  };
  value.windows_assessment = {
    ...assessment(status),
    provider: "windows-update-agent",
    source: "configured_windows_update_service",
    catalog_applicable: false,
    current_catalog: false,
  };
  value.windows_assessment.result.windows_updates = {
    status: "complete",
    queried_at: queriedAt,
    summary: { offers: 2, actionable: status === "updates_offered" ? 2 : 0 },
  };
  return value;
}

test("only Windows Update Agent evidence bypasses an inapplicable MSRC catalog", () => {
  const value = clientQueryHost();
  assert.equal(current(value.windows_assessment), true);
  assert.equal(assessmentWarning(value.windows_assessment), "");
  for (const change of [
    { provider: "msrc-cvrf" },
    { provider: "vendor-software-catalog" },
    { provider: "unknown" },
    { catalog_applicable: true },
  ]) {
    assert.equal(current({ ...value.windows_assessment, ...change }), false);
  }
});

test("no update offers is a neutral result, never a green OS baseline", () => {
  const value = clientQueryHost("no_update_offers");
  assert.equal(hostState(value).attention, false);
  assert.equal(hostState(value).baseline, false);
});

test("feature, definition and optional offers are not required security patch counts", () => {
  const value = clientQueryHost();
  value.windows_assessment.result.windows_updates.summary = {
    offers: 2,
    feature: 1,
    definition: 1,
    optional: 1,
    security: 0,
    quality: 0,
    actionable: 0,
  };
  assert.equal(hostState(value).attention, false);
  value.windows_assessment.result.windows_updates.summary.actionable = 2;
  assert.equal(hostState(value).attention, true);
  assert.equal(hostState(value).baseline, false);
});

test("incomplete or old client queries never produce baseline success", () => {
  for (const status of ["update_query_required", "update_query_incomplete", "stale_evidence"]) {
    const value = clientQueryHost(status);
    assert.equal(hostState(value).unknown, true);
    assert.equal(hostState(value).baseline, false);
  }
});

test("only a fresh explicit successful online query enables client offer assessment", () => {
  assert.equal(freshWindowsUpdateQuery(clientQueryHost()), true);
  for (const change of [
    (value) => {
      value.inventory.mode = "inventory";
    },
    (value) => {
      value.inventory.windows_updates = null;
    },
    (value) => {
      value.inventory.windows_updates.status = "partial";
    },
    (value) => {
      value.inventory.windows_updates.status = "timeout";
    },
    (value) => {
      value.inventory.windows_updates.status = "unavailable";
    },
    (value) => {
      value.inventory.windows_updates.result_code = 3;
    },
    (value) => {
      value.inventory.windows_updates.truncated = true;
    },
    (value) => {
      value.inventory.windows_updates.has_evidence = false;
    },
    (value) => {
      value.inventory.windows_updates.queried_at = new Date(
        Date.now() - 25 * 3600000,
      ).toISOString();
    },
    (value) => {
      value.inventory.windows_updates.queried_at = new Date(Date.now() + 3600000).toISOString();
    },
  ]) {
    const value = clientQueryHost();
    change(value);
    const retained = structuredClone(value.inventory.os);
    assert.equal(freshWindowsUpdateQuery(value), false);
    assert.deepEqual(
      value.inventory.os,
      retained,
      "Failed update lookup keeps collected OS identity",
    );
  }
});
