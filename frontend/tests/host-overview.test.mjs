import assert from "node:assert/strict";
import { test } from "node:test";
import {
  assessmentWarning,
  current,
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
