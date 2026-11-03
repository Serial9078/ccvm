import assert from "node:assert/strict";
import test from "node:test";
import { serviceCoverage } from "../src/features/networks/coverage.ts";
import { secureAuditAccess } from "../src/features/host-audits/security.ts";

const location = (href) => ({
  href,
  protocol: new URL(href).protocol,
  origin: new URL(href).origin,
});
test("credentials require HTTPS and the same-origin API", () => {
  assert.equal(secureAuditAccess(location("https://ccvm.test/host-audits"), "/api/v1"), true);
  assert.equal(secureAuditAccess(location("http://ccvm.test/host-audits"), "/api/v1"), false);
  assert.equal(
    secureAuditAccess(location("https://ccvm.test/host-audits"), "http://ccvm.test/api/v1"),
    false,
  );
  assert.equal(
    secureAuditAccess(location("https://ccvm.test/host-audits"), "https://other.test/api/v1"),
    false,
  );
});
test("coverage separates no rule, missing result, shared host evidence and pending work", () => {
  const service = (port, checks = []) => ({ port, service: "fixture", state: "open", checks });
  const scan = {
    jobs: [{ plugin: "networkaudit", status: "finished" }],
    observations: [
      {
        services: [
          service(22, [{ status: "completed" }]),
          service(139, [{ status: "host-level" }]),
          { ...service(25), audit_coverage: "no_rule" },
          service(443, [{ status: "unavailable" }]),
        ],
      },
      {
        services: [
          { ...service(25), audit_coverage: "no_rule" },
          { ...service(25), state: "closed" },
        ],
      },
    ],
  };
  const groups = serviceCoverage(scan);
  assert.equal(groups.find((row) => row.label.startsWith("25/")).noRule, 2);
  assert.equal(groups.find((row) => row.label.startsWith("139/")).shared, 1);
  assert.equal(groups.find((row) => row.label.startsWith("443/")).unavailable, 1);
  assert.equal(groups.find((row) => row.label.startsWith("22/")).completed, 1);
  scan.jobs[0].status = "queued";
  scan.observations[0].services.push(service(3389));
  assert.equal(serviceCoverage(scan).find((row) => row.label.startsWith("3389/")).pending, 1);
});
