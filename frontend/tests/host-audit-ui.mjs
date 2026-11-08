import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { resolve, extname } from "node:path";
import { chromium } from "playwright";

// All documents, assets and APIs are intercepted. No DNS, remote login or
// network scan is performed; the HTTPS origin exercises the production guard.
const origin = "https://ccvm-ui.test";
const token = "synthetic-operator-token-browser-fixture";
const password = "synthetic-credential-browser-fixture";
const root = resolve("dist");
const browser = await chromium.launch({
  args: ["--no-sandbox"],
  executablePath: process.env.CCVM_TEST_CHROMIUM || undefined,
});
let page;
try {
  page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  page.setDefaultTimeout(15000);
  const errors = [];
  const logoRequests = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  let credentials = [];
  let runs = [];
  let rejectSave = false;
  let modes = [];
  const submissions = [];
  const apiCalls = [];
  let overviewExtras = [];
  let wuaQueryRequests = 0;
  const now = new Date().toISOString();
  let catalog = {
    id: 1,
    source: "msrc-cvrf",
    sha256: "a".repeat(64),
    retrieved_at: now,
    created_at: now,
    coverage_start: "2026-09-01",
    coverage_end: "2026-11-07",
    document_ids: ["2026-Oct", "2026-Nov"],
    entry_count: 3,
    expired: false,
  };
  let assessmentStatus = "build_gap";
  const assessments = [];
  let assessmentRequests = 0;
  let softwareCatalog = {
    id: 1,
    source: "vendor-software-ranges",
    sha256: "c".repeat(64),
    retrieved_at: now,
    created_at: now,
    coverage_start: "2026-09-01",
    coverage_end: "2026-11-07",
    entry_count: 2,
    coverage: [
      {
        product_key: "edge-windows",
        discovered: 1,
        parsed: 1,
        unavailable_cves: [],
        scope: "Recent Edge advisories",
      },
      {
        product_key: "7zip-windows",
        discovered: 1,
        parsed: 1,
        unavailable_cves: [],
        scope: "One curated advisory",
      },
    ],
    expired: false,
  };
  const synchronizedWindowsCatalog = structuredClone(catalog);
  const synchronizedSoftwareCatalog = structuredClone(softwareCatalog);
  let softwareStatus = "version_matches_found";
  const softwareAssessments = [];
  let softwareRequests = 0;
  const stageIds = [
    "discovery",
    "inventory",
    "configuration",
    "os_baseline",
    "software_checks",
    "offered_updates",
  ];
  const platformCapability = (id, name, offered = false) => ({
    id,
    name,
    stages: Object.fromEntries(
      stageIds.map((stage) => [
        stage,
        {
          status:
            stage === "discovery"
              ? "available"
              : stage === "inventory" && id !== "vmware"
                ? "limited"
                : stage === "offered_updates" && offered
                  ? "limited"
                  : "unavailable",
          provider:
            stage === "offered_updates" && offered
              ? "windows-update-agent"
              : "synthetic-capability",
          scope:
            stage === "offered_updates" && offered
              ? "Explizite Onlineabfrage der konfigurierten Updatequelle; keine vollständige CVE-Abdeckung"
              : stage === "os_baseline"
                ? "Für diese Plattform noch keine OS-Patchbewertung angebunden"
                : "Synthetischer, begrenzter Prüfumfang",
          prerequisites: stage === "inventory" ? ["Freigegebenes Inventurkonto"] : [],
          limitations: ["Nicht verfügbare Prüfstufen sind keine Entwarnung"],
        },
      ]),
    ),
  });
  const capabilities = {
    version: "1",
    stage_labels: [
      { id: "discovery", name: "Erkennung" },
      { id: "inventory", name: "Inventur" },
      { id: "configuration", name: "Konfiguration" },
      { id: "os_baseline", name: "OS-Baseline" },
      { id: "software_checks", name: "Software-Regeln" },
      { id: "offered_updates", name: "Updateangebote" },
    ],
    platforms: [
      platformCapability("windows_server", "Windows Server"),
      platformCapability("windows_client", "Windows Clients", true),
      platformCapability("linux", "Linux"),
      platformCapability("vmware", "VMware"),
    ],
    limitations: ["Ein Netzwerkscan ersetzt keine authentifizierte Patchprüfung"],
  };
  function discoveredResponse(offset) {
    const count = offset === 0 ? 200 : 1;
    return {
      customer_id: 1,
      total: 201,
      limit: 200,
      offset,
      has_more: offset === 0,
      items: Array.from({ length: count }, (_, index) => {
        const number = offset + index + 1;
        return {
          asset_id: 300 + number,
          ip_address: `192.0.2.${number}`,
          last_seen: now,
          scan_id: 9,
          discovery_status: "observed",
          services:
            number === 80
              ? [
                  {
                    port: 443,
                    protocol: "tcp",
                    state: "open",
                    service: "https",
                    product: "VMware vSphere SOAP service",
                    version: "",
                    audit_coverage: "unavailable",
                  },
                ]
              : [
                  {
                    port: 22,
                    protocol: "tcp",
                    state: "open",
                    service: "ssh",
                    product: "Reported SSH service",
                    version: "",
                    audit_coverage: "unavailable",
                  },
                ],
          services_total: 1,
          services_truncated: false,
          inventory_status: "not_inventoried",
          host_audit_id: null,
          inventory_collected_at: null,
        };
      }),
      limitations: ["Netzwerkbeobachtungen bestimmen keine OS-Version oder Patchabdeckung"],
    };
  }
  function wuaReport(status = "complete", empty = false, stale = false) {
    const items = empty
      ? []
      : [
          [
            "00000000-0000-0000-0000-000000000001",
            "Synthetic security update",
            "KB9999001",
            "security",
            false,
            true,
          ],
          [
            "00000000-0000-0000-0000-000000000002",
            "Synthetic quality update",
            "KB9999002",
            "quality",
            false,
            true,
          ],
          [
            "00000000-0000-0000-0000-000000000003",
            "Synthetic feature offer",
            "KB9999003",
            "feature",
            true,
            false,
          ],
          [
            "00000000-0000-0000-0000-000000000004",
            "Synthetic definition update",
            "KB9999004",
            "definition",
            false,
            false,
          ],
        ].map(([update_id, title, kb, classification, is_optional, actionable]) => ({
          update_id,
          revision: 1,
          title,
          kbs: [kb],
          classification,
          is_optional,
          is_mandatory: false,
          actionable,
          categories: [
            {
              id: {
                security: "0fa1201d-4330-4fa8-8ae9-b877473b6441",
                quality: "e6cf1350-c01b-414d-a61f-263d14d133b4",
                feature: "3689bdc8-b205-4af4-8d4a-a63924c5e9d5",
                definition: "e0789628-ce08-4437-be74-2495b842f43b",
              }[classification],
              name: classification,
              type: "UpdateClassification",
            },
          ],
          is_hidden: false,
          is_installed: false,
        }));
    return {
      schema_version: 1,
      source: "windows-update-agent",
      mode: "online",
      server_selection: "default",
      queried_at: stale ? new Date(Date.now() - 3 * 86400000).toISOString() : now,
      status,
      result_code: status === "complete" ? 2 : 3,
      total: items.length,
      truncated: false,
      items_truncated: false,
      reboot_required: !empty,
      hidden_updates: "not_assessed",
      drivers: "not_assessed",
      superseded: "excluded",
      items,
      summary: {
        offers: items.length,
        security: empty ? 0 : 1,
        quality: empty ? 0 : 1,
        feature: empty ? 0 : 1,
        definition: empty ? 0 : 1,
        other: 0,
        optional: empty ? 0 : 1,
        optional_unknown: 0,
        actionable: empty ? 0 : 2,
      },
    };
  }
  function clientAssessment(run, status = "updates_offered") {
    const incomplete = [
      "update_query_required",
      "update_query_incomplete",
      "stale_evidence",
    ].includes(status);
    const report =
      status === "update_query_required"
        ? null
        : wuaReport(
            status === "update_query_incomplete" ? "partial" : "complete",
            status === "no_update_offers",
            status === "stale_evidence",
          );
    const valid =
      status === "update_query_required" || status === "stale_evidence"
        ? null
        : new Date(Date.now() + 86400000).toISOString();
    const result = {
      schema_version: 1,
      engine_version: "windows-client-wua-v1",
      provider: "windows-update-agent",
      source: "configured_windows_update_service",
      catalog_applicable: false,
      status,
      reason:
        status === "no_update_offers"
          ? "The configured update source offered no visible software updates. This does not establish that the device is fully patched."
          : incomplete
            ? "Collect a complete and current online Windows update query."
            : "The configured update source offered security, quality, feature and definition updates.",
      evaluated_at: now,
      valid_until: valid,
      evidence_collected_at: now,
      windows_updates: report,
      limitations: [
        "No offers does not mean fully patched. Configured source approvals and deferrals affect results.",
        "No updates are downloaded or installed; drivers and hidden updates are not assessed.",
      ],
    };
    return {
      id: 4000 + run.id,
      customer_id: 1,
      asset_id: run.asset_id ?? 106,
      host_audit_id: run.id,
      catalog_id: null,
      provider: "windows-update-agent",
      source: result.source,
      catalog_applicable: false,
      current_catalog: false,
      evidence_matches: true,
      engine_current: true,
      engine_version: result.engine_version,
      evidence_sha256: "e".repeat(64),
      status,
      result,
      evaluated_at: now,
      expired: !valid,
    };
  }
  function assessSoftware(run) {
    const status = softwareCatalog ? softwareStatus : "catalog_unavailable";
    const available = ["version_matches_found", "no_matches_in_checked_ranges"].includes(status);
    const matched = status === "version_matches_found";
    const result = {
      schema_version: 1,
      engine_version: "software-fixture-v1",
      status,
      reason: available
        ? "Recorded versions were compared with scoped advisory ranges."
        : "Synchronize the software advisory catalog before assessing installed programs.",
      evaluated_at: now,
      valid_until: available ? new Date(Date.now() + 7 * 86400000).toISOString() : null,
      evidence_collected_at: now,
      catalog_retrieved_at: softwareCatalog?.retrieved_at ?? null,
      summary: {
        inventory_entries: 30,
        identified_entries: 1,
        assessed_entries: available ? 1 : 0,
        unassessed_entries: available ? 29 : 30,
        product_versions: available ? 1 : 0,
        matched_product_versions: matched ? 1 : 0,
        cve_matches: matched ? 1 : 0,
      },
      coverage: {
        scope: "windows_machine_registry_vendor_ranges",
        status: available ? "limited" : "unavailable",
        package_status: "complete",
        catalog_start: softwareCatalog?.coverage_start ?? null,
        catalog_end: softwareCatalog?.coverage_end ?? null,
        vendor_catalog: softwareCatalog?.coverage ?? [],
        exploitability: "not_verified",
        per_user: "not_collected",
      },
      products: available
        ? [
            {
              product_key: "edge-windows",
              name: "Microsoft Edge",
              version: "150.0.1000.1",
              publisher: "Microsoft Corporation",
              evidence_basis: "registry-uninstall",
              evidence_count: 1,
              status: matched ? "version_matches_affected_range" : "no_match_in_catalog",
              reason: matched
                ? "The recorded version falls in an explicit affected range."
                : "No recorded version match in the checked catalog scope.",
              checked_cves: 1,
              catalog_scope: "Recent Edge advisories",
              matches_total: matched ? 1 : 0,
              matches_truncated: false,
              reference_fix: matched ? "150.0.1000.2" : null,
              reference_fix_complete: true,
              matches: matched
                ? [
                    {
                      cve: "CVE-2026-99998",
                      title: "Synthetic software advisory",
                      severity: "high",
                      source_product: "Microsoft Edge for Windows",
                      affected_ranges: [{ introduced: "1.0.0.0", fixed: "150.0.1000.2" }],
                      source_urls: [
                        "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99998",
                      ],
                      document_ids: ["CVE-2026-99998"],
                    },
                  ]
                : [],
            },
          ]
        : [],
      unassessed: available
        ? [
            {
              name: "Fixture legacy app",
              version: "2.0",
              publisher: "Fixture publisher",
              reason: "No supported product rule.",
              evidence_count: 1,
            },
            {
              name: "Fixture missing publisher",
              version: "1.0",
              publisher: "",
              reason: "Collect a new inventory with publisher evidence.",
              evidence_count: 28,
            },
          ]
        : [],
      products_total: available ? 1 : 0,
      products_truncated: false,
      unassessed_total: available ? 2 : 0,
      unassessed_truncated: false,
      limitations: [
        "Synthetic software coverage is limited; no target authentication was performed.",
      ],
      sources: [],
    };
    return {
      id: softwareAssessments.length + 1,
      customer_id: 1,
      asset_id: 1,
      host_audit_id: run.id,
      catalog_id: softwareCatalog?.id ?? null,
      engine_version: result.engine_version,
      evidence_sha256: "d".repeat(64),
      status,
      result,
      evaluated_at: now,
      expired: !available,
    };
  }
  function assess(run) {
    if (run.mode === "windows_updates") return clientAssessment(run);
    const status = catalog ? assessmentStatus : "catalog_unavailable";
    const available = status === "build_gap" || status === "meets_catalog_baseline";
    const result = {
      schema_version: 1,
      engine_version: "fixture-engine-v1",
      status,
      reason:
        status === "build_gap"
          ? "The recorded OS build is below the published Microsoft update baseline."
          : status === "identity_incomplete"
            ? "Collect a new inventory to record the Windows installation type."
            : status === "catalog_unavailable"
              ? "Synchronize the Microsoft update catalog before assessing patches."
              : "No applicable build gap in this fixture's catalog scope.",
      evaluated_at: now,
      valid_until: available ? new Date(Date.now() + 7 * 86400000).toISOString() : null,
      evidence_collected_at: now,
      catalog_retrieved_at: catalog?.retrieved_at ?? null,
      installed_build: "10.0.20348.1",
      product: available
        ? {
            id: "11923",
            name: "Windows Server 2022",
            year: "2022",
            installation_type: "Server",
            edition_id: "ServerStandard",
          }
        : null,
      baseline_build: available ? "10.0.20348.9000" : null,
      baseline_kbs: available ? ["KB9999999"] : [],
      cve_references: available
        ? [
            {
              cve: "CVE-2026-99999",
              title: "Synthetic related advisory",
              severity: "Important",
              cvss_score: 7.0,
              kbs: ["KB9999999"],
              source_urls: [],
              document_ids: ["2026-Oct"],
            },
          ]
        : [],
      cve_references_total: available ? 1 : 0,
      cve_references_truncated: false,
      coverage: {
        scope: "windows_server_standard_cumulative_os_build",
        status: available ? "evaluated" : "unavailable",
        catalog_start: catalog?.coverage_start ?? null,
        catalog_end: catalog?.coverage_end ?? null,
        component_applicability: "not_checked",
        third_party_software: "unavailable",
        linux: "unavailable",
        hotpatch: "unavailable",
      },
      limitations: ["Synthetic assessment metadata; no target authentication was performed."],
      sources: available
        ? [
            {
              document_id: "2026-Oct",
              url: "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Oct",
              sha256: "a".repeat(64),
              current_release_date: now,
              initial_release_date: now,
            },
          ]
        : [],
    };
    return {
      id: assessments.length + 1,
      customer_id: 1,
      asset_id: 1,
      host_audit_id: run.id,
      catalog_id: catalog?.id ?? null,
      engine_version: result.engine_version,
      evidence_sha256: "b".repeat(64),
      status,
      result,
      evaluated_at: now,
      expired: !available,
    };
  }
  const evidence = {
    os: {
      family: "Linux",
      name: "Fixture Linux",
      version: "12",
      kernel: "6.1",
      architecture: "x86_64",
      hostname: "lab-host",
    },
    packages: {
      status: "complete",
      source: "dpkg",
      items: [{ name: "fixture-package", version: "1:2.0-3", architecture: "amd64" }],
    },
    hotfixes: { status: "not_applicable", source: "none", items: [] },
  };
  function inventoryEvidence(run) {
    const windows =
      credentials.find((credential) => credential.id === run.credential_id)?.kind === "winrm";
    const data = windows
      ? {
          schema_version: 1,
          os: {
            family: "Windows",
            name: "Fixture Windows Server 2022",
            version: "10.0.20348",
            kernel: "20348.1",
            architecture: "AMD64",
            hostname: "lab-windows",
            product_type: "3",
          },
          packages: { ...evidence.packages, source: "registry-uninstall" },
          hotfixes: {
            status: "complete",
            source: "Get-HotFix",
            items: [{ id: "KB0000001", description: "Fixture update" }],
          },
        }
      : { schema_version: 1, ...evidence };
    if (run.mode === "windows_updates") {
      data.os = {
        ...data.os,
        name: "Fixture Windows 11",
        hostname: "lab-client",
        version: "10.0.26100",
        kernel: "26100.1",
        product_type: "1",
      };
      data.windows_updates = wuaReport();
    }
    return data;
  }
  function overviewAssessment(item) {
    if (!item) return null;
    const copy = structuredClone(item);
    if (copy.result.coverage?.vendor_catalog)
      copy.result.coverage.vendor_catalog = copy.result.coverage.vendor_catalog.map((scope) => ({
        ...scope,
        unavailable_count: scope.unavailable_cves.length,
      }));
    return {
      ...copy,
      current_catalog: copy.catalog_applicable === false ? false : true,
      evidence_matches: true,
      engine_current: true,
    };
  }
  function overviewResponse() {
    const targets = [...new Set(runs.map((run) => run.target))];
    const dynamic = [];
    for (const target of targets) {
      const selected = runs.find(
        (run) =>
          run.target === target &&
          ["inventory", "windows_updates"].includes(run.mode) &&
          !run.failedNoEvidence,
      );
      if (!selected) continue;
      const collected = inventoryEvidence(selected);
      const latest = runs.find((run) => run.target === target);
      const updates = collected.windows_updates;
      dynamic.push({
        asset_id: selected.asset_id ?? 1,
        target,
        platform:
          collected.os.family === "Linux"
            ? "linux"
            : collected.os.product_type === "1"
              ? "windows_client"
              : "windows_server",
        latest_run: {
          id: latest.id,
          credential_id: latest.credential_id,
          port: latest.port,
          winrm_transport: latest.winrm_transport ?? "https",
          ssh_fingerprint: latest.ssh_fingerprint ?? null,
          mode: latest.mode,
          status: latest.job.status,
          message: latest.job.message,
          created_at: latest.created_at,
          completed_at: latest.completed_at,
        },
        inventory: {
          id: selected.id,
          mode: selected.mode,
          completed_at: selected.completed_at,
          os: collected.os,
          package_count: collected.packages.items.length,
          package_status: collected.packages.status,
          hotfix_count: collected.hotfixes.items.length,
          hotfix_status: collected.hotfixes.status,
          windows_updates: updates
            ? {
                has_evidence: true,
                queried_at: updates.queried_at,
                status: updates.status,
                result_code: updates.result_code,
                total: updates.total,
                reboot_required: updates.reboot_required,
                truncated: updates.truncated,
              }
            : null,
        },
        windows_assessment: overviewAssessment(
          assessments.find((item) => item.host_audit_id === selected.id),
        ),
        software_assessment: overviewAssessment(
          softwareAssessments.find((item) => item.host_audit_id === selected.id),
        ),
        issues: latest.failedNoEvidence ? ["latest_collection_failed"] : [],
      });
    }
    const hosts = [
      ...dynamic,
      ...overviewExtras.filter((host) => !dynamic.some((item) => item.target === host.target)),
    ];
    return {
      customer_id: 1,
      generated_at: now,
      hosts,
      issues: [],
      catalogs: {
        windows: catalog
          ? { id: catalog.id, retrieved_at: catalog.retrieved_at, expired: catalog.expired }
          : null,
        software: softwareCatalog
          ? {
              id: softwareCatalog.id,
              retrieved_at: softwareCatalog.retrieved_at,
              expired: softwareCatalog.expired,
            }
          : null,
      },
      limit: 200,
      hosts_total: hosts.length,
      hosts_truncated: false,
    };
  }
  await page.route(`${origin}/**`, async (route) => {
    const request = route.request();
    assert.equal(request.url().includes(token) || request.url().includes(password), false);
    const url = new URL(request.url());
    const path = url.pathname;
    if (path === "/assets/cloudcollab-logo.jpg") logoRequests.push(request.method());
    const respond = (json, status = 200) =>
      route.fulfill({ status, json, headers: { "Cache-Control": "no-store" } });
    if (path.startsWith("/api/v1/")) {
      if (path === "/api/v1/auth/session") return respond({ mode: "legacy", authenticated: false });
      apiCalls.push({ path, method: request.method(), query: url.search });
      if (
        [
          "/api/v1/domains",
          "/api/v1/urls",
          "/api/v1/url-details",
          "/api/v1/url-security",
          "/api/v1/url-screenshots",
          "/api/v1/findings",
          "/api/v1/network-scans",
        ].includes(path)
      ) {
        assert.equal(request.method(), "GET", "Category navigation must never submit a scan");
        assert.equal(
          request.headers()["authorization"],
          undefined,
          "Operator token must not leak into public category clients",
        );
        return respond([]);
      }
      if (path === "/api/v1/network-scans/capabilities")
        return respond({
          enabled: true,
          allowed_cidrs: ["192.0.2.0/24"],
          max_addresses: 256,
          tcp: true,
          udp: false,
          credentialed: false,
        });
      if (path === "/api/v1/customers")
        return respond([{ id: 1, name: "Lab customer", uuid: "synthetic-customer" }]);
      assert.equal(request.headers()["authorization"], `Bearer ${token}`);
      if (path === "/api/v1/host-audits/capabilities") {
        assert.equal(request.method(), "GET");
        return respond(capabilities);
      }
      if (path === "/api/v1/host-audits/discovered") {
        assert.equal(request.method(), "GET");
        assert.equal(url.searchParams.get("customer_id"), "1");
        assert.equal(url.searchParams.get("limit"), "200");
        return respond(discoveredResponse(Number(url.searchParams.get("offset") || 0)));
      }
      if (path === "/api/v1/host-audits/overview") {
        assert.equal(request.method(), "GET");
        assert.equal(url.searchParams.get("customer_id"), "1");
        return respond(overviewResponse());
      }
      if (path === "/api/v1/host-audits/patch-catalog") {
        assert.equal(request.method(), "GET");
        return respond(catalog);
      }
      if (path === "/api/v1/host-audits/software-catalog") {
        assert.equal(request.method(), "GET");
        return respond(softwareCatalog);
      }
      if (/\/api\/v1\/host-audits\/\d+\/assess-software$/.test(path)) {
        assert.equal(request.method(), "POST");
        assert.deepEqual(request.postDataJSON(), {});
        softwareRequests++;
        const run = runs.find((candidate) => candidate.id === Number(path.split("/").at(-2)));
        assert.ok(["inventory", "windows_updates"].includes(run.mode));
        const result = assessSoftware(run);
        softwareAssessments.unshift(result);
        return respond(result);
      }
      if (/\/api\/v1\/host-audits\/\d+\/software-assessments$/.test(path)) {
        assert.equal(request.method(), "GET");
        return respond(
          [
            ...softwareAssessments,
            ...overviewExtras.map((host) => host.software_assessment).filter(Boolean),
          ].filter((item) => item.host_audit_id === Number(path.split("/").at(-2))),
        );
      }
      if (/\/api\/v1\/host-audits\/\d+\/assess$/.test(path)) {
        assert.equal(request.method(), "POST");
        assert.deepEqual(request.postDataJSON(), {});
        assessmentRequests++;
        const run = runs.find((candidate) => candidate.id === Number(path.split("/").at(-2)));
        assert.ok(["inventory", "windows_updates"].includes(run.mode));
        assert.equal(
          credentials.find((credential) => credential.id === run.credential_id).kind,
          "winrm",
        );
        const result = assess(run);
        assessments.unshift(result);
        return respond(result);
      }
      if (/\/api\/v1\/host-audits\/\d+\/assessments$/.test(path)) {
        assert.equal(request.method(), "GET");
        return respond(
          [
            ...assessments,
            ...overviewExtras.map((host) => host.windows_assessment).filter(Boolean),
          ].filter((item) => item.host_audit_id === Number(path.split("/").at(-2))),
        );
      }
      if (path === "/api/v1/host-audits/credentials" && request.method() === "POST") {
        const payload = request.postDataJSON();
        assert.equal(payload.customer_id, 1);
        assert.equal(payload.password, password);
        assert.deepEqual(payload.allowed_cidrs, ["192.0.2.0/24"]);
        if (rejectSave) return respond({ detail: "Fixture save rejected" }, 422);
        const credential = {
          id: credentials.length + 1,
          customer_id: 1,
          name: payload.name,
          kind: payload.kind,
          username: payload.username,
          allowed_cidrs: payload.allowed_cidrs,
          enabled: true,
        };
        credentials.push(credential);
        return respond(credential, 201);
      }
      if (path === "/api/v1/host-audits/credentials") return respond(credentials);
      if (/\/api\/v1\/host-audits\/credentials\/\d+\/revoke$/.test(path)) {
        const credential = credentials.find((cred) => cred.id === Number(path.split("/").at(-2)));
        credential.enabled = false;
        return respond(credential);
      }
      if (path === "/api/v1/host-audits" && request.method() === "POST") {
        const payload = request.postDataJSON();
        modes.push(payload.mode);
        submissions.push(payload);
        assert.equal(
          payload.target,
          payload.mode === "windows_updates" ? "192.0.2.30" : "192.0.2.1",
        );
        if (payload.mode === "windows_updates") wuaQueryRequests++;
        const credential = credentials.find((cred) => cred.id === payload.credential_id);
        if (credential.kind === "winrm") {
          assert.ok(["https", "http_ntlm"].includes(payload.winrm_transport));
          assert.equal(Object.hasOwn(payload, "ssh_fingerprint"), false);
        } else {
          assert.equal(Object.hasOwn(payload, "winrm_transport"), false);
          assert.equal(payload.ssh_fingerprint, "SHA256:" + "A".repeat(43));
        }
        const run = {
          id: runs.length + 1,
          customer_id: 1,
          asset_id: payload.target === "192.0.2.30" ? 106 : 1,
          credential_id: credential.id,
          target: payload.target,
          port:
            payload.port ||
            (credential.kind === "winrm"
              ? payload.winrm_transport === "http_ntlm"
                ? 5985
                : 5986
              : 22),
          ...(credential.kind === "winrm" ? { winrm_transport: payload.winrm_transport } : {}),
          mode: payload.mode,
          ssh_fingerprint: payload.ssh_fingerprint ?? null,
          created_at: now,
          completed_at: now,
          cancel_requested: false,
          job: {
            id: runs.length + 1,
            status: "finished",
            progress: 100,
            message: "Fixture inventory finished",
          },
        };
        runs.unshift(run);
        return respond(run, 201);
      }
      if (path === "/api/v1/host-audits") return respond(runs);
      if (/\/api\/v1\/host-audits\/\d+$/.test(path)) {
        const run = runs.find((candidate) => candidate.id === Number(path.split("/").at(-1)));
        return respond({ ...run, inventory: run.failedNoEvidence ? null : inventoryEvidence(run) });
      }
      throw new Error(`Unexpected fixture endpoint ${path}`);
    }
    const file = [
      "/host-audits",
      "/windows-servers",
      "/windows-clients",
      "/linux",
      "/vmware",
      "/domains",
      "/urls",
      "/networks",
      "/",
    ].includes(path)
      ? resolve(root, "index.html")
      : resolve(root, path.replace(/^\//, ""));
    assert.ok(file.startsWith(root + "/"));
    const contentType =
      {
        ".html": "text/html",
        ".js": "text/javascript",
        ".css": "text/css",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".svg": "image/svg+xml",
      }[extname(file)] || "application/octet-stream";
    return route.fulfill({ body: await readFile(file), contentType });
  });
  async function openInventory() {
    const form = page.getByTestId("inventory-form-dialog");
    await form.waitFor({ state: "hidden" });
    await page.getByRole("button", { name: "Inventur starten", exact: true }).click();
    await form.waitFor();
  }
  async function closeInventory() {
    if (await page.getByTestId("inventory-form-dialog").isVisible())
      await page.getByRole("button", { name: "Inventur schließen", exact: true }).click();
    await page.getByTestId("inventory-form-dialog").waitFor({ state: "hidden" });
  }
  async function workspaceTab(name) {
    await page.getByRole("tab", { name: new RegExp(`^${name}`) }).click();
  }
  async function openHistory() {
    await workspaceTab("Prüfverlauf");
    const heading = page.getByRole("button", { name: /Verlauf und technische Details/ });
    if ((await heading.getAttribute("aria-expanded")) !== "true") await heading.click();
  }
  async function openCatalogs() {
    await workspaceTab("Datenquellen");
    const heading = page.getByRole("button", { name: /Kataloge und Prüfumfang/ });
    if ((await heading.getAttribute("aria-expanded")) !== "true") await heading.click();
  }
  async function historyAction(name) {
    await openHistory();
    await page.getByRole("button", { name, exact: true }).click();
  }
  await page.goto(`${origin}/host-audits?customer_id=1`);
  await page.getByRole("heading", { name: "Host-Übersicht", exact: true }).waitFor();
  const logo = page.getByRole("img", { name: "CloudCollab", exact: true });
  await logo.waitFor();
  await logo.evaluate((element) => element.decode());
  assert.equal(await logo.getAttribute("src"), "/assets/cloudcollab-logo.jpg");
  assert.equal(
    await logo.evaluate((element) => element.complete && element.naturalWidth > 0),
    true,
  );
  assert.ok(logoRequests.length >= 1 && logoRequests.every((method) => method === "GET"));
  assert.equal(
    createHash("sha256")
      .update(await readFile(resolve(root, "assets/cloudcollab-logo.jpg")))
      .digest("hex"),
    "088bb3bb2fa7ef8ac5a1e17f62d114d094528be72f8c0f05f2d2cf19aeaeecd3",
    "The built app must use the original CloudCollab JPEG bytes",
  );
  assert.deepEqual(
    await page.evaluate(() => ({
      body: getComputedStyle(document.body).backgroundColor,
      header: getComputedStyle(document.querySelector("header")).backgroundColor,
    })),
    { body: "rgb(8, 8, 8)", header: "rgb(0, 0, 0)" },
  );

  await page.getByRole("combobox", { name: "Customer", exact: true }).click();
  await page.getByRole("option", { name: "Lab customer" }).click();
  await page.getByLabel("Operator token", { exact: true }).fill(token);
  await page.waitForFunction(() => {
    const button = [...document.querySelectorAll("button")].find(
      (element) => element.textContent === "Unlock host audits",
    );
    return (
      button &&
      !button.disabled &&
      getComputedStyle(button).backgroundColor === "rgb(250, 250, 250)"
    );
  });
  assert.deepEqual(
    await page
      .getByRole("button", { name: "Unlock host audits", exact: true })
      .evaluate((element) => ({
        background: getComputedStyle(element).backgroundColor,
        color: getComputedStyle(element).color,
      })),
    { background: "rgb(250, 250, 250)", color: "rgb(0, 0, 0)" },
    "Primary actions follow the monochrome CloudCollab brand",
  );
  await page.getByRole("button", { name: "Unlock host audits" }).click();
  await openInventory();
  await page.getByRole("button", { name: "Add credential" }).click();
  await page.getByLabel("Credential name", { exact: true }).fill("Linux lab");
  await page.getByLabel("Username", { exact: true }).fill("inventory");
  await page.getByLabel("Allowed credential CIDRs", { exact: true }).fill("192.0.2.0/24");
  await page.getByLabel("Password", { exact: true }).fill(password);
  rejectSave = true;
  await page.getByRole("button", { name: "Save credential", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Add encrypted credential", exact: true })
    .getByText("Fixture save rejected", { exact: true })
    .waitFor();
  assert.equal(await page.getByLabel("Password", { exact: true }).inputValue(), "");
  rejectSave = false;
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save credential", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Add encrypted credential", exact: true })
    .waitFor({ state: "hidden" });
  await page.getByLabel("Target IP", { exact: true }).fill("192.0.2.1");
  assert.equal(
    await page.getByRole("button", { name: "Collect inventory", exact: true }).isDisabled(),
    true,
  );
  await page
    .getByLabel("Approved SSH fingerprint", { exact: true })
    .fill("SHA256:" + "A".repeat(43));
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await openHistory();
  await page.getByText("Fixture inventory finished", { exact: true }).waitFor();
  await openInventory();
  await page.getByRole("button", { name: "Collect inventory", exact: true }).click();
  await page.getByRole("button", { name: "View evidence", exact: true }).first().waitFor();
  assert.equal(
    await page.getByRole("button", { name: "Assess Windows patches", exact: true }).count(),
    0,
  );
  assert.equal(
    await page.getByRole("button", { name: "Assess installed software", exact: true }).count(),
    0,
  );
  await page.getByRole("button", { name: "View evidence", exact: true }).first().click();
  await page.getByRole("dialog").getByText("fixture-package", { exact: true }).waitFor();
  assert.equal(await page.getByRole("dialog").getByText("1:2.0-3", { exact: true }).count(), 1);
  await mkdir("test-artifacts", { recursive: true });
  await page.screenshot({
    path: "test-artifacts/authenticated-evidence.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("button", { name: "Close evidence", exact: true }).click();
  await page.screenshot({
    path: "test-artifacts/authenticated-inventory.png",
    fullPage: true,
    animations: "disabled",
  });
  await openInventory();
  await page.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await page.getByRole("button", { name: "Keep credential", exact: true }).click();
  assert.equal(credentials[0].enabled, true);
  await page.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await page.getByRole("button", { name: "Revoke and erase secret", exact: true }).click();
  await page
    .getByRole("button", { name: "Revoke and erase secret", exact: true })
    .waitFor({ state: "hidden" });
  assert.equal(credentials[0].enabled, false);
  assert.deepEqual(modes, ["connection", "inventory"]);
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await page.getByLabel("Credential name", { exact: true }).fill("Windows lab");
  await page.getByRole("combobox", { name: "Authentication", exact: true }).click();
  await page.getByRole("option", { name: "Windows · WinRM / NTLM", exact: true }).click();
  await page.getByLabel("Username", { exact: true }).fill("LAB\\inventory");
  await page.getByLabel("Allowed credential CIDRs", { exact: true }).fill("192.0.2.0/24");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save credential", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Add encrypted credential", exact: true })
    .waitFor({ state: "hidden" });
  const connection = page.getByRole("combobox", { name: "WinRM connection", exact: true });
  await connection.waitFor();
  assert.equal(await connection.innerText(), "HTTPS / NTLM · verified certificate");
  assert.equal(await page.getByLabel("Approved SSH fingerprint", { exact: true }).count(), 0);
  await page.getByText("Default 5986 · HTTPS / NTLM", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page.getByText("HTTPS / NTLM · certificate validation required", { exact: true }).waitFor();
  assert.equal(submissions.at(-1).winrm_transport, "https");
  assert.equal(Object.hasOwn(submissions.at(-1), "port"), false);
  await openInventory();
  await page.getByLabel("Port (optional)", { exact: true }).fill("5990");
  await connection.click();
  await page.getByRole("option", { name: "HTTP / NTLM · encrypted messages", exact: true }).click();
  await page.getByRole("listbox").waitFor({ state: "hidden" });
  assert.equal(await page.getByLabel("Port (optional)", { exact: true }).inputValue(), "");
  await page.getByText("Default 5985 · HTTP / NTLM", { exact: true }).waitFor();
  await page
    .getByText("Messages are encrypted; server identity is not verified by a certificate.", {
      exact: true,
    })
    .waitFor();
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page.getByText("HTTP / NTLM · message encryption required", { exact: true }).waitFor();
  assert.equal(submissions.at(-1).winrm_transport, "http_ntlm");
  assert.equal(Object.hasOwn(submissions.at(-1), "port"), false);
  await openInventory();
  await page.getByLabel("Port (optional)", { exact: true }).fill("5991");
  await page.getByRole("button", { name: "Collect inventory", exact: true }).click();
  await page.getByText("192.0.2.1:5991", { exact: true }).waitFor();
  assert.equal(submissions.at(-1).winrm_transport, "http_ntlm");
  assert.equal(submissions.at(-1).port, 5991);
  await page.screenshot({
    path: "test-artifacts/authenticated-winrm-http.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("button", { name: "View evidence", exact: true }).first().click();
  await page
    .getByRole("dialog")
    .getByText(
      "HTTP / NTLM · message encryption required. Server identity was not verified by a certificate.",
      { exact: true },
    )
    .waitFor();
  await page
    .getByRole("dialog")
    .getByText("Fixture Windows Server 2022", { exact: true })
    .waitFor();
  await page.getByRole("button", { name: "Close evidence", exact: true }).click();
  await openCatalogs();
  const inventorySubmissions = submissions.length;
  const retainedRuns = JSON.stringify(runs);
  await historyAction("Assess Windows patches");
  await page
    .getByRole("dialog")
    .getByText("Below Microsoft update baseline", { exact: true })
    .waitFor();
  await page.getByRole("dialog").getByText("10.0.20348.9000", { exact: true }).waitFor();
  await page.getByRole("dialog").getByRole("link", { name: "KB9999999", exact: true }).waitFor();
  await page
    .getByRole("dialog")
    .getByRole("link", { name: "CVE-2026-99999", exact: true })
    .waitFor();
  await page
    .getByRole("dialog")
    .getByText(
      "References associated with the baseline update. These are not confirmed vulnerabilities on this host.",
      { exact: true },
    )
    .waitFor();
  assert.equal(submissions.length, inventorySubmissions);
  assert.equal(JSON.stringify(runs), retainedRuns);
  await page.screenshot({
    path: "test-artifacts/authenticated-patch-assessment.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("button", { name: "Close assessment", exact: true }).click();
  assessmentStatus = "identity_incomplete";
  await historyAction("Assess Windows patches");
  await page
    .getByRole("dialog")
    .getByText("More OS identity evidence needed", { exact: true })
    .waitFor();
  await page
    .getByRole("dialog")
    .getByText("Collect a new inventory to record the Windows installation type.", { exact: true })
    .waitFor();
  await page.getByRole("button", { name: "Close assessment", exact: true }).click();
  catalog = null;
  await openCatalogs();
  await page.getByRole("button", { name: "Refresh catalog status", exact: true }).click();
  await page
    .getByText(
      "No Microsoft update catalog has been synchronized. Patch assessments will report missing coverage.",
      { exact: true },
    )
    .waitFor();
  await historyAction("Assess Windows patches");
  await page
    .getByRole("dialog")
    .getByText("Microsoft update catalog unavailable", { exact: true })
    .waitFor();
  assert.equal(
    await page
      .getByRole("dialog")
      .getByText(
        "This saved assessment has expired. Collect current inventory or synchronize the catalog, then assess again.",
        { exact: true },
      )
      .count(),
    0,
  );
  assert.equal(assessmentRequests, 3);
  assert.equal(submissions.length, inventorySubmissions);
  assert.equal(JSON.stringify(runs), retainedRuns);
  await page.getByRole("button", { name: "Close assessment", exact: true }).click();
  const expired = structuredClone(assessments.find((item) => item.status === "build_gap"));
  expired.id = 4;
  expired.status = "meets_catalog_baseline";
  expired.result.status = expired.status;
  expired.result.reason = "Historical build comparison retained for review.";
  expired.expired = true;
  expired.result.valid_until = new Date(Date.now() - 86400000).toISOString();
  assessments.unshift(expired);
  await historyAction("View assessments");
  await page
    .getByRole("dialog")
    .getByRole("combobox", { name: "Saved assessment", exact: true })
    .waitFor();
  await page
    .getByRole("dialog")
    .getByText("Meets catalog build baseline", { exact: true })
    .waitFor();
  await page
    .getByRole("dialog")
    .getByText(
      "This saved assessment has expired. Collect current inventory or synchronize the catalog, then assess again.",
      { exact: true },
    )
    .waitFor();
  assert.equal(assessmentRequests, 3);
  await page.getByRole("button", { name: "Close assessment", exact: true }).click();
  await historyAction("Assess installed software");
  const softwareDialog = page.getByRole("dialog");
  await softwareDialog.getByText("Affected version ranges matched", { exact: true }).waitFor();
  await softwareDialog
    .getByText("30 inventory entries · 1 assessed · 29 unassessed", { exact: true })
    .waitFor();
  await softwareDialog.getByText("CVE-2026-99998", { exact: true }).waitFor();
  await softwareDialog.getByText("Fixed in 150.0.1000.2", { exact: false }).waitFor();
  await softwareDialog.getByText("Fixture legacy app", { exact: true }).waitFor();
  await softwareDialog
    .getByText("Collect a new inventory with publisher evidence.", { exact: false })
    .waitFor();
  assert.equal(
    await softwareDialog.getByRole("link", { name: "Source 1", exact: true }).getAttribute("href"),
    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-99998",
  );
  assert.equal(submissions.length, inventorySubmissions);
  assert.equal(JSON.stringify(runs), retainedRuns);
  await page.screenshot({
    path: "test-artifacts/authenticated-software-assessment.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("button", { name: "Close software assessment", exact: true }).click();
  softwareStatus = "no_matches_in_checked_ranges";
  await historyAction("Assess installed software");
  await softwareDialog
    .getByText("No match in the checked advisory ranges", { exact: true })
    .waitFor();
  await softwareDialog.getByText("Unassessed software · 2", { exact: true }).waitFor();
  assert.equal(await softwareDialog.locator(".MuiChip-colorSuccess").count(), 0);
  await page.getByRole("button", { name: "Close software assessment", exact: true }).click();
  softwareCatalog = null;
  await openCatalogs();
  await page.getByRole("button", { name: "Refresh software catalog status", exact: true }).click();
  await page
    .getByText(
      "No software advisory catalog has been synchronized. Installed software assessments will report missing coverage.",
      { exact: true },
    )
    .waitFor();
  await historyAction("Assess installed software");
  await softwareDialog
    .getByText("Software advisory catalog unavailable", { exact: true })
    .waitFor();
  assert.equal(
    await softwareDialog
      .getByText(
        "This saved software assessment has expired. Collect current inventory or synchronize the catalog, then assess again.",
        { exact: true },
      )
      .count(),
    0,
  );
  await page.getByRole("button", { name: "Close software assessment", exact: true }).click();
  const expiredSoftware = structuredClone(
    softwareAssessments.find((item) => item.status === "no_matches_in_checked_ranges"),
  );
  expiredSoftware.id = 4;
  expiredSoftware.expired = true;
  expiredSoftware.result.valid_until = new Date(Date.now() - 86400000).toISOString();
  softwareAssessments.unshift(expiredSoftware);
  await historyAction("View software assessments");
  await softwareDialog
    .getByRole("combobox", { name: "Saved software assessment", exact: true })
    .waitFor();
  await softwareDialog
    .getByText(
      "This saved software assessment has expired. Collect current inventory or synchronize the catalog, then assess again.",
      { exact: true },
    )
    .waitFor();
  assert.equal(softwareRequests, 3);
  assert.equal(submissions.length, inventorySubmissions);
  assert.equal(JSON.stringify(runs), retainedRuns);
  await page.getByRole("button", { name: "Close software assessment", exact: true }).click();
  await openInventory();
  await connection.click();
  await page
    .getByRole("option", { name: "HTTPS / NTLM · verified certificate", exact: true })
    .click();
  assert.equal(await page.getByLabel("Port (optional)", { exact: true }).inputValue(), "");
  assert.equal(
    await page
      .getByText("Messages are encrypted; server identity is not verified by a certificate.", {
        exact: true,
      })
      .count(),
    0,
  );
  await page.getByText("Default 5986 · HTTPS / NTLM", { exact: true }).waitFor();
  await closeInventory();
  // Coverage and discovered-device preparation read private metadata only.
  // Neither expanding a capability nor preparing a target authenticates to it.
  const metadataPosts = apiCalls.filter((call) => call.method !== "GET").length;
  assert.equal(
    apiCalls.filter(
      (call) => call.path.endsWith("/capabilities") && call.path.includes("host-audits"),
    ).length,
    0,
  );
  assert.equal(apiCalls.filter((call) => call.path.endsWith("/discovered")).length, 0);
  await openCatalogs();
  const capabilityPanel = page.getByTestId("capabilities-panel");
  await capabilityPanel
    .getByRole("button", { name: "Prüfumfang nach Plattform", exact: true })
    .click();
  const capabilityTable = page.getByRole("table", { name: "Plattform-Prüfumfang", exact: true });
  await capabilityTable.waitFor();
  for (const platform of ["VMware", "Linux"]) {
    const row = capabilityTable
      .getByRole("row")
      .filter({ has: page.getByText(platform, { exact: true }) });
    await row
      .getByRole("button", {
        name: `${platform} · OS-Baseline: Nicht verfügbar. Prüfumfang anzeigen`,
        exact: true,
      })
      .waitFor();
  }
  await capabilityTable
    .getByRole("button", {
      name: "Windows Clients · Updateangebote: Begrenzt. Prüfumfang anzeigen",
      exact: true,
    })
    .click();
  const scopeDialog = page.getByRole("dialog", {
    name: "Windows Clients · Updateangebote",
    exact: true,
  });
  await scopeDialog
    .getByText(
      "Explizite Onlineabfrage der konfigurierten Updatequelle; keine vollständige CVE-Abdeckung",
      { exact: true },
    )
    .waitFor();
  await scopeDialog.getByRole("button", { name: "Schließen", exact: true }).click();
  await scopeDialog.waitFor({ state: "hidden" });
  await capabilityPanel
    .getByRole("button", { name: "Prüfumfang nach Plattform", exact: true })
    .click();
  await workspaceTab("Erkannte Geräte");
  const discoveryPanel = page.getByTestId("discovered-devices-panel");
  await discoveryPanel.getByRole("button", { name: "Erkannte Geräte", exact: true }).click();
  const deviceTable = page.getByRole("table", { name: "Erkannte Netzwerkgeräte", exact: true });
  const observed = deviceTable
    .getByRole("row")
    .filter({ has: page.getByText("192.0.2.80", { exact: true }) });
  await observed.getByText("Gemeldet: VMware vSphere SOAP service", { exact: true }).waitFor();
  await observed.getByText("Inventur fehlt", { exact: true }).waitFor();
  assert.equal(await observed.locator(".MuiChip-colorSuccess").count(), 0);
  assert.equal(
    await discoveryPanel
      .getByRole("link", { name: "Netzwerk öffnen", exact: true })
      .getAttribute("href"),
    "/networks?customer_id=1",
  );
  await discoveryPanel.getByRole("button", { name: "Weiter", exact: true }).click();
  await deviceTable.getByText("192.0.2.201", { exact: true }).waitFor();
  assert.ok(
    apiCalls.some(
      (call) =>
        call.path.endsWith("/discovered") &&
        new URLSearchParams(call.query).get("offset") === "200",
    ),
  );
  await discoveryPanel.getByRole("button", { name: "Zurück", exact: true }).click();
  await observed.waitFor();
  await observed
    .getByRole("button", { name: "Inventur vorbereiten für 192.0.2.80", exact: true })
    .click();
  const prepared = page.getByTestId("inventory-form-dialog");
  await prepared.waitFor();
  assert.equal(await prepared.getByLabel("Target IP", { exact: true }).inputValue(), "192.0.2.80");
  assert.equal(
    await prepared
      .getByRole("combobox", { name: "Credential", exact: true })
      .locator("..")
      .locator("input")
      .inputValue(),
    "",
  );
  assert.equal(
    await prepared.getByRole("button", { name: "Collect inventory", exact: true }).isDisabled(),
    true,
  );
  assert.equal(apiCalls.filter((call) => call.method !== "GET").length, metadataPosts);
  await closeInventory();
  await discoveryPanel.getByRole("button", { name: /Erkannte Geräte/ }).click();
  // The default surface shows patch decisions; historical runs, catalogs and
  // collection forms remain available without displacing the current overview.
  catalog = structuredClone(synchronizedWindowsCatalog);
  softwareCatalog = structuredClone(synchronizedSoftwareCatalog);
  const freshUntil = new Date(Date.now() + 86400000).toISOString();
  function sampleHost(
    id,
    target,
    platform,
    patchStatus,
    softwareState = "no_matches_in_checked_ranges",
  ) {
    const os =
      platform === "linux"
        ? {
            family: "Linux",
            name: "Fixture Linux",
            hostname: `fixture-${id}`,
            version: "12",
            kernel: "6.1",
          }
        : {
            family: "Windows",
            name:
              platform === "windows_client" ? "Fixture Windows 11" : "Fixture Windows Server 2022",
            hostname: `fixture-${id}`,
            version: "10.0.20348",
            kernel: "20348.9000",
            product_type: platform === "windows_client" ? "1" : "3",
          };
    const windows = structuredClone(assessments.find((item) => item.status === "build_gap"));
    Object.assign(windows, {
      id: 1000 + id,
      host_audit_id: id,
      status: patchStatus,
      expired: false,
      current_catalog: true,
      evidence_matches: true,
      engine_current: true,
    });
    Object.assign(windows.result, {
      status: patchStatus,
      valid_until: freshUntil,
      installed_build: patchStatus === "build_gap" ? "10.0.20348.1" : "10.0.20348.9000",
    });
    const software = structuredClone(
      softwareAssessments.find((item) => item.status === "version_matches_found"),
    );
    Object.assign(software, {
      id: 2000 + id,
      host_audit_id: id,
      status: softwareState,
      expired: false,
      current_catalog: true,
      evidence_matches: true,
      engine_current: true,
    });
    Object.assign(software.result, { status: softwareState, valid_until: freshUntil });
    software.result.summary = {
      ...software.result.summary,
      inventory_entries: 1,
      assessed_entries: 1,
      unassessed_entries: 0,
      matched_product_versions: softwareState === "version_matches_found" ? 1 : 0,
      cve_matches: softwareState === "version_matches_found" ? 1 : 0,
    };
    if (softwareState !== "version_matches_found")
      software.result.products.forEach((product) => {
        product.matches = [];
        product.matches_total = 0;
        product.status = "no_match_in_catalog";
      });
    software.result.coverage.vendor_catalog = software.result.coverage.vendor_catalog.map(
      (scope) => ({ ...scope, unavailable_count: scope.unavailable_cves.length }),
    );
    return {
      asset_id: id,
      target,
      platform,
      latest_run: {
        id,
        credential_id: 2,
        port: 5985,
        winrm_transport: "http_ntlm",
        ssh_fingerprint: null,
        mode: "inventory",
        status: "finished",
        message: "Fixture collection finished",
        created_at: now,
        completed_at: now,
      },
      inventory: {
        id,
        completed_at: now,
        os,
        package_count: 1,
        package_status: "complete",
        hotfix_count: 1,
        hotfix_status: "complete",
      },
      windows_assessment: windows,
      software_assessment: software,
      issues: [],
    };
  }
  const needsPatch = sampleHost(
    101,
    "192.0.2.20",
    "windows_server",
    "build_gap",
    "version_matches_found",
  );
  needsPatch.windows_assessment.result.cve_references_total = 977;
  const baselineHost = sampleHost(102, "192.0.2.21", "windows_server", "meets_catalog_baseline");
  const staleHost = sampleHost(103, "192.0.2.22", "windows_server", "meets_catalog_baseline");
  staleHost.windows_assessment.expired = true;
  staleHost.windows_assessment.result.valid_until = new Date(Date.now() - 86400000).toISOString();
  staleHost.issues = ["windows_assessment_stale"];
  const failedHost = sampleHost(104, "192.0.2.23", "windows_server", "meets_catalog_baseline");
  failedHost.latest_run = {
    ...failedHost.latest_run,
    id: 204,
    status: "failed",
    message: "The fixed inventory command failed",
  };
  failedHost.issues = ["latest_collection_failed"];
  const unknownHost = sampleHost(105, "192.0.2.24", "windows_server", "meets_catalog_baseline");
  unknownHost.windows_assessment = null;
  unknownHost.software_assessment = null;
  unknownHost.issues = ["windows_assessment_missing", "software_assessment_missing"];
  const clientHost = sampleHost(106, "192.0.2.30", "windows_client", "unsupported");
  clientHost.windows_assessment = null;
  clientHost.inventory.mode = "inventory";
  clientHost.inventory.windows_updates = null;
  const queryClientHost = (id, target, status) => {
    const value = sampleHost(id, target, "windows_client", "unsupported");
    const report = clientAssessment({ id, asset_id: id }, status);
    value.windows_assessment = report;
    value.inventory.mode = "windows_updates";
    value.latest_run.mode = "windows_updates";
    const query = report.result.windows_updates;
    value.inventory.windows_updates = query
      ? {
          has_evidence: true,
          queried_at: query.queried_at,
          status: query.status,
          result_code: query.result_code,
          total: query.total,
          reboot_required: query.reboot_required,
          truncated: query.items_truncated,
        }
      : null;
    return value;
  };
  const noOffers = queryClientHost(109, "192.0.2.31", "no_update_offers");
  const incompleteClient = queryClientHost(110, "192.0.2.32", "update_query_incomplete");
  const staleClient = queryClientHost(111, "192.0.2.33", "stale_evidence");
  const timeoutClient = queryClientHost(112, "192.0.2.34", "update_query_incomplete");
  timeoutClient.windows_assessment.result.windows_updates.status = "timeout";
  timeoutClient.inventory.windows_updates.status = "timeout";
  timeoutClient.latest_run.status = "failed";
  timeoutClient.issues = ["latest_collection_failed"];

  const linuxHost = sampleHost(107, "192.0.2.40", "linux", "unsupported");
  linuxHost.windows_assessment = null;
  linuxHost.software_assessment = null;
  const unclassified = sampleHost(108, "192.0.2.50", "unclassified", "unsupported");
  unclassified.inventory = null;
  unclassified.windows_assessment = null;
  unclassified.software_assessment = null;
  unclassified.latest_run.status = "failed";
  unclassified.issues = ["latest_collection_failed"];
  const partialHost = sampleHost(113, "192.0.2.60", "windows_server", "meets_catalog_baseline");
  partialHost.latest_run.status = "failed";
  partialHost.latest_run.message = "Fixture partial inventory";
  partialHost.inventory.package_status = "partial";
  partialHost.windows_assessment = null;
  partialHost.software_assessment = null;
  partialHost.issues = ["latest_collection_failed", "inventory_partial"];
  runs.unshift({
    ...structuredClone(runs[0]),
    id: 6,
    failedNoEvidence: true,
    mode: "inventory",
    job: {
      id: 6,
      status: "failed",
      progress: 100,
      message: "Fixture failed collector: no evidence",
    },
  });
  overviewExtras = [
    needsPatch,
    baselineHost,
    staleHost,
    failedHost,
    unknownHost,
    clientHost,
    noOffers,
    incompleteClient,
    staleClient,
    timeoutClient,
    linuxHost,
    unclassified,
    partialHost,
  ];
  await workspaceTab("Systeme");
  await page.getByRole("button", { name: "Status aktualisieren", exact: true }).click();
  const overview = page.getByTestId("host-overview");
  const hostRow = (ip) => overview.getByRole("row").filter({ hasText: ip });
  await hostRow("192.0.2.20").waitFor();
  await openHistory();
  const failedRun = page.getByTestId("run-card-6");
  await failedRun.getByText("Fixture failed collector: no evidence", { exact: true }).waitFor();
  for (const name of ["Assess Windows patches", "Assess installed software"]) {
    const button = failedRun.getByRole("button", { name, exact: true });
    assert.ok((await button.count()) === 0 || (await button.isDisabled()));
  }
  // Switch back to decisions; technical histories and catalogs live in separate tabs.
  await workspaceTab("Systeme");

  await hostRow("192.0.2.20").getByText("Update nötig", { exact: true }).waitFor();
  await hostRow("192.0.2.20").getByText("KB9999999", { exact: true }).waitFor();
  await hostRow("192.0.2.20").getByText("1 Versionen prüfen", { exact: true }).waitFor();
  assert.equal(
    (await overview.innerText()).includes("977"),
    false,
    "Related advisory references must not become patch or vulnerability counters",
  );
  await hostRow("192.0.2.21").getByText("Build-Baseline erfüllt", { exact: true }).waitFor();
  await hostRow("192.0.2.21")
    .getByText("Kein Treffer in geprüften Regeln", { exact: true })
    .waitFor();
  assert.equal(await hostRow("192.0.2.22").locator(".MuiChip-colorSuccess").count(), 0);
  assert.equal(await hostRow("192.0.2.23").locator(".MuiChip-colorSuccess").count(), 0);
  await hostRow("192.0.2.23")
    .getByText("Neuester Versuch fehlgeschlagen", { exact: true })
    .waitFor();
  assert.equal(await hostRow("192.0.2.24").locator(".MuiChip-colorSuccess").count(), 0);
  assert.equal(await hostRow("192.0.2.50").locator(".MuiChip-colorSuccess").count(), 0);
  await hostRow("192.0.2.20")
    .getByRole("button", { name: /Host öffnen/ })
    .click();
  const statusDialog = page.getByRole("dialog", { name: "Host-Status · 192.0.2.20", exact: true });
  await statusDialog.waitFor();
  await statusDialog.getByRole("tab", { name: "Software", exact: true }).click();
  await statusDialog.getByText("Microsoft Edge", { exact: true }).waitFor();
  await statusDialog
    .getByText("Installiert: 150.0.1000.1 · Zielversion: 150.0.1000.2", { exact: true })
    .waitFor();
  // Closing a status dialog only reads saved evidence. No scan or login starts.
  await statusDialog.getByRole("button", { name: "Host-Status schließen", exact: true }).click();
  await statusDialog.waitFor({ state: "hidden" });
  // The host title clears immediately; wait for Modal's exit transition to restore the workspace.
  await hostRow("192.0.2.20").waitFor();
  // One operational bucket per host makes the counts additive, and the cards are filters.
  const buckets = ["update-count", "unknown-count", "assessment-count", "baseline-count"];
  const bucketTotal = (
    await Promise.all(
      buckets.map(async (id) => Number(await overview.getByTestId(id).locator("h3").innerText())),
    )
  ).reduce((sum, count) => sum + count, 0);
  assert.equal(bucketTotal, (await overview.getByRole("row").count()) - 1);
  await overview.getByTestId("update-count").click();
  assert.equal(await overview.getByTestId("update-count").getAttribute("aria-pressed"), "true");
  await hostRow("192.0.2.20").waitFor();
  assert.equal(await hostRow("192.0.2.23").count(), 0);
  await overview.getByTestId("update-count").click();
  assert.equal(await overview.getByTestId("update-count").getAttribute("aria-pressed"), "false");

  // A failed first inventory explains the next step instead of displaying empty assessments.
  const beforeRepair = apiCalls.filter((request) => request.method !== "GET").length;
  const failedDetailButton = hostRow("192.0.2.50").getByRole("button", { name: /Host öffnen/ });
  await failedDetailButton.focus();
  await page.keyboard.press("Enter");
  const failedDetail = page.getByRole("dialog", { name: "Host-Status · 192.0.2.50", exact: true });
  await failedDetail.waitFor();
  assert.equal(await failedDetail.getByTestId("host-next-action").count(), 1);
  await failedDetail
    .getByTestId("host-next-action")
    .getByText("Verbindung prüfen", { exact: true })
    .waitFor();
  assert.equal(await failedDetail.getByRole("tab", { name: "Software", exact: true }).count(), 0);
  assert.equal(
    await failedDetail.getByRole("button", { name: "Windows jetzt bewerten", exact: true }).count(),
    0,
  );
  await page.screenshot({
    path: "test-artifacts/host-next-step-desktop.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.keyboard.press("Escape");
  await failedDetail.waitFor({ state: "hidden" });
  await failedDetailButton.waitFor();
  await failedDetailButton.click();
  await failedDetail
    .getByRole("button", { name: "Verbindung & Inventur prüfen", exact: true })
    .click();
  await failedDetail.waitFor({ state: "hidden" });
  const repairForm = page.getByTestId("inventory-form-dialog");
  await repairForm.waitFor();
  assert.equal(
    await repairForm.getByLabel("Target IP", { exact: true }).inputValue(),
    "192.0.2.50",
  );
  assert.equal(
    apiCalls.filter((request) => request.method !== "GET").length,
    beforeRepair,
    "Opening a recovery form only prepares the host; it must not authenticate or submit an inventory",
  );
  await closeInventory();
  await hostRow("192.0.2.23")
    .getByRole("button", { name: /Host öffnen/ })
    .click();
  const retainedDetail = page.getByRole("dialog", {
    name: "Host-Status · 192.0.2.23",
    exact: true,
  });
  await retainedDetail.getByRole("tab", { name: "Prüfdetails", exact: true }).click();
  await retainedDetail
    .getByText(
      "Diese Daten stammen aus einer früheren Erfassung; der neueste Versuch war nicht erfolgreich.",
      { exact: false },
    )
    .waitFor();
  await page.keyboard.press("Escape");
  await retainedDetail.waitFor({ state: "hidden" });
  await hostRow("192.0.2.60").waitFor();
  await hostRow("192.0.2.60")
    .getByRole("button", { name: /Host öffnen/ })
    .click();
  const partialDetail = page.getByRole("dialog", { name: "Host-Status · 192.0.2.60", exact: true });
  await partialDetail.getByRole("tab", { name: "Prüfdetails", exact: true }).click();
  await partialDetail
    .getByText(
      "Der fehlgeschlagene Lauf hat Teilinformationen gespeichert. Die Erfassung wurde nicht erfolgreich abgeschlossen.",
      { exact: false },
    )
    .waitFor();
  assert.equal(
    await partialDetail
      .getByText("Diese Daten stammen aus einer früheren Erfassung", { exact: false })
      .count(),
    0,
  );
  await page.keyboard.press("Escape");
  await partialDetail.waitFor({ state: "hidden" });
  await hostRow("192.0.2.60").waitFor();

  const requestsBeforeFiltering = apiCalls.filter((request) => request.method !== "GET").length;
  await overview.getByLabel("Host suchen", { exact: true }).fill("192.0.2.21");
  await hostRow("192.0.2.21").waitFor();
  assert.equal(await overview.getByRole("row").count(), 2);
  await overview.getByLabel("Host suchen", { exact: true }).fill("");
  await overview.getByRole("combobox", { name: "Statusfilter", exact: true }).click();
  await page.getByRole("option", { name: "Inventur nötig", exact: true }).click();
  assert.equal(
    await hostRow("192.0.2.20").count(),
    0,
    "A fully evaluated build gap is actionable, not an unknown result",
  );
  await hostRow("192.0.2.23").waitFor();
  await overview.getByRole("combobox", { name: "Statusfilter", exact: true }).click();
  await page.getByRole("option", { name: "Alle Systeme", exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({
    path: "test-artifacts/host-patch-overview.png",
    fullPage: true,
    animations: "disabled",
  });
  // A search from another platform must not silently hide systems after navigation.
  // The first route below must restore the Windows Server row despite this empty selection.
  await overview.getByLabel("Host suchen", { exact: true }).fill("no-system-matches-this-search");
  await overview.getByText("Keine Systeme in dieser Auswahl", { exact: true }).waitFor();
  for (const [label, path, shown, hidden] of [
    ["Windows Server", "/windows-servers", "192.0.2.20", "192.0.2.30"],
    ["Windows Clients", "/windows-clients", "192.0.2.30", "192.0.2.20"],
    ["Linux", "/linux", "192.0.2.40", "192.0.2.20"],
    ["VMware", "/vmware", null, "192.0.2.20"],
  ]) {
    await page.getByRole("link", { name: label, exact: true }).click();
    await page.getByRole("heading", { name: label, exact: true }).waitFor();
    assert.equal(new URL(page.url()).pathname, path);
    assert.equal(new URL(page.url()).searchParams.get("customer_id"), "1");
    assert.equal(
      await page.getByRole("button", { name: "Unlock host audits", exact: true }).count(),
      0,
      "Platform navigation retains the volatile in-memory operator session",
    );
    if (label === "Windows Clients") {
      const clientOverview = page.getByTestId("host-overview");
      const clientRow = (ip) =>
        clientOverview.getByRole("row").filter({ has: page.getByText(ip, { exact: true }) });
      await clientRow("192.0.2.30")
        .getByText("Windows-Updateabfrage nötig", { exact: true })
        .waitFor();
      await clientRow("192.0.2.31").getByText("Keine Updateangebote", { exact: true }).waitFor();
      for (const ip of ["192.0.2.30", "192.0.2.31", "192.0.2.32", "192.0.2.33", "192.0.2.34"]) {
        assert.equal(
          await clientRow(ip).locator(".MuiChip-colorSuccess").count(),
          0,
          "No client query outcome proves a fully patched OS",
        );
      }
      await clientRow("192.0.2.32")
        .getByText("Updateabfrage unvollständig", { exact: true })
        .waitFor();
      await clientRow("192.0.2.33")
        .getByText("Windows-Updateabfrage nötig", { exact: true })
        .waitFor();
      await clientRow("192.0.2.33").getByText("Stand nicht aktuell", { exact: true }).waitFor();
      await clientRow("192.0.2.34")
        .getByText("Neuester Versuch fehlgeschlagen", { exact: true })
        .waitFor();
      await clientRow("192.0.2.34").getByText("Fixture Windows 11", { exact: true }).waitFor();
      await clientRow("192.0.2.30")
        .getByRole("button", { name: /Host öffnen/ })
        .click();
      let clientDetail = page.getByRole("dialog", {
        name: "Host-Status · 192.0.2.30",
        exact: true,
      });
      await clientDetail.getByRole("tab", { name: "Systemupdates", exact: true }).click();
      assert.equal(
        await clientDetail
          .getByRole("tabpanel")
          .getByRole("button", { name: "Windows jetzt bewerten", exact: true })
          .isDisabled(),
        true,
      );
      const beforeQuery = apiCalls.filter((call) => call.method !== "GET").length;
      await clientDetail
        .getByTestId("host-next-action")
        .getByRole("button", { name: "Windows-Updates abfragen", exact: true })
        .click();
      await clientDetail.waitFor({ state: "hidden" });
      const queryForm = page.getByRole("dialog", { name: "Windows-Updates abfragen", exact: true });
      await queryForm.waitFor();
      assert.equal(await page.getByRole("dialog").count(), 1,
        "The inventory form replaces host details rather than stacking another active dialog");
      assert.equal(
        await queryForm.getByLabel("Target IP", { exact: true }).inputValue(),
        "192.0.2.30",
      );
      await queryForm
        .getByRole("button", { name: "Updateabfrage vorbereiten", exact: true })
        .click();
      const confirmation = page.getByRole("dialog", {
        name: "Windows-Updatequelle abfragen",
        exact: true,
      });
      await confirmation.waitFor();
      assert.equal(
        apiCalls.filter((call) => call.method !== "GET").length,
        beforeQuery,
        "Preparing an online query must not submit it",
      );
      assert.equal(wuaQueryRequests, 0);
      await confirmation.getByRole("button", { name: "Abfrage starten", exact: true }).click();
      await confirmation.waitFor({ state: "hidden" });
      await queryForm.waitFor({ state: "hidden" });
      assert.equal(wuaQueryRequests, 1);
      assert.equal(submissions.at(-1).mode, "windows_updates");
      assert.equal(submissions.at(-1).winrm_transport, "http_ntlm");
      assert.equal(submissions.at(-1).target, "192.0.2.30");
      await clientRow("192.0.2.30")
        .getByRole("button", { name: /Host öffnen/ })
        .click();
      clientDetail = page.getByRole("dialog", { name: "Host-Status · 192.0.2.30", exact: true });
      await clientDetail.getByRole("tab", { name: "Systemupdates", exact: true }).click();
      await clientDetail
        .getByRole("tabpanel")
        .getByRole("button", { name: "Windows jetzt bewerten", exact: true })
        .click();
      const updateDialog = page.getByRole("dialog", {
        name: "Windows-Updateangebote · 192.0.2.30",
        exact: true,
      });
      await updateDialog.getByText("Updates angeboten", { exact: true }).waitFor();
      assert.equal(await page.getByRole("dialog").count(), 1,
        "The assessment report replaces host details rather than stacking another active dialog");
      for (const text of [
        "Sicherheitsupdates: 1",
        "Qualitätsupdates: 1",
        "Funktionsupdates / Upgrades: 1",
        "Definitionsupdates: 1",
        "Synthetic security update",
        "Synthetic quality update",
        "Synthetic feature offer",
        "Synthetic definition update",
      ]) {
        await updateDialog.getByText(text, { exact: true }).waitFor();
      }
      await updateDialog.getByText("Optional · separat entscheiden", { exact: true }).waitFor();
      assert.equal(await updateDialog.locator(".MuiChip-colorSuccess").count(), 0);
      assert.equal(
        await updateDialog.getByText("Microsoft baseline build:", { exact: false }).count(),
        0,
        "Client offers must not be presented as a Server build baseline",
      );
      assert.equal(
        wuaQueryRequests,
        1,
        "Assessment reads saved query evidence without another Windows query",
      );
      await page.screenshot({
        path: "test-artifacts/windows-client-update-offers.png",
        fullPage: true,
        animations: "disabled",
      });
      await updateDialog.getByRole("button", { name: "Close assessment", exact: true }).click();
      await updateDialog.waitFor({ state: "hidden" });
      await clientRow("192.0.2.30").waitFor();
      if (await clientDetail.isVisible()) {
        await clientDetail
          .getByRole("button", { name: "Host-Status schließen", exact: true })
          .click();
        await clientDetail.waitFor({ state: "hidden" });
      }
      await clientRow("192.0.2.30").getByText("Updates angeboten", { exact: true }).waitFor();
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({
        path: "test-artifacts/windows-clients-overview.png",
        fullPage: true,
        animations: "disabled",
      });
    }
    if (shown)
      await page.getByTestId("host-overview").getByRole("row").filter({ hasText: shown }).waitFor();
    assert.equal(
      await page.getByTestId("host-overview").getByRole("row").filter({ hasText: hidden }).count(),
      0,
    );
  }
  await page
    .getByText("VMware: Netzwerkdienste können erkannt werden. Authentifizierte Inventur und", {
      exact: false,
    })
    .waitFor();
  assert.equal(
    apiCalls.filter((request) => request.method !== "GET").length,
    requestsBeforeFiltering + 2,
    "Only the explicitly confirmed client query and saved-evidence assessment may submit requests",
  );
  for (const [label, path] of [
    ["Domains", "/domains"],
    ["URLs", "/urls"],
    ["Netzwerk", "/networks"],
  ]) {
    await page.getByRole("link", { name: label, exact: true }).click();
    await page.waitForURL((url) => url.pathname === path);
    assert.equal(new URL(page.url()).searchParams.get("customer_id"), "1");
  }
  assert.equal(
    apiCalls.filter((request) => request.method !== "GET").length,
    requestsBeforeFiltering + 2,
  );
  await page.getByRole("link", { name: "Host-Inventur", exact: true }).click();
  await page.getByRole("heading", { name: "Host-Übersicht", exact: true }).waitFor();
  // Leaving private inventory clears its in-memory session; no token is kept
  // in a public route, browser storage or customer query string.
  await page.getByLabel("Operator token", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).click();
  await page.getByText("Operatorzugang aktiv", { exact: true }).waitFor();
  assert.deepEqual(modes, [
    "connection",
    "inventory",
    "connection",
    "connection",
    "inventory",
    "windows_updates",
  ]);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal((await page.content()).includes(token), false);
  assert.equal((await page.content()).includes(password), false);
  await page.getByRole("button", { name: "Sperren", exact: true }).click();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.equal(await page.getByRole("button", { name: "View evidence", exact: true }).count(), 0);
  await page.getByLabel("Operator token", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).click();
  await page.getByText("Operatorzugang aktiv", { exact: true }).waitFor();
  await page.evaluate(() =>
    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })),
  );
  await page.getByText("Sitzung wird geprüft …", { exact: true }).waitFor();
  await page.evaluate(() =>
    window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })),
  );
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).waitFor();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.equal(await page.getByRole("button", { name: "View evidence", exact: true }).count(), 0);
  await page.reload();
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).waitFor();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Navigation öffnen", exact: true }).click();
  const mobileNavigation = page.getByRole("navigation", { name: "Hauptnavigation", exact: true });
  for (const label of [
    "Domains",
    "URLs",
    "Netzwerk",
    "Windows Server",
    "Windows Clients",
    "Linux",
    "VMware",
  ]) {
    assert.equal(await mobileNavigation.getByRole("link", { name: label, exact: true }).count(), 1);
  }
  await mobileNavigation.getByRole("link", { name: "Windows Server", exact: true }).click();
  await page.getByRole("heading", { name: "Windows Server", exact: true }).waitFor();
  await mobileNavigation.waitFor({ state: "hidden" });
  assert.equal(new URL(page.url()).searchParams.get("customer_id"), "1");
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  await page.getByLabel("Operator token", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).click();
  await page.getByTestId("host-mobile-101").waitFor();
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal((await page.content()).includes(token), false);
  assert.ok(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    "Mobile layout must not overflow the page",
  );
  await page.screenshot({
    path: "test-artifacts/host-platform-mobile.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("button", { name: "Navigation öffnen", exact: true }).click();
  await mobileNavigation.getByRole("link", { name: "Host-Inventur", exact: true }).click();
  await page.getByTestId("host-mobile-108").waitFor();
  await page
    .getByTestId("host-mobile-108")
    .getByRole("button", { name: /Host öffnen/ })
    .click();
  const mobileDetail = page.getByRole("dialog", { name: "Host-Status · 192.0.2.50", exact: true });
  await mobileDetail
    .getByRole("button", { name: "Verbindung & Inventur prüfen", exact: true })
    .waitFor();
  assert.equal(await mobileDetail.getByTestId("host-next-action").count(), 1);
  const mobileRect = await mobileDetail.boundingBox();
  assert.ok(
    mobileRect && mobileRect.x >= 0 && mobileRect.x + mobileRect.width <= 391,
    "Host details must fit a mobile viewport",
  );
  assert.ok(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
  );
  await page.screenshot({
    path: "test-artifacts/host-next-step-mobile.png",
    fullPage: true,
    animations: "disabled",
  });
  await page.keyboard.press("Escape");
  await mobileDetail.waitFor({ state: "hidden" });
  await page.getByTestId("host-mobile-108").getByRole("button", { name: /Host öffnen/ }).waitFor();
  assert.deepEqual(errors, []);
  console.log(
    "Host audit UI passed: patch priorities and explicit fixes, scoped baselines, failed/stale/unknown coverage, separate platform routes, customer context, responsive navigation, volatile secrets, encrypted inventory and retained histories",
  );
} catch (error) {
  await mkdir("test-artifacts", { recursive: true });
  // Retain the last observed UI for diagnosis; this is not a passing-state screenshot.
  await page?.screenshot({
    path: "test-artifacts/host-workspace-last-state.png",
    fullPage: true,
    animations: "disabled",
  }).catch(() => {});
  console.error(
    await page?.locator(".MuiMenu-root").evaluateAll((elements) =>
      elements.map((element) => ({
        text: element.textContent,
        rect: element.getBoundingClientRect().toJSON(),
        papers: [...element.querySelectorAll(".MuiPaper-root")].map((paper) => ({
          style: paper.getAttribute("style"),
          rect: paper.getBoundingClientRect().toJSON(),
        })),
      })),
    ),
  );
  throw error;
} finally {
  await browser.close();
}
