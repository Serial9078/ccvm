import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { chromium } from "playwright";

const origin = "http://127.0.0.1:4179";
const server = spawn(
  process.execPath,
  [
    "node_modules/vite/bin/vite.js",
    "preview",
    "--host",
    "127.0.0.1",
    "--port",
    "4179",
    "--strictPort",
  ],
  { stdio: "pipe" },
);
let output = "";
server.stderr.on("data", (data) => {
  output += data;
});
let browser;
try {
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      if ((await fetch(origin)).ok) break;
    } catch {
      /* wait for the local build server */
    }
    if (attempt === 49) throw new Error(`Preview did not start: ${output}`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  browser = await chromium.launch({
    args: ["--no-sandbox"],
    executablePath: process.env.CCVM_TEST_CHROMIUM || undefined,
  });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  page.setDefaultTimeout(15000);
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  let enabled = true;
  let scans = [];
  const submitted = [];
  let previewCount = 0;
  const job = (id, plugin, parent, status = "running", progress = 10) => ({
    id,
    uuid: `job-${id}`,
    plugin,
    parent_job_id: parent,
    status,
    progress,
    message: "Fixture scan activity",
    worker: "fixture",
  });
  const model = () => ({
    id: 1,
    customer_id: 1,
    asset_id: 1,
    pipeline_id: "fixture-pipeline",
    target: "192.0.2.0/29",
    exclusions: ["192.0.2.2/32", "192.0.2.3/32"],
    profile: "custom",
    ports: "22,443",
    rate: 20,
    timeout_seconds: 7200,
    address_count: 4,
    status: "running",
    cancel_requested: false,
    hosts_checked: 4,
    open_services: 2,
    findings_created: 1,
    findings_updated: 0,
    scanner_version: "fixture",
    created_at: "2026-11-03T06:00:00Z",
    jobs: [job(1, "networkdiscovery", null), job(2, "networkaudit", 1, "queued", 0)],
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace("/api/v1", "");
    const respond = (json, status = 200) => route.fulfill({ status, json });
    if (path === "/customers") return respond([{ id: 1, uuid: "customer", name: "Lab customer" }]);
    if (path === "/network-scans/capabilities")
      return respond({
        enabled,
        allowed_cidrs: enabled ? ["192.0.2.0/29"] : [],
        max_addresses: 4096,
        tcp: true,
        udp: false,
        credentialed: false,
      });
    if (path === "/network-scans/preview") {
      previewCount++;
      const payload = request.postDataJSON();
      if (payload.target === "bad-scope")
        return respond({ detail: "Use a literal IP or CIDR network" }, 422);
      assert.equal(payload.profile, "custom");
      assert.deepEqual(payload.exclusions, ["192.0.2.2", "192.0.2.3/32"]);
      return respond({
        target: "192.0.2.0/29",
        address_count: 4,
        sample: ["192.0.2.1", "192.0.2.4"],
        exclusions: payload.exclusions,
        ports_per_host: 2,
        minimum_portscan_seconds: 1,
        ip_version: 4,
      });
    }
    if (path === "/network-scans" && request.method() === "POST") {
      submitted.push(request.postDataJSON());
      scans = [model()];
      return respond(scans[0], 201);
    }
    if (path === "/network-scans") return respond(scans);
    if (path === "/network-scans/1/cancel") {
      scans[0] = { ...scans[0], status: "cancelling", cancel_requested: true };
      return respond(scans[0]);
    }
    if (path === "/network-scans/1")
      return respond({
        ...scans[0],
        observations: [
          {
            id: 1,
            host_id: 1,
            asset_id: 2,
            ip_address: "192.0.2.1",
            services: [
              {
                port: 22,
                protocol: "tcp",
                state: "open",
                service: "ssh",
                product: "OpenSSH",
                version: "8.2",
                cpe: ["cpe:/a:openbsd:openssh:8.2"],
                method: "probed",
                checks: [
                  {
                    check: "ssh2-enum-algos",
                    status: "completed",
                    output: "diffie-hellman-group1-sha1",
                  },
                ],
              },
            ],
          },
        ],
      });
    throw new Error(`Unexpected fixture API request: ${request.method()} ${path}`);
  });
  await page.goto(`${origin}/networks`);
  await page.getByRole("heading", { name: "Network scans", exact: true }).waitFor();
  await page.getByRole("combobox", { name: /Customer/ }).click();
  await page.getByRole("option", { name: "Lab customer" }).click();
  await page.getByRole("textbox", { name: "Network or IP" }).fill("bad-scope");
  await page.getByRole("combobox", { name: "TCP port profile" }).click();
  await page.getByRole("option", { name: "Custom ports", exact: true }).click();
  await page.getByRole("textbox", { name: "TCP ports", exact: true }).fill("22,443");
  await page
    .getByRole("textbox", { name: "Excluded IPs or CIDRs" })
    .fill("192.0.2.2,\n192.0.2.3/32");
  await page.getByRole("spinbutton", { name: "Maximum portscan probes per second" }).fill("20");
  await page.getByRole("spinbutton", { name: "Time budget per stage (hours)" }).fill("2");
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText("Use a literal IP or CIDR network", { exact: true }).waitFor();
  assert.equal(submitted.length, 0);
  await page.getByRole("textbox", { name: "Network or IP" }).fill("192.0.2.0/29");
  await page.getByRole("button", { name: "Preview scope" }).click();
  await page.getByText(/Scope: 192\.0\.2\.0\/29/).waitFor();
  await page.getByRole("button", { name: "Start network scan", exact: true }).click();
  await page.getByRole("button", { name: "Observed services" }).waitFor();
  assert.equal(previewCount, 2);
  assert.equal(submitted.length, 1);
  assert.equal(submitted[0].customer_id, 1);
  assert.equal(submitted[0].timeout_seconds, 7200);
  assert.equal(submitted[0].rate, 20);
  assert.equal(submitted[0].ports, "22,443");
  assert.deepEqual(submitted[0].exclusions, ["192.0.2.2", "192.0.2.3/32"]);
  await mkdir("test-artifacts", { recursive: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await page.screenshot({ path: "test-artifacts/network-scans.png", fullPage: true });
  await page.getByRole("button", { name: "Observed services" }).click();
  await page.getByRole("dialog").getByText("OpenSSH 8.2", { exact: true }).waitFor();
  await page.getByRole("dialog").getByText("ssh2-enum-algos: completed", { exact: true }).waitFor();
  await page.getByRole("dialog").getByText("ssh2-enum-algos: completed", { exact: true }).click();
  await page.getByRole("dialog").getByText("diffie-hellman-group1-sha1", { exact: true }).waitFor();
  await page.screenshot({ path: "test-artifacts/network-services.png", fullPage: true });
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Cancel scan", exact: true }).click();
  await page.getByText("CANCELLING", { exact: true }).waitFor();
  assert.equal(
    await page.getByRole("button", { name: "Cancel scan", exact: true }).isDisabled(),
    true,
  );
  enabled = false;
  await page.reload();
  await page.getByText(/Network scanning is not enabled on this scanner/).waitFor();
  await page.getByRole("combobox", { name: /Customer/ }).click();
  await page.getByRole("option", { name: "Lab customer" }).click();
  await page.getByRole("textbox", { name: "Network or IP" }).fill("192.0.2.0/29");
  assert.equal(
    await page.getByRole("button", { name: "Start network scan", exact: true }).isDisabled(),
    true,
  );
  assert.deepEqual(errors, []);
  console.log(
    "Network UI passed: scope errors, exclusions, preview, queue, service evidence, cancel and disabled scanner",
  );
} finally {
  await browser?.close();
  server.kill("SIGTERM");
}
