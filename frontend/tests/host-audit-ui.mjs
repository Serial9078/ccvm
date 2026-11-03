import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
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
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  page.setDefaultTimeout(15000);
  const errors = [];
  page.on("pageerror", (error) => errors.push(String(error)));
  let credentials = [];
  let runs = [];
  let rejectSave = false;
  let modes = [];
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
  await page.route(`${origin}/**`, async (route) => {
    const request = route.request();
    assert.equal(request.url().includes(token) || request.url().includes(password), false);
    const url = new URL(request.url());
    const path = url.pathname;
    const respond = (json, status = 200) =>
      route.fulfill({ status, json, headers: { "Cache-Control": "no-store" } });
    if (path.startsWith("/api/v1/")) {
      if (path === "/api/v1/customers")
        return respond([{ id: 1, name: "Lab customer", uuid: "synthetic-customer" }]);
      assert.equal(request.headers()["authorization"], `Bearer ${token}`);
      if (path === "/api/v1/host-audits/credentials" && request.method() === "POST") {
        const payload = request.postDataJSON();
        assert.equal(payload.customer_id, 1);
        assert.equal(payload.password, password);
        assert.deepEqual(payload.allowed_cidrs, ["192.0.2.0/24"]);
        if (rejectSave) return respond({ detail: "Fixture save rejected" }, 422);
        credentials = [
          {
            id: 1,
            customer_id: 1,
            name: payload.name,
            kind: payload.kind,
            username: payload.username,
            allowed_cidrs: payload.allowed_cidrs,
            enabled: true,
          },
        ];
        return respond(credentials[0], 201);
      }
      if (path === "/api/v1/host-audits/credentials") return respond(credentials);
      if (path === "/api/v1/host-audits/credentials/1/revoke") {
        credentials = credentials.map((cred) => ({ ...cred, enabled: false }));
        return respond(credentials[0]);
      }
      if (path === "/api/v1/host-audits" && request.method() === "POST") {
        const payload = request.postDataJSON();
        modes.push(payload.mode);
        assert.equal(payload.target, "192.0.2.1");
        assert.equal(payload.ssh_fingerprint, "SHA256:" + "A".repeat(43));
        const run = {
          id: runs.length + 1,
          customer_id: 1,
          credential_id: 1,
          target: payload.target,
          port: 22,
          mode: payload.mode,
          created_at: "2026-11-03T12:00:00Z",
          completed_at: "2026-11-03T12:00:01Z",
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
      if (/\/api\/v1\/host-audits\/\d+$/.test(path))
        return respond({
          ...runs.find((run) => run.id === Number(path.split("/").at(-1))),
          inventory: evidence,
        });
      throw new Error(`Unexpected fixture endpoint ${path}`);
    }
    const file =
      path === "/host-audits" || path === "/"
        ? resolve(root, "index.html")
        : resolve(root, path.replace(/^\//, ""));
    assert.ok(file.startsWith(root + "/"));
    const contentType =
      {
        ".html": "text/html",
        ".js": "text/javascript",
        ".css": "text/css",
        ".png": "image/png",
        ".svg": "image/svg+xml",
      }[extname(file)] || "application/octet-stream";
    return route.fulfill({ body: await readFile(file), contentType });
  });
  await page.goto(`${origin}/host-audits`);
  await page.getByRole("heading", { name: "Authenticated inventory", exact: true }).waitFor();
  await page.getByRole("combobox", { name: "Customer", exact: true }).click();
  await page.getByRole("option", { name: "Lab customer" }).click();
  await page.getByLabel("Operator token", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Unlock host audits" }).click();
  await page.getByRole("button", { name: "Add credential" }).click();
  await page.getByLabel("Credential name", { exact: true }).fill("Linux lab");
  await page.getByLabel("Username", { exact: true }).fill("inventory");
  await page.getByLabel("Allowed credential CIDRs", { exact: true }).fill("192.0.2.0/24");
  await page.getByLabel("Password", { exact: true }).fill(password);
  rejectSave = true;
  await page.getByRole("button", { name: "Save credential", exact: true }).click();
  await page.getByText("Fixture save rejected", { exact: true }).waitFor();
  assert.equal(await page.getByLabel("Password", { exact: true }).inputValue(), "");
  rejectSave = false;
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save credential", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  await page.getByLabel("Target IP", { exact: true }).fill("192.0.2.1");
  assert.equal(
    await page.getByRole("button", { name: "Collect inventory", exact: true }).isDisabled(),
    true,
  );
  await page
    .getByLabel("Approved SSH fingerprint", { exact: true })
    .fill("SHA256:" + "A".repeat(43));
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page.getByText("Fixture inventory finished", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Collect inventory", exact: true }).click();
  await page.getByRole("button", { name: "View evidence", exact: true }).first().waitFor();
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
  await page.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await page.getByRole("button", { name: "Keep credential", exact: true }).click();
  assert.equal(credentials[0].enabled, true);
  await page.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await page.getByRole("button", { name: "Revoke and erase secret", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  assert.equal(credentials[0].enabled, false);
  assert.deepEqual(modes, ["connection", "inventory"]);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal((await page.content()).includes(token), false);
  assert.equal((await page.content()).includes(password), false);
  await page.getByRole("button", { name: "Lock and clear session", exact: true }).click();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.equal(await page.getByRole("button", { name: "View evidence", exact: true }).count(), 0);
  await page.reload();
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).waitFor();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.deepEqual(errors, []);
  console.log(
    "Host audit UI passed: HTTPS, volatile token, encrypted credential request, failure secret clearing, pinned connection/inventory, evidence, revocation and lock",
  );
} finally {
  await browser.close();
}
