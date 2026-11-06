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
  const submissions = [];
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
        assert.equal(payload.target, "192.0.2.1");
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
      if (/\/api\/v1\/host-audits\/\d+$/.test(path)) {
        const run = runs.find((candidate) => candidate.id === Number(path.split("/").at(-1)));
        const windows =
          credentials.find((credential) => credential.id === run.credential_id)?.kind === "winrm";
        return respond({
          ...run,
          inventory: windows
            ? {
                os: {
                  family: "Windows",
                  name: "Fixture Windows",
                  version: "10.0",
                  kernel: "20348.1",
                  architecture: "AMD64",
                  hostname: "lab-windows",
                },
                packages: { ...evidence.packages, source: "Uninstall registry" },
                hotfixes: {
                  status: "complete",
                  source: "Get-HotFix",
                  items: [{ id: "KB0000001", description: "Fixture update" }],
                },
              }
            : evidence,
        });
      }
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
  await page.getByRole("button", { name: "Add credential", exact: true }).click();
  await page.getByLabel("Credential name", { exact: true }).fill("Windows lab");
  await page.getByRole("combobox", { name: "Authentication", exact: true }).click();
  await page.getByRole("option", { name: "Windows · WinRM / NTLM", exact: true }).click();
  await page.getByLabel("Username", { exact: true }).fill("LAB\\inventory");
  await page.getByLabel("Allowed credential CIDRs", { exact: true }).fill("192.0.2.0/24");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Save credential", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  const connection = page.getByRole("combobox", { name: "WinRM connection", exact: true });
  await connection.waitFor();
  assert.equal(await connection.innerText(), "HTTPS / NTLM · verified certificate");
  assert.equal(await page.getByLabel("Approved SSH fingerprint", { exact: true }).count(), 0);
  await page.getByText("Default 5986 · HTTPS / NTLM", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page.getByText("HTTPS / NTLM · certificate validation required", { exact: true }).waitFor();
  assert.equal(submissions.at(-1).winrm_transport, "https");
  assert.equal(Object.hasOwn(submissions.at(-1), "port"), false);
  await page.getByLabel("Port (optional)", { exact: true }).fill("5990");
  await connection.click();
  await page.getByRole("option", { name: "HTTP / NTLM · encrypted messages", exact: true }).click();
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
  await page.getByRole("dialog").getByText("Fixture Windows", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Close evidence", exact: true }).click();
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
  assert.deepEqual(modes, ["connection", "inventory", "connection", "connection", "inventory"]);
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal((await page.content()).includes(token), false);
  assert.equal((await page.content()).includes(password), false);
  await page.getByRole("button", { name: "Lock and clear session", exact: true }).click();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.equal(await page.getByRole("button", { name: "View evidence", exact: true }).count(), 0);
  await page.getByLabel("Operator token", { exact: true }).fill(token);
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).click();
  await page.getByText("Operator access unlocked", { exact: true }).waitFor();
  await page.evaluate(() =>
    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })),
  );
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).waitFor();
  await page.evaluate(() =>
    window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })),
  );
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.equal(await page.getByRole("button", { name: "View evidence", exact: true }).count(), 0);
  await page.reload();
  await page.getByRole("button", { name: "Unlock host audits", exact: true }).waitFor();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).inputValue(), "");
  assert.deepEqual(errors, []);
  console.log(
    "Host audit UI passed: HTTPS, volatile token, encrypted credential request, failure secret clearing, pinned SSH and HTTPS/HTTP WinRM runs, explicit encrypted-HTTP selection, mode and port reset, transport evidence, revocation and lock",
  );
} finally {
  await browser.close();
}
