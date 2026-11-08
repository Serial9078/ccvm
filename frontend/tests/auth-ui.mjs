import assert from "node:assert/strict";
import { mkdir, readFile } from "node:fs/promises";
import { extname, resolve } from "node:path";
import { chromium } from "playwright";

// Every resource is synthetic and intercepted; no remote login or scan occurs.
const origin = "https://ccvm-auth.test";
const root = resolve("dist");
const secret = "synthetic-login-password";
const csrf = "synthetic-csrf-" + "x".repeat(40);
const browser = await chromium.launch({
  args: ["--no-sandbox"],
  executablePath: process.env.CCVM_TEST_CHROMIUM || undefined,
});
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
let authenticated = false;
let rejectSession = false;
let serverCookie = "";
let loginCount = 0;
let privateCalls = 0;
let mutationCalls = 0;
let logoutCalls = 0;
const errors = [];
const customers = [
  { id: 1, uuid: "one", name: "Kunde Eins" },
  { id: 2, uuid: "two", name: "Kunde Zwei" },
];
const session = () => ({
  mode: "local",
  authenticated: true,
  user: { username: "inventory-admin" },
  csrf_token: csrf,
  expires_at: new Date(Date.now() + 3600000).toISOString(),
});
function overview(customer) {
  return {
    customer_id: customer,
    generated_at: new Date().toISOString(),
    catalogs: { windows: null, software: null },
    limit: 200,
    hosts_total: 1,
    hosts_truncated: false,
    issues: [],
    hosts: [
      {
        asset_id: customer,
        target: customer === 1 ? "192.0.2.10" : "192.0.2.20",
        platform: "unclassified",
        inventory: null,
        windows_assessment: null,
        software_assessment: null,
        issues: ["inventory_missing", "latest_connection_failed"],
        latest_run: {
          id: customer,
          credential_id: customer,
          port: 5985,
          winrm_transport: "http_ntlm",
          mode: "connection",
          status: "failed",
          message: "The target rejected authentication",
          created_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
        },
      },
    ],
  };
}
await context.route(`${origin}/**`, async (route) => {
  const request = route.request();
  const url = new URL(request.url());
  assert.equal(url.href.includes(secret) || url.href.includes(csrf), false);
  const path = url.pathname;
  const respond = (json, status = 200, headers = {}) =>
    route.fulfill({ status, json, headers: { "Cache-Control": "no-store", ...headers } });
  const hasCookie =
    (request.headers().cookie ?? "").includes(`__Host-ccvm_session=${serverCookie}`) &&
    Boolean(serverCookie);
  if (path === "/api/v1/auth/session") {
    assert.equal(request.method(), "GET");
    if (rejectSession) return respond({ detail: "unavailable" }, 503);
    return respond(
      authenticated && hasCookie ? session() : { mode: "local", authenticated: false },
    );
  }
  if (path === "/api/v1/auth/login") {
    assert.equal(request.headers()["x-ccvm-request"], "1");
    assert.equal(request.headers().origin, origin);
    const body = request.postDataJSON();
    assert.deepEqual(Object.keys(body).sort(), ["code", "password", "username"]);
    assert.equal(body.username, "inventory-admin");
    assert.equal(body.password, secret);
    if (body.code !== "123456") return respond({ detail: "invalid" }, 401);
    authenticated = true;
    serverCookie = `synthetic-session-${++loginCount}`;
    return respond(session(), 200, {
      "Set-Cookie": `__Host-ccvm_session=${serverCookie}; HttpOnly; Secure; SameSite=Strict; Path=/`,
    });
  }
  if (path === "/api/v1/auth/logout") {
    assert.equal(request.method(), "POST");
    assert.equal(request.headers()["x-csrf-token"], csrf);
    assert.equal(hasCookie, true);
    logoutCalls++;
    if (!authenticated) return respond({ detail: "already expired" }, 401);
    authenticated = false;
    return route.fulfill({
      status: 204,
      headers: {
        "Set-Cookie": "__Host-ccvm_session=; Max-Age=0; HttpOnly; Secure; SameSite=Strict; Path=/",
        "Cache-Control": "no-store",
      },
    });
  }
  if (path.startsWith("/api/v1/")) {
    privateCalls++;
    assert.equal(
      request.headers().authorization,
      undefined,
      "Local sessions never emit a Bearer token",
    );
    assert.equal(hasCookie, true, "All local API requests use the server cookie");
    if (!authenticated) return respond({ detail: "login required" }, 401);
    if (request.method() !== "GET") {
      mutationCalls++;
      assert.equal(
        request.headers()["x-csrf-token"],
        csrf,
        "Every mutation, including legacy API routes, needs CSRF",
      );
      assert.equal(request.headers()["x-ccvm-request"], "1");
    }
    const customer = Number(url.searchParams.get("customer_id") || 1);
    if (path === "/api/v1/customers")
      return respond(
        request.method() === "GET"
          ? customers
          : { ...request.postDataJSON(), id: 3, uuid: "three" },
      );
    if (path === "/api/v1/host-audits/overview") return respond(overview(customer));
    if (["/api/v1/host-audits/patch-catalog", "/api/v1/host-audits/software-catalog"].includes(path))
      return respond(null);
    if (path === "/api/v1/host-audits/credentials")
      return respond([
        {
          id: customer,
          customer_id: customer,
          name: `Konto ${customer}`,
          kind: "winrm",
          username: "fixture-user",
          allowed_cidrs: ["192.0.2.0/24"],
          enabled: true,
        },
      ]);
    if (path === "/api/v1/host-audits") {
      if (request.method() === "POST")
        return respond({
          id: 8,
          ...request.postDataJSON(),
          job: { id: 8, status: "queued", progress: 0, message: "Synthetic connection test" },
        });
      return respond([]);
    }
    errors.push(`Unmocked private API ${request.method()} ${path}`);
    return respond({ detail: "Unexpected API call in the browser fixture" }, 500);
  }
  const file = path === "/" || !extname(path) ? "index.html" : path.slice(1);
  const contentType = file.endsWith(".js")
    ? "text/javascript"
    : file.endsWith(".jpg")
      ? "image/jpeg"
      : file.endsWith(".css")
        ? "text/css"
        : "text/html";
  return route.fulfill({ status: 200, contentType, body: await readFile(resolve(root, file)) });
});
const page = await context.newPage();
page.setDefaultTimeout(10000);
page.on("pageerror", (error) => errors.push(String(error)));
const login = async (code = "123456") => {
  await page.getByLabel(/^Benutzername/).fill("inventory-admin");
  await page.getByLabel(/^Passwort/).fill(secret);
  await page.getByLabel(/^Bestätigungscode/).fill(code);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
};
try {
  await page.goto(`${origin}/host-audits?customer_id=1`);
  await page.getByRole("heading", { name: "Bei CCVM anmelden" }).waitFor();
  await page.getByRole("button", { name: "Anmelden", exact: true }).waitFor();
  await mkdir("test-artifacts", { recursive: true });
  await page.screenshot({ path: "test-artifacts/secure-login-desktop.png", fullPage: true });
  assert.equal(privateCalls, 0, "No private route loads before session verification and login");
  assert.equal(await page.getByLabel("Operator token", { exact: true }).count(), 0);
  await login("000000");
  await page
    .getByRole("alert")
    .getByText("Benutzername, Passwort oder Bestätigungscode stimmen nicht.")
    .waitFor();
  assert.equal(await page.getByLabel(/^Passwort/).inputValue(), "");
  assert.equal(await page.getByLabel(/^Bestätigungscode/).inputValue(), "");
  await login();
  await page.getByText("192.0.2.10", { exact: true }).first().waitFor();
  await page.getByText("Zugangsdaten prüfen", { exact: true }).first().waitFor();
  assert.equal(await page.getByLabel("Operator token", { exact: true }).count(), 0);
  assert.equal(
    await page.evaluate(() => document.cookie),
    "",
    "The authentication cookie is HttpOnly",
  );
  assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  assert.equal(
    (await page.content()).includes(secret) || (await page.content()).includes(csrf),
    false,
  );

  await page.reload();
  await page.getByText("192.0.2.10", { exact: true }).first().waitFor();
  assert.equal(loginCount, 1, "Reload restores the session without asking for credentials");
  await page.evaluate(() =>
    window.dispatchEvent(new PageTransitionEvent("pagehide", { persisted: true })),
  );
  await page.getByText("Sitzung wird geprüft …", { exact: true }).waitFor();
  assert.equal(await page.getByText("192.0.2.10", { exact: true }).count(), 0);
  await page.evaluate(() =>
    window.dispatchEvent(new PageTransitionEvent("pageshow", { persisted: true })),
  );
  await page.getByText("192.0.2.10", { exact: true }).first().waitFor();

  await page.getByLabel("Kunde", { exact: true }).click();
  await page.getByRole("option", { name: "Kunde Zwei", exact: true }).click();
  await page.getByText("192.0.2.20", { exact: true }).first().waitFor();
  assert.equal(
    await page.getByText("192.0.2.10", { exact: true }).count(),
    0,
    "Customer change removes the prior private view",
  );
  await page.getByRole("button", { name: "Inventur starten", exact: true }).click();
  await page.getByLabel("Credential", { exact: true }).click();
  await page.getByRole("option", { name: "Konto 2 · fixture-user · winrm", exact: true }).click();
  await page.getByLabel("Target IP", { exact: true }).fill("192.0.2.20");
  await page.getByLabel("WinRM connection", { exact: true }).click();
  await page.getByRole("option", { name: "HTTP / NTLM · encrypted messages", exact: true }).click();
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page
    .getByRole("button", { name: "Test connection", exact: true })
    .waitFor({ state: "hidden" });
  assert.equal(mutationCalls, 1, "Host-audit mutations carry CSRF");

  await page.getByRole("link", { name: "Kunden", exact: true }).click();
  await page.getByRole("button", { name: "New Customer", exact: true }).click();
  await page.getByRole("dialog").getByLabel(/^Name/).fill("Synthetic customer");
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await page.getByRole("dialog").waitFor({ state: "hidden" });
  assert.equal(mutationCalls, 2, "Shared Axios mutations carry CSRF too");

  authenticated = false;
  await page.getByRole("link", { name: "Host-Inventur", exact: true }).click();
  await page.getByRole("button", { name: "Anmelden", exact: true }).waitFor();
  assert.equal(
    await page.getByText("192.0.2.20", { exact: true }).count(),
    0,
    "A 401 removes private content immediately",
  );
  await login();
  await page.getByText("192.0.2.20", { exact: true }).first().waitFor();
  const other = await context.newPage();
  await other.goto(`${origin}/host-audits?customer_id=1`);
  await other.getByText("192.0.2.10", { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Abmelden", exact: true }).click();
  await page.getByRole("button", { name: "Anmelden", exact: true }).waitFor();
  await other.getByRole("button", { name: "Anmelden", exact: true }).waitFor();
  assert.equal(logoutCalls, 1);
  await other.close();
  await page.reload();
  await page.getByRole("button", { name: "Anmelden", exact: true }).waitFor();
  assert.equal(await page.getByText("192.0.2.20", { exact: true }).count(), 0);
  await login();
  await page.getByText("192.0.2.20", { exact: true }).first().waitFor();
  authenticated = false;
  await page.getByRole("button", { name: "Abmelden", exact: true }).click();
  await page.getByRole("button", { name: "Anmelden", exact: true }).waitFor();
  assert.equal(
    await page.getByRole("button", { name: "Abmeldung erneut versuchen", exact: true }).count(),
    0,
    "Logging out an already expired session does not trap the user in a retry loop",
  );
  assert.equal(logoutCalls, 2);
  await page.setViewportSize({ width: 390, height: 844 });
  assert.ok(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
  );
  await mkdir("test-artifacts", { recursive: true });
  await page.screenshot({ path: "test-artifacts/secure-login-mobile.png", fullPage: true });

  rejectSession = true;
  await page.reload();
  await page.getByRole("button", { name: "Erneut versuchen", exact: true }).waitFor();
  assert.equal(
    await page.getByLabel("Operator token", { exact: true }).count(),
    0,
    "Session errors never downgrade to the legacy token UI",
  );
  assert.equal(await page.getByRole("link", { name: "Kunden", exact: true }).count(), 0);
  assert.deepEqual(errors, []);
  console.log(
    "Authentication UI passed: MFA form, HttpOnly cookie restore, CSRF on both API clients, customer isolation, stale/private-view clearing, expiry, cross-tab logout, fail-closed errors and mobile layout",
  );
} catch (failure) {
  await mkdir("test-artifacts", { recursive: true });
  await page.screenshot({ path: "test-artifacts/secure-login-failure.png", fullPage: true }).catch(() => {});
  throw failure;
} finally {
  await browser.close();
}
