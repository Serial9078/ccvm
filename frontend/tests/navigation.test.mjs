import assert from "node:assert/strict";
import test from "node:test";
import { customerNavigationSearch, navigationGroups } from "../src/shared/layout/navigation.ts";

test("the requested web and infrastructure categories each have a separate navigation target", () => {
  const groups = Object.fromEntries(navigationGroups.map((group) => [group.label, group.items]));
  assert.deepEqual(groups.Web.map(({ label, path }) => [label, path]), [
    ["Domains", "/domains"], ["URLs", "/urls"],
  ]);
  assert.deepEqual(groups.Infrastruktur.map(({ label, path }) => [label, path]), [
    ["Netzwerk", "/networks"],
    ["Windows Server", "/windows-servers"],
    ["Windows Clients", "/windows-clients"],
    ["Linux", "/linux"],
    ["VMware", "/vmware"],
  ]);
  const paths = navigationGroups.flatMap((group) => group.items.map((item) => item.path));
  assert.equal(new Set(paths).size, paths.length);
  for (const path of ["/host-audits", "/subdomains", "/hosts", "/ports", "/technologies",
    "/screenshots", "/assets", "/scans", "/findings", "/reports", "/settings", "/pipelines"])
    assert.ok(paths.includes(path), `Existing destination ${path} remains available`);
});

test("only one positive customer identifier survives navigation; secrets and other query data do not", () => {
  assert.equal(customerNavigationSearch("?customer_id=17&token=private&target=example.test"),
    "?customer_id=17");
  for (const query of ["", "?token=private", "?customer_id=0", "?customer_id=-1",
    "?customer_id=1.5", "?customer_id=abc", "?customer_id=1&customer_id=2",
    "?customer_id=12345678901", "?customer_id=1%26token%3Dprivate"])
    assert.equal(customerNavigationSearch(query), "");
});
