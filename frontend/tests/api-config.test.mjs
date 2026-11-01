import assert from "node:assert/strict";
import test from "node:test";

import { apiBaseUrl, apiResourceUrl, resolveApiBaseUrl } from "../src/shared/api/config.ts";
import { screenshotUrl, toGridRow } from "../src/features/urls/utils.ts";

for (const [input, expected] of [
  [undefined, "/api/v1"],
  ["", "/api/v1"],
  ["   ", "/api/v1"],
  ["/api/v1/", "/api/v1"],
  [" https://ccvm-ci.invalid/api/v1/// ", "https://ccvm-ci.invalid/api/v1"],
]) {
  test(`API base ${JSON.stringify(input)} resolves without a deployment host`, () => {
    assert.equal(resolveApiBaseUrl(input), expected);
  });
}

test("same-origin requests and configured resources retain the API prefix", () => {
  assert.equal(apiBaseUrl, "/api/v1");
  assert.equal(apiResourceUrl("/urls"), "/api/v1/urls");
  assert.equal(apiResourceUrl("screenshots/ci.png", "https://ccvm-ci.invalid/api/v1/"),
    "https://ccvm-ci.invalid/api/v1/screenshots/ci.png");
});

for (const input of ["ci.png", "/screenshots/ci.png", "/api/v1/screenshots/ci.png", "/data/screenshots/ci.png"]) {
  test(`screenshot path ${input} uses the same API route`, () => {
    assert.equal(screenshotUrl(input), "/api/v1/screenshots/ci.png");
  });
}

test("missing screenshot stays absent and filenames are encoded", () => {
  assert.equal(screenshotUrl(null), null);
  assert.equal(screenshotUrl("/screenshots/a b.png"), "/api/v1/screenshots/a%20b.png");
});

test("failed probe keeps an unknown score and zero remains a real score", () => {
  const row = { id: 1, url: "https://example.test/", findings: [],
    security: { security_score: null, error: "timeout" } };
  assert.equal(toGridRow(row).displayScore, null);
  assert.equal(toGridRow({ ...row, security: { security_score: 0 } }).displayScore, 0);
});
