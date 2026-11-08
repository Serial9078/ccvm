import assert from "node:assert/strict";
import test from "node:test";
import {
  apiSession,
  invalidateApiSession,
  onSessionUnauthorized,
  parseSession,
  secureSameOrigin,
  sessionRequestHeaders,
  setApiSession,
} from "../src/shared/auth/session.ts";

const local = () => ({
  mode: "local",
  authenticated: true,
  user: { username: "fixture" },
  csrf_token: "x".repeat(43),
  expires_at: new Date(Date.now() + 60000).toISOString(),
});

test("only explicit legacy mode permits legacy access; malformed sessions fail closed", () => {
  assert.deepEqual(parseSession({ mode: "legacy", authenticated: false }), {
    mode: "legacy",
    authenticated: false,
  });
  assert.deepEqual(parseSession({ mode: "local", authenticated: false }), {
    mode: "local",
    authenticated: false,
  });
  for (const value of [
    null,
    {},
    { mode: "local", authenticated: true },
    { ...local(), csrf_token: "short" },
    { ...local(), expires_at: "2000-01-01T00:00:00Z" },
  ])
    assert.throws(() => parseSession(value));
  assert.deepEqual(parseSession(local()).user, { username: "fixture" });
});

test("CSRF values are sent only on unsafe methods and unauthenticated local requests fail", () => {
  const session = local();
  for (const method of ["get", "HEAD", "OPTIONS"])
    assert.deepEqual(sessionRequestHeaders(method, session), {});
  for (const method of ["POST", "PATCH", "DELETE"])
    assert.deepEqual(sessionRequestHeaders(method, session), {
      "X-CSRF-Token": session.csrf_token,
      "X-CCVM-Request": "1",
    });
  assert.throws(() => sessionRequestHeaders("POST", { mode: "local", authenticated: false }));
  assert.deepEqual(sessionRequestHeaders("POST", { mode: "legacy", authenticated: false }), {});
});

test("a stale request cannot invalidate a newer login session", () => {
  let calls = 0;
  const stop = onSessionUnauthorized(() => calls++);
  const old = local();
  const current = local();
  setApiSession(current);
  invalidateApiSession(old);
  assert.equal(apiSession(), current);
  assert.equal(calls, 0);
  invalidateApiSession(current);
  assert.deepEqual(apiSession(), { mode: "local", authenticated: false });
  assert.equal(calls, 1);
  stop();
  setApiSession(null);
});

test("cookie API access requires same-origin HTTPS", () => {
  const location = {
    href: "https://ccvm.test/host-audits",
    protocol: "https:",
    origin: "https://ccvm.test",
  };
  assert.equal(secureSameOrigin(location, "/api/v1"), true);
  assert.equal(secureSameOrigin(location, "https://other.test/api"), false);
  assert.equal(secureSameOrigin(location, "http://ccvm.test/api"), false);
});
