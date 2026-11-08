export interface OperatorSession {
  mode: "local";
  authenticated: true;
  user: { username: string };
  csrf_token: string;
  expires_at: string;
}

export type SessionResponse = OperatorSession | { mode: "local" | "legacy"; authenticated: false };

// Only non-secret session metadata and the CSRF value live in memory. The
// authentication cookie is HttpOnly and is never read or copied by JavaScript.
let current: SessionResponse | null = null;
const unauthorizedListeners = new Set<() => void>();

export function setApiSession(session: SessionResponse | null) {
  current = session;
}

export function apiSession() {
  return current;
}

export function onSessionUnauthorized(listener: () => void) {
  unauthorizedListeners.add(listener);
  return () => unauthorizedListeners.delete(listener);
}

export function invalidateApiSession(expected?: SessionResponse) {
  if (expected && current !== expected) return;
  if (current?.mode !== "local") return;
  current = { mode: "local", authenticated: false };
  for (const listener of unauthorizedListeners) listener();
}

export function secureSameOrigin(
  location: { href: string; protocol: string; origin: string },
  destination: string,
) {
  const target = new URL(destination, location.href);
  return (
    location.protocol === "https:" &&
    target.protocol === "https:" &&
    target.origin === location.origin
  );
}

export function sessionRequestHeaders(method: string, session = current): Record<string, string> {
  if (session?.mode !== "local") return {};
  if (!session.authenticated) throw new Error("Bitte anmelden.");
  return ["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase())
    ? {}
    : { "X-CSRF-Token": session.csrf_token, "X-CCVM-Request": "1" };
}

export function parseSession(value: unknown): SessionResponse {
  if (!value || typeof value !== "object") throw new Error("Ungültige Sitzungsantwort.");
  const candidate = value as Record<string, unknown>;
  if (
    (candidate.mode === "legacy" || candidate.mode === "local") &&
    candidate.authenticated === false
  )
    return { mode: candidate.mode, authenticated: false };
  const user = candidate.user as Record<string, unknown> | undefined;
  if (
    candidate.mode === "local" &&
    candidate.authenticated === true &&
    typeof user?.username === "string" &&
    user.username.length > 0 &&
    typeof candidate.csrf_token === "string" &&
    candidate.csrf_token.length >= 32 &&
    typeof candidate.expires_at === "string" &&
    Number.isFinite(Date.parse(candidate.expires_at)) &&
    Date.parse(candidate.expires_at) > Date.now()
  )
    return {
      mode: "local",
      authenticated: true,
      user: { username: user.username },
      csrf_token: candidate.csrf_token,
      expires_at: candidate.expires_at,
    };
  throw new Error("Ungültige oder abgelaufene Sitzungsantwort.");
}
