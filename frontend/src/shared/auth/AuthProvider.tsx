import { useCallback, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from "@mui/material";
import { apiBaseUrl } from "../api/config";
import { onSessionUnauthorized, parseSession, secureSameOrigin, setApiSession } from "./session";
import type { SessionResponse } from "./session";
import { AuthContext } from "./context";

async function authRequest(path: string, body?: unknown, csrf?: string) {
  const destination = `${apiBaseUrl}/auth${path}`;
  if (new URL(destination, window.location.href).origin !== window.location.origin)
    throw new Error("Die Anmeldung benötigt den API-Proxy derselben Adresse.");
  if (body !== undefined && !secureSameOrigin(window.location, destination))
    throw new Error("Die Anmeldung benötigt HTTPS.");
  const response = await fetch(destination, {
    method: body === undefined ? "GET" : "POST",
    headers: {
      "Content-Type": "application/json",
      ...(body === undefined ? {} : { "X-CCVM-Request": "1" }),
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
    cache: "no-store",
    redirect: "error",
    signal: AbortSignal.timeout(15000),
  });
  // An expired/revoked session is already logged out. Retrying a 401 cannot
  // revoke anything further and must not leave the login screen blocked.
  if (response.status === 204 || (path === "/logout" && response.status === 401)) return undefined;
  const data = await response.json();
  if (!response.ok) {
    const message =
      response.status === 429
        ? "Zu viele Anmeldeversuche. Bitte später erneut versuchen."
        : response.status === 401
          ? "Benutzername, Passwort oder Bestätigungscode stimmen nicht."
          : "Die Anmeldung ist derzeit nicht verfügbar. Bitte erneut versuchen.";
    throw new Error(message);
  }
  return data;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queries = useQueryClient();
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [checking, setChecking] = useState(true);
  const [generation, setGeneration] = useState(0);
  const [error, setError] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const revision = useRef(0);
  const pendingLogout = useRef<string | null>(null);
  const channel = useRef<BroadcastChannel | null>(null);
  const clearPrivate = useCallback(() => {
    revision.current++;
    setApiSession(null);
    setSession(null);
    setGeneration((prior) => prior + 1);
    setPassword("");
    setCode("");
    setBusy(false);
    void queries.cancelQueries();
    queries.clear();
  }, [queries]);
  const accept = useCallback((value: unknown) => {
    const next = parseSession(value);
    if (next.mode === "local" && !secureSameOrigin(window.location, apiBaseUrl))
      throw new Error("Die sichere Anmeldung benötigt HTTPS und den API-Proxy derselben Adresse.");
    setApiSession(next);
    setSession(next);
    setChecking(false);
  }, []);
  const restore = useCallback(async () => {
    clearPrivate();
    if (pendingLogout.current) {
      setChecking(false);
      setError(
        "Die Server-Sitzung konnte nicht beendet werden. Bitte die Abmeldung erneut versuchen.",
      );
      return;
    }
    const attempt = revision.current;
    setChecking(true);
    setError("");
    try {
      const next = await authRequest("/session");
      if (attempt === revision.current) accept(next);
    } catch (failure) {
      if (attempt === revision.current) {
        setChecking(false);
        setError(
          failure instanceof Error ? failure.message : "Sitzung konnte nicht geprüft werden.",
        );
      }
    }
  }, [accept, clearPrivate]);
  useEffect(() => {
    void restore();
    const unauthenticated = () => {
      clearPrivate();
      const next = { mode: "local", authenticated: false } as const;
      setApiSession(next);
      setSession(next);
      setChecking(false);
      setError("Die Sitzung ist abgelaufen. Bitte erneut anmelden.");
    };
    const unsubscribe = onSessionUnauthorized(unauthenticated);
    const hide = () => {
      clearPrivate();
      setChecking(true);
    };
    const show = (event: PageTransitionEvent) => {
      if (event.persisted) void restore();
    };
    window.addEventListener("pagehide", hide);
    window.addEventListener("pageshow", show);
    let broadcast: BroadcastChannel | null = null;
    if (typeof BroadcastChannel !== "undefined") {
      broadcast = new BroadcastChannel("ccvm-session");
      broadcast.onmessage = (event) => {
        if (event.data === "logout") unauthenticated();
      };
      channel.current = broadcast;
    }
    const invalidatePending = () => {
      revision.current++;
    };
    return () => {
      invalidatePending();
      unsubscribe();
      window.removeEventListener("pagehide", hide);
      window.removeEventListener("pageshow", show);
      broadcast?.close();
      channel.current = null;
    };
  }, [clearPrivate, restore]);
  useEffect(() => {
    if (session?.mode !== "local" || !session.authenticated) return;
    const timer = window.setTimeout(
      () => {
        clearPrivate();
        const next = { mode: "local", authenticated: false } as const;
        setApiSession(next);
        setSession(next);
        setError("Die Sitzung ist abgelaufen. Bitte erneut anmelden.");
      },
      Math.max(0, Date.parse(session.expires_at) - Date.now()),
    );
    return () => window.clearTimeout(timer);
  }, [session, clearPrivate]);
  const login = async () => {
    const attempt = ++revision.current;
    setBusy(true);
    setError("");
    const submitted = { username: username.trim(), password, code };
    setPassword("");
    setCode("");
    try {
      const next = parseSession(await authRequest("/login", submitted));
      if (next.mode !== "local" || !next.authenticated)
        throw new Error("Anmeldung wurde nicht bestätigt.");
      if (attempt === revision.current) {
        queries.clear();
        setGeneration((prior) => prior + 1);
        accept(next);
      }
    } catch (failure) {
      if (attempt === revision.current)
        setError(failure instanceof Error ? failure.message : "Anmeldung fehlgeschlagen.");
    } finally {
      if (attempt === revision.current) setBusy(false);
    }
  };
  const logout = async () => {
    const csrf =
      pendingLogout.current ??
      (session?.mode === "local" && session.authenticated ? session.csrf_token : null);
    if (!csrf) return;
    pendingLogout.current = csrf;
    clearPrivate();
    setBusy(true);
    setChecking(false);
    setError("");
    channel.current?.postMessage("logout");
    try {
      await authRequest("/logout", {}, csrf);
      pendingLogout.current = null;
      const next = { mode: "local", authenticated: false } as const;
      setApiSession(next);
      setSession(next);
    } catch {
      setError(
        "Die Server-Sitzung konnte nicht beendet werden. Bitte die Abmeldung erneut versuchen.",
      );
    } finally {
      setBusy(false);
    }
  };
  const allowed =
    session?.mode === "legacy" || (session?.mode === "local" && session.authenticated);
  return (
    <AuthContext.Provider value={{ session, generation, logout }}>
      {allowed && !checking ? (
        <Box key={generation}>{children}</Box>
      ) : (
        <Box
          component="main"
          sx={{ minHeight: "100vh", display: "grid", placeItems: "center", p: 2 }}
        >
          <Paper sx={{ width: "100%", maxWidth: 440, p: { xs: 3, sm: 4 } }}>
            <Stack spacing={2.5}>
              <Box
                component="img"
                src="/assets/cloudcollab-logo.jpg"
                alt="CloudCollab"
                sx={{ width: 72, height: 72 }}
              />
              <Box>
                <Typography variant="h4">Bei CCVM anmelden</Typography>
                <Typography color="text.secondary" sx={{ mt: 1 }}>
                  Vulnerability Manager · CloudCollab
                </Typography>
              </Box>
              {checking ? (
                <Stack direction="row" spacing={2} sx={{ alignItems: "center" }}>
                  <CircularProgress size={20} />
                  <Typography>Sitzung wird geprüft …</Typography>
                </Stack>
              ) : (
                <>
                  {error && (
                    <Alert severity="error" role="alert">
                      {error}
                    </Alert>
                  )}
                  {pendingLogout.current ? (
                    <Button variant="contained" disabled={busy} onClick={() => void logout()}>
                      Abmeldung erneut versuchen
                    </Button>
                  ) : session?.mode === "local" ? (
                    <Box
                      component="form"
                      onSubmit={(event) => {
                        event.preventDefault();
                        void login();
                      }}
                    >
                      <Stack spacing={2}>
                        <TextField
                          label="Benutzername"
                          name="username"
                          autoComplete="username"
                          autoFocus
                          required
                          value={username}
                          disabled={busy}
                          onChange={(event) => setUsername(event.target.value)}
                        />
                        <TextField
                          label="Passwort"
                          name="password"
                          type="password"
                          autoComplete="current-password"
                          required
                          value={password}
                          disabled={busy}
                          onChange={(event) => setPassword(event.target.value)}
                        />
                        <TextField
                          label="Bestätigungscode"
                          name="code"
                          autoComplete="one-time-code"
                          required
                          value={code}
                          disabled={busy}
                          onChange={(event) =>
                            setCode(event.target.value.replace(/\D/g, "").slice(0, 6))
                          }
                          slotProps={{
                            htmlInput: { inputMode: "numeric", pattern: "[0-9]{6}", maxLength: 6 },
                          }}
                          helperText="6-stelliger Code aus deiner Authenticator-App"
                        />
                        <Button
                          type="submit"
                          variant="contained"
                          disabled={busy || !username.trim() || !password || !/^\d{6}$/.test(code)}
                        >
                          {busy ? "Anmeldung läuft …" : "Anmelden"}
                        </Button>
                      </Stack>
                    </Box>
                  ) : (
                    <Button variant="contained" disabled={busy} onClick={() => void restore()}>
                      Erneut versuchen
                    </Button>
                  )}
                </>
              )}
            </Stack>
          </Paper>
        </Box>
      )}
    </AuthContext.Provider>
  );
}
