import axios from "axios";

import { apiBaseUrl } from "./config";
import { apiSession, invalidateApiSession, secureSameOrigin, sessionRequestHeaders } from "../auth/session";
import type { SessionResponse } from "../auth/session";

export const api = axios.create({
  baseURL: apiBaseUrl,
  timeout: 30000,
});

const requestSessions = new WeakMap<object, SessionResponse>();
api.interceptors.request.use((config) => {
  const session = apiSession();
  if (!session) throw new Error("Die Sitzung wird geprüft. Bitte erneut versuchen.");
  if (session?.mode === "local") {
    if (!secureSameOrigin(window.location, axios.getUri(config)))
      throw new Error("CCVM benötigt HTTPS und den API-Proxy derselben Adresse.");
    for (const [name, value] of Object.entries(sessionRequestHeaders(config.method ?? "GET", session)))
      config.headers.set(name, value);
    config.headers.set("Cache-Control", "no-store");
    config.withCredentials = true;
    requestSessions.set(config, session);
  }
  return config;
});
api.interceptors.response.use((response) => response, (error) => {
  const session = error.config && requestSessions.get(error.config);
  if (error.response?.status === 401 && session) invalidateApiSession(session);
  return Promise.reject(error);
});
