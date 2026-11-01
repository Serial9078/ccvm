export function resolveApiBaseUrl(value?: string): string {
  return value?.trim().replace(/\/+$/, "") || "/api/v1";
}

// Vite replaces this at build time. The optional lookup also supports Node tests.
export const apiBaseUrl = resolveApiBaseUrl(import.meta.env?.VITE_API_URL);

export function apiResourceUrl(resource: string, baseUrl = apiBaseUrl): string {
  return `${resolveApiBaseUrl(baseUrl)}/${resource.replace(/^\/+/, "")}`;
}
