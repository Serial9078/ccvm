import { api } from "../../shared/api/api";


export interface DiscoveredUrl {
  id: number;
  customer_id: number;
  domain_id: number;
  host_id?: number | null;

  url: string;
  method: string;

  status_code?: number | null;
  content_type?: string | null;

  source: string;
}


export interface UrlDetail {
  id: number;
  url_id: number;

  status_code?: number | null;
  title?: string | null;
  content_type?: string | null;
  content_length?: number | null;

  webserver?: string | null;
  ip_address?: string | null;
  final_url?: string | null;

  response_time_seconds?: number | null;

  method: string;
  source: string;
}


export interface UrlSecurity {
  id: number;
  url_id: number;

  checked_url?: string | null;
  status_code?: number | null;

  server?: string | null;
  powered_by?: string | null;

  strict_transport_security?: string | null;
  content_security_policy?: string | null;
  x_frame_options?: string | null;
  x_content_type_options?: string | null;
  referrer_policy?: string | null;
  permissions_policy?: string | null;

  cache_control?: string | null;
  etag?: string | null;
  last_modified?: string | null;

  hsts_present: boolean;
  csp_present: boolean;
  xfo_present: boolean;
  xcto_present: boolean;
  referrer_policy_present: boolean;
  permissions_policy_present: boolean;

  missing_headers?: string | null;
  security_score?: number | null;

  error?: string | null;
  source: string;
}


export interface UrlScreenshot {
  id: number;
  url_id: number;

  screenshot_path?: string | null;
  filename?: string | null;

  title?: string | null;
  final_url?: string | null;

  status_code?: number | null;
  duration_ms?: number | null;

  viewport_width: number;
  viewport_height: number;

  error?: string | null;
  source: string;
}


export interface UrlFinding {
  id: number;

  asset_id?: number | null;
  job_id?: number | null;

  scanner: string;
  template_id?: string | null;

  name: string;
  severity: string;
  status: string;

  host?: string | null;
  matched_at?: string | null;

  description?: string | null;
  remediation?: string | null;
  reference?: string | null;

  cve?: string | null;
  cvss_score?: number | null;

  raw_json?: string | null;
}


export interface UrlInventoryRow
  extends DiscoveredUrl {
  detail?: UrlDetail;
  security?: UrlSecurity;
  screenshot?: UrlScreenshot;
  findings: UrlFinding[];
}


function normalizeUrl(
  value?: string | null,
): string {
  if (!value) {
    return "";
  }

  try {
    const parsed = new URL(value);

    parsed.hash = "";

    if (
      parsed.pathname !== "/"
      && parsed.pathname.endsWith("/")
    ) {
      parsed.pathname =
        parsed.pathname.slice(0, -1);
    }

    return parsed.toString();
  } catch {
    return value.trim();
  }
}


function urlOrigin(
  value?: string | null,
): string {
  if (!value) {
    return "";
  }

  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}


function findingMatchesUrl(
  finding: UrlFinding,
  row: DiscoveredUrl,
  detail?: UrlDetail,
  security?: UrlSecurity,
): boolean {
  const rowCandidates = [
    row.url,
    detail?.final_url,
    security?.checked_url,
  ]
    .map(normalizeUrl)
    .filter(Boolean);

  const findingCandidates = [
    finding.matched_at,
    finding.host,
  ]
    .map(normalizeUrl)
    .filter(Boolean);

  if (
    findingCandidates.some(
      (candidate) =>
        rowCandidates.includes(candidate),
    )
  ) {
    return true;
  }

  const rowOrigins = new Set(
    [
      row.url,
      detail?.final_url,
      security?.checked_url,
    ]
      .map(urlOrigin)
      .filter(Boolean),
  );

  const findingOrigins = [
    finding.matched_at,
    finding.host,
  ]
    .map(urlOrigin)
    .filter(Boolean);

  if (
    finding.scanner === "headerprobe"
    && findingOrigins.some(
      (origin) => rowOrigins.has(origin),
    )
  ) {
    return true;
  }

  return false;
}


export async function getUrls():
Promise<DiscoveredUrl[]> {
  const { data } =
    await api.get<DiscoveredUrl[]>(
      "/urls",
    );

  return data;
}


export async function getUrlDetails():
Promise<UrlDetail[]> {
  const { data } =
    await api.get<UrlDetail[]>(
      "/url-details",
    );

  return data;
}


export async function getUrlSecurity():
Promise<UrlSecurity[]> {
  const { data } =
    await api.get<UrlSecurity[]>(
      "/url-security",
    );

  return data;
}


export async function getUrlScreenshots():
Promise<UrlScreenshot[]> {
  const { data } =
    await api.get<UrlScreenshot[]>(
      "/url-screenshots",
    );

  return data;
}


export async function getFindings():
Promise<UrlFinding[]> {
  const { data } =
    await api.get<UrlFinding[]>(
      "/findings",
    );

  return data;
}


export async function getUrlInventory():
Promise<UrlInventoryRow[]> {
  const [
    urls,
    details,
    security,
    screenshots,
    findings,
  ] = await Promise.all([
    getUrls(),
    getUrlDetails(),
    getUrlSecurity(),
    getUrlScreenshots(),
    getFindings(),
  ]);

  const detailByUrlId = new Map(
    details.map((detail) => [
      detail.url_id,
      detail,
    ]),
  );

  const securityByUrlId = new Map(
    security.map((record) => [
      record.url_id,
      record,
    ]),
  );

  const screenshotByUrlId = new Map(
    screenshots.map((record) => [
      record.url_id,
      record,
    ]),
  );

  return urls.map((url) => {
    const detail =
      detailByUrlId.get(url.id);

    const securityRecord =
      securityByUrlId.get(url.id);

    const matchingFindings =
      findings
        .filter((finding) =>
          findingMatchesUrl(
            finding,
            url,
            detail,
            securityRecord,
          ),
        )
        .sort((left, right) => {
          const severityOrder:
          Record<string, number> = {
            critical: 1,
            high: 2,
            medium: 3,
            low: 4,
            info: 5,
          };

          return (
            (
              severityOrder[
                left.severity.toLowerCase()
              ] ?? 99
            )
            - (
              severityOrder[
                right.severity.toLowerCase()
              ] ?? 99
            )
            || right.id - left.id
          );
        });

    return {
      ...url,
      detail,
      security: securityRecord,
      screenshot:
        screenshotByUrlId.get(url.id),
      findings: matchingFindings,
    };
  });
}
