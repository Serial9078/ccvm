import { apiResourceUrl } from "../../shared/api/config";
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


export interface ScreenshotInventoryRow {
  id: number;
  url_id: number;

  url: string;
  hostname: string;

  domain_id: number;
  host_id: number | null;

  title: string | null;
  final_url: string | null;

  status_code: number | null;
  duration_ms: number | null;

  screenshot_path: string;
  screenshot_url: string;
  filename: string;

  viewport_width: number;
  viewport_height: number;

  source: string;
}


function hostnameFromUrl(
  value: string,
): string {
  try {
    return new URL(value).hostname;
  } catch {
    return "unknown";
  }
}


function filenameFromScreenshot(
  screenshot: UrlScreenshot,
): string | null {
  if (screenshot.filename) {
    return screenshot.filename;
  }

  if (!screenshot.screenshot_path) {
    return null;
  }

  const parts = screenshot.screenshot_path
    .split("/")
    .filter(Boolean);

  if (parts.length === 0) {
    return null;
  }

  return parts[
    parts.length - 1
  ] || null;
}


function buildScreenshotUrl(
  filename: string,
): string {
  return apiResourceUrl(`screenshots/${encodeURIComponent(filename)}`);
}


export async function getScreenshotInventory():
Promise<ScreenshotInventoryRow[]> {
  const [
    urlsResponse,
    screenshotsResponse,
  ] = await Promise.all([
    api.get<DiscoveredUrl[]>(
      "/urls",
    ),
    api.get<UrlScreenshot[]>(
      "/url-screenshots",
    ),
  ]);

  const urlById = new Map<
    number,
    DiscoveredUrl
  >();

  for (
    const urlRecord
    of urlsResponse.data
  ) {
    urlById.set(
      urlRecord.id,
      urlRecord,
    );
  }

  const inventory:
  ScreenshotInventoryRow[] = [];

  for (
    const screenshot
    of screenshotsResponse.data
  ) {
    if (screenshot.error) {
      continue;
    }

    const filename =
      filenameFromScreenshot(
        screenshot,
      );

    if (!filename) {
      continue;
    }

    const urlRecord = urlById.get(
      screenshot.url_id,
    );

    const effectiveUrl =
      screenshot.final_url
      || urlRecord?.url
      || "";

    if (!effectiveUrl) {
      continue;
    }

    inventory.push({
      id: screenshot.id,
      url_id: screenshot.url_id,

      url:
        urlRecord?.url
        || effectiveUrl,

      hostname:
        hostnameFromUrl(
          effectiveUrl,
        ),

      domain_id:
        urlRecord?.domain_id
        || 0,

      host_id:
        urlRecord?.host_id
        ?? null,

      title:
        screenshot.title
        ?? null,

      final_url:
        screenshot.final_url
        ?? null,

      status_code:
        screenshot.status_code
        ?? urlRecord?.status_code
        ?? null,

      duration_ms:
        screenshot.duration_ms
        ?? null,

      screenshot_path:
        screenshot.screenshot_path
        || `/screenshots/${filename}`,

      screenshot_url:
        buildScreenshotUrl(
          filename,
        ),

      filename,

      viewport_width:
        screenshot.viewport_width,

      viewport_height:
        screenshot.viewport_height,

      source:
        screenshot.source,
    });
  }

  inventory.sort(
    (
      left,
      right,
    ) => {
      const hostnameResult =
        left.hostname.localeCompare(
          right.hostname,
        );

      if (hostnameResult !== 0) {
        return hostnameResult;
      }

      return left.url.localeCompare(
        right.url,
      );
    },
  );

  return inventory;
}
