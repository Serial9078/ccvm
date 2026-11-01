import type {
  UrlFinding,
  UrlInventoryRow,
} from "./api";


export type ChipColor =
  | "primary"
  | "error"
  | "info"
  | "success"
  | "warning";


export type StatusFilter =
  | "all"
  | "success"
  | "redirect"
  | "client-error"
  | "server-error"
  | "unknown";


export interface UrlFilters {
  search: string;
  status: StatusFilter;
  findingsOnly: boolean;
  missingHeadersOnly: boolean;
  screenshotsOnly: boolean;
  loginPagesOnly: boolean;
}


export interface UrlGridRow
  extends UrlInventoryRow {
  displayStatus: number | null;
  displayScore: number | null;
  displayTitle: string;
  displayServer: string;

  openFindingCount: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;

  hasMissingHeaders: boolean;
  hasScreenshot: boolean;
  isLoginPage: boolean;
}


export const initialUrlFilters:
UrlFilters = {
  search: "",
  status: "all",
  findingsOnly: false,
  missingHeadersOnly: false,
  screenshotsOnly: false,
  loginPagesOnly: false,
};


export function statusColor(
  statusCode?: number | null,
): ChipColor {
  if (
    statusCode === null
    || statusCode === undefined
  ) {
    return "primary";
  }

  if (
    statusCode >= 200
    && statusCode < 300
  ) {
    return "success";
  }

  if (
    statusCode >= 300
    && statusCode < 400
  ) {
    return "warning";
  }

  return "error";
}


export function scoreColor(
  score?: number | null,
): ChipColor {
  if (
    score === null
    || score === undefined
  ) {
    return "primary";
  }

  if (score >= 80) {
    return "success";
  }

  if (score >= 50) {
    return "warning";
  }

  return "error";
}


export function severityColor(
  severity?: string | null,
): ChipColor {
  const value = String(
    severity || "",
  ).toLowerCase();

  if (
    value === "critical"
    || value === "high"
  ) {
    return "error";
  }

  if (value === "medium") {
    return "warning";
  }

  if (value === "low") {
    return "info";
  }

  return "primary";
}


export function screenshotUrl(
  path?: string | null,
): string | null {
  if (!path) {
    return null;
  }

  if (path.startsWith("/api/")) {
    return path;
  }

  if (
    path.startsWith(
      "/screenshots/",
    )
  ) {
    return `/api/v1${path}`;
  }

  const parts = path
    .split("/")
    .filter(Boolean);

  const filename =
    parts.length > 0
      ? parts[parts.length - 1]
      : path;

  return (
    "/api/v1/screenshots/"
    + encodeURIComponent(filename)
  );
}


export function isOpenFinding(
  finding: UrlFinding,
): boolean {
  return (
    finding.status
      .toLowerCase()
    === "open"
  );
}


function severityCount(
  findings: UrlFinding[],
  severity: string,
): number {
  return findings.filter(
    (finding) =>
      isOpenFinding(finding)
      && finding.severity
        .toLowerCase()
        === severity,
  ).length;
}


export function detectLoginPage(
  row: UrlInventoryRow,
): boolean {
  const value = [
    row.url,
    row.detail?.title,
    row.screenshot?.title,
    row.detail?.final_url,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  const indicators = [
    "login",
    "log-in",
    "signin",
    "sign-in",
    "auth",
    "sso",
    "account",
    "portal",
    "admin",
    "wp-login",
  ];

  return indicators.some(
    (indicator) =>
      value.includes(indicator),
  );
}


export function toGridRow(
  row: UrlInventoryRow,
): UrlGridRow {
  const openFindings =
    row.findings.filter(
      isOpenFinding,
    );

  return {
    ...row,

    displayStatus:
      row.detail?.status_code
      ?? row.status_code
      ?? row.security?.status_code
      ?? null,

    displayScore:
      row.security?.security_score
      ?? null,

    displayTitle:
      row.detail?.title
      || row.screenshot?.title
      || "-",

    displayServer:
      row.detail?.webserver
      || row.security?.server
      || "-",

    openFindingCount:
      openFindings.length,

    criticalCount:
      severityCount(
        row.findings,
        "critical",
      ),

    highCount:
      severityCount(
        row.findings,
        "high",
      ),

    mediumCount:
      severityCount(
        row.findings,
        "medium",
      ),

    lowCount:
      severityCount(
        row.findings,
        "low",
      ),

    hasMissingHeaders:
      Boolean(
        row.security
          ?.missing_headers
          ?.trim(),
      ),

    hasScreenshot:
      Boolean(
        row.screenshot
          ?.screenshot_path,
      ),

    isLoginPage:
      detectLoginPage(row),
  };
}


function matchesStatus(
  row: UrlGridRow,
  filter: StatusFilter,
): boolean {
  const status =
    row.displayStatus;

  if (filter === "all") {
    return true;
  }

  if (
    status === null
    || status === undefined
  ) {
    return filter === "unknown";
  }

  if (filter === "success") {
    return (
      status >= 200
      && status < 300
    );
  }

  if (filter === "redirect") {
    return (
      status >= 300
      && status < 400
    );
  }

  if (
    filter === "client-error"
  ) {
    return (
      status >= 400
      && status < 500
    );
  }

  if (
    filter === "server-error"
  ) {
    return (
      status >= 500
      && status < 600
    );
  }

  return false;
}


export function filterUrlRows(
  rows: UrlGridRow[],
  filters: UrlFilters,
): UrlGridRow[] {
  const searchValue =
    filters.search
      .trim()
      .toLowerCase();

  return rows.filter((row) => {
    if (
      !matchesStatus(
        row,
        filters.status,
      )
    ) {
      return false;
    }

    if (
      filters.findingsOnly
      && row.openFindingCount === 0
    ) {
      return false;
    }

    if (
      filters.missingHeadersOnly
      && !row.hasMissingHeaders
    ) {
      return false;
    }

    if (
      filters.screenshotsOnly
      && !row.hasScreenshot
    ) {
      return false;
    }

    if (
      filters.loginPagesOnly
      && !row.isLoginPage
    ) {
      return false;
    }

    if (!searchValue) {
      return true;
    }

    const searchableValues = [
      row.url,
      row.method,
      row.content_type,
      row.displayTitle,
      row.displayServer,
      row.security
        ?.missing_headers,
      row.security?.powered_by,
      row.detail?.ip_address,

      ...row.findings.flatMap(
        (finding) => [
          finding.name,
          finding.template_id,
          finding.cve,
          finding.scanner,
          finding.description,
        ],
      ),
    ];

    return searchableValues.some(
      (value) =>
        String(value || "")
          .toLowerCase()
          .includes(
            searchValue,
          ),
    );
  });
}


function csvValue(
  value: unknown,
): string {
  const text = String(
    value ?? "",
  );

  return `"${text.replaceAll(
    "\"",
    "\"\"",
  )}"`;
}


export function exportUrlRowsCsv(
  rows: UrlGridRow[],
): void {
  const header = [
    "URL",
    "Method",
    "Status",
    "Security Score",
    "Open Findings",
    "Critical",
    "High",
    "Medium",
    "Low",
    "Title",
    "Server",
    "IP Address",
    "Content Type",
    "Missing Headers",
    "Login Page",
    "Screenshot",
  ];

  const csvRows = rows.map(
    (row) => [
      row.url,
      row.method,
      row.displayStatus
        ?? "UNKNOWN",
      row.displayScore ?? "",
      row.openFindingCount,
      row.criticalCount,
      row.highCount,
      row.mediumCount,
      row.lowCount,
      row.displayTitle,
      row.displayServer,
      row.detail?.ip_address
        || "",
      row.detail?.content_type
        || row.content_type
        || "",
      row.security
        ?.missing_headers
        || "",
      row.isLoginPage
        ? "yes"
        : "no",
      row.hasScreenshot
        ? "yes"
        : "no",
    ],
  );

  const content = [
    header,
    ...csvRows,
  ]
    .map(
      (columns) =>
        columns
          .map(csvValue)
          .join(";"),
    )
    .join("\n");

  const blob = new Blob(
    [`\uFEFF${content}`],
    {
      type:
        "text/csv;charset=utf-8",
    },
  );

  const objectUrl =
    URL.createObjectURL(blob);

  const anchor =
    document.createElement("a");

  anchor.href = objectUrl;

  anchor.download =
    `ccvm-url-intelligence-${
      new Date()
        .toISOString()
        .slice(0, 10)
    }.csv`;

  document.body.appendChild(
    anchor,
  );

  anchor.click();
  anchor.remove();

  URL.revokeObjectURL(
    objectUrl,
  );
}
