import { useEffect, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Link,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import { auditRequest } from "./api";
import type { SoftwareAssessment, SoftwareCatalog } from "./api";

const products: Record<string, string> = {
  "edge-windows": "Microsoft Edge for Windows",
  "7zip-windows": "7-Zip for Windows",
};
const statuses: Record<string, string> = {
  version_matches_found: "Affected version ranges matched",
  no_matches_in_checked_ranges: "No match in the checked advisory ranges",
  coverage_unavailable: "No usable software coverage",
  stale_evidence: "Inventory evidence is too old",
  stale_catalog: "Software catalog is too old",
  catalog_unavailable: "Software advisory catalog unavailable",
  unsupported: "Inventory outside software assessment scope",
  identity_incomplete: "More software identity evidence needed",
};
const productStatuses: Record<string, string> = {
  version_matches_affected_range: "Affected version range matched",
  no_match_in_catalog: "No match in checked ranges",
  catalog_incomplete: "Advisory coverage incomplete",
};

function date(value: string | null | undefined) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "Unavailable" : parsed.toLocaleString();
}

function sourceUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" &&
      [
        "raw.githubusercontent.com",
        "github.com",
        "api.msrc.microsoft.com",
        "msrc.microsoft.com",
        "www.7-zip.org",
        "7-zip.org",
      ].includes(url.hostname) &&
      !url.username &&
      !url.password
      ? value
      : undefined;
  } catch {
    return undefined;
  }
}

export function SoftwareCatalogPanel({ token }: { token: string }) {
  const [catalog, setCatalog] = useState<SoftwareCatalog | null | undefined>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void auditRequest<SoftwareCatalog | null>(
      token,
      "/software-catalog",
      undefined,
      controller.signal,
    )
      .then(setCatalog)
      .catch((failure) => {
        if (!controller.signal.aborted)
          setError(
            failure instanceof Error ? failure.message : "Software catalog status unavailable.",
          );
      });
    return () => controller.abort();
  }, [token]);
  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      setCatalog(await auditRequest<SoftwareCatalog | null>(token, "/software-catalog"));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Software catalog status unavailable.");
    } finally {
      setLoading(false);
    }
  };
  return (
    <Paper sx={{ p: 3 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 2 }}>
        <Typography variant="h6">Software advisory catalog</Typography>
        <Button disabled={loading} onClick={refresh}>
          Refresh software catalog status
        </Button>
      </Stack>
      {error && (
        <Alert severity="warning" sx={{ mt: 1 }}>
          {error}
        </Alert>
      )}
      {catalog === undefined && !error ? (
        <Typography color="text.secondary">Loading software catalog status…</Typography>
      ) : catalog === undefined ? null : catalog === null ? (
        <Typography color="text.secondary">
          No software advisory catalog has been synchronized. Installed software assessments will
          report missing coverage.
        </Typography>
      ) : (
        <Stack spacing={1}>
          <Typography color="text.secondary">
            Retrieved {date(catalog.retrieved_at)} · Selected Edge advisory discovery{" "}
            {catalog.coverage_start}
            {" to "}
            {catalog.coverage_end} · {catalog.entry_count.toLocaleString()} usable advisory ranges
          </Typography>
          {catalog.coverage.map((coverage) => (
            <Typography key={coverage.product_key} variant="body2" color="text.secondary">
              {products[coverage.product_key] ?? coverage.product_key} · {coverage.parsed}/
              {coverage.discovered} discovered advisories have usable version ranges
              {coverage.unavailable_cves.length > 0 &&
                ` · ${coverage.unavailable_cves.length} could not be evaluated`}{" "}
              · {coverage.scope}
            </Typography>
          ))}
          {catalog.expired && (
            <Alert severity="warning">
              This catalog is too old for a current assessment. Synchronize software advisory data
              before assessing installed programs.
            </Alert>
          )}
        </Stack>
      )}
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        Scope: selected Microsoft Edge-specific advisories and the curated 7-Zip advisory
        CVE-2025-55188. Upstream Chromium advisories, other component CVEs and other products remain
        unassessed.
      </Typography>
    </Paper>
  );
}

export function SoftwareAssessmentDialog({
  target,
  assessments,
  close,
}: {
  target: string;
  assessments: SoftwareAssessment[];
  close: () => void;
}) {
  const [selected, setSelected] = useState(assessments[0]?.id);
  const [limit, setLimit] = useState(100);
  const assessment = assessments.find((item) => item.id === selected) ?? assessments[0];
  const result = assessment?.result;
  const validity = result?.valid_until ? new Date(result.valid_until).valueOf() : NaN;
  const expired =
    (Number.isFinite(validity) && (assessment?.expired || validity <= Date.now())) ||
    ["stale_evidence", "stale_catalog"].includes(assessment?.status ?? "");
  const validityUnknown =
    ["version_matches_found", "no_matches_in_checked_ranges"].includes(assessment?.status ?? "") &&
    !Number.isFinite(validity);
  return (
    <Dialog open onClose={close} maxWidth="lg" fullWidth>
      <DialogTitle>Installed software assessment · {target}</DialogTitle>
      <DialogContent>
        {!result ? (
          <Typography>No saved software assessments for this inventory yet.</Typography>
        ) : (
          <Stack spacing={2}>
            {assessments.length > 1 && (
              <TextField
                select
                label="Saved software assessment"
                value={assessment.id}
                onChange={(event) => {
                  setSelected(Number(event.target.value));
                  setLimit(100);
                }}
              >
                {assessments.map((item) => (
                  <MenuItem key={item.id} value={item.id}>
                    {date(item.evaluated_at)} · {statuses[item.status] ?? "Assessment unavailable"}
                  </MenuItem>
                ))}
              </TextField>
            )}
            <Box>
              <Chip
                label={statuses[assessment.status] ?? "Assessment unavailable"}
                color={
                  assessment.status === "version_matches_found" || expired ? "warning" : "default"
                }
                sx={{ mb: 1 }}
              />
              <Typography>{result.reason}</Typography>
              <Typography variant="body2" color="text.secondary">
                Assessed {date(assessment.evaluated_at)} · Inventory{" "}
                {date(result.evidence_collected_at)}
              </Typography>
            </Box>
            {expired && (
              <Alert severity="warning">
                This saved software assessment has expired. Collect current inventory or synchronize
                the catalog, then assess again.
              </Alert>
            )}
            {validityUnknown && (
              <Alert severity="warning">
                This saved software comparison has no valid assessment window. Obtain current
                inventory and catalog data before relying on it.
              </Alert>
            )}
            <Alert severity="info">
              Only the listed product and advisory ranges were checked. Version matches require
              review; exploitability was not verified. Unassessed software remains outside coverage.
              Edge coverage excludes upstream Chromium advisories and other component CVEs.
            </Alert>
            <Typography variant="h6">
              {result.summary.inventory_entries.toLocaleString()} inventory entries ·{" "}
              {result.summary.assessed_entries.toLocaleString()} assessed ·{" "}
              {result.summary.unassessed_entries.toLocaleString()} unassessed
            </Typography>
            <Typography color="text.secondary">
              {result.summary.product_versions.toLocaleString()} identified product versions ·{" "}
              {result.summary.cve_matches.toLocaleString()} version/advisory matches
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Software catalog retrieved {date(result.catalog_retrieved_at)} · Selected Edge
              discovery {result.coverage.catalog_start ?? "unavailable"} to{" "}
              {result.coverage.catalog_end ?? "unavailable"} · Package inventory{" "}
              {result.coverage.package_status.replaceAll("_", " ")}
            </Typography>
            {result.coverage.package_status !== "complete" && (
              <Alert severity="warning">
                Package evidence is incomplete. Available entries were retained; missing programs
                could not be assessed.
              </Alert>
            )}
            {result.coverage.vendor_catalog.map((coverage) => (
              <Typography key={coverage.product_key} variant="body2" color="text.secondary">
                {products[coverage.product_key] ?? coverage.product_key}: {coverage.parsed}/
                {coverage.discovered} discovered advisories have usable ranges · {coverage.scope}
                {coverage.unavailable_cves.length > 0 &&
                  ` · Unavailable: ${coverage.unavailable_cves.join(", ")}`}
              </Typography>
            ))}
            {result.products.map((product) => (
              <Paper
                key={`${product.product_key}:${product.version}`}
                variant="outlined"
                sx={{ p: 2 }}
              >
                <Typography variant="h6">
                  {product.name} · {product.version}
                </Typography>
                <Typography variant="body2" color="text.secondary">
                  Publisher: {product.publisher} · {product.evidence_basis} ·{" "}
                  {product.evidence_count} registry{" "}
                  {product.evidence_count === 1 ? "entry" : "entries"}
                </Typography>
                <Chip
                  size="small"
                  label={productStatuses[product.status] ?? "Coverage unavailable"}
                  color={product.status === "no_match_in_catalog" ? "default" : "warning"}
                  sx={{ my: 1 }}
                />
                <Typography>{product.reason}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {product.checked_cves} advisory ranges checked · {product.catalog_scope}
                </Typography>
                {product.matches.length > 0 && (
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Advisory</TableCell>
                        <TableCell>Affected versions and fix</TableCell>
                        <TableCell>Published severity</TableCell>
                        <TableCell>Official sources</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {product.matches.slice(0, limit).map((match) => (
                        <TableRow key={match.cve}>
                          <TableCell sx={{ overflowWrap: "anywhere" }}>
                            <strong>{match.cve}</strong>
                            <br />
                            {match.title}
                            <Typography variant="caption" component="div" color="text.secondary">
                              Source product: {match.source_product}
                            </Typography>
                          </TableCell>
                          <TableCell>
                            {match.affected_ranges.map((range) => (
                              <Typography
                                key={`${range.introduced}:${range.fixed}`}
                                variant="body2"
                              >
                                {range.introduced} ≤ version &lt; {range.fixed}
                                <br />
                                Fixed in {range.fixed}
                              </Typography>
                            ))}
                          </TableCell>
                          <TableCell>{match.severity}</TableCell>
                          <TableCell>
                            {match.source_urls.map(
                              (url, index) =>
                                sourceUrl(url) && (
                                  <Link
                                    key={url}
                                    href={sourceUrl(url)}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    sx={{ display: "block" }}
                                  >
                                    Source {index + 1}
                                  </Link>
                                ),
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
                {product.matches.length > limit && (
                  <Button onClick={() => setLimit(limit + 100)}>
                    Show 100 more version matches
                  </Button>
                )}
                {product.matches_truncated && (
                  <Typography color="text.secondary">
                    The stored match list is limited; total matches: {product.matches_total}.
                  </Typography>
                )}
              </Paper>
            ))}
            {result.products_truncated && (
              <Typography color="text.secondary">
                The stored product list is limited; total product versions: {result.products_total}.
              </Typography>
            )}
            {result.unassessed.length > 0 && (
              <Box>
                <Typography variant="h6">
                  Unassessed software · {result.unassessed_total}
                </Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Recorded program</TableCell>
                      <TableCell>Version</TableCell>
                      <TableCell>Publisher</TableCell>
                      <TableCell>Coverage gap</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.unassessed.slice(0, limit).map((item, index) => (
                      <TableRow key={index}>
                        <TableCell sx={{ overflowWrap: "anywhere" }}>{item.name}</TableCell>
                        <TableCell>{item.version || "Unavailable"}</TableCell>
                        <TableCell>{item.publisher || "Unavailable"}</TableCell>
                        <TableCell>
                          {item.reason}
                          {item.evidence_count > 1 && ` · ${item.evidence_count} entries`}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {result.unassessed.length > limit && (
                  <Button onClick={() => setLimit(limit + 100)}>
                    Show 100 more unassessed programs
                  </Button>
                )}
                {result.unassessed_truncated && (
                  <Typography color="text.secondary">
                    The stored unassessed list is limited; total entries: {result.unassessed_total}.
                  </Typography>
                )}
              </Box>
            )}
            {result.limitations.length > 0 && (
              <Typography variant="body2" color="text.secondary">
                {result.limitations.join(" ")}
              </Typography>
            )}
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Close software assessment</Button>
      </DialogActions>
    </Dialog>
  );
}
