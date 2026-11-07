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
import type { HostAssessment, PatchCatalog } from "./api";
import { WindowsUpdateReport } from "./windows-update-report";
import { updateStatusLabels } from "./overview-state";

const statuses: Record<string, string> = {
  ...updateStatusLabels,
  build_gap: "Below Microsoft update baseline",
  meets_catalog_baseline: "Meets catalog build baseline",
  identity_incomplete: "More OS identity evidence needed",
  unsupported: "OS not covered by this assessment",
  catalog_unavailable: "Microsoft update catalog unavailable",
  stale_evidence: "Inventory evidence is too old",
  stale_catalog: "Microsoft update catalog is too old",
  coverage_unavailable: "No applicable build baseline available",
};

function date(value: string | null | undefined) {
  if (!value) return "Unavailable";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "Unavailable" : parsed.toLocaleString();
}

function referenceUrl(documentId: string) {
  return /^\d{4}-[A-Za-z]{3}$/.test(documentId)
    ? `https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/${documentId}`
    : undefined;
}

export function PatchCatalogPanel({ token }: { token: string }) {
  const [catalog, setCatalog] = useState<PatchCatalog | null | undefined>();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void auditRequest<PatchCatalog | null>(token, "/patch-catalog", undefined, controller.signal)
      .then(setCatalog)
      .catch((failure) => {
        if (!controller.signal.aborted)
          setError(failure instanceof Error ? failure.message : "Catalog status unavailable.");
      });
    return () => controller.abort();
  }, [token]);
  const refresh = async () => {
    setLoading(true);
    setError("");
    try {
      setCatalog(await auditRequest<PatchCatalog | null>(token, "/patch-catalog"));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Catalog status unavailable.");
    } finally {
      setLoading(false);
    }
  };
  return (
    <Paper sx={{ p: 3 }}>
      <Stack direction="row" sx={{ alignItems: "center", justifyContent: "space-between", gap: 2 }}>
        <Typography variant="h6">Microsoft update catalog</Typography>
        <Button disabled={loading} onClick={refresh}>
          Refresh catalog status
        </Button>
      </Stack>
      {error && (
        <Alert severity="warning" sx={{ mt: 1 }}>
          {error}
        </Alert>
      )}
      {catalog === undefined && !error ? (
        <Typography color="text.secondary">Loading catalog status…</Typography>
      ) : catalog === undefined ? null : catalog === null ? (
        <Typography color="text.secondary">
          No Microsoft update catalog has been synchronized. Patch assessments will report missing
          coverage.
        </Typography>
      ) : (
        <>
          <Typography color="text.secondary">
            MSRC · Retrieved {date(catalog.retrieved_at)} · Coverage {catalog.coverage_start} to{" "}
            {catalog.coverage_end}
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Documents: {catalog.document_ids.join(", ")} · {catalog.entry_count.toLocaleString()}{" "}
            update references
          </Typography>
          {catalog.expired && (
            <Alert severity="warning" sx={{ mt: 1 }}>
              This catalog is too old for a current assessment. Synchronize Microsoft update data
              before assessing patches.
            </Alert>
          )}
        </>
      )}
    </Paper>
  );
}

export function PatchAssessmentDialog({
  target,
  assessments,
  close,
}: {
  target: string;
  assessments: HostAssessment[];
  close: () => void;
}) {
  const [selected, setSelected] = useState(assessments[0]?.id);
  const [limit, setLimit] = useState(100);
  const assessment = assessments.find((item) => item.id === selected) ?? assessments[0];
  const result = assessment?.result;
  const validUntil = result?.valid_until ? new Date(result.valid_until).valueOf() : NaN;
  const hasValidity = Number.isFinite(validUntil);
  const expired =
    Boolean(hasValidity && (assessment?.expired || validUntil <= Date.now())) ||
    ["stale_evidence", "stale_catalog"].includes(assessment?.status ?? "");
  const validityUnknown =
    ["build_gap", "meets_catalog_baseline"].includes(assessment?.status ?? "") && !hasValidity;
  return (
    <Dialog open onClose={close} maxWidth="lg" fullWidth>
      <DialogTitle>
        {result?.provider === "windows-update-agent"
          ? "Windows-Updateangebote"
          : "Windows patch assessment"}{" "}
        · {target}
      </DialogTitle>
      <DialogContent>
        {!result ? (
          <Typography>No saved patch assessments for this inventory yet.</Typography>
        ) : (
          <Stack spacing={2}>
            {assessments.length > 1 && (
              <TextField
                select
                label="Saved assessment"
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
                  assessment.status === "meets_catalog_baseline" && !expired && !validityUnknown
                    ? "success"
                    : ["build_gap", "updates_offered", "update_query_incomplete"].includes(
                          assessment.status,
                        ) ||
                        expired ||
                        validityUnknown
                      ? "warning"
                      : "default"
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
                {result.provider === "windows-update-agent"
                  ? "Diese gespeicherte Updateabfrage ist veraltet. Eine neue Onlineabfrage starten und die neue Evidenz bewerten."
                  : "This saved assessment has expired. Collect current inventory or synchronize the catalog, then assess again."}
              </Alert>
            )}
            {validityUnknown && (
              <Alert severity="warning">
                This saved build comparison has no valid assessment window. Obtain current evidence
                and catalog data before relying on it.
              </Alert>
            )}
            {result.provider === "windows-update-agent" ? (
              <WindowsUpdateReport result={result} />
            ) : (
              <>
                {result.product && <Typography variant="h6">{result.product.name}</Typography>}
                <Stack direction="row" useFlexGap sx={{ gap: 3, flexWrap: "wrap" }}>
                  <Typography>
                    Installed OS build: <strong>{result.installed_build ?? "Unavailable"}</strong>
                  </Typography>
                  <Typography>
                    Microsoft baseline build:{" "}
                    <strong>{result.baseline_build ?? "Unavailable"}</strong>
                  </Typography>
                </Stack>
                {result.baseline_kbs.length > 0 && (
                  <Typography>
                    Baseline update:{" "}
                    {result.baseline_kbs.map((kb, index) => (
                      <span key={kb}>
                        {index > 0 && ", "}
                        {/^KB\d+$/.test(kb) ? (
                          <Link
                            href={`https://support.microsoft.com/help/${kb.slice(2)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {kb}
                          </Link>
                        ) : (
                          kb
                        )}
                      </span>
                    ))}
                  </Typography>
                )}
                <Typography variant="body2" color="text.secondary">
                  MSRC catalog retrieved {date(result.catalog_retrieved_at)} · Document coverage{" "}
                  {result.coverage.catalog_start ?? "unavailable"} to{" "}
                  {result.coverage.catalog_end ?? "unavailable"}
                </Typography>
                <Alert severity="info">
                  This compares standard Windows Server OS builds only. Component applicability,
                  third-party software, Linux and hotpatch coverage are not assessed.
                </Alert>
                {result.limitations.length > 0 && (
                  <Typography variant="body2" color="text.secondary">
                    {result.limitations.join(" ")}
                  </Typography>
                )}
                {result.cve_references.length > 0 && (
                  <Box>
                    <Typography variant="h6">
                      Related CVE advisories · {result.cve_references_total.toLocaleString()}
                    </Typography>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      References associated with the baseline update. These are not confirmed
                      vulnerabilities on this host.
                    </Typography>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Advisory</TableCell>
                          <TableCell>Title</TableCell>
                          <TableCell>Published severity</TableCell>
                          <TableCell>Source documents</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {result.cve_references.slice(0, limit).map((reference) => (
                          <TableRow key={reference.cve}>
                            <TableCell>
                              {/^CVE-\d{4}-\d{4,}$/.test(reference.cve) ? (
                                <Link
                                  href={`https://msrc.microsoft.com/update-guide/vulnerability/${reference.cve}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                >
                                  {reference.cve}
                                </Link>
                              ) : (
                                reference.cve
                              )}
                            </TableCell>
                            <TableCell sx={{ overflowWrap: "anywhere" }}>
                              {reference.title}
                            </TableCell>
                            <TableCell>
                              {reference.severity}
                              {reference.cvss_score != null && ` · CVSS ${reference.cvss_score}`}
                            </TableCell>
                            <TableCell>{reference.document_ids.join(", ")}</TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                    {result.cve_references.length > limit && (
                      <Button onClick={() => setLimit(limit + 100)}>
                        Show 100 more advisories
                      </Button>
                    )}
                    {result.cve_references_truncated && (
                      <Typography color="text.secondary">
                        The stored advisory list is limited; total references:{" "}
                        {result.cve_references_total.toLocaleString()}.
                      </Typography>
                    )}
                  </Box>
                )}
                {result.sources.length > 0 && (
                  <Box>
                    <Typography variant="subtitle1">Microsoft source documents</Typography>
                    {result.sources.map((source) => (
                      <Typography
                        key={source.document_id}
                        variant="body2"
                        color="text.secondary"
                        sx={{ overflowWrap: "anywhere", mb: 1 }}
                      >
                        <Link
                          href={referenceUrl(source.document_id)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          {source.document_id}
                        </Link>{" "}
                        · Revision {date(source.current_release_date)}
                        <br />
                        SHA-256 {source.sha256}
                      </Typography>
                    ))}
                  </Box>
                )}
              </>
            )}
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Close assessment</Button>
      </DialogActions>
    </Dialog>
  );
}
