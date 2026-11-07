import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Alert,
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  LinearProgress,
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
import { useCustomers } from "../customers/hooks";
import { auditRequest, canUseAuditApi } from "./api";
import type {
  Credential,
  AuditMode,
  HostAssessment,
  HostAudit,
  InventorySection,
  SoftwareAssessment,
  WinrmTransport,
} from "./api";
import { PatchAssessmentDialog, PatchCatalogPanel } from "./patch-assessments";
import { SoftwareAssessmentDialog, SoftwareCatalogPanel } from "./software-assessments";
import { HostOverviewPanel } from "./overview";
import { platformNames, matchesPlatform, freshWindowsUpdateQuery } from "./overview-state";
import { HostStatusDialog } from "./host-status-dialog";
import { CapabilitiesPanel } from "./capabilities-panel";
import { DiscoveredDevicesPanel } from "./discovered-devices";
import type { HostOverview, HostPlatformFilter, OverviewHost } from "./overview-state";

const emptyCredential = {
  name: "",
  kind: "ssh_password" as Credential["kind"],
  username: "",
  cidrs: "",
  password: "",
  key: "",
  passphrase: "",
};
function winrmLabel(transport: WinrmTransport | undefined) {
  return transport === "http_ntlm"
    ? "HTTP / NTLM · message encryption required"
    : "HTTPS / NTLM · certificate validation required";
}

function errorText(error: unknown) {
  return error instanceof Error ? error.message : "Host audit request failed.";
}

function Section({
  title,
  section,
  columns,
}: {
  title: string;
  section: InventorySection;
  columns: string[];
}) {
  const [search, setSearch] = useState("");
  const [limit, setLimit] = useState(100);
  const rows = section.items.filter((row) =>
    Object.values(row).some((value) => value.toLowerCase().includes(search.toLowerCase())),
  );
  return (
    <Box sx={{ mt: 3 }}>
      <Typography variant="h6">
        {title} · {section.items.length.toLocaleString()}
      </Typography>
      <Typography variant="body2" color="text.secondary">
        {section.source} · {section.status.replaceAll("_", " ")}
      </Typography>
      {section.items.length > 0 && (
        <>
          <TextField
            label={`Filter ${title.toLowerCase()}`}
            size="small"
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setLimit(100);
            }}
            sx={{ my: 2 }}
          />
          <Table size="small">
            <TableHead>
              <TableRow>
                {columns.map((key) => (
                  <TableCell key={key}>{key}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {rows.slice(0, limit).map((row, i) => (
                <TableRow key={i}>
                  {columns.map((key) => (
                    <TableCell key={key} sx={{ overflowWrap: "anywhere" }}>
                      {row[key]}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {rows.length > limit && (
            <Button onClick={() => setLimit(limit + 100)}>Show 100 more</Button>
          )}
        </>
      )}
    </Box>
  );
}

function AuditPanel({
  token,
  customerId,
  lock,
  platform,
}: {
  token: string;
  customerId: number;
  lock: () => void;
  platform: HostPlatformFilter;
}) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [runs, setRuns] = useState<HostAudit[]>([]);
  const [overview, setOverview] = useState<HostOverview | null>(null);
  const [overviewLoaded, setOverviewLoaded] = useState(false);
  const [overviewDetail, setOverviewDetail] = useState<OverviewHost | null>(null);
  const [collectOpen, setCollectOpen] = useState(false);
  const [collectionMode, setCollectionMode] =
    useState<Exclude<AuditMode, "connection">>("inventory");
  const [updateQueryConfirm, setUpdateQueryConfirm] = useState(false);
  const [form, setForm] = useState(emptyCredential);
  const [createOpen, setCreateOpen] = useState(false);
  const fileGeneration = useRef(0);
  const [credentialId, setCredentialId] = useState("");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("");
  const [winrmTransport, setWinrmTransport] = useState<WinrmTransport>("https");
  const [fingerprint, setFingerprint] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [detail, setDetail] = useState<HostAudit | null>(null);
  const [assessmentView, setAssessmentView] = useState<{
    target: string;
    assessments: HostAssessment[];
  } | null>(null);
  const [softwareView, setSoftwareView] = useState<{
    target: string;
    assessments: SoftwareAssessment[];
  } | null>(null);
  const [revoke, setRevoke] = useState<Credential | null>(null);
  const closeCredential = () => {
    fileGeneration.current++;
    setCreateOpen(false);
    setForm(emptyCredential);
  };
  useEffect(() => {
    setCollectOpen(false);
    setUpdateQueryConfirm(false);
    setCollectionMode("inventory");
    setOverviewDetail(null);
    setDetail(null);
    setAssessmentView(null);
    setSoftwareView(null);
    setCredentialId("");
    setPort("");
    setFingerprint("");
    setWinrmTransport("https");
    fileGeneration.current++;
    setCreateOpen(false);
    setForm(emptyCredential);
    setRevoke(null);
  }, [platform]);
  const selected = credentials.find((c) => c.id === Number(credentialId) && c.enabled);
  const refresh = async (signal?: AbortSignal) => {
    const [creds, audits, status] = await Promise.allSettled([
      auditRequest<Credential[]>(
        token,
        `/credentials?customer_id=${customerId}`,
        undefined,
        signal,
      ),
      auditRequest<HostAudit[]>(token, `?customer_id=${customerId}`, undefined, signal),
      auditRequest<HostOverview>(token, `/overview?customer_id=${customerId}`, undefined, signal),
    ]);
    if (creds.status === "fulfilled") setCredentials(creds.value);
    if (audits.status === "fulfilled") setRuns(audits.value);
    setOverviewLoaded(true);
    if (status.status === "fulfilled") {
      setOverview(status.value);
      setOverviewDetail((prior) =>
        prior
          ? (status.value.hosts.find((host) => host.asset_id === prior.asset_id) ?? null)
          : null,
      );
    } else {
      setOverview(null);
      setOverviewDetail(null);
    }
    for (const result of [creds, audits, status])
      if (result.status === "rejected") throw result.reason;
  };
  useEffect(() => {
    const controller = new AbortController();
    const load = () =>
      refresh(controller.signal).catch((e) => {
        if (!controller.signal.aborted) setError(errorText(e));
      });
    void load();
    const timer = window.setInterval(load, 5000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
    // This component is replaced when the operator locks or changes customer.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, customerId]);
  const action = async (work: () => Promise<void>) => {
    setBusy(true);
    setError("");
    try {
      await work();
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  const saveCredential = () =>
    action(async () => {
      try {
        const result = await auditRequest<Credential>(token, "/credentials", {
          customer_id: customerId,
          name: form.name,
          kind: form.kind,
          username: form.username,
          allowed_cidrs: form.cidrs.split(/[\s,]+/).filter(Boolean),
          ...(form.kind === "ssh_key"
            ? { private_key: form.key, ...(form.passphrase ? { passphrase: form.passphrase } : {}) }
            : { password: form.password }),
        });
        setCredentialId(String(result.id));
        setWinrmTransport("https");
        setPort("");
        setFingerprint("");
        setCreateOpen(false);
      } finally {
        // Clear secret inputs after success AND failed requests. Never retain
        // submitted credential payloads in React Query's mutation history.
        setForm((previous) => ({ ...previous, password: "", key: "", passphrase: "" }));
      }
    });
  const queue = (mode: HostAudit["mode"]) =>
    action(async () => {
      await auditRequest(token, "", {
        customer_id: customerId,
        credential_id: Number(credentialId),
        target,
        ...(port ? { port: Number(port) } : {}),
        ...(selected?.kind === "winrm" ? { winrm_transport: winrmTransport } : {}),
        ...(selected?.kind.startsWith("ssh_") ? { ssh_fingerprint: fingerprint } : {}),
        mode,
      });
      setCollectOpen(false);
      setUpdateQueryConfirm(false);
    });
  const assessWindows = (auditId: number) =>
    action(async () => {
      const assessment = await auditRequest<HostAssessment>(token, `/${auditId}/assess`, {});
      const saved = await auditRequest<HostAssessment[]>(token, `/${auditId}/assessments`);
      setAssessmentView({
        target: overview?.hosts.find((host) => host.inventory?.id === auditId)?.target ?? "",
        assessments: [assessment, ...saved.filter((item) => item.id !== assessment.id)],
      });
    });
  const assessSoftware = (auditId: number) =>
    action(async () => {
      const assessment = await auditRequest<SoftwareAssessment>(
        token,
        `/${auditId}/assess-software`,
        {},
      );
      const saved = await auditRequest<SoftwareAssessment[]>(
        token,
        `/${auditId}/software-assessments`,
      );
      setSoftwareView({
        target: overview?.hosts.find((host) => host.inventory?.id === auditId)?.target ?? "",
        assessments: [assessment, ...saved.filter((item) => item.id !== assessment.id)],
      });
    });
  const visibleTargets = new Set(
    (overview?.hosts ?? [])
      .filter((host) => matchesPlatform(host, platform))
      .map((host) => host.target),
  );
  const visibleRuns = runs.filter((run) => platform === "all" || visibleTargets.has(run.target));
  const valid = Boolean(
    selected &&
    target &&
    (selected.kind === "winrm" || /^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)),
  );
  const prepareHostCollection = (host: OverviewHost, mode?: "inventory" | "windows_updates") => {
    setTarget(host.target);
    setCredentialId(String(host.latest_run.credential_id));
    setPort(String(host.latest_run.port));
    setFingerprint(host.latest_run.ssh_fingerprint ?? "");
    setWinrmTransport(host.latest_run.winrm_transport);
    setCollectionMode(
      mode ?? (host.latest_run.mode === "windows_updates" ? "windows_updates" : "inventory"),
    );
    setUpdateQueryConfirm(false);
    setOverviewDetail(null);
    setCollectOpen(true);
  };
  return (
    <Stack spacing={3}>
      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        <Chip color="success" variant="outlined" label="Operator access unlocked" />
        <Button onClick={lock}>Lock and clear session</Button>
        <Box sx={{ flexGrow: 1 }} />
        <Button
          variant="contained"
          disabled={platform === "vmware"}
          onClick={() => {
            setCollectionMode("inventory");
            setCollectOpen(true);
          }}
        >
          Inventur starten
        </Button>
        {platform === "windows-client" && (
          <Button
            variant="outlined"
            disabled={busy}
            onClick={() => {
              setCollectionMode("windows_updates");
              if (selected?.kind !== "winrm") setCredentialId("");
              setCollectOpen(true);
            }}
          >
            Windows-Updates abfragen
          </Button>
        )}
        <Button disabled={busy} onClick={() => void action(async () => {})}>
          Status aktualisieren
        </Button>
      </Stack>
      {error && !createOpen && !revoke && <Alert severity="error">{error}</Alert>}
      <HostOverviewPanel
        overview={overview}
        platform={platform}
        loading={!overviewLoaded}
        onDetail={setOverviewDetail}
      />
      <DiscoveredDevicesPanel
        token={token}
        customerId={customerId}
        onInventory={(address) => {
          setTarget(address);
          setCredentialId("");
          setPort("");
          setFingerprint("");
          setWinrmTransport("https");
          setCollectionMode("inventory");
          setUpdateQueryConfirm(false);
          setCollectOpen(true);
        }}
      />
      <CapabilitiesPanel token={token} />
      <Dialog
        open={collectOpen}
        onClose={() => {
          if (!busy) {
            setCollectOpen(false);
            setUpdateQueryConfirm(false);
          }
        }}
        maxWidth="md"
        fullWidth
        data-testid="inventory-form-dialog"
      >
        <DialogTitle>
          {collectionMode === "windows_updates" ? "Windows-Updates abfragen" : "Inventur starten"}
        </DialogTitle>
        <DialogContent>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {collectionMode === "windows_updates"
              ? "Windows-Inventur und explizite Onlineabfrage der am Gerät konfigurierten Windows Update-/WSUS-Quelle."
              : "Read-only host inventory"}
          </Typography>
          {collectionMode === "windows_updates" && (
            <Alert severity="info" sx={{ mb: 2 }}>
              Die Abfrage kontaktiert die konfigurierte Updatequelle und kann Metadaten
              herunterladen sowie den lokalen Updatecache verändern. Sie installiert keine Updates
              und startet das Gerät nicht neu. Keine Änderung der Updatequelle oder Richtlinien.
              Laufzeit bis zu 180 Sekunden.
            </Alert>
          )}
          <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 2 }}>
            <TextField
              select
              label="Credential"
              value={credentialId}
              onChange={(e) => {
                setCredentialId(e.target.value);
                setWinrmTransport("https");
                setPort("");
                setFingerprint("");
              }}
            >
              {credentials
                .filter(
                  (c) =>
                    c.enabled &&
                    (collectionMode === "windows_updates"
                      ? c.kind === "winrm"
                      : platform === "linux"
                        ? c.kind.startsWith("ssh_")
                        : ["windows-server", "windows-client"].includes(platform)
                          ? c.kind === "winrm"
                          : true),
                )
                .map((c) => (
                  <MenuItem key={c.id} value={String(c.id)}>
                    {c.name} · {c.username} · {c.kind.replaceAll("_", " ")}
                  </MenuItem>
                ))}
            </TextField>
            <TextField
              label="Target IP"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              helperText="One address inside the customer credential scope"
            />
            {selected?.kind === "winrm" && (
              <TextField
                select
                label="WinRM connection"
                value={winrmTransport}
                onChange={(e) => {
                  setWinrmTransport(e.target.value as WinrmTransport);
                  setPort("");
                }}
                helperText="Changing the connection resets the optional port"
              >
                <MenuItem value="https">HTTPS / NTLM · verified certificate</MenuItem>
                <MenuItem value="http_ntlm">HTTP / NTLM · encrypted messages</MenuItem>
              </TextField>
            )}
            <TextField
              label="Port (optional)"
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              helperText={
                selected?.kind === "winrm"
                  ? winrmTransport === "http_ntlm"
                    ? "Default 5985 · HTTP / NTLM"
                    : "Default 5986 · HTTPS / NTLM"
                  : "Default 22 · SSH"
              }
            />
            {selected?.kind.startsWith("ssh_") && (
              <TextField
                label="Approved SSH fingerprint"
                value={fingerprint}
                onChange={(e) => setFingerprint(e.target.value)}
                helperText="SHA256 fingerprint verified through a trusted channel"
              />
            )}
          </Box>
          {selected && (
            <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
              Credential scope: {selected.allowed_cidrs.join(", ")}
            </Typography>
          )}
          {selected?.kind === "winrm" && (
            <Alert severity={winrmTransport === "http_ntlm" ? "warning" : "info"} sx={{ mt: 2 }}>
              {winrmTransport === "http_ntlm"
                ? "Messages are encrypted; server identity is not verified by a certificate."
                : "HTTPS requires a trusted certificate with the target IP in its subject alternative names. Certificate checks cannot be disabled."}
            </Alert>
          )}
          <Stack direction="row" spacing={2} useFlexGap sx={{ mt: 2, flexWrap: "wrap" }}>
            <Button disabled={!valid || busy} onClick={() => queue("connection")}>
              Test connection
            </Button>
            <Button
              variant="contained"
              disabled={
                !valid ||
                busy ||
                (collectionMode === "windows_updates" && selected?.kind !== "winrm")
              }
              onClick={() =>
                collectionMode === "windows_updates"
                  ? setUpdateQueryConfirm(true)
                  : queue("inventory")
              }
            >
              {collectionMode === "windows_updates"
                ? "Updateabfrage vorbereiten"
                : "Collect inventory"}
            </Button>
            <Button
              disabled={busy}
              onClick={() => {
                setForm({
                  ...emptyCredential,
                  kind: collectionMode === "windows_updates" ? "winrm" : emptyCredential.kind,
                });
                fileGeneration.current++;
                setError("");
                setCreateOpen(true);
              }}
            >
              Add credential
            </Button>
            {selected && (
              <Button color="warning" disabled={busy} onClick={() => setRevoke(selected)}>
                Revoke credential
              </Button>
            )}
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button disabled={busy} onClick={() => setCollectOpen(false)}>
            Inventur schließen
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog
        open={updateQueryConfirm}
        onClose={() => !busy && setUpdateQueryConfirm(false)}
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle>Windows-Updatequelle abfragen</DialogTitle>
        <DialogContent>
          <Stack spacing={2}>
            {error && <Alert severity="error">{error}</Alert>}
            <Typography>
              Auf {target} wird zuerst die Inventur gelesen und anschließend eine neue Onlineabfrage
              der am Gerät konfigurierten Windows Update-/WSUS-Quelle ausgeführt.
            </Typography>
            <Alert severity="info">
              Die Abfrage lädt gegebenenfalls Metadaten und aktualisiert den Updatecache. Sie
              installiert keine Updates, ändert keine Updatequelle oder Richtlinie und löst keinen
              Neustart aus. Laufzeit bis zu 180 Sekunden.
            </Alert>
            <Typography variant="body2" color="text.secondary">
              Optionale, Funktions- und Definitionsangebote werden getrennt ausgewiesen. Keine
              Angebote bedeuten keine vollständige Patchfreigabe.
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button disabled={busy} onClick={() => setUpdateQueryConfirm(false)}>
            Zurück
          </Button>
          <Button
            variant="contained"
            disabled={busy || !valid || selected?.kind !== "winrm"}
            onClick={() => queue("windows_updates")}
          >
            Abfrage starten
          </Button>
        </DialogActions>
      </Dialog>
      <Accordion data-testid="catalog-panel" disableGutters>
        <AccordionSummary>
          <Typography>Kataloge und Prüfumfang</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Stack spacing={2}>
            <PatchCatalogPanel token={token} />
            <SoftwareCatalogPanel token={token} />
            <Alert severity="info">
              Linux: OS, kernel and installed dpkg/RPM packages; Python 3 is required. Windows: OS
              build, machine-wide uninstall registry and Get-HotFix. Completed Windows inventories
              can be assessed against Microsoft OS build baselines and the listed software advisory
              ranges. Software coverage is limited to supported product rules. Linux patch
              assessment and per-user software are not included.
            </Alert>
          </Stack>
        </AccordionDetails>
      </Accordion>
      <Accordion data-testid="history-panel" disableGutters>
        <AccordionSummary>
          <Typography>Verlauf und technische Details · {visibleRuns.length} Läufe</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Stack spacing={2}>
            {!visibleRuns.length && (
              <Typography color="text.secondary">
                Noch keine Inventurläufe in diesem Bereich.
              </Typography>
            )}
            {visibleRuns.map((run) => (
              <Paper key={run.id} data-testid={`run-card-${run.id}`} sx={{ p: 3 }}>
                <Stack
                  direction="row"
                  sx={{ justifyContent: "space-between", alignItems: "center", gap: 2 }}
                >
                  <Box>
                    <Typography variant="h6">
                      {run.target}:{run.port}
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                      {run.mode === "connection"
                        ? "Connection test"
                        : run.mode === "windows_updates"
                          ? "Windows-Updateabfrage mit Inventur"
                          : "Host inventory"}{" "}
                      · {new Date(run.created_at).toLocaleString()}
                    </Typography>
                    {credentials.find((credential) => credential.id === run.credential_id)?.kind ===
                      "winrm" && (
                      <Typography variant="body2" color="text.secondary">
                        {winrmLabel(run.winrm_transport)}
                      </Typography>
                    )}
                  </Box>
                  <Chip
                    label={run.job.status.toUpperCase()}
                    color={
                      run.job.status === "finished"
                        ? "success"
                        : run.job.status === "failed"
                          ? "error"
                          : "default"
                    }
                  />
                </Stack>
                <Typography sx={{ my: 2 }}>{run.job.message}</Typography>
                {["queued", "running"].includes(run.job.status) ? (
                  <>
                    <LinearProgress
                      variant={run.job.status === "queued" ? "determinate" : "indeterminate"}
                      value={0}
                    />
                    <Button
                      color="warning"
                      disabled={busy || run.cancel_requested}
                      sx={{ mt: 1 }}
                      onClick={() =>
                        action(async () => {
                          await auditRequest(token, `/${run.id}/cancel`, {});
                        })
                      }
                    >
                      {run.cancel_requested ? "Cancelling…" : "Cancel run"}
                    </Button>
                  </>
                ) : (
                  <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: "wrap" }}>
                    <Button
                      disabled={busy}
                      onClick={() =>
                        action(async () =>
                          setDetail(await auditRequest<HostAudit>(token, `/${run.id}`)),
                        )
                      }
                    >
                      View evidence
                    </Button>
                    {["inventory", "windows_updates"].includes(run.mode) &&
                      ["finished", "failed"].includes(run.job.status) &&
                      credentials.find((credential) => credential.id === run.credential_id)
                        ?.kind === "winrm" && (
                        <>
                          <Button
                            disabled={
                              busy ||
                              (run.job.status === "failed" &&
                                !overview?.hosts.some((host) => host.inventory?.id === run.id) &&
                                !(detail?.id === run.id && detail.inventory))
                            }
                            onClick={() =>
                              action(async () => {
                                const assessment = await auditRequest<SoftwareAssessment>(
                                  token,
                                  `/${run.id}/assess-software`,
                                  {},
                                );
                                const saved = await auditRequest<SoftwareAssessment[]>(
                                  token,
                                  `/${run.id}/software-assessments`,
                                );
                                setSoftwareView({
                                  target: run.target,
                                  assessments: [
                                    assessment,
                                    ...saved.filter((item) => item.id !== assessment.id),
                                  ],
                                });
                              })
                            }
                          >
                            Assess installed software
                          </Button>
                          <Button
                            disabled={
                              busy ||
                              (run.job.status === "failed" &&
                                !overview?.hosts.some((host) => host.inventory?.id === run.id) &&
                                !(detail?.id === run.id && detail.inventory))
                            }
                            onClick={() =>
                              action(async () => {
                                const saved = await auditRequest<SoftwareAssessment[]>(
                                  token,
                                  `/${run.id}/software-assessments`,
                                );
                                setSoftwareView({ target: run.target, assessments: saved });
                              })
                            }
                          >
                            View software assessments
                          </Button>
                          <Button
                            disabled={
                              busy ||
                              (overview?.hosts.find((host) => host.target === run.target)
                                ?.platform === "windows_client" &&
                                !overview?.hosts.some(
                                  (host) =>
                                    host.inventory?.id === run.id && freshWindowsUpdateQuery(host),
                                )) ||
                              (run.job.status === "failed" &&
                                !overview?.hosts.some((host) => host.inventory?.id === run.id) &&
                                !(detail?.id === run.id && detail.inventory))
                            }
                            onClick={() =>
                              action(async () => {
                                const assessment = await auditRequest<HostAssessment>(
                                  token,
                                  `/${run.id}/assess`,
                                  {},
                                );
                                const saved = await auditRequest<HostAssessment[]>(
                                  token,
                                  `/${run.id}/assessments`,
                                );
                                setAssessmentView({
                                  target: run.target,
                                  assessments: [
                                    assessment,
                                    ...saved.filter((item) => item.id !== assessment.id),
                                  ],
                                });
                              })
                            }
                          >
                            Assess Windows patches
                          </Button>
                          <Button
                            disabled={
                              busy ||
                              (run.job.status === "failed" &&
                                !overview?.hosts.some((host) => host.inventory?.id === run.id) &&
                                !(detail?.id === run.id && detail.inventory))
                            }
                            onClick={() =>
                              action(async () => {
                                const saved = await auditRequest<HostAssessment[]>(
                                  token,
                                  `/${run.id}/assessments`,
                                );
                                setAssessmentView({ target: run.target, assessments: saved });
                              })
                            }
                          >
                            View assessments
                          </Button>
                        </>
                      )}
                  </Stack>
                )}
              </Paper>
            ))}
          </Stack>
        </AccordionDetails>
      </Accordion>
      <HostStatusDialog
        host={overviewDetail}
        busy={busy}
        close={() => setOverviewDetail(null)}
        inspect={(host) => {
          if (host.inventory)
            void action(async () =>
              setDetail(await auditRequest<HostAudit>(token, `/${host.inventory!.id}`)),
            );
        }}
        assessWindows={(host) => {
          if (host.inventory) void assessWindows(host.inventory.id);
        }}
        assessSoftware={(host) => {
          if (host.inventory) void assessSoftware(host.inventory.id);
        }}
        openWindows={(host) => {
          if (host.inventory)
            void action(async () =>
              setAssessmentView({
                target: host.target,
                assessments: await auditRequest<HostAssessment[]>(
                  token,
                  `/${host.inventory!.id}/assessments`,
                ),
              }),
            );
        }}
        openSoftware={(host) => {
          if (host.inventory)
            void action(async () =>
              setSoftwareView({
                target: host.target,
                assessments: await auditRequest<SoftwareAssessment[]>(
                  token,
                  `/${host.inventory!.id}/software-assessments`,
                ),
              }),
            );
        }}
        collect={(host) => {
          prepareHostCollection(host);
        }}
        queryWindows={(host) => prepareHostCollection(host, "windows_updates")}
      />
      <Dialog
        open={createOpen}
        onClose={() => {
          if (!busy) {
            closeCredential();
          }
        }}
        fullWidth
        maxWidth="sm"
      >
        <DialogTitle>Add encrypted credential</DialogTitle>
        <DialogContent>
          <Stack spacing={2} sx={{ pt: 1 }}>
            {error && <Alert severity="error">{error}</Alert>}
            <TextField
              label="Credential name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
            <TextField
              select
              label="Authentication"
              value={form.kind}
              onChange={(e) => {
                fileGeneration.current++;
                setForm({
                  ...form,
                  kind: e.target.value as Credential["kind"],
                  password: "",
                  key: "",
                  passphrase: "",
                });
              }}
            >
              {collectionMode !== "windows_updates" && (
                <MenuItem value="ssh_password">Linux · SSH password</MenuItem>
              )}
              {collectionMode !== "windows_updates" && (
                <MenuItem value="ssh_key">Linux · SSH private key</MenuItem>
              )}
              <MenuItem value="winrm">Windows · WinRM / NTLM</MenuItem>
            </TextField>
            <TextField
              label="Username"
              value={form.username}
              onChange={(e) => setForm({ ...form, username: e.target.value })}
              autoComplete="off"
            />
            <TextField
              label="Allowed credential CIDRs"
              value={form.cidrs}
              onChange={(e) => setForm({ ...form, cidrs: e.target.value })}
              helperText="Restrict this account to approved networks or single addresses"
            />
            {form.kind === "ssh_key" ? (
              <>
                <Button component="label" variant="outlined">
                  {form.key ? "Private key loaded · replace file" : "Load private key file"}
                  <input
                    type="file"
                    hidden
                    aria-label="Private key file"
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      if (!file) return;
                      const generation = ++fileGeneration.current;
                      setForm((previous) => ({ ...previous, key: "" }));
                      if (file.size > 32768) {
                        setError("Private key file exceeds 32 KiB.");
                        return;
                      }
                      try {
                        const value = await file.text();
                        if (generation === fileGeneration.current) {
                          setForm((previous) => ({ ...previous, key: value }));
                          setError("");
                        }
                      } catch {
                        if (generation === fileGeneration.current)
                          setError("Private key file could not be read.");
                      }
                    }}
                  />
                </Button>
                <TextField
                  label="Key passphrase (optional)"
                  type="password"
                  value={form.passphrase}
                  onChange={(e) => setForm({ ...form, passphrase: e.target.value })}
                  autoComplete="new-password"
                />
              </>
            ) : (
              <TextField
                label="Password"
                type="password"
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                autoComplete="new-password"
              />
            )}
            <Typography variant="body2" color="text.secondary">
              Use a dedicated inventory account. Secrets are encrypted and cannot be read back.
              Replace an account by creating a new credential and revoking the old one.
            </Typography>
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button
            disabled={busy}
            onClick={() => {
              closeCredential();
            }}
          >
            Cancel
          </Button>
          <Button
            variant="contained"
            disabled={
              busy ||
              !form.name ||
              !form.username ||
              !form.cidrs ||
              !(form.kind === "ssh_key" ? form.key : form.password)
            }
            onClick={saveCredential}
          >
            Save credential
          </Button>
        </DialogActions>
      </Dialog>
      {assessmentView && (
        <PatchAssessmentDialog
          key={`${assessmentView.target}:${assessmentView.assessments[0]?.id ?? "empty"}`}
          target={assessmentView.target}
          assessments={assessmentView.assessments}
          close={() => setAssessmentView(null)}
        />
      )}
      {softwareView && (
        <SoftwareAssessmentDialog
          key={`${softwareView.target}:${softwareView.assessments[0]?.id ?? "empty"}`}
          target={softwareView.target}
          assessments={softwareView.assessments}
          close={() => setSoftwareView(null)}
        />
      )}
      <Dialog open={revoke !== null} onClose={() => !busy && setRevoke(null)}>
        <DialogTitle>Revoke {revoke?.name}?</DialogTitle>
        <DialogContent>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          This erases the stored secret and stops queued or running audits using this credential.
          Existing inventory evidence is retained.
        </DialogContent>
        <DialogActions>
          <Button disabled={busy} onClick={() => setRevoke(null)}>
            Keep credential
          </Button>
          <Button
            color="warning"
            disabled={busy}
            onClick={() =>
              action(async () => {
                await auditRequest(token, `/credentials/${revoke!.id}/revoke`, {});
                setCredentialId("");
                setRevoke(null);
              })
            }
          >
            Revoke and erase secret
          </Button>
        </DialogActions>
      </Dialog>
      <Dialog open={detail !== null} onClose={() => setDetail(null)} maxWidth="lg" fullWidth>
        <DialogTitle>Host evidence · {detail?.target}</DialogTitle>
        <DialogContent>
          {detail &&
            credentials.find((credential) => credential.id === detail.credential_id)?.kind ===
              "winrm" && (
              <Alert
                severity={detail.winrm_transport === "http_ntlm" ? "warning" : "info"}
                sx={{ mb: 2 }}
              >
                {winrmLabel(detail.winrm_transport)}
                {detail.winrm_transport === "http_ntlm" &&
                  ". Server identity was not verified by a certificate."}
              </Alert>
            )}
          {detail?.inventory ? (
            <>
              <Typography variant="h6">{detail.inventory.os.name}</Typography>
              <Typography color="text.secondary">
                Version {detail.inventory.os.version} · Kernel / build {detail.inventory.os.kernel}{" "}
                · {detail.inventory.os.architecture}
              </Typography>
              <Typography>Host: {detail.inventory.os.hostname}</Typography>
              {detail.inventory.windows_updates && (
                <Alert
                  severity={
                    detail.inventory.windows_updates.status === "complete" ? "info" : "warning"
                  }
                  sx={{ mt: 2 }}
                >
                  Windows-Updateabfrage: {detail.inventory.windows_updates.status} ·{" "}
                  {detail.inventory.windows_updates.total} Angebote der konfigurierten Gerätequelle
                  ·{" "}
                  {detail.inventory.windows_updates.queried_at
                    ? new Date(detail.inventory.windows_updates.queried_at).toLocaleString()
                    : "Zeitpunkt nicht verfügbar"}
                  . Die Abfrage installiert keine Updates. Angebote und Klassifikation unter
                  „Windows jetzt bewerten“ öffnen.
                </Alert>
              )}
              {detail.job.status === "failed" && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  This inventory is incomplete. Available evidence is retained; unavailable sections
                  were not passed.
                </Alert>
              )}
              <Section
                title="Packages"
                section={detail.inventory.packages}
                columns={
                  detail.inventory.os.family === "Windows"
                    ? ["name", "version", "publisher", "architecture"]
                    : ["name", "version", "architecture"]
                }
              />
              <Section
                title="Hotfixes"
                section={detail.inventory.hotfixes}
                columns={["id", "description"]}
              />
            </>
          ) : (
            <Typography>No inventory evidence was collected. {detail?.job.message}</Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetail(null)}>Close evidence</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}

export function HostAudits({ platform = "all" }: { platform?: HostPlatformFilter }) {
  const [query, setQuery] = useSearchParams();
  const queryValue = query.get("customer_id") ?? "";
  const queryCustomer = /^[1-9][0-9]{0,9}$/.test(queryValue) ? queryValue : "";
  const { data: customers = [] } = useCustomers();
  const [customer, setCustomer] = useState(queryCustomer);
  const [input, setInput] = useState("");
  const [session, setSession] = useState<{ token: string; customerId: number } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const secure = canUseAuditApi();
  const sessionGeneration = useRef(0);
  useEffect(() => {
    if (queryCustomer && queryCustomer !== customer) {
      sessionGeneration.current++;
      setSession(null);
      setInput("");
      setCustomer(queryCustomer);
    }
  }, [queryCustomer, customer]);
  useEffect(() => {
    const clear = () => {
      sessionGeneration.current++;
      setSession(null);
      setInput("");
    };
    // Full-page navigation can preserve React state in the back/forward cache.
    // Lock before leaving and again when a cached page is restored.
    window.addEventListener("pagehide", clear);
    window.addEventListener("pageshow", clear);
    return () => {
      clear();
      window.removeEventListener("pagehide", clear);
      window.removeEventListener("pageshow", clear);
    };
  }, []);
  const unlock = async () => {
    const generation = ++sessionGeneration.current;
    setBusy(true);
    setError("");
    try {
      await auditRequest(input, `/credentials?customer_id=${Number(customer)}`);
      if (generation === sessionGeneration.current) {
        setSession({ token: input, customerId: Number(customer) });
        setInput("");
      }
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4">{platformNames[platform]}</Typography>
        <Typography color="text.secondary">
          {platform === "windows-client"
            ? "Updateangebote der Gerätequelle, Neustartbedarf und offene Prüfungen auf einen Blick."
            : platform === "linux"
              ? "OS- und Paketinventur sowie offene Prüfungen auf einen Blick."
              : platform === "vmware"
                ? "Erkannte Dienste und noch offene VMware-Prüfabdeckung auf einen Blick."
                : "Updatebedarf, geprüfte OS-Baseline und offene Abdeckung auf einen Blick."}
        </Typography>
      </Box>
      {session ? (
        <>
          <Typography variant="h6">
            {customers.find((c) => c.id === session.customerId)?.name ??
              `Customer #${session.customerId}`}
          </Typography>
          <AuditPanel
            token={session.token}
            customerId={session.customerId}
            platform={platform}
            lock={() => {
              setSession(null);
              setInput("");
            }}
          />
        </>
      ) : (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Operator access
          </Typography>
          {!secure && (
            <Alert severity="info" sx={{ mb: 2 }}>
              Open CCVM through HTTPS with its same-origin API proxy to manage credentials and run
              authenticated inventory.
            </Alert>
          )}
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <Stack spacing={2}>
            <TextField
              select
              label="Customer"
              value={customer}
              onChange={(e) => {
                setCustomer(e.target.value);
                setQuery(e.target.value ? { customer_id: e.target.value } : {}, { replace: true });
              }}
              disabled={!secure || busy}
            >
              {customers.map((c) => (
                <MenuItem key={c.id} value={String(c.id)}>
                  {c.name}
                </MenuItem>
              ))}
            </TextField>
            <TextField
              label="Operator token"
              type="password"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              autoComplete="off"
              disabled={!secure || busy}
              helperText="Kept only in this page's memory; locking or leaving clears the session"
            />
            <Button
              variant="contained"
              disabled={!secure || !customer || !input || busy}
              onClick={unlock}
            >
              Unlock host audits
            </Button>
          </Stack>
        </Paper>
      )}
    </Stack>
  );
}
