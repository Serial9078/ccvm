import { useEffect, useId, useState } from "react";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import CloseIcon from "@mui/icons-material/Close";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import {
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
  Divider,
  IconButton,
  Paper,
  Stack,
  Tab,
  Tabs,
  Typography,
} from "@mui/material";
import { WindowsStatus, SoftwareStatus } from "./overview";
import { current, date, freshWindowsUpdateQuery, softwareFix } from "./overview-state";
import { hostPresentation } from "./host-presentation";
import type { OverviewHost } from "./overview-state";

const platformLabels: Record<OverviewHost["platform"], string> = {
  windows_server: "Windows Server",
  windows_client: "Windows Client",
  linux: "Linux",
  vmware: "VMware",
  unclassified: "Plattform noch offen",
};

function RunDetails({ host }: { host: OverviewHost }) {
  const run = host.latest_run;
  const statusLabels: Record<string, string> = {
    failed: "Fehlgeschlagen",
    finished: "Abgeschlossen",
    running: "Läuft",
    queued: "Wartet",
  };
  const rows = [
    ["Letzter Versuch", date(run.completed_at ?? run.created_at)],
    ["Ergebnis", statusLabels[run.status] ?? run.status],
    ["Ziel", `${host.target}:${run.port}`],
    ["Letzte Inventur", date(host.inventory?.completed_at)],
  ];
  return (
    <Stack spacing={2}>
      <Box
        component="dl"
        sx={{ m: 0, display: "grid", gridTemplateColumns: { xs: "1fr", sm: "150px 1fr" }, gap: 1 }}
      >
        {rows.map(([label, value]) => (
          <Box key={label} sx={{ display: "contents" }}>
            <Typography component="dt" variant="body2" color="text.secondary">
              {label}
            </Typography>
            <Typography component="dd" variant="body2" sx={{ m: 0, overflowWrap: "anywhere" }}>
              {value}
            </Typography>
          </Box>
        ))}
      </Box>
      <Box sx={{ p: 2, bgcolor: "background.default", borderRadius: 1.5 }}>
        <Typography variant="caption" color="text.secondary">
          Technische Rückmeldung
        </Typography>
        <Typography variant="body2" sx={{ mt: 0.5, overflowWrap: "anywhere" }}>
          {run.message}
        </Typography>
      </Box>
      {host.inventory && (
        <Typography variant="body2" color="text.secondary">
          Gespeicherte Inventur: {host.inventory.package_count} Software-Einträge ·{" "}
          {host.inventory.hotfix_count} Hotfix-Einträge.
          {run.status === "failed" &&
            (run.id === host.inventory.id
              ? " Der fehlgeschlagene Lauf hat Teilinformationen gespeichert. Die Erfassung wurde nicht erfolgreich abgeschlossen."
              : " Diese Daten stammen aus einer früheren Erfassung; der neueste Versuch war nicht erfolgreich.")}
        </Typography>
      )}
    </Stack>
  );
}

export function HostStatusDialog({
  host,
  busy,
  close,
  inspect,
  assessWindows,
  assessSoftware,
  openWindows,
  openSoftware,
  collect,
  queryWindows,
}: {
  host: OverviewHost | null;
  busy: boolean;
  close: () => void;
  inspect: (host: OverviewHost) => void;
  assessWindows: (host: OverviewHost) => void;
  assessSoftware: (host: OverviewHost) => void;
  openWindows: (host: OverviewHost) => void;
  openSoftware: (host: OverviewHost) => void;
  collect: (host: OverviewHost) => void;
  queryWindows: (host: OverviewHost) => void;
}) {
  const [tab, setTab] = useState("overview");
  const titleId = useId();
  useEffect(() => setTab("overview"), [host?.asset_id]);
  const windows = host && ["windows_server", "windows_client"].includes(host.platform);
  const presentation = host ? hostPresentation(host) : null;
  const pending = host && ["queued", "running"].includes(host.latest_run.status);
  const navigate = (action: (host: OverviewHost) => void) => {
    if (!host) return;
    close();
    action(host);
  };
  const actions = {
    collect,
    queryWindows,
    assessWindows,
    assessSoftware,
    openWindows,
    openSoftware,
  };
  const title = host?.inventory?.os.hostname || host?.target;
  const canAssessWindows = Boolean(
    host?.inventory && (host.platform !== "windows_client" || freshWindowsUpdateQuery(host)),
  );
  const affected = current(host?.software_assessment ?? null)
    ? (host?.software_assessment?.result.products.filter((product) => product.matches_total > 0) ??
      [])
    : [];
  return (
    <Dialog
      open={host !== null}
      onClose={close}
      aria-labelledby={titleId}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            m: { xs: 1, sm: 3 },
            width: { xs: "calc(100% - 16px)", sm: "100%" },
            maxHeight: "calc(100% - 32px)",
          },
        },
      }}
    >
      <DialogTitle id={`${titleId}-heading`} component="div" sx={{ px: { xs: 2, sm: 3 }, py: 2 }}>
        <Box
          component="span"
          id={titleId}
          sx={{
            position: "absolute",
            width: 1,
            height: 1,
            p: 0,
            m: -1,
            overflow: "hidden",
            clip: "rect(0, 0, 0, 0)",
            whiteSpace: "nowrap",
            border: 0,
          }}
        >
          {`Host-Status · ${host?.target ?? ""}`}
        </Box>
        <Stack
          direction="row"
          sx={{ justifyContent: "space-between", alignItems: "flex-start", gap: 2 }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Typography variant="overline" color="text.secondary">
              Host-Status
            </Typography>
            <Typography component="h2" variant="h5" sx={{ overflowWrap: "anywhere" }}>
              {title}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
              {host?.target !== title && `${host?.target} · `}
              {host && platformLabels[host.platform]}
            </Typography>
          </Box>
          <IconButton onClick={close} aria-label="Host-Status schließen" size="small">
            <CloseIcon />
          </IconButton>
        </Stack>
      </DialogTitle>
      <DialogContent sx={{ p: { xs: 2, sm: 3 } }}>
        {host && presentation && (
          <Stack spacing={3} sx={{ pt: 0.5 }}>
            <Paper
              variant="outlined"
              data-testid="host-next-action"
              sx={{
                p: { xs: 2, sm: 2.5 },
                borderLeft: 3,
                borderLeftColor:
                  presentation.tone === "default" ? "divider" : `${presentation.tone}.main`,
              }}
            >
              <Stack
                direction={{ xs: "column", sm: "row" }}
                sx={{ justifyContent: "space-between", gap: 2, alignItems: { sm: "center" } }}
              >
                <Box sx={{ minWidth: 0 }}>
                  <Chip
                    size="small"
                    variant="outlined"
                    color={presentation.tone}
                    label={presentation.label}
                  />
                  <Typography sx={{ mt: 1.25 }}>{presentation.description}</Typography>
                </Box>
                {presentation.action && (
                  <Button
                    variant="contained"
                    endIcon={<ArrowForwardIcon />}
                    disabled={
                      busy ||
                      (Boolean(pending) &&
                        !["openWindows", "openSoftware"].includes(presentation.action))
                    }
                    onClick={() => navigate(actions[presentation.action!])}
                    sx={{ flexShrink: 0, alignSelf: { xs: "flex-start", sm: "center" } }}
                  >
                    {presentation.actionLabel}
                  </Button>
                )}
              </Stack>
            </Paper>
            {!host.inventory ? (
              <>
                {host.platform !== "vmware" && (
                  <Box>
                    <Typography component="h3" variant="h6">
                      So geht es weiter
                    </Typography>
                    <Stack spacing={2} sx={{ mt: 2 }}>
                      {[
                        [
                          "Verbindung prüfen",
                          "Zieladresse, Port und Zugangsdaten im Inventurformular kontrollieren und die Verbindung testen.",
                        ],
                        [
                          "Inventur erfassen",
                          "Nach erfolgreichem Verbindungstest Betriebssystem und installierte Software auslesen.",
                        ],
                        [
                          "Ergebnisse bewerten",
                          "Erst mit verwertbaren Inventurdaten lassen sich unterstützte Update- und Softwareregeln prüfen.",
                        ],
                      ].map(([label, description], index) => (
                        <Stack key={label} direction="row" spacing={1.5}>
                          <Box
                            sx={{
                              width: 28,
                              height: 28,
                              flexShrink: 0,
                              border: "1px solid",
                              borderColor: "divider",
                              borderRadius: "50%",
                              textAlign: "center",
                              lineHeight: "26px",
                              fontSize: 13,
                            }}
                          >
                            {index + 1}
                          </Box>
                          <Box>
                            <Typography variant="body2" sx={{ fontWeight: 700 }}>
                              {label}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {description}
                            </Typography>
                          </Box>
                        </Stack>
                      ))}
                    </Stack>
                  </Box>
                )}
                <Accordion>
                  <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                    <Typography variant="body2">Letzten Versuch ansehen</Typography>
                  </AccordionSummary>
                  <AccordionDetails>
                    <RunDetails host={host} />
                  </AccordionDetails>
                </Accordion>
              </>
            ) : (
              <Box>
                <Tabs
                  value={tab}
                  onChange={(_, value: string) => setTab(value)}
                  aria-label="Host-Bereiche"
                  variant="scrollable"
                  scrollButtons="auto"
                  sx={{ borderBottom: "1px solid", borderColor: "divider", mb: 2.5 }}
                >
                  <Tab
                    value="overview"
                    label="Übersicht"
                    id="host-tab-overview"
                    aria-controls="host-panel-overview"
                  />
                  {windows && (
                    <Tab
                      value="updates"
                      label="Systemupdates"
                      id="host-tab-updates"
                      aria-controls="host-panel-updates"
                    />
                  )}
                  {windows && (
                    <Tab
                      value="software"
                      label="Software"
                      id="host-tab-software"
                      aria-controls="host-panel-software"
                    />
                  )}
                  <Tab
                    value="details"
                    label="Prüfdetails"
                    id="host-tab-details"
                    aria-controls="host-panel-details"
                  />
                </Tabs>
                <Box role="tabpanel" id={`host-panel-${tab}`} aria-labelledby={`host-tab-${tab}`}>
                  {tab === "overview" && (
                    <Stack spacing={2}>
                      <Typography variant="body2" color="text.secondary">
                        {host.inventory.os.name || platformLabels[host.platform]} · Inventur vom{" "}
                        {date(host.inventory.completed_at)}
                      </Typography>
                      <Box
                        sx={{
                          display: "grid",
                          gridTemplateColumns: { xs: "1fr", sm: windows ? "1fr 1fr" : "1fr" },
                          gap: 2,
                        }}
                      >
                        {windows ? (
                          <>
                            <Paper variant="outlined" sx={{ p: 2 }}>
                              <Typography component="h3" variant="subtitle2" sx={{ mb: 1.5 }}>
                                Systemupdates
                              </Typography>
                              <WindowsStatus host={host} />
                              <Button
                                size="small"
                                endIcon={<ArrowForwardIcon />}
                                onClick={() => setTab("updates")}
                                sx={{ mt: 1.5 }}
                              >
                                Updates ansehen
                              </Button>
                            </Paper>
                            <Paper variant="outlined" sx={{ p: 2 }}>
                              <Typography component="h3" variant="subtitle2" sx={{ mb: 1.5 }}>
                                Installierte Software
                              </Typography>
                              <SoftwareStatus host={host} />
                              <Button
                                size="small"
                                endIcon={<ArrowForwardIcon />}
                                onClick={() => setTab("software")}
                                sx={{ mt: 1.5 }}
                              >
                                Software ansehen
                              </Button>
                            </Paper>
                          </>
                        ) : (
                          <Paper variant="outlined" sx={{ p: 2 }}>
                            <Typography component="h3" variant="subtitle2">
                              Inventur gespeichert
                            </Typography>
                            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                              {host.inventory.package_count} Software-Einträge erfasst. Für diese
                              Plattform ist noch keine authentifizierte Patchbewertung verfügbar.
                            </Typography>
                          </Paper>
                        )}
                      </Box>
                      {windows && (
                        <Typography variant="caption" color="text.secondary">
                          Die Bereiche werden getrennt geprüft. Eine erfüllte OS-Baseline bestätigt
                          ausschließlich den geprüften Windows-Build.
                        </Typography>
                      )}
                    </Stack>
                  )}
                  {tab === "updates" && windows && (
                    <Stack spacing={2}>
                      <Typography component="h3" variant="h6">
                        {host.platform === "windows_client"
                          ? "Windows-Updateangebote"
                          : "Windows-Build und Zielstand"}
                      </Typography>
                      <WindowsStatus host={host} />
                      <Typography variant="body2" color="text.secondary">
                        {host.platform === "windows_client"
                          ? "Die konfigurierte Windows Update-/WSUS-Quelle bestimmt das Angebot. Eine Abfrage gilt höchstens 24 Stunden. Keine Angebote bestätigen keine vollständige Patchfreigabe; optionale Updates bleiben eine eigene Entscheidung."
                          : "Der installierte OS-Build wird mit der Microsoft-Katalogbaseline verglichen. Andere Windows-Komponenten und installierte Programme werden separat betrachtet."}
                      </Typography>
                      <Stack direction="row" useFlexGap sx={{ flexWrap: "wrap", gap: 1 }}>
                        {host.platform === "windows_client" && (
                          <Button
                            variant="outlined"
                            disabled={busy || Boolean(pending)}
                            onClick={() => navigate(queryWindows)}
                          >
                            Windows-Updates abfragen
                          </Button>
                        )}
                        <Button
                          variant="outlined"
                          disabled={busy || !canAssessWindows || Boolean(pending)}
                          onClick={() => navigate(assessWindows)}
                        >
                          Windows jetzt bewerten
                        </Button>
                        {host.windows_assessment && (
                          <Button disabled={busy} onClick={() => navigate(openWindows)}>
                            Gespeicherte Bewertung öffnen
                          </Button>
                        )}
                      </Stack>
                    </Stack>
                  )}
                  {tab === "software" && windows && (
                    <Stack spacing={2}>
                      <Typography component="h3" variant="h6">
                        Installierte Software
                      </Typography>
                      {affected.length ? (
                        <Typography variant="body2">
                          {host.software_assessment?.result.summary.matched_product_versions}{" "}
                          Software-Versionen mit CVE-Zuordnungen in den geprüften Regeln.
                        </Typography>
                      ) : (
                        <SoftwareStatus host={host} />
                      )}
                      {affected.map((product) => (
                        <Paper
                          key={`${product.product_key}:${product.version}`}
                          variant="outlined"
                          sx={{ p: 2, borderLeft: 3, borderLeftColor: "error.main" }}
                        >
                          <Typography sx={{ fontWeight: 700 }}>{product.name}</Typography>
                          <Typography variant="body2" sx={{ mt: 0.5 }}>
                            Installiert: {product.version} · Zielversion:{" "}
                            {softwareFix(product) ?? "Fixdetails in der Bewertung prüfen"}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {product.matches_total} CVE-Versionszuordnungen · {product.publisher}
                            {product.matches_truncated ? " · Trefferanzeige gekürzt" : ""}
                          </Typography>
                        </Paper>
                      ))}
                      <Typography variant="body2" color="text.secondary">
                        Abgedeckt sind ausgewählte Edge-spezifische Meldungen und die kuratierte
                        7-Zip-Regel. Weitere Programme und CVEs bleiben ungeprüft.
                        Versionszuordnungen belegen keine Ausnutzbarkeit.
                      </Typography>
                      <Stack direction="row" useFlexGap sx={{ flexWrap: "wrap", gap: 1 }}>
                        <Button
                          variant="outlined"
                          disabled={busy || Boolean(pending)}
                          onClick={() => navigate(assessSoftware)}
                        >
                          Software jetzt bewerten
                        </Button>
                        {host.software_assessment && (
                          <Button disabled={busy} onClick={() => navigate(openSoftware)}>
                            Gespeicherte Softwarebewertung öffnen
                          </Button>
                        )}
                      </Stack>
                    </Stack>
                  )}
                  {tab === "details" && (
                    <Stack spacing={2}>
                      <RunDetails host={host} />
                      <Divider />
                      <Stack direction="row" useFlexGap sx={{ flexWrap: "wrap", gap: 1 }}>
                        <Button
                          variant="outlined"
                          disabled={busy}
                          onClick={() => navigate(inspect)}
                        >
                          Inventur-Evidenz öffnen
                        </Button>
                        {host.platform !== "vmware" && (
                          <Button
                            disabled={busy || Boolean(pending)}
                            onClick={() => navigate(collect)}
                          >
                            Inventur aktualisieren
                          </Button>
                        )}
                      </Stack>
                    </Stack>
                  )}
                </Box>
              </Box>
            )}
          </Stack>
        )}
      </DialogContent>
      <DialogActions
        sx={{ px: { xs: 2, sm: 3 }, py: 1.5, borderTop: "1px solid", borderColor: "divider" }}
      >
        <Typography variant="caption" color="text.secondary" sx={{ flexGrow: 1 }}>
          Prüfungen installieren keine Updates.
        </Typography>
        <Button onClick={close}>Schließen</Button>
      </DialogActions>
    </Dialog>
  );
}
