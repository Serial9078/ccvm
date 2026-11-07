import {
  Alert,
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Paper,
  Stack,
  Typography,
} from "@mui/material";
import { HostIssueList, WindowsStatus, SoftwareStatus } from "./overview";
import { current, date, freshWindowsUpdateQuery, softwareFix } from "./overview-state";
import type { OverviewHost } from "./overview-state";

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
  const windows = host && ["windows_server", "windows_client"].includes(host.platform);
  return (
    <Dialog open={host !== null} onClose={close} maxWidth="lg" fullWidth>
      <DialogTitle>Host-Status · {host?.target}</DialogTitle>
      <DialogContent>
        {host && (
          <Stack spacing={2}>
            <Box>
              <Typography variant="h6">{host.inventory?.os.hostname || host.target}</Typography>
              <Typography color="text.secondary">
                {host.inventory?.os.name || "Plattform noch nicht bestimmt"}
              </Typography>
              <Typography variant="body2">
                Letzte gespeicherte Inventur: {date(host.inventory?.completed_at)}
              </Typography>
            </Box>
            <HostIssueList host={host} />
            {host.latest_run.status === "failed" && (
              <Alert severity="warning">
                Neuester Lauf fehlgeschlagen: {host.latest_run.message}. Ältere Evidenz bestätigt
                keinen erfolgreichen neuen Lauf.
              </Alert>
            )}
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="h6" sx={{ mb: 1 }}>
                {host.platform === "windows_client"
                  ? "Windows-Updateangebote"
                  : windows
                    ? "Windows-Build"
                    : "Systemupdates"}
              </Typography>
              <WindowsStatus host={host} />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                {host.platform === "windows_client"
                  ? "Die konfigurierte Windows Update-/WSUS-Quelle bestimmt das Angebot. Keine Angebote bestätigen keine vollständige Patchfreigabe; optionale Updates sind separat zu entscheiden."
                  : windows
                    ? "Die OS-Build-Baseline bewertet weder andere Windows-Komponenten noch installierte Programme."
                    : "Für diese Plattform ist noch keine authentifizierte Patchbewertung verfügbar."}
              </Typography>
            </Paper>
            {host.platform === "windows_client" && !freshWindowsUpdateQuery(host) && (
              <Alert severity="info">
                Für eine aktuelle Bewertung zuerst „Windows-Updates abfragen“ starten. Eine normale
                Inventur enthält keine Online-Updateabfrage. Die gespeicherte Abfrage gilt höchstens
                24 Stunden.
              </Alert>
            )}
            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="h6" sx={{ mb: 1 }}>
                Installierte Software
              </Typography>
              <SoftwareStatus host={host} />
              {current(host.software_assessment) &&
                host.software_assessment?.result.products
                  .filter((product) => product.matches_total > 0)
                  .map((product) => (
                    <Box
                      key={`${product.product_key}:${product.version}`}
                      sx={{
                        mt: 2,
                        p: 2,
                        borderLeft: 3,
                        borderColor: "error.main",
                        bgcolor: "rgba(239, 68, 68, .05)",
                      }}
                    >
                      <Typography sx={{ fontWeight: 700 }}>{product.name}</Typography>
                      <Typography variant="body2">
                        Installiert: {product.version} · Fix laut geprüften Meldungen:{" "}
                        {softwareFix(product) ?? "Fixdetails öffnen"}
                      </Typography>
                      <Typography variant="caption" color="text.secondary">
                        {product.matches_total} CVE-Versionszuordnungen · {product.publisher}
                        {product.matches_truncated ? " · Trefferanzeige gekürzt" : ""}
                      </Typography>
                    </Box>
                  ))}
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                Nur ausgewählte Edge-spezifische Meldungen und die kuratierte 7-Zip-Regel sind
                abgedeckt. Weitere Programme und CVEs bleiben ungeprüft. Versionszuordnungen belegen
                keine Ausnutzbarkeit.
              </Typography>
            </Paper>
            <Stack direction="row" useFlexGap sx={{ flexWrap: "wrap", gap: 1 }}>
              <Button
                variant="outlined"
                disabled={busy || host.platform === "vmware"}
                onClick={() => collect(host)}
              >
                Inventur aktualisieren
              </Button>
              <Button disabled={busy || !host.inventory} onClick={() => inspect(host)}>
                Inventur-Evidenz
              </Button>
              {windows && (
                <>
                  {host.platform === "windows_client" && (
                    <Button variant="contained" disabled={busy} onClick={() => queryWindows(host)}>
                      Windows-Updates abfragen
                    </Button>
                  )}
                  <Button
                    disabled={
                      busy ||
                      !host.inventory ||
                      (host.platform === "windows_client" && !freshWindowsUpdateQuery(host))
                    }
                    onClick={() => assessWindows(host)}
                  >
                    Windows jetzt bewerten
                  </Button>
                  <Button disabled={busy || !host.inventory} onClick={() => assessSoftware(host)}>
                    Software jetzt bewerten
                  </Button>
                  <Button disabled={busy || !host.inventory} onClick={() => openWindows(host)}>
                    Windows-Bewertung öffnen
                  </Button>
                  <Button disabled={busy || !host.inventory} onClick={() => openSoftware(host)}>
                    Software-Bewertung öffnen
                  </Button>
                </>
              )}
            </Stack>
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={close}>Host-Status schließen</Button>
      </DialogActions>
    </Dialog>
  );
}
