import { useMemo, useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Chip,
  MenuItem,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from "@mui/material";
import {
  current,
  date,
  hostState,
  matchesPlatform,
  assessmentWarning,
  softwareFix,
} from "./overview-state";
import type { OverviewHost, HostOverview, HostPlatformFilter } from "./overview-state";

const issueLabels: Record<string, string> = {
  latest_collection_failed: "Neueste Inventur fehlgeschlagen",
  collection_pending: "Inventur läuft oder wartet",
  inventory_partial: "Inventur unvollständig",
  inventory_stale: "Inventur veraltet",
  windows_assessment_missing: "Windows-Bewertung fehlt",
  software_assessment_missing: "Software-Bewertung fehlt",
  windows_assessment_stale: "Windows-Bewertung veraltet",
  software_assessment_stale: "Software-Bewertung veraltet",
  latest_connection_failed: "Neuester Verbindungstest fehlgeschlagen",
  inventory_missing: "Noch keine verwertbare Inventur",
  windows_client_patch_coverage_unavailable: "Windows-Client-OS noch nicht abgedeckt",
  patch_assessment_unsupported: "Patchbewertung dieser Plattform noch nicht verfügbar",
  inventory_identity_incomplete: "Plattformzuordnung unvollständig",
  software_details_truncated: "Software-Detailanzeige gekürzt",
  windows_catalog_changed: "Windows-Katalog wurde erneuert",
  software_catalog_changed: "Software-Katalog wurde erneuert",
};
export function WindowsStatus({ host }: { host: OverviewHost }) {
  const assessment = host.windows_assessment;
  const state = hostState(host);
  if (host.platform === "windows_client")
    return (
      <Typography variant="body2" color="text.secondary">
        OS-Patchbewertung für Clients noch nicht verfügbar
      </Typography>
    );
  if (state.needsWindows)
    return (
      <Stack spacing={0.5}>
        <Chip size="small" color="error" label="Windows-Update nötig" />
        <Typography variant="body2">
          {assessment?.result.installed_build} → {assessment?.result.baseline_build}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {assessment?.result.baseline_kbs.join(", ")}
        </Typography>
      </Stack>
    );
  if (state.baseline)
    return (
      <Stack spacing={0.5}>
        <Chip size="small" color="success" variant="outlined" label="OS-Baseline erfüllt" />
        <Typography variant="caption" color="text.secondary">
          Build {assessment?.result.installed_build}
        </Typography>
      </Stack>
    );
  if (
    current(assessment) &&
    assessment?.status === "meets_catalog_baseline" &&
    state.collectionIssue
  )
    return (
      <Typography variant="body2" color="warning.main">
        Letzte bekannte Baseline erfüllt · Inventur aktualisieren
      </Typography>
    );
  const unsupported =
    !["windows_server", "windows_client"].includes(host.platform) ||
    assessment?.status === "unsupported";
  return (
    <Typography variant="body2" color="text.secondary">
      {unsupported ? "Keine OS-Patchbewertung verfügbar" : assessmentWarning(assessment)}
    </Typography>
  );
}
export function SoftwareStatus({ host }: { host: OverviewHost }) {
  const assessment = host.software_assessment;
  const state = hostState(host);
  const affected = assessment?.result.products.filter((product) => product.matches_total > 0) ?? [];
  const unavailable =
    assessment?.result.coverage.vendor_catalog.reduce(
      (count, scope) => count + scope.unavailable_count,
      0,
    ) ?? 0;
  if (state.needsSoftware)
    return (
      <Stack spacing={0.5}>
        <Chip
          size="small"
          color="error"
          label={`${assessment!.result.summary.matched_product_versions} Software-Versionen prüfen`}
        />
        {affected.slice(0, 2).map((product) => (
          <Typography key={`${product.product_key}:${product.version}`} variant="body2">
            {product.name} {product.version} → {softwareFix(product) ?? "Fixdetails öffnen"}
          </Typography>
        ))}
        {assessment!.result.summary.matched_product_versions > 2 && (
          <Typography variant="caption" color="text.secondary">
            {assessment!.result.summary.matched_product_versions - 2} weitere betroffene Versionen ·
            Details öffnen
          </Typography>
        )}
        <Typography variant="caption">
          {assessment!.result.summary.cve_matches} CVE-Versionszuordnungen
        </Typography>
        {!!assessment!.result.summary.unassessed_entries && (
          <Typography variant="caption" color="text.secondary">
            {assessment!.result.summary.unassessed_entries} weitere Einträge ungeprüft
          </Typography>
        )}
        {unavailable > 0 && (
          <Typography variant="caption" color="warning.main">
            {unavailable} Meldungen nicht bewertet
          </Typography>
        )}
      </Stack>
    );
  if (current(assessment) && assessment?.status === "no_matches_in_checked_ranges")
    return (
      <Stack spacing={0.5}>
        <Typography variant="body2">Kein Treffer in geprüften Regeln</Typography>
        <Typography variant="caption" color="text.secondary">
          {assessment.result.summary.assessed_entries} geprüft ·{" "}
          {assessment.result.summary.unassessed_entries} ungeprüft
        </Typography>
        {unavailable > 0 && (
          <Typography variant="caption" color="warning.main">
            {unavailable} Meldungen nicht bewertet
          </Typography>
        )}
      </Stack>
    );
  return (
    <Typography variant="body2" color="text.secondary">
      {assessmentWarning(assessment) || "Kein auswertbarer Produktabgleich"}
    </Typography>
  );
}

export function HostOverviewPanel({
  overview,
  platform,
  loading,
  onDetail,
}: {
  overview: HostOverview | null;
  platform: HostPlatformFilter;
  loading: boolean;
  onDetail: (host: OverviewHost) => void;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const hosts = useMemo(
    () => (overview?.hosts ?? []).filter((host) => matchesPlatform(host, platform)),
    [overview, platform],
  );
  const rows = hosts
    .filter((host) => {
      const state = hostState(host);
      return (
        (filter === "all" ||
          (filter === "updates" && state.attention) ||
          (filter === "unknown" && state.unknown) ||
          (filter === "baseline" && state.baseline)) &&
        [host.target, host.inventory?.os.hostname, host.inventory?.os.name].some((text) =>
          text?.toLocaleLowerCase().includes(search.toLocaleLowerCase()),
        )
      );
    })
    .sort((left, right) => {
      const a = hostState(left);
      const b = hostState(right);
      return (
        Number(b.attention) - Number(a.attention) ||
        Number(b.unknown) - Number(a.unknown) ||
        left.target.localeCompare(right.target)
      );
    });
  return (
    <Stack spacing={2} data-testid="host-overview">
      <Box
        sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(3, 1fr)" }, gap: 2 }}
      >
        {[
          {
            id: "update-count",
            label: "Updatebedarf",
            value: hosts.filter((host) => hostState(host).attention).length,
            color: "error.main",
            hint: "Hosts mit aktuellem Build- oder Software-Befund",
          },
          {
            id: "baseline-count",
            label: "OS-Baseline erfüllt",
            value: hosts.filter((host) => hostState(host).baseline).length,
            color: "success.main",
            hint: "Windows-OS-Build; keine Entwarnung für alle Programme",
          },
          {
            id: "unknown-count",
            label: "Ungeprüft / Fehler",
            value: hosts.filter((host) => hostState(host).unknown).length,
            color: "warning.main",
            hint: "Fehlende, veraltete oder unvollständige Abdeckung",
          },
        ].map((card) => (
          <Paper
            key={card.label}
            data-testid={card.id}
            sx={{ p: 2.5, borderTop: 3, borderColor: card.color }}
          >
            <Typography variant="body2" color="text.secondary">
              {card.label}
            </Typography>
            <Typography variant="h3" sx={{ my: 0.5 }}>
              {card.value}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {card.hint}
            </Typography>
          </Paper>
        ))}
      </Box>
      <Paper sx={{ p: { xs: 2, md: 3 } }}>
        <Stack spacing={2}>
          <Stack
            direction={{ xs: "column", sm: "row" }}
            sx={{ justifyContent: "space-between", gap: 2 }}
          >
            <Box>
              <Typography variant="h6">Patch- und Inventurstatus</Typography>
              <Typography variant="body2" color="text.secondary">
                {hosts.length} Hosts · nach Handlungsbedarf sortiert
              </Typography>
            </Box>
            <Stack direction="row" spacing={1}>
              <TextField
                size="small"
                label="Host suchen"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
              <TextField
                size="small"
                select
                label="Statusfilter"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                sx={{ minWidth: 170 }}
              >
                <MenuItem value="all">Alle Status</MenuItem>
                <MenuItem value="updates">Updatebedarf</MenuItem>
                <MenuItem value="unknown">Ungeprüft / Fehler</MenuItem>
                <MenuItem value="baseline">OS-Baseline erfüllt</MenuItem>
              </TextField>
            </Stack>
          </Stack>
          {platform === "vmware" && (
            <Alert severity="info">
              Für VMware ist noch keine authentifizierte Inventur oder Patchbewertung angebunden.
              Netzwerkbeobachtungen ersetzen keine ESXi- oder vCenter-Buildprüfung.
            </Alert>
          )}
          {platform === "windows-client" && (
            <Alert severity="info">
              Die Softwareprüfung unterstützt ausgewählte Produktregeln. Die OS-Patchbewertung ist
              derzeit nur für Windows Server verfügbar.
            </Alert>
          )}
          {platform === "linux" && (
            <Alert severity="info">
              Linux-Inventuren liefern OS-, Kernel- und Paketstände. Ein Abgleich mit
              distributionsspezifischen Sicherheitsupdates ist noch nicht verfügbar.
            </Alert>
          )}
          {overview?.hosts_truncated && (
            <Alert severity="warning">
              Die Übersicht zeigt höchstens {overview.limit} von {overview.hosts_total} Hosts.
              Weitere Hosts sind in dieser Ansicht noch nicht abgedeckt.
            </Alert>
          )}
          {overview && overview.issues.length > 0 && (
            <Alert severity="warning">
              Mindestens ein Katalog ist nicht verfügbar oder nicht auswertbar. Die betroffenen
              Bewertungen gelten nicht als aktuell.
            </Alert>
          )}
          {platform !== "all" &&
            overview?.hosts.some((host) => host.platform === "unclassified") && (
              <Alert
                severity="info"
                action={
                  <Button
                    component={RouterLink}
                    to={`/host-audits?customer_id=${overview.customer_id}`}
                    size="small"
                  >
                    Host-Übersicht
                  </Button>
                }
              >
                {overview.hosts.filter((host) => host.platform === "unclassified").length} Hosts
                sind noch keiner Plattform zugeordnet. Sie bleiben in der allgemeinen Host-Übersicht
                sichtbar.
              </Alert>
            )}
          {!overview ? (
            <Typography color="text.secondary">
              {loading ? "Host-Status wird geladen…" : "Host-Status noch nicht verfügbar."}
            </Typography>
          ) : !rows.length ? (
            <Typography color="text.secondary">
              {hosts.length
                ? "Keine Hosts passen zum Filter."
                : "Für diesen Bereich ist noch keine passende Inventur vorhanden."}
            </Typography>
          ) : (
            <TableContainer>
              <Table size="small" aria-label="Patchstatus der Hosts">
                <TableHead>
                  <TableRow>
                    <TableCell>Host / Betriebssystem</TableCell>
                    <TableCell>OS-Patchstatus</TableCell>
                    <TableCell>Installierte Software</TableCell>
                    <TableCell>Letzte Inventur</TableCell>
                    <TableCell />
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.map((host) => {
                    const state = hostState(host);
                    return (
                      <TableRow
                        key={host.asset_id}
                        data-testid={`host-row-${host.asset_id}`}
                        sx={{
                          verticalAlign: "top",
                          bgcolor: state.attention ? "rgba(239, 68, 68, .05)" : undefined,
                        }}
                      >
                        <TableCell>
                          <Typography sx={{ fontWeight: 700 }}>
                            {host.inventory?.os.hostname || host.target}
                          </Typography>
                          <Typography variant="body2">{host.target}</Typography>
                          <Typography variant="caption" color="text.secondary">
                            {host.inventory?.os.name || "Plattform noch nicht bestimmt"}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <WindowsStatus host={host} />
                        </TableCell>
                        <TableCell>
                          <SoftwareStatus host={host} />
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2">
                            {date(host.inventory?.completed_at)}
                          </Typography>
                          {host.latest_run.status === "failed" && (
                            <Chip
                              size="small"
                              color="warning"
                              label="Neuester Lauf fehlgeschlagen"
                              sx={{ mt: 1 }}
                            />
                          )}
                          {["queued", "running"].includes(host.latest_run.status) && (
                            <Chip size="small" label="Prüfung läuft / wartet" sx={{ mt: 1 }} />
                          )}
                          {!!host.inventory && (
                            <Typography
                              variant="caption"
                              sx={{ display: "block" }}
                              color="text.secondary"
                            >
                              {host.inventory.package_count} Software-Einträge
                            </Typography>
                          )}
                        </TableCell>
                        <TableCell>
                          <Button size="small" onClick={() => onDetail(host)}>
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </TableContainer>
          )}
          <Typography variant="caption" color="text.secondary">
            Die Kennzahlen beschreiben getrennte Aspekte und können denselben Host enthalten. Grün
            bestätigt ausschließlich die geprüfte OS-Baseline. Fehlende Regeln, Software und
            Plattformen bleiben ungeprüft.
          </Typography>
        </Stack>
      </Paper>
    </Stack>
  );
}

export function HostIssueList({ host }: { host: OverviewHost }) {
  const known = host.issues.map((issue) => issueLabels[issue]).filter(Boolean);
  return <>{known.length > 0 && <Alert severity="warning">{known.join(" · ")}</Alert>}</>;
}
