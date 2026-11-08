import { useMemo, useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import {
  Alert,
  Box,
  Button,
  Chip,
  ButtonBase,
  InputAdornment,
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
  updateStatusLabels,
} from "./overview-state";
import type { OverviewHost, HostOverview, HostPlatformFilter } from "./overview-state";
import SearchIcon from "@mui/icons-material/Search";
import ArrowForwardIcon from "@mui/icons-material/ArrowForward";
import { hostPresentation } from "./host-presentation";
import type { HostAction } from "./host-presentation";

export function WindowsStatus({ host }: { host: OverviewHost }) {
  const assessment = host.windows_assessment;
  const state = hostState(host);
  if (host.platform === "windows_client") {
    const query = assessment?.result.windows_updates;
    const fresh = current(assessment) && !state.collectionIssue;
    return (
      <Stack spacing={0.5}>
        <Chip
          size="small"
          variant="outlined"
          color={fresh && assessment?.status === "updates_offered" ? "warning" : "default"}
          label={
            !assessment
              ? "Updateabfrage erforderlich"
              : ["update_query_required", "update_query_incomplete", "stale_evidence"].includes(
                    assessment.status,
                  )
                ? updateStatusLabels[assessment.status]
                : !fresh
                  ? assessmentWarning(assessment) ||
                    updateStatusLabels[assessment.status] ||
                    "Updateabfrage erforderlich"
                  : updateStatusLabels[assessment.status] || "Updateabfrage erforderlich"
          }
        />
        {query && (
          <Typography variant="body2">
            {query.summary?.security ?? 0} Sicherheit · {query.summary?.quality ?? 0} Qualität ·{" "}
            {query.summary?.feature ?? 0} Funktion · {query.summary?.definition ?? 0} Definition
          </Typography>
        )}
        <Typography variant="caption" color="text.secondary">
          {query
            ? `Geräte-Updatequelle · ${date(query.queried_at)}`
            : "Explizite Onlineabfrage der Geräte-Updatequelle starten"}
        </Typography>
        {assessment?.status === "no_update_offers" && (
          <Typography variant="caption" color="text.secondary">
            Keine Angebote der konfigurierten Quelle · keine vollständige Patchfreigabe
          </Typography>
        )}
        {query?.reboot_required === true && (
          <Typography variant="caption" color="warning.main">
            Gerät meldet ausstehenden Neustart
          </Typography>
        )}
      </Stack>
    );
  }
  if (state.needsWindows)
    return (
      <Stack spacing={0.5}>
        <Chip size="small" color="error" label="Windows-Update nötig" />
        <Typography variant="body2">
          {assessment?.result.installed_build} → {assessment?.result.baseline_build}
        </Typography>
        <Typography variant="caption" color="text.secondary">
          {assessment?.result.baseline_kbs?.join(", ")}
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

const groups = [
  {
    id: "updates",
    testId: "update-count",
    label: "Updatebedarf",
    hint: "Aktuelle Update- oder Software-Befunde",
    color: "error.main",
  },
  {
    id: "collection",
    testId: "unknown-count",
    label: "Inventur nötig",
    hint: "Verbindung, fehlende oder veraltete Daten",
    color: "warning.main",
  },
  {
    id: "assessment",
    testId: "assessment-count",
    label: "Bewertung offen",
    hint: "Bewertung fehlt oder Prüfumfang begrenzt",
    color: "info.main",
  },
  {
    id: "checked",
    testId: "baseline-count",
    label: "Geprüfter Stand",
    hint: "Ergebnisse vorhanden · nur geprüfter Umfang",
    color: "info.main",
  },
] as const;
const groupFor = (host: OverviewHost) => {
  const status = hostPresentation(host).status;
  return status === "unsupported" ? "assessment" : status;
};

function CompactSystemStatus({ host }: { host: OverviewHost }) {
  const assessment = host.windows_assessment;
  const state = hostState(host);
  const fresh = current(assessment) && !state.collectionIssue;
  const label = !host.inventory
    ? "Noch nicht geprüft"
    : !assessment
      ? ["windows_client", "windows_server"].includes(host.platform)
        ? "Bewertung fehlt"
        : "Noch nicht unterstützt"
      : !fresh
        ? "Stand nicht aktuell"
        : host.platform === "windows_client"
          ? updateStatusLabels[assessment.status] || "Abfrage unvollständig"
          : state.needsWindows
            ? "Update nötig"
            : state.baseline
              ? "Build-Baseline erfüllt"
              : "Nicht bewertet";
  return (
    <Stack spacing={0.5}>
      <Typography
        variant="body2"
        sx={{ fontWeight: 600 }}
        color={state.needsWindows ? "error.main" : state.baseline ? "success.main" : "text.primary"}
      >
        {label}
      </Typography>
      {fresh && assessment?.result.baseline_kbs?.length ? (
        <Typography variant="caption" color="text.secondary">
          {assessment.result.baseline_kbs.join(", ")}
        </Typography>
      ) : null}
      {host.platform === "windows_client" &&
        assessment?.result.windows_updates?.reboot_required && (
          <Typography variant="caption" color="warning.main">
            Neustart ausstehend
          </Typography>
        )}
    </Stack>
  );
}
function CompactSoftwareStatus({ host }: { host: OverviewHost }) {
  const assessment = host.software_assessment;
  const fresh = current(assessment);
  const summary = assessment?.result.summary;
  return (
    <Stack spacing={0.5}>
      <Typography
        variant="body2"
        sx={{ fontWeight: 600 }}
        color={fresh && summary?.cve_matches ? "error.main" : "text.primary"}
      >
        {!host.inventory
          ? "Noch nicht geprüft"
          : !fresh
            ? "Bewertung offen"
            : summary?.cve_matches
              ? `${summary.matched_product_versions} Versionen prüfen`
              : "Kein Treffer in geprüften Regeln"}
      </Typography>
      {fresh && summary && (
        <Typography variant="caption" color="text.secondary">
          {summary.assessed_entries} geprüft · {summary.unassessed_entries} ungeprüft
        </Typography>
      )}
    </Stack>
  );
}

export function HostOverviewPanel({
  overview,
  platform,
  loading,
  onDetail,
  onAction,
  busy = false,
}: {
  overview: HostOverview | null;
  platform: HostPlatformFilter;
  loading: boolean;
  onDetail: (host: OverviewHost) => void;
  onAction: (host: OverviewHost, action: HostAction) => void;
  busy?: boolean;
}) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("all");
  const hosts = useMemo(
    () => (overview?.hosts ?? []).filter((host) => matchesPlatform(host, platform)),
    [overview, platform],
  );
  const rows = hosts
    .filter(
      (host) =>
        (filter === "all" || groupFor(host) === filter) &&
        [host.target, host.inventory?.os.hostname, host.inventory?.os.name].some((text) =>
          text?.toLocaleLowerCase().includes(search.toLocaleLowerCase()),
        ),
    )
    .sort(
      (a, b) =>
        groups.findIndex((group) => group.id === groupFor(a)) -
          groups.findIndex((group) => group.id === groupFor(b)) || a.target.localeCompare(b.target),
    );
  const actionButton = (host: OverviewHost) => {
    const state = hostPresentation(host);
    return (
      <Stack spacing={0.5} sx={{ alignItems: { xs: "stretch", md: "flex-start" } }}>
        {state.action && (
          <Button
            size="small"
            variant="outlined"
            disabled={busy}
            endIcon={<ArrowForwardIcon fontSize="small" />}
            onClick={() => onAction(host, state.action!)}
          >
            {state.actionLabel}
          </Button>
        )}
        <Button
          size="small"
          aria-label={`Host öffnen: ${host.target}`}
          onClick={() => onDetail(host)}
          sx={{ justifyContent: "flex-start" }}
        >
          Details
        </Button>
      </Stack>
    );
  };
  const hostIdentity = (host: OverviewHost) => (
    <Stack spacing={0.35}>
      <Button
        onClick={() => onDetail(host)}
        sx={{
          p: 0,
          minWidth: 0,
          justifyContent: "flex-start",
          alignSelf: "flex-start",
          fontSize: 15,
        }}
      >
        {host.inventory?.os.hostname || host.target}
      </Button>
      {host.inventory?.os.hostname && (
        <Typography variant="body2" color="text.secondary">
          {host.target}
        </Typography>
      )}
      <Typography variant="caption" color="text.secondary">
        {host.inventory?.os.name || "Plattform noch nicht erkannt"}
      </Typography>
      <Typography variant="caption" color="text.secondary">
        {host.inventory ? `Inventur: ${date(host.inventory.completed_at)}` : "Keine Inventurdaten"}
      </Typography>
    </Stack>
  );
  const hostResult = (host: OverviewHost) => {
    const state = hostPresentation(host);
    return (
      <Stack spacing={0.75}>
        <Chip
          size="small"
          variant="outlined"
          color={state.tone}
          label={state.label}
          sx={{
            alignSelf: "flex-start",
            maxWidth: "100%",
            height: "auto",
            minHeight: 26,
            "& .MuiChip-label": { whiteSpace: "normal", py: 0.35 },
          }}
        />
        <Typography variant="caption" color="text.secondary">
          {host.latest_run.status === "failed"
            ? "Neuester Versuch fehlgeschlagen"
            : state.status === "updates"
              ? "Aktuelle Befunde vorhanden"
              : state.status === "collection"
                ? "Daten erfassen oder erneuern"
                : state.status === "checked"
                  ? "Gilt nur für den geprüften Umfang"
                  : "Prüfumfang und nächste Schritte ansehen"}
        </Typography>
      </Stack>
    );
  };
  return (
    <Stack spacing={2.5} data-testid="host-overview">
      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: { xs: "repeat(2, 1fr)", lg: "repeat(4, 1fr)" },
          gap: 1.5,
        }}
      >
        {groups.map((group) => (
          <ButtonBase
            key={group.id}
            data-testid={group.testId}
            aria-pressed={filter === group.id}
            onClick={() => setFilter(filter === group.id ? "all" : group.id)}
            sx={{
              textAlign: "left",
              display: "block",
              p: { xs: 2, md: 2.5 },
              border: "1px solid",
              borderColor: filter === group.id ? group.color : "divider",
              borderRadius: 2,
              bgcolor: filter === group.id ? "action.selected" : "background.paper",
              "&:hover": { bgcolor: "action.hover", borderColor: group.color },
              "&:focus-visible": { outline: "2px solid #00ff41", outlineOffset: 3 },
            }}
          >
            <Stack
              direction="row"
              sx={{ alignItems: "center", justifyContent: "space-between", gap: 1 }}
            >
              <Typography variant="body2" sx={{ fontWeight: 650 }}>
                {group.label}
              </Typography>
              <Box sx={{ width: 7, height: 7, borderRadius: "50%", bgcolor: group.color }} />
            </Stack>
            <Typography variant="h3" sx={{ fontSize: { xs: 30, md: 36 }, my: 1 }}>
              {hosts.filter((host) => groupFor(host) === group.id).length}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {group.hint}
            </Typography>
          </ButtonBase>
        ))}
      </Box>
      <Paper sx={{ overflow: "hidden" }}>
        <Stack spacing={2} sx={{ p: { xs: 2, md: 2.5 } }}>
          <Stack
            direction={{ xs: "column", lg: "row" }}
            sx={{ justifyContent: "space-between", gap: 2 }}
          >
            <Box>
              <Typography variant="h6">Systeme und Handlungsbedarf</Typography>
              <Typography variant="body2" color="text.secondary">
                {rows.length} von {hosts.length} Systemen · nach nächstem Arbeitsschritt sortiert
              </Typography>
            </Box>
            <Stack direction={{ xs: "column", sm: "row" }} spacing={1}>
              <TextField
                size="small"
                label="Host suchen"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                slotProps={{
                  input: {
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon fontSize="small" />
                      </InputAdornment>
                    ),
                  },
                }}
              />
              <TextField
                size="small"
                select
                label="Statusfilter"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
                sx={{ minWidth: 180 }}
              >
                <MenuItem value="all">Alle Systeme</MenuItem>
                {groups.map((group) => (
                  <MenuItem key={group.id} value={group.id}>
                    {group.label}
                  </MenuItem>
                ))}
              </TextField>
            </Stack>
          </Stack>
          {platform === "vmware" && (
            <Alert severity="info">
              VMware: Netzwerkdienste können erkannt werden. Authentifizierte Inventur und
              Buildprüfung sind noch nicht angebunden.
            </Alert>
          )}
          {platform === "linux" && (
            <Alert severity="info">
              Linux: OS-, Kernel- und Paketstände werden erfasst. Distributionsspezifische
              Patchbewertungen sind noch nicht verfügbar.
            </Alert>
          )}
          {overview?.hosts_truncated && (
            <Alert severity="warning">
              {overview.limit} von {overview.hosts_total} Hosts geladen. Weitere Hosts sind hier
              noch nicht abgedeckt.
            </Alert>
          )}
          {!!overview?.issues.length && (
            <Alert severity="warning">
              Ein Katalog ist nicht auswertbar. Betroffene Bewertungen sind nicht aktuell.
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
                {overview.hosts.filter((host) => host.platform === "unclassified").length} Systeme
                haben noch keine Plattformzuordnung.
              </Alert>
            )}
          {!overview ? (
            <Typography color="text.secondary">
              {loading ? "Systeme werden geladen…" : "Host-Status noch nicht verfügbar."}
            </Typography>
          ) : !rows.length ? (
            <Box sx={{ py: 4, textAlign: "center" }}>
              <Typography sx={{ fontWeight: 650 }}>
                {hosts.length
                  ? "Keine Systeme in dieser Auswahl"
                  : "Noch keine Inventur in diesem Bereich"}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                {hosts.length
                  ? "Einen anderen Status wählen oder die Suche zurücksetzen."
                  : "Eine Inventur starten oder erkannte Geräte übernehmen."}
              </Typography>
              {hosts.length > 0 && (
                <Button
                  sx={{ mt: 1 }}
                  onClick={() => {
                    setSearch("");
                    setFilter("all");
                  }}
                >
                  Alle Systeme anzeigen
                </Button>
              )}
            </Box>
          ) : (
            <>
              <TableContainer sx={{ display: { xs: "none", md: "block" } }}>
                <Table aria-label="Patchstatus der Hosts" size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell sx={{ width: "22%" }}>System</TableCell>
                      <TableCell sx={{ width: "28%" }}>Handlungsbedarf</TableCell>
                      <TableCell>Systemupdates</TableCell>
                      <TableCell>Software</TableCell>
                      <TableCell>Nächster Schritt</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rows.map((host) => (
                      <TableRow
                        hover
                        key={host.asset_id}
                        data-testid={`host-row-${host.asset_id}`}
                        sx={{ verticalAlign: "top", "& td": { py: 2 } }}
                      >
                        <TableCell>{hostIdentity(host)}</TableCell>
                        <TableCell>{hostResult(host)}</TableCell>
                        <TableCell>
                          <CompactSystemStatus host={host} />
                        </TableCell>
                        <TableCell>
                          <CompactSoftwareStatus host={host} />
                        </TableCell>
                        <TableCell>{actionButton(host)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              <Stack spacing={1.5} sx={{ display: { md: "none" } }}>
                {rows.map((host) => (
                  <Paper
                    variant="outlined"
                    key={host.asset_id}
                    data-testid={`host-mobile-${host.asset_id}`}
                    sx={{ p: 2 }}
                  >
                    <Stack spacing={2}>
                      {hostIdentity(host)}
                      {hostResult(host)}
                      <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2 }}>
                        <Box>
                          <Typography variant="overline">Systemupdates</Typography>
                          <CompactSystemStatus host={host} />
                        </Box>
                        <Box>
                          <Typography variant="overline">Software</Typography>
                          <CompactSoftwareStatus host={host} />
                        </Box>
                      </Box>
                      {actionButton(host)}
                    </Stack>
                  </Paper>
                ))}
              </Stack>
            </>
          )}
        </Stack>
        <Box
          sx={{
            px: { xs: 2, md: 2.5 },
            py: 1.5,
            borderTop: "1px solid",
            borderColor: "divider",
            bgcolor: "background.default",
          }}
        >
          <Typography variant="caption" color="text.secondary">
            Jedes System zählt in genau einer Gruppe. „Geprüfter Stand“ gilt nur für die geprüfte
            OS-Baseline bzw. Updatequelle und Software-Regeln; ungeprüfte Komponenten bleiben offen.
          </Typography>
        </Box>
      </Paper>
    </Stack>
  );
}
