import {
  Alert,
  Box,
  Chip,
  Link,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { WindowsUpdateAssessmentResult, WindowsUpdateClassification } from "./api";
import { date } from "./overview-state";

const groups: { key: WindowsUpdateClassification; label: string }[] = [
  { key: "security", label: "Sicherheitsupdates" },
  { key: "quality", label: "Qualitätsupdates" },
  { key: "feature", label: "Funktionsupdates / Upgrades" },
  { key: "definition", label: "Definitionsupdates" },
  { key: "other", label: "Weitere / unklare Klassifikation" },
];

export function WindowsUpdateReport({ result }: { result: WindowsUpdateAssessmentResult }) {
  const query = result.windows_updates;
  return (
    <Stack spacing={2} data-testid="windows-update-report">
      <Alert severity="info">
        Angebote der am Gerät konfigurierten Windows Update- oder WSUS-Quelle. Freigaben,
        Zurückstellungen und Schutzsperren können das Angebot begrenzen. Keine Updateangebote
        bedeuten keine vollständige Patchfreigabe. Diese Abfrage installiert keine Updates.
      </Alert>
      {!query ? (
        <Typography>
          Unter „Windows-Updates abfragen“ zuerst eine neue Onlineabfrage starten. Anschließend die
          gespeicherte Evidenz bewerten.
        </Typography>
      ) : (
        <>
          <Box>
            <Typography sx={{ fontWeight: 700 }}>
              Konfigurierte Windows Update-/WSUS-Quelle
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Onlineabfrage: {date(query.queried_at)} · maximal 24 Stunden gültig · Quellenwahl:
              Gerätestandard
            </Typography>
            <Typography variant="body2" color="text.secondary">
              {query.total} Angebote gemeldet · {query.items.length} im Bericht gespeichert
            </Typography>
          </Box>
          <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: "wrap" }}>
            {groups.map((group) => (
              <Chip
                key={group.key}
                variant="outlined"
                label={`${group.label}: ${query.summary?.[group.key] ?? 0}`}
              />
            ))}
          </Stack>
          <Typography variant="body2">
            {query.summary?.actionable ?? 0} nicht optionale Sicherheits-/Qualitätsangebote zur
            Prüfung · {query.summary?.optional ?? 0} optionale Angebote ·{" "}
            {query.summary?.optional_unknown ?? 0} ohne eindeutige Optionalitätsangabe
          </Typography>
          <Alert severity={query.reboot_required === true ? "warning" : "info"}>
            {query.reboot_required === true
              ? "Das Gerät meldet einen ausstehenden Neustart. Die Abfrage hat keinen Neustart ausgelöst."
              : query.reboot_required === false
                ? "Das Gerät meldet keinen ausstehenden Neustart. Dies ist unabhängig von angebotenen Updates."
                : "Der Neustartstatus konnte nicht bestimmt werden."}
          </Alert>
          {(query.status !== "complete" || query.items_truncated) && (
            <Alert severity="warning">
              Diese Abfrage ist unvollständig. Angezeigte Angebote sind Teilergebnisse; fehlende
              Angebote lassen keine Aussage zum Patchstand zu.
            </Alert>
          )}
          {query.items.length > 0 && (
            <TableContainer>
              <Table size="small" aria-label="Angebotene Windows-Updates">
                <TableHead>
                  <TableRow>
                    <TableCell>Update / KB</TableCell>
                    <TableCell>Klassifikation</TableCell>
                    <TableCell>Prüfhinweis</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {query.items.map((offer) => (
                    <TableRow key={`${offer.update_id}:${offer.revision}`}>
                      <TableCell sx={{ overflowWrap: "anywhere" }}>
                        <Typography variant="body2">{offer.title}</Typography>
                        <Stack direction="row" useFlexGap sx={{ gap: 1, flexWrap: "wrap" }}>
                          {offer.kbs.map((kb) =>
                            /^KB\d+$/.test(kb) ? (
                              <Link
                                key={kb}
                                href={`https://support.microsoft.com/help/${kb.slice(2)}`}
                                target="_blank"
                                rel="noopener noreferrer"
                              >
                                {kb}
                              </Link>
                            ) : (
                              <Typography key={kb} variant="caption">
                                {kb}
                              </Typography>
                            ),
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        {groups.find((group) => group.key === offer.classification)?.label ??
                          "Unklar"}
                      </TableCell>
                      <TableCell>
                        {offer.is_optional === true
                          ? "Optional · separat entscheiden"
                          : offer.actionable
                            ? "Sicherheits-/Qualitätsangebot prüfen"
                            : "Angebot prüfen · keine pauschale Patchpflicht"}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
          <Typography variant="caption" color="text.secondary">
            Klassifikation anhand stabiler Microsoft-Kategorie-IDs. Ausgeblendete Updates, Treiber,
            ersetzte Updates, CVE-Anwendbarkeit, ESU-Berechtigung und Software außerhalb der
            konfigurierten Quelle sind nicht bewertet.
          </Typography>
        </>
      )}
    </Stack>
  );
}
