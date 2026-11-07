import { useEffect, useMemo, useState } from "react";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Button,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import { auditRequest } from "./api";

type CapabilityStatus = "available" | "limited" | "unavailable";
type StageId =
  | "discovery"
  | "inventory"
  | "configuration"
  | "os_baseline"
  | "software_checks"
  | "offered_updates";

interface CapabilityStage {
  status: CapabilityStatus;
  provider: string | null;
  scope: string;
  prerequisites: string[];
  limitations: string[];
}

interface CapabilityPlatform {
  id: string;
  name: string;
  stages: Record<StageId, CapabilityStage>;
}

interface Capabilities {
  version: string;
  stage_labels: { id: StageId; name: string }[];
  platforms: CapabilityPlatform[];
  limitations: string[];
}

const statusNames: Record<CapabilityStatus, string> = {
  available: "Verfügbar",
  limited: "Begrenzt",
  unavailable: "Nicht verfügbar",
};

export function CapabilitiesPanel({ token }: { token: string }) {
  const [expanded, setExpanded] = useState(false);
  const [revision, setRevision] = useState(0);
  const context = useMemo(() => ({ token, revision }), [token, revision]);
  const [response, setResponse] = useState<{
    context: object;
    data?: Capabilities;
    error?: string;
  }>();
  const [selection, setSelection] = useState<{
    context: object;
    platform: CapabilityPlatform;
    stage: { id: StageId; name: string };
  }>();
  const current = response?.context === context ? response : undefined;
  const detail = selection?.context === context ? selection : undefined;
  const stageDetail = detail?.platform.stages[detail.stage.id];

  useEffect(() => {
    setResponse(undefined);
    setSelection(undefined);
    if (!expanded) return;
    const controller = new AbortController();
    void auditRequest<Capabilities>(token, "/capabilities", undefined, controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setResponse({ context, data });
      })
      .catch((failure) => {
        if (!controller.signal.aborted)
          setResponse({
            context,
            error:
              failure instanceof Error
                ? failure.message
                : "Der Prüfumfang konnte nicht geladen werden.",
          });
      });
    return () => controller.abort();
  }, [token, context, expanded]);

  return (
    <Accordion
      expanded={expanded}
      onChange={(_, open) => setExpanded(open)}
      data-testid="capabilities-panel"
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography component="h2" variant="subtitle1">
          Prüfumfang nach Plattform
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            Diese Übersicht zeigt verfügbare Prüffunktionen. Ob ein einzelner Host geprüft wurde,
            steht in seinem Inventur- und Prüfstatus. Status auswählen, um Umfang und
            Voraussetzungen zu sehen.
          </Typography>
          {current?.error && <Alert severity="error">{current.error}</Alert>}
          {!current && (
            <Typography role="status" color="text.secondary">
              Prüfumfang wird geladen …
            </Typography>
          )}
          {current?.data && (
            <>
              <TableContainer>
                <Table size="small" aria-label="Plattform-Prüfumfang" sx={{ minWidth: 1020 }}>
                  <TableHead>
                    <TableRow>
                      <TableCell>Plattform</TableCell>
                      {current.data.stage_labels.map((stage) => (
                        <TableCell key={stage.id}>{stage.name}</TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {current.data.platforms.map((platform) => (
                      <TableRow key={platform.id}>
                        <TableCell component="th" scope="row">
                          <Typography variant="body2" sx={{ fontWeight: 600 }}>
                            {platform.name}
                          </Typography>
                        </TableCell>
                        {current.data!.stage_labels.map((stage) => {
                          const capability = platform.stages[stage.id];
                          return (
                            <TableCell key={stage.id}>
                              <Chip
                                size="small"
                                variant="outlined"
                                color={capability.status === "limited" ? "warning" : "default"}
                                label={statusNames[capability.status]}
                                aria-label={`${platform.name} · ${stage.name}: ${statusNames[capability.status]}. Prüfumfang anzeigen`}
                                onClick={() => setSelection({ context, platform, stage })}
                              />
                            </TableCell>
                          );
                        })}
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
              {current.data.limitations.length > 0 && (
                <Alert severity="info">
                  <Stack spacing={0.5}>
                    {current.data.limitations.map((limitation, index) => (
                      <Typography key={index} variant="body2">
                        {limitation}
                      </Typography>
                    ))}
                  </Stack>
                </Alert>
              )}
            </>
          )}
          <Button
            sx={{ alignSelf: "flex-start" }}
            onClick={() => setRevision((value) => value + 1)}
          >
            Prüfumfang aktualisieren
          </Button>
        </Stack>
      </AccordionDetails>
      <Dialog open={!!detail} onClose={() => setSelection(undefined)} fullWidth maxWidth="sm">
        <DialogTitle>
          {detail?.platform.name} · {detail?.stage.name}
        </DialogTitle>
        <DialogContent>
          {stageDetail && (
            <Stack spacing={2}>
              <Chip
                sx={{ alignSelf: "flex-start" }}
                variant="outlined"
                color={stageDetail.status === "limited" ? "warning" : "default"}
                label={statusNames[stageDetail.status]}
              />
              <Typography>{stageDetail.scope}</Typography>
              {stageDetail.provider && (
                <Typography variant="body2" color="text.secondary">
                  Prüfquelle: {stageDetail.provider}
                </Typography>
              )}
              {stageDetail.prerequisites.length > 0 && (
                <Stack spacing={0.5}>
                  <Typography variant="subtitle2">Voraussetzungen</Typography>
                  {stageDetail.prerequisites.map((item, index) => (
                    <Typography key={index} variant="body2">
                      {item}
                    </Typography>
                  ))}
                </Stack>
              )}
              {stageDetail.limitations.length > 0 && (
                <Alert severity="info">
                  <Stack spacing={0.5}>
                    {stageDetail.limitations.map((item, index) => (
                      <Typography key={index} variant="body2">
                        {item}
                      </Typography>
                    ))}
                  </Stack>
                </Alert>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelection(undefined)}>Schließen</Button>
        </DialogActions>
      </Dialog>
    </Accordion>
  );
}
