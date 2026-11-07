import { useEffect, useMemo, useState } from "react";
import { Link as RouterLink } from "react-router-dom";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
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

interface ObservedService {
  port: number;
  protocol: "tcp";
  state: "open";
  service: string | null;
  product: string | null;
  version: string | null;
  audit_coverage: string | null;
}

type InventoryStatus = "not_inventoried" | "pending" | "failed" | "inventoried" | "partial";

interface DiscoveredDevice {
  asset_id: number;
  ip_address: string;
  last_seen: string;
  scan_id: number;
  discovery_status: string;
  services: ObservedService[];
  services_total: number;
  services_truncated: boolean;
  inventory_status: InventoryStatus;
  host_audit_id: number | null;
  inventory_collected_at: string | null;
}

interface DiscoveredDevices {
  customer_id: number;
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
  items: DiscoveredDevice[];
  limitations: string[];
}

const pageSize = 200;
const inventoryNames: Record<InventoryStatus, string> = {
  not_inventoried: "Inventur fehlt",
  pending: "Inventur ausstehend / läuft",
  failed: "Inventur fehlgeschlagen",
  inventoried: "Inventur vorhanden",
  partial: "Inventur unvollständig",
};

function date(value: string | null) {
  if (!value) return "Nicht verfügbar";
  const parsed = new Date(value);
  return Number.isNaN(parsed.valueOf()) ? "Nicht verfügbar" : parsed.toLocaleString("de-DE");
}

function ServiceLabel({ service }: { service: ObservedService }) {
  const reportedProduct = [service.product, service.version].filter(Boolean).join(" ");
  return (
    <Box>
      <Typography variant="body2">
        {service.port}/{service.protocol}
        {service.service ? ` · ${service.service}` : ""}
      </Typography>
      {reportedProduct && (
        <Typography variant="caption" color="text.secondary" sx={{ overflowWrap: "anywhere" }}>
          Gemeldet: {reportedProduct}
        </Typography>
      )}
    </Box>
  );
}

export function DiscoveredDevicesPanel({
  token,
  customerId,
  onInventory,
}: {
  token: string;
  customerId: number;
  onInventory: (target: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const [cursor, setCursor] = useState({ customerId, offset: 0 });
  const offset = cursor.customerId === customerId ? cursor.offset : 0;
  const [revision, setRevision] = useState(0);
  const context = useMemo(
    () => ({ token, customerId, offset, revision }),
    [token, customerId, offset, revision],
  );
  const [response, setResponse] = useState<{
    context: object;
    data?: DiscoveredDevices;
    error?: string;
  }>();
  const [selectedDevice, setSelectedDevice] = useState<{
    context: object;
    device: DiscoveredDevice;
  }>();
  const current = response?.context === context ? response : undefined;
  const detail = selectedDevice?.context === context ? selectedDevice.device : undefined;
  const data = current?.data;
  const validCustomer = Number.isSafeInteger(customerId) && customerId > 0;

  useEffect(() => {
    setCursor({ customerId, offset: 0 });
  }, [customerId]);

  useEffect(() => {
    setResponse(undefined);
    setSelectedDevice(undefined);
    if (!expanded || !validCustomer) return;
    const controller = new AbortController();
    void auditRequest<DiscoveredDevices>(
      token,
      `/discovered?customer_id=${customerId}&limit=${pageSize}&offset=${offset}`,
      undefined,
      controller.signal,
    )
      .then((result) => {
        if (!controller.signal.aborted) {
          if (result.customer_id !== customerId || result.offset !== offset)
            throw new Error("Die Geräteantwort passt nicht zum gewählten Kunden oder zur Seite.");
          setResponse({ context, data: result });
        }
      })
      .catch((failure) => {
        if (!controller.signal.aborted)
          setResponse({
            context,
            error:
              failure instanceof Error
                ? failure.message
                : "Die erkannten Geräte konnten nicht geladen werden.",
          });
      });
    return () => controller.abort();
  }, [token, customerId, offset, context, expanded, validCustomer]);

  return (
    <Accordion
      expanded={expanded}
      onChange={(_, open) => setExpanded(open)}
      data-testid="discovered-devices-panel"
    >
      <AccordionSummary expandIcon={<ExpandMoreIcon />}>
        <Typography component="h2" variant="subtitle1">
          Erkannte Geräte
          {data ? ` · ${data.total.toLocaleString("de-DE")}` : ""}
        </Typography>
      </AccordionSummary>
      <AccordionDetails>
        <Stack spacing={2}>
          <Typography variant="body2" color="text.secondary">
            Geräte mit beobachteten offenen TCP-Diensten aus den Netzwerkscans dieses Kunden.
            Gemeldete Produkte bestätigen kein Betriebssystem und keinen Patchstatus.
          </Typography>
          {!validCustomer && <Alert severity="warning">Bitte einen Kunden auswählen.</Alert>}
          {current?.error && <Alert severity="error">{current.error}</Alert>}
          {!current && validCustomer && (
            <Typography role="status" color="text.secondary">
              Erkannte Geräte werden geladen …
            </Typography>
          )}
          {data && data.items.length === 0 && (
            <Alert severity="info">
              {data.total === 0
                ? "Für diesen Kunden liegen noch keine positiven Netzwerkbeobachtungen vor. Ein Netzwerkscan kann erreichbare TCP-Dienste erfassen."
                : "Auf dieser Seite liegen keine Geräte vor. Zurückblättern oder die Liste aktualisieren."}
            </Alert>
          )}
          {data && data.items.length > 0 && (
            <TableContainer sx={{ maxHeight: 560 }}>
              <Table
                size="small"
                stickyHeader
                aria-label="Erkannte Netzwerkgeräte"
                sx={{ minWidth: 760 }}
              >
                <TableHead>
                  <TableRow>
                    <TableCell>Gerät / Scanzeit</TableCell>
                    <TableCell>Beobachtete offene TCP-Dienste</TableCell>
                    <TableCell>Authentifizierte Inventur</TableCell>
                    <TableCell>Aktion</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.items.map((device) => (
                    <TableRow key={device.asset_id}>
                      <TableCell component="th" scope="row" sx={{ minWidth: 175 }}>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
                          {device.ip_address}
                        </Typography>
                        <Typography
                          variant="caption"
                          color="text.secondary"
                          sx={{ display: "block" }}
                        >
                          Scan vom {date(device.last_seen)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                          Netzwerkscan #{device.scan_id}
                        </Typography>
                      </TableCell>
                      <TableCell sx={{ maxWidth: 360 }}>
                        <Stack spacing={0.75}>
                          {device.services.slice(0, 2).map((service) => (
                            <ServiceLabel
                              key={`${service.protocol}:${service.port}`}
                              service={service}
                            />
                          ))}
                          {(device.services.length > 2 || device.services_truncated) && (
                            <Button
                              size="small"
                              sx={{ alignSelf: "flex-start" }}
                              onClick={() => setSelectedDevice({ context, device })}
                              aria-label={`Dienste anzeigen für ${device.ip_address}`}
                            >
                              {device.services_total} Dienste · Details
                            </Button>
                          )}
                        </Stack>
                      </TableCell>
                      <TableCell>
                        <Chip
                          size="small"
                          variant="outlined"
                          color={
                            device.inventory_status === "failed"
                              ? "error"
                              : device.inventory_status === "not_inventoried" ||
                                  device.inventory_status === "partial"
                                ? "warning"
                                : "default"
                          }
                          label={inventoryNames[device.inventory_status]}
                        />
                        {device.inventory_collected_at && (
                          <Typography
                            variant="caption"
                            color="text.secondary"
                            sx={{ display: "block" }}
                          >
                            Erfasst: {date(device.inventory_collected_at)}
                          </Typography>
                        )}
                      </TableCell>
                      <TableCell>
                        <Button
                          onClick={() => onInventory(device.ip_address)}
                          aria-label={`Inventur vorbereiten für ${device.ip_address}`}
                        >
                          Inventur vorbereiten
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
          {data && data.total > 0 && (
            <Stack direction="row" spacing={1} sx={{ alignItems: "center", flexWrap: "wrap" }}>
              <Typography variant="body2" color="text.secondary" sx={{ mr: "auto" }}>
                {data.items.length > 0 ? offset + 1 : 0}–{offset + data.items.length} von{" "}
                {data.total.toLocaleString("de-DE")} Geräten
              </Typography>
              <Button
                disabled={offset === 0}
                onClick={() => setCursor({ customerId, offset: Math.max(0, offset - pageSize) })}
              >
                Zurück
              </Button>
              <Button
                disabled={!data.has_more}
                onClick={() => setCursor({ customerId, offset: offset + pageSize })}
              >
                Weiter
              </Button>
            </Stack>
          )}
          {data?.limitations && data.limitations.length > 0 && (
            <Typography variant="caption" color="text.secondary">
              {data.limitations.join(" ")}
            </Typography>
          )}
          <Typography variant="body2" color="text.secondary">
            „Inventur vorbereiten“ trägt nur die Ziel-IP ein. Zugangsdaten und Prüfung wählst du
            anschließend selbst aus.
          </Typography>
          <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap" }}>
            <Button
              disabled={!validCustomer}
              onClick={() => {
                setCursor({ customerId, offset: 0 });
                setRevision((value) => value + 1);
              }}
            >
              Geräteliste aktualisieren
            </Button>
            {validCustomer && (
              <Button component={RouterLink} to={`/networks?customer_id=${customerId}`}>
                Netzwerk öffnen
              </Button>
            )}
          </Stack>
        </Stack>
      </AccordionDetails>
      <Dialog open={!!detail} onClose={() => setSelectedDevice(undefined)} fullWidth maxWidth="sm">
        <DialogTitle>Beobachtete TCP-Dienste · {detail?.ip_address}</DialogTitle>
        <DialogContent>
          {detail && (
            <Stack spacing={2}>
              <Typography variant="body2" color="text.secondary">
                Gemeldete Dienst- und Produktangaben aus Netzwerkscan #{detail.scan_id}, Scan vom{" "}
                {date(detail.last_seen)}. Die Scanzeit ist kein genauer Zeitpunkt der einzelnen
                Hostbeobachtung.
              </Typography>
              {detail.services.map((service) => (
                <ServiceLabel key={`${service.protocol}:${service.port}`} service={service} />
              ))}
              {detail.services_truncated && (
                <Alert severity="info">
                  {detail.services.length} von {detail.services_total} Diensten werden angezeigt.
                  Weitere Details stehen beim Netzwerkscan.
                </Alert>
              )}
            </Stack>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelectedDevice(undefined)}>Schließen</Button>
        </DialogActions>
      </Dialog>
    </Accordion>
  );
}
