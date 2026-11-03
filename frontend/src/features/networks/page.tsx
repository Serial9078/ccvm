import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link as RouterLink } from "react-router-dom";
import {
  Alert,
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
import {
  cancelNetwork,
  listNetworkScans,
  networkCapabilities,
  networkDetail,
  previewNetwork,
  startNetwork,
} from "./api";
import type { NetworkPreview, NetworkRequest } from "./api";
import { serviceCoverage } from "./coverage";

function failure(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } })?.response?.data?.detail;
  if (Array.isArray(detail))
    return detail
      .map((item) =>
        item && typeof item === "object" && "msg" in item
          ? String(item.msg)
          : "Invalid scan option",
      )
      .join("; ");
  return typeof detail === "string"
    ? detail
    : "The network scan request failed. Check the scanner connection.";
}

export function Networks() {
  const cache = useQueryClient();
  const { data: customers = [] } = useCustomers();
  const scans = useQuery({
    queryKey: ["network-scans"],
    queryFn: listNetworkScans,
    refetchInterval: 5000,
  });
  const capabilities = useQuery({
    queryKey: ["network-capabilities"],
    queryFn: networkCapabilities,
  });
  const [form, setForm] = useState({
    customer: "",
    target: "",
    name: "",
    exclusions: "",
    profile: "standard" as NetworkRequest["profile"],
    ports: "22,80,443,445,3389",
    rate: "100",
    hours: "8",
  });
  const [preview, setPreview] = useState<NetworkPreview | null>(null);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<number | null>(null);
  const detail = useQuery({
    queryKey: ["network-detail", selected],
    queryFn: () => networkDetail(selected!),
    enabled: selected !== null,
    refetchInterval: 5000,
  });
  const invalidate = () => {
    for (const key of [
      "network-scans",
      "network-detail",
      "pipelines",
      "jobs",
      "assets",
      "hosts",
      "ports",
      "findings",
    ])
      cache.invalidateQueries({ queryKey: [key] });
  };
  const start = useMutation({
    mutationFn: startNetwork,
    onSuccess: () => {
      setError("");
      invalidate();
    },
    onError: (e) => setError(failure(e)),
  });
  const scope = useMutation({
    mutationFn: previewNetwork,
    onSuccess: (value) => {
      setPreview(value);
      setError("");
    },
    onError: (e) => {
      setPreview(null);
      setError(failure(e));
    },
  });
  const cancel = useMutation({
    mutationFn: cancelNetwork,
    onSuccess: invalidate,
    onError: (e) => setError(failure(e)),
  });
  const payload = (): NetworkRequest => ({
    customer_id: Number(form.customer),
    target: form.target,
    name: form.name || undefined,
    exclusions: form.exclusions.split(/[\s,]+/).filter(Boolean),
    profile: form.profile,
    ports: form.profile === "custom" ? form.ports : undefined,
    rate: Number(form.rate),
    timeout_seconds: Math.round(Number(form.hours) * 3600),
  });
  const change = (key: keyof typeof form, value: string) => {
    setForm((previous) => ({ ...previous, [key]: value }));
    setPreview(null);
  };
  const disabled = !capabilities.data?.enabled || !form.customer || !form.target || start.isPending;

  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4">Network scans</Typography>
        <Typography color="text.secondary">
          Discover TCP services in IP ranges and verify SSH, TLS, SMB and RDP configuration.
        </Typography>
      </Box>
      {capabilities.error && <Alert severity="error">{failure(capabilities.error)}</Alert>}
      {capabilities.data && !capabilities.data.enabled && (
        <Alert severity="info">
          Network scanning is not enabled on this scanner. Configure its allowed network ranges
          before starting a scan.
        </Alert>
      )}
      {capabilities.data?.enabled && (
        <Box>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Scanner networks · maximum {capabilities.data.max_addresses.toLocaleString()} addresses
            per run
          </Typography>
          <Stack direction="row" useFlexGap sx={{ flexWrap: "wrap" }} spacing={1}>
            {capabilities.data.allowed_cidrs.map((value) => (
              <Chip key={value} label={value} size="small" />
            ))}
            <Chip label="TCP · unauthenticated" size="small" variant="outlined" />
          </Stack>
        </Box>
      )}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          New network scan
        </Typography>
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 2 }}>
          <TextField
            select
            label="Customer"
            value={form.customer}
            onChange={(e) => change("customer", e.target.value)}
            required
          >
            {customers.map((customer) => (
              <MenuItem key={customer.id} value={String(customer.id)}>
                {customer.name}
              </MenuItem>
            ))}
          </TextField>
          <TextField
            label="Network or IP"
            placeholder="192.168.50.0/24"
            value={form.target}
            onChange={(e) => change("target", e.target.value)}
            required
          />
          <TextField
            label="Name (optional)"
            value={form.name}
            onChange={(e) => change("name", e.target.value)}
          />
          <TextField
            select
            label="TCP port profile"
            value={form.profile}
            onChange={(e) => change("profile", e.target.value)}
          >
            <MenuItem value="fast">Fast · top 100 ports</MenuItem>
            <MenuItem value="standard">Standard · top 1,000 ports</MenuItem>
            <MenuItem value="full">Full · all 65,535 TCP ports</MenuItem>
            <MenuItem value="custom">Custom ports</MenuItem>
          </TextField>
          {form.profile === "custom" && (
            <TextField
              label="TCP ports"
              value={form.ports}
              onChange={(e) => change("ports", e.target.value)}
              helperText="For example 22,80,443,445,3389 or 8000-8100"
            />
          )}
          <TextField
            label="Excluded IPs or CIDRs"
            multiline
            minRows={2}
            value={form.exclusions}
            onChange={(e) => change("exclusions", e.target.value)}
            helperText="Separate addresses or networks with commas or new lines."
          />
          <TextField
            label="Maximum portscan probes per second"
            type="number"
            value={form.rate}
            onChange={(e) => change("rate", e.target.value)}
          />
          <TextField
            label="Time budget per stage (hours)"
            type="number"
            value={form.hours}
            onChange={(e) => change("hours", e.target.value)}
          />
        </Box>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          The audit checks observed protocol settings. Installed patch levels and credentialed
          operating-system checks are not included.
        </Typography>
        {preview && (
          <Alert severity="info" sx={{ mt: 2 }}>
            Scope: {preview.target} · {preview.address_count.toLocaleString()} addresses ·{" "}
            {preview.ports_per_host.toLocaleString()} TCP ports per address. Portscan minimum:{" "}
            {Math.ceil(preview.minimum_portscan_seconds / 60)} minutes; service detection and audits
            take additional time.
            <Typography variant="body2">Sample: {preview.sample.join(", ")}</Typography>
          </Alert>
        )}
        <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
          <Button
            disabled={Boolean(disabled) || scope.isPending}
            onClick={() => scope.mutate(payload())}
          >
            Preview scope
          </Button>
          <Button
            variant="contained"
            disabled={Boolean(disabled)}
            onClick={() => start.mutate(payload())}
          >
            {start.isPending ? "Queuing…" : "Start network scan"}
          </Button>
        </Stack>
      </Paper>
      {error && <Alert severity="error">{error}</Alert>}
      {scans.error && <Alert severity="error">{failure(scans.error)}</Alert>}
      {scans.isLoading && <LinearProgress />}
      {!scans.isLoading && !scans.data?.length && (
        <Typography color="text.secondary">No network scans yet.</Typography>
      )}
      {scans.data?.map((scan) => (
        <Paper key={scan.id} sx={{ p: 3 }}>
          <Stack direction="row" sx={{ justifyContent: "space-between", gap: 2, flexWrap: "wrap" }}>
            <Box>
              <Typography variant="h6">{scan.target}</Typography>
              <Typography variant="body2" color="text.secondary">
                {customers.find((c) => c.id === scan.customer_id)?.name ??
                  `Customer #${scan.customer_id}`}{" "}
                · {new Date(scan.created_at).toLocaleString()}
              </Typography>
            </Box>
            <Chip
              label={scan.status.toUpperCase()}
              color={
                scan.status === "finished"
                  ? "success"
                  : scan.status === "failed"
                    ? "error"
                    : "default"
              }
            />
          </Stack>
          <Typography sx={{ my: 2 }}>
            {scan.address_count} addresses · {scan.open_services} open services ·{" "}
            {scan.findings_created} new findings · {scan.findings_updated} updated
          </Typography>
          <Stack spacing={2}>
            {scan.jobs.map((job) => (
              <Box key={job.id}>
                <Typography variant="body2">
                  {job.plugin === "networkdiscovery"
                    ? "Host & service discovery"
                    : "Protocol configuration audit"}{" "}
                  · {job.status} · {job.progress}%
                </Typography>
                <LinearProgress
                  variant="determinate"
                  value={job.progress}
                  color={job.status === "failed" ? "error" : "primary"}
                  sx={{ my: 1 }}
                />
                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{ overflowWrap: "anywhere" }}
                >
                  {job.message}
                </Typography>
              </Box>
            ))}
          </Stack>
          <Stack direction="row" spacing={2} sx={{ mt: 2 }}>
            <Button onClick={() => setSelected(scan.id)}>Observed services</Button>
            <Button component={RouterLink} to="/findings">
              All findings
            </Button>
            {["queued", "running", "cancelling"].includes(scan.status) && (
              <Button
                color="warning"
                disabled={scan.cancel_requested || cancel.isPending}
                onClick={() => cancel.mutate(scan.id)}
              >
                Cancel scan
              </Button>
            )}
          </Stack>
        </Paper>
      ))}
      <Dialog open={selected !== null} onClose={() => setSelected(null)} maxWidth="lg" fullWidth>
        <DialogTitle>Observed network services · {detail.data?.target}</DialogTitle>
        <DialogContent>
          {detail.isLoading && <LinearProgress />}
          {detail.error && <Alert severity="error">{failure(detail.error)}</Alert>}
          {detail.data && (
            <Box sx={{ mb: 3 }}>
              <Typography variant="h6">Protocol audit coverage</Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                Counts refer to open service endpoints. Completed means evidence was collected;
                findings are shown separately. Host references share an audit performed on another
                port.
              </Typography>
              <Table size="small" aria-label="Protocol audit coverage">
                <TableHead>
                  <TableRow>
                    {[
                      "Service",
                      "Endpoints",
                      "Completed",
                      "Host reference",
                      "Unavailable",
                      "No rule",
                      "Pending",
                      "Not run",
                    ].map((label) => (
                      <TableCell key={label}>{label}</TableCell>
                    ))}
                  </TableRow>
                </TableHead>
                <TableBody>
                  {serviceCoverage(detail.data).map((row) => (
                    <TableRow key={row.label}>
                      <TableCell>{row.label}</TableCell>
                      {[
                        row.total,
                        row.completed,
                        row.shared,
                        row.unavailable,
                        row.noRule,
                        row.pending,
                        row.notRun,
                      ].map((value, index) => (
                        <TableCell key={index}>{value}</TableCell>
                      ))}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Box>
          )}
          <Table size="small">
            <TableHead>
              <TableRow>
                {["IP", "Port", "Service", "Product / version", "CPE", "Checks"].map((label) => (
                  <TableCell key={label}>{label}</TableCell>
                ))}
              </TableRow>
            </TableHead>
            <TableBody>
              {detail.data?.observations.flatMap((host) =>
                host.services.map((service) => (
                  <TableRow key={`${host.id}-${service.port}`}>
                    <TableCell>{host.ip_address}</TableCell>
                    <TableCell>{service.port}/tcp</TableCell>
                    <TableCell>
                      {service.tunnel ? `${service.tunnel}/` : ""}
                      {service.service ?? "unknown"}
                      <Typography
                        variant="caption"
                        color="text.secondary"
                        sx={{ display: "block" }}
                      >
                        {service.method === "probed" ? "Active service probe" : "Port lookup"}
                      </Typography>
                    </TableCell>
                    <TableCell sx={{ maxWidth: 250, overflowWrap: "anywhere" }}>
                      {service.product} {service.version}
                    </TableCell>
                    <TableCell sx={{ maxWidth: 250, overflowWrap: "anywhere" }}>
                      {service.cpe.join(", ") || "—"}
                    </TableCell>
                    <TableCell>
                      {service.checks.length
                        ? service.checks.map((check) => (
                            <details key={check.check}>
                              <summary>
                                {check.check}: {check.status}
                              </summary>
                              <Typography
                                component="pre"
                                variant="body2"
                                sx={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}
                              >
                                {check.output || "No enumeration details"}
                              </Typography>
                            </details>
                          ))
                        : service.audit_coverage === "no_rule"
                          ? "No applicable protocol audit"
                          : "No audit evidence yet"}
                    </TableCell>
                  </TableRow>
                )),
              )}
            </TableBody>
          </Table>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSelected(null)}>Close</Button>
        </DialogActions>
      </Dialog>
    </Stack>
  );
}
