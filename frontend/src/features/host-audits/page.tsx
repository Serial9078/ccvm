import { useEffect, useRef, useState } from "react";
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
import { auditRequest, canUseAuditApi } from "./api";
import type { Credential, HostAudit, InventorySection } from "./api";

const emptyCredential = {
  name: "",
  kind: "ssh_password" as Credential["kind"],
  username: "",
  cidrs: "",
  password: "",
  key: "",
  passphrase: "",
};
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
}: {
  token: string;
  customerId: number;
  lock: () => void;
}) {
  const [credentials, setCredentials] = useState<Credential[]>([]);
  const [runs, setRuns] = useState<HostAudit[]>([]);
  const [form, setForm] = useState(emptyCredential);
  const [createOpen, setCreateOpen] = useState(false);
  const fileGeneration = useRef(0);
  const [credentialId, setCredentialId] = useState("");
  const [target, setTarget] = useState("");
  const [port, setPort] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [detail, setDetail] = useState<HostAudit | null>(null);
  const [revoke, setRevoke] = useState<Credential | null>(null);
  const closeCredential = () => {
    fileGeneration.current++;
    setCreateOpen(false);
    setForm(emptyCredential);
  };
  const selected = credentials.find((c) => c.id === Number(credentialId) && c.enabled);
  const refresh = async (signal?: AbortSignal) => {
    const [creds, audits] = await Promise.all([
      auditRequest<Credential[]>(
        token,
        `/credentials?customer_id=${customerId}`,
        undefined,
        signal,
      ),
      auditRequest<HostAudit[]>(token, `?customer_id=${customerId}`, undefined, signal),
    ]);
    setCredentials(creds);
    setRuns(audits);
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
        ...(selected?.kind.startsWith("ssh_") ? { ssh_fingerprint: fingerprint } : {}),
        mode,
      });
    });
  const valid = Boolean(
    selected &&
    target &&
    (selected.kind === "winrm" || /^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint)),
  );
  return (
    <Stack spacing={3}>
      <Stack direction="row" spacing={2} sx={{ alignItems: "center", flexWrap: "wrap" }}>
        <Chip color="success" variant="outlined" label="Operator access unlocked" />
        <Button onClick={lock}>Lock and clear session</Button>
      </Stack>
      {error && !createOpen && !revoke && <Alert severity="error">{error}</Alert>}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" sx={{ mb: 2 }}>
          Read-only host inventory
        </Typography>
        <Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", md: "1fr 1fr" }, gap: 2 }}>
          <TextField
            select
            label="Credential"
            value={credentialId}
            onChange={(e) => {
              setCredentialId(e.target.value);
              setPort("");
              setFingerprint("");
            }}
          >
            {credentials
              .filter((c) => c.enabled)
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
          <TextField
            label="Port (optional)"
            type="number"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            helperText={
              selected?.kind === "winrm" ? "Default 5986 · HTTPS / NTLM" : "Default 22 · SSH"
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
          <Alert severity="info" sx={{ mt: 2 }}>
            WinRM requires a trusted certificate with the target IP in its subject alternative
            names. Certificate checks cannot be disabled.
          </Alert>
        )}
        <Stack direction="row" spacing={2} useFlexGap sx={{ mt: 2, flexWrap: "wrap" }}>
          <Button disabled={!valid || busy} onClick={() => queue("connection")}>
            Test connection
          </Button>
          <Button variant="contained" disabled={!valid || busy} onClick={() => queue("inventory")}>
            Collect inventory
          </Button>
          <Button
            disabled={busy}
            onClick={() => {
              setForm(emptyCredential);
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
      </Paper>
      <Alert severity="info">
        Linux: OS, kernel and installed dpkg/RPM packages; Python 3 is required. Windows: OS build,
        machine-wide uninstall registry and Get-HotFix. These sources have limited coverage; CVE
        matching, missing-patch assessment and per-user software are not included.
      </Alert>
      {!runs.length && (
        <Typography color="text.secondary">No authenticated runs for this customer yet.</Typography>
      )}
      {runs.map((run) => (
        <Paper key={run.id} sx={{ p: 3 }}>
          <Stack
            direction="row"
            sx={{ justifyContent: "space-between", alignItems: "center", gap: 2 }}
          >
            <Box>
              <Typography variant="h6">
                {run.target}:{run.port}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {run.mode === "connection" ? "Connection test" : "Host inventory"} ·{" "}
                {new Date(run.created_at).toLocaleString()}
              </Typography>
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
            <Button
              disabled={busy}
              onClick={() =>
                action(async () => setDetail(await auditRequest<HostAudit>(token, `/${run.id}`)))
              }
            >
              View evidence
            </Button>
          )}
        </Paper>
      ))}
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
              <MenuItem value="ssh_password">Linux · SSH password</MenuItem>
              <MenuItem value="ssh_key">Linux · SSH private key</MenuItem>
              <MenuItem value="winrm">Windows · WinRM over HTTPS</MenuItem>
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
          {detail?.inventory ? (
            <>
              <Typography variant="h6">{detail.inventory.os.name}</Typography>
              <Typography color="text.secondary">
                Version {detail.inventory.os.version} · Kernel / build {detail.inventory.os.kernel}{" "}
                · {detail.inventory.os.architecture}
              </Typography>
              <Typography>Host: {detail.inventory.os.hostname}</Typography>
              {detail.job.status === "failed" && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  This inventory is incomplete. Available evidence is retained; unavailable sections
                  were not passed.
                </Alert>
              )}
              <Section
                title="Packages"
                section={detail.inventory.packages}
                columns={["name", "version", "architecture"]}
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

export function HostAudits() {
  const { data: customers = [] } = useCustomers();
  const [customer, setCustomer] = useState("");
  const [input, setInput] = useState("");
  const [session, setSession] = useState<{ token: string; customerId: number } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const secure = canUseAuditApi();
  const unlock = async () => {
    setBusy(true);
    setError("");
    try {
      await auditRequest(input, `/credentials?customer_id=${Number(customer)}`);
      setSession({ token: input, customerId: Number(customer) });
      setInput("");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Stack spacing={3}>
      <Box>
        <Typography variant="h4">Authenticated inventory</Typography>
        <Typography color="text.secondary">
          Read operating-system and software evidence through verified SSH or WinRM connections.
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
              onChange={(e) => setCustomer(e.target.value)}
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
