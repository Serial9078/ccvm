import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  MenuItem,
  TextField,
  Typography,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useState } from "react";
import { useAssets, useCreateAsset } from "./hooks";
import { useCustomers } from "../customers/hooks";

export function Assets() {
  const { data: assets = [], isLoading, error } = useAssets();
  const { data: customers = [] } = useCustomers();
  const createAsset = useCreateAsset();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    customer_id: "",
    name: "",
    target: "",
    hostname: "",
    fqdn: "",
    ip_address: "",
    type: "url",
    exposure: "external",
    environment: "production",
    criticality: "medium",
    owner: "",
    tags: "",
    description: "",
  });

  const columns: GridColDef[] = [
    { field: "name", headerName: "Name", flex: 1 },
    { field: "target", headerName: "Target", flex: 1.5 },
    { field: "ip_address", headerName: "IP", flex: 1 },
    { field: "type", headerName: "Type", flex: 1 },
    { field: "environment", headerName: "Environment", flex: 1 },
    { field: "criticality", headerName: "Criticality", flex: 1 },
    { field: "exposure", headerName: "Exposure", flex: 1 },
    {
      field: "customer_id",
      headerName: "Customer",
      flex: 1,
      valueGetter: (_value, row) => {
        const customer = customers.find((c) => c.id === row.customer_id);
        return customer?.name ?? row.customer_id;
      },
    },
  ];

  const saveAsset = async () => {
    await createAsset.mutateAsync({
      customer_id: Number(form.customer_id),
      name: form.name || undefined,
      target: form.target,
      hostname: form.hostname || undefined,
      fqdn: form.fqdn || undefined,
      ip_address: form.ip_address || undefined,
      type: form.type,
      exposure: form.exposure,
      environment: form.environment,
      criticality: form.criticality,
      owner: form.owner || undefined,
      tags: form.tags || undefined,
      description: form.description || undefined,
    });

    setForm({
      customer_id: "",
      name: "",
      target: "",
      hostname: "",
      fqdn: "",
      ip_address: "",
      type: "url",
      exposure: "external",
      environment: "production",
      criticality: "medium",
      owner: "",
      tags: "",
      description: "",
    });
    setOpen(false);
  };

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h4">Assets</Typography>
        <Button variant="contained" onClick={() => setOpen(true)}>
          New Asset
        </Button>
      </Box>

      <Box sx={{ height: 560, width: "100%" }}>
        <DataGrid
          rows={assets}
          columns={columns}
          loading={isLoading}
          getRowId={(row) => row.id}
          pageSizeOptions={[10, 25, 50]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 10, page: 0 },
            },
          }}
        />
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="md">
        <DialogTitle>New Asset</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 2, mt: 1 }}>
            <TextField
              select
              label="Customer"
              value={form.customer_id}
              onChange={(e) => setForm({ ...form, customer_id: e.target.value })}
              required
            >
              {customers.map((customer) => (
                <MenuItem key={customer.uuid} value={customer.id}>
                  {customer.name}
                </MenuItem>
              ))}
            </TextField>

            <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />

            <TextField
              label="Target"
              value={form.target}
              onChange={(e) => setForm({ ...form, target: e.target.value })}
              required
            />

            <TextField label="Hostname" value={form.hostname} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
            <TextField label="FQDN" value={form.fqdn} onChange={(e) => setForm({ ...form, fqdn: e.target.value })} />
            <TextField label="IP Address" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} />

            <TextField select label="Type" value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
              <MenuItem value="url">URL</MenuItem>
              <MenuItem value="fqdn">FQDN</MenuItem>
              <MenuItem value="ip">IP</MenuItem>
              <MenuItem value="network">Network</MenuItem>
              <MenuItem value="server">Server</MenuItem>
              <MenuItem value="windows_server">Windows Server</MenuItem>
              <MenuItem value="linux_server">Linux Server</MenuItem>
              <MenuItem value="network_device">Network Device</MenuItem>
              <MenuItem value="firewall">Firewall</MenuItem>
              <MenuItem value="vmware">VMware</MenuItem>
            </TextField>

            <TextField select label="Exposure" value={form.exposure} onChange={(e) => setForm({ ...form, exposure: e.target.value })}>
              <MenuItem value="external">External</MenuItem>
              <MenuItem value="internal">Internal</MenuItem>
            </TextField>

            <TextField select label="Environment" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
              <MenuItem value="production">Production</MenuItem>
              <MenuItem value="staging">Staging</MenuItem>
              <MenuItem value="development">Development</MenuItem>
              <MenuItem value="lab">Lab</MenuItem>
            </TextField>

            <TextField select label="Criticality" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
              <MenuItem value="critical">Critical</MenuItem>
              <MenuItem value="high">High</MenuItem>
              <MenuItem value="medium">Medium</MenuItem>
              <MenuItem value="low">Low</MenuItem>
            </TextField>

            <TextField label="Owner" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} />
            <TextField label="Tags" value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} />

            <TextField
              label="Description"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              multiline
              minRows={3}
              sx={{ gridColumn: "1 / -1" }}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={saveAsset}
            disabled={!form.customer_id || !form.target || createAsset.isPending}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
