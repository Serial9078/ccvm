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
import { useAssets, useCreateAsset } from "../hooks/useAssets";
import { useCustomers } from "../hooks/useCustomers";

export function Assets() {
  const { data: assets = [], isLoading, error } = useAssets();
  const { data: customers = [] } = useCustomers();
  const createAsset = useCreateAsset();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    customer_id: "",
    target: "",
    type: "url",
    exposure: "external",
  });

  const columns: GridColDef[] = [
    { field: "target", headerName: "Target", flex: 1.6 },
    { field: "type", headerName: "Type", flex: 1 },
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
      target: form.target,
      type: form.type,
      exposure: form.exposure,
    });

    setForm({ customer_id: "", target: "", type: "url", exposure: "external" });
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

      <Box sx={{ height: 520, width: "100%" }}>
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

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New Asset</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
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

            <TextField
              label="Target"
              value={form.target}
              onChange={(e) => setForm({ ...form, target: e.target.value })}
              placeholder="https://example.com oder 192.168.1.10"
              required
            />

            <TextField
              select
              label="Type"
              value={form.type}
              onChange={(e) => setForm({ ...form, type: e.target.value })}
            >
              <MenuItem value="url">URL</MenuItem>
              <MenuItem value="fqdn">FQDN</MenuItem>
              <MenuItem value="ip">IP</MenuItem>
              <MenuItem value="network">Network</MenuItem>
              <MenuItem value="server">Server</MenuItem>
              <MenuItem value="network_device">Network Device</MenuItem>
            </TextField>

            <TextField
              select
              label="Exposure"
              value={form.exposure}
              onChange={(e) => setForm({ ...form, exposure: e.target.value })}
            >
              <MenuItem value="external">External</MenuItem>
              <MenuItem value="internal">Internal</MenuItem>
            </TextField>
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
