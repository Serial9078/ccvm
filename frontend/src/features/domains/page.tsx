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
import { useCustomers } from "../customers/hooks";
import { useCreateDomain, useDomains } from "./hooks";

export function Domains() {
  const { data: domains = [], isLoading, error } = useDomains();
  const { data: customers = [] } = useCustomers();
  const createDomain = useCreateDomain();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    customer_id: "",
    name: "",
    description: "",
  });

  const columns: GridColDef[] = [
    { field: "name", headerName: "Domain", flex: 1.5 },
    { field: "description", headerName: "Description", flex: 2 },
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

  const saveDomain = async () => {
    await createDomain.mutateAsync({
      customer_id: Number(form.customer_id),
      name: form.name,
      description: form.description || undefined,
    });

    setForm({ customer_id: "", name: "", description: "" });
    setOpen(false);
  };

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h4">Domains</Typography>
        <Button variant="contained" onClick={() => setOpen(true)}>
          New Domain
        </Button>
      </Box>

      <Box sx={{ height: 560, width: "100%" }}>
        <DataGrid
          rows={domains}
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
        <DialogTitle>New Domain</DialogTitle>
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
              label="Domain"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="example.com"
              required
            />

            <TextField
              label="Description"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              multiline
              minRows={3}
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={saveDomain}
            disabled={!form.customer_id || !form.name || createDomain.isPending}
          >
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
