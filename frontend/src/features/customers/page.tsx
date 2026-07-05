import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  Typography,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useState } from "react";
import { useCreateCustomer, useCustomers } from "./hooks";

export function Customers() {
  const { data = [], isLoading, error } = useCustomers();
  const createCustomer = useCreateCustomer();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: "",
    company: "",
    city: "",
    contact_email: "",
  });

  const columns: GridColDef[] = [
    { field: "name", headerName: "Name", flex: 1 },
    { field: "company", headerName: "Company", flex: 1.5 },
    { field: "city", headerName: "City", flex: 1 },
    { field: "contact_email", headerName: "Email", flex: 1.5 },
  ];

  const saveCustomer = async () => {
    await createCustomer.mutateAsync(form);
    setForm({ name: "", company: "", city: "", contact_email: "" });
    setOpen(false);
  };

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h4">Customers</Typography>
        <Button variant="contained" onClick={() => setOpen(true)}>
          New Customer
        </Button>
      </Box>

      <Box sx={{ height: 520, width: "100%" }}>
        <DataGrid
          rows={data}
          columns={columns}
          loading={isLoading}
          getRowId={(row) => row.uuid}
          pageSizeOptions={[10, 25, 50]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 10, page: 0 },
            },
          }}
          sx={{
            borderColor: "#1e293b",
            "& .MuiDataGrid-columnHeaders": {
              backgroundColor: "#0f172a",
            },
          }}
        />
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New Customer</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <TextField label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <TextField label="Company" value={form.company} onChange={(e) => setForm({ ...form, company: e.target.value })} />
            <TextField label="City" value={form.city} onChange={(e) => setForm({ ...form, city: e.target.value })} />
            <TextField label="Contact Email" value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={saveCustomer} disabled={!form.name || createCustomer.isPending}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
