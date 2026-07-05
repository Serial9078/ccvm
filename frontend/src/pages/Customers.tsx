import {
  Box,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  TextField,
  Typography,
} from "@mui/material";
import { useState } from "react";
import { useCreateCustomer, useCustomers } from "../hooks/useCustomers";

export function Customers() {
  const { data, isLoading, error } = useCustomers();
  const createCustomer = useCreateCustomer();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    name: "",
    company: "",
    city: "",
    contact_email: "",
  });

  const saveCustomer = async () => {
    await createCustomer.mutateAsync(form);
    setForm({ name: "", company: "", city: "", contact_email: "" });
    setOpen(false);
  };

  if (isLoading) return <Typography>Lade Kunden...</Typography>;
  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h4">Customers</Typography>
        <Button variant="contained" onClick={() => setOpen(true)}>
          New Customer
        </Button>
      </Box>

      {data?.map((customer) => (
        <Card key={customer.uuid} sx={{ mb: 2 }}>
          <CardContent>
            <Typography variant="h6">{customer.name}</Typography>
            <Typography color="text.secondary">{customer.company}</Typography>
            <Typography color="text.secondary">{customer.city}</Typography>
            <Typography color="text.secondary">{customer.contact_email}</Typography>
          </CardContent>
        </Card>
      ))}

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New Customer</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <TextField
              label="Name"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
            <TextField
              label="Company"
              value={form.company}
              onChange={(e) => setForm({ ...form, company: e.target.value })}
            />
            <TextField
              label="City"
              value={form.city}
              onChange={(e) => setForm({ ...form, city: e.target.value })}
            />
            <TextField
              label="Contact Email"
              value={form.contact_email}
              onChange={(e) => setForm({ ...form, contact_email: e.target.value })}
            />
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
