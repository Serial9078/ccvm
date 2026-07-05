import { Box, Card, CardContent, Typography } from "@mui/material";
import { useCustomers } from "../hooks/useCustomers";

export function Customers() {
  const { data, isLoading, error } = useCustomers();

  if (isLoading) return <Typography>Lade Kunden...</Typography>;
  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Customers
      </Typography>

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
    </Box>
  );
}
