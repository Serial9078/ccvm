import { Box, Card, CardContent, LinearProgress, Typography } from "@mui/material";
import { useDashboardSummary } from "./hooks";

function KpiCard({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <Card>
      <CardContent>
        <Typography color="text.secondary" variant="body2">
          {label}
        </Typography>
        <Typography variant="h4" sx={{ mt: 1, fontWeight: 700 }}>
          {value}
        </Typography>
      </CardContent>
    </Card>
  );
}

export function Dashboard() {
  const { data, isLoading, error } = useDashboardSummary();

  if (isLoading) {
    return (
      <Box>
        <Typography variant="h4" sx={{ mb: 3 }}>
          Dashboard
        </Typography>
        <LinearProgress />
      </Box>
    );
  }

  if (error || !data) {
    return <Typography color="error">Fehler beim Laden des Dashboards.</Typography>;
  }

  const severityCards = [
    { label: "Critical", value: data.critical },
    { label: "High", value: data.high },
    { label: "Medium", value: data.medium },
    { label: "Low", value: data.low },
    { label: "Info", value: data.info },
    { label: "Open", value: data.open },
    { label: "Fixed", value: data.fixed },
    { label: "Running Jobs", value: data.running_jobs },
  ];

  const inventoryCards = [
    { label: "Customers", value: data.customers },
    { label: "Domains", value: data.domains },
    { label: "Assets", value: data.assets },
    { label: "Findings", value: data.findings },
    { label: "Jobs", value: data.jobs },
  ];

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Executive Dashboard
      </Typography>

      <Typography variant="h6" sx={{ mb: 2 }}>
        Risk Overview
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: 2,
          mb: 4,
        }}
      >
        {severityCards.map((card) => (
          <KpiCard key={card.label} label={card.label} value={card.value} />
        ))}
      </Box>

      <Typography variant="h6" sx={{ mb: 2 }}>
        Inventory
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(5, minmax(0, 1fr))",
          gap: 2,
        }}
      >
        {inventoryCards.map((card) => (
          <KpiCard key={card.label} label={card.label} value={card.value} />
        ))}
      </Box>
    </Box>
  );
}
