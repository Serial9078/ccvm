import { Grid, Typography, Card, CardContent, Box } from '@mui/material';
import { useQuery } from '@tanstack/react-query';
import { getDashboardStats } from '../api/queries';
import { StatCard } from '../components/StatCard';

export function Dashboard() {
  const { data, isLoading } = useQuery({ queryKey: ['dashboard-stats'], queryFn: getDashboardStats });

  const stats = data ?? { customers: 0, assets: 0, scans: 0, findings: 0, critical: 0, high: 0, medium: 0, low: 0 };

  return (
    <Box>
      <Typography variant="h4" gutterBottom>Dashboard</Typography>
      <Typography color="text.secondary" sx={{ mb: 3 }}>Operational overview for customers, assets, scans and exposure risk.</Typography>
      {isLoading && <Typography>Loading dashboard...</Typography>}
      <Grid container spacing={2}>
        <Grid item xs={12} md={3}><StatCard label="Customers" value={stats.customers} /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Assets" value={stats.assets} /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Scans" value={stats.scans} /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Findings" value={stats.findings} /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Critical" value={stats.critical} tone="#ef4444" /></Grid>
        <Grid item xs={12} md={3}><StatCard label="High" value={stats.high} tone="#f97316" /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Medium" value={stats.medium} tone="#f59e0b" /></Grid>
        <Grid item xs={12} md={3}><StatCard label="Low" value={stats.low} tone="#38bdf8" /></Grid>
        <Grid item xs={12}>
          <Card sx={{ border: '1px solid #1e293b' }}>
            <CardContent>
              <Typography variant="h6">Phoenix milestone</Typography>
              <Typography color="text.secondary" sx={{ mt: 1 }}>
                CCVM now has a real React application shell, API integration and a backend prepared for scanner plugins.
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}
