import { Grid, Paper, Typography } from '@mui/material';

const stats = [
  ['Customers', '0'], ['Assets', '0'], ['Critical', '0'], ['High', '0']
];

export default function Dashboard() {
  return <>
    <Typography variant="h4" gutterBottom>Dashboard</Typography>
    <Grid container spacing={2}>
      {stats.map(([label, value]) => <Grid item xs={12} md={3} key={label}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="overline">{label}</Typography>
          <Typography variant="h3">{value}</Typography>
        </Paper>
      </Grid>)}
    </Grid>
  </>;
}
