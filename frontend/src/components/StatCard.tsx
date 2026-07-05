import { Card, CardContent, Typography } from '@mui/material';

export function StatCard({ label, value, tone }: { label: string; value: number | string; tone?: string }) {
  return (
    <Card sx={{ height: '100%', border: '1px solid #1e293b' }}>
      <CardContent>
        <Typography color="text.secondary" variant="body2">{label}</Typography>
        <Typography variant="h4" sx={{ mt: 1, color: tone || 'inherit' }}>{value}</Typography>
      </CardContent>
    </Card>
  );
}
