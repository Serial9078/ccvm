import { Card, CardContent, Typography } from '@mui/material';

export function Placeholder({ title }: { title: string }) {
  return <Card sx={{ border: '1px solid #1e293b' }}><CardContent><Typography variant="h4">{title}</Typography><Typography color="text.secondary" sx={{ mt: 1 }}>This module is planned for the next sprints.</Typography></CardContent></Card>;
}
