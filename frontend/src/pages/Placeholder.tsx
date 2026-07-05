import { Paper, Typography } from '@mui/material';

export default function Placeholder({ title }: { title: string }) {
  return <><Typography variant="h4" gutterBottom>{title}</Typography><Paper sx={{ p: 3 }}>Coming in a later sprint.</Paper></>;
}
