import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { Paper, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';

type Asset = { id: number; customer_id: number; target: string; type: string };

export default function Assets() {
  const { data = [] } = useQuery({ queryKey: ['assets'], queryFn: async () => (await api.get<Asset[]>('/assets')).data });
  return <>
    <Typography variant="h4" gutterBottom>Assets</Typography>
    <Paper><Table><TableHead><TableRow><TableCell>ID</TableCell><TableCell>Customer ID</TableCell><TableCell>Target</TableCell><TableCell>Type</TableCell></TableRow></TableHead><TableBody>
      {data.map(a => <TableRow key={a.id}><TableCell>{a.id}</TableCell><TableCell>{a.customer_id}</TableCell><TableCell>{a.target}</TableCell><TableCell>{a.type}</TableCell></TableRow>)}
    </TableBody></Table></Paper>
  </>;
}
