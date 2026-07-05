import { useQuery } from '@tanstack/react-query';
import { api } from '../api/client';
import { Paper, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material';

type Customer = { id: number; name: string; email?: string };

export default function Customers() {
  const { data = [] } = useQuery({ queryKey: ['customers'], queryFn: async () => (await api.get<Customer[]>('/customers')).data });
  return <>
    <Typography variant="h4" gutterBottom>Customers</Typography>
    <Paper><Table><TableHead><TableRow><TableCell>ID</TableCell><TableCell>Name</TableCell><TableCell>Email</TableCell></TableRow></TableHead><TableBody>
      {data.map(c => <TableRow key={c.id}><TableCell>{c.id}</TableCell><TableCell>{c.name}</TableCell><TableCell>{c.email}</TableCell></TableRow>)}
    </TableBody></Table></Paper>
  </>;
}
