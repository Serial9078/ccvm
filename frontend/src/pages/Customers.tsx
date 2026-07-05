import { Button, Card, CardContent, Stack, TextField, Typography, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { createCustomer, getCustomers } from '../api/queries';

export function Customers() {
  const qc = useQueryClient();
  const { data = [] } = useQuery({ queryKey: ['customers'], queryFn: getCustomers });
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const mutation = useMutation({
    mutationFn: createCustomer,
    onSuccess: () => { setName(''); setEmail(''); qc.invalidateQueries({ queryKey: ['customers'] }); qc.invalidateQueries({ queryKey: ['dashboard-stats'] }); },
  });

  return (
    <Stack spacing={3}>
      <div>
        <Typography variant="h4">Customers</Typography>
        <Typography color="text.secondary">Create and manage customer tenants.</Typography>
      </div>
      <Card sx={{ border: '1px solid #1e293b' }}><CardContent>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField label="Company" value={name} onChange={(e) => setName(e.target.value)} fullWidth />
          <TextField label="E-Mail" value={email} onChange={(e) => setEmail(e.target.value)} fullWidth />
          <Button variant="contained" onClick={() => mutation.mutate({ name, email })} disabled={!name}>Create</Button>
        </Stack>
      </CardContent></Card>
      <Card sx={{ border: '1px solid #1e293b' }}><CardContent>
        <Table>
          <TableHead><TableRow><TableCell>ID</TableCell><TableCell>Name</TableCell><TableCell>E-Mail</TableCell></TableRow></TableHead>
          <TableBody>{data.map(c => <TableRow key={c.id}><TableCell>{c.id}</TableCell><TableCell>{c.name}</TableCell><TableCell>{c.email}</TableCell></TableRow>)}</TableBody>
        </Table>
      </CardContent></Card>
    </Stack>
  );
}
