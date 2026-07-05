import { Button, Card, CardContent, MenuItem, Stack, TextField, Typography, Table, TableBody, TableCell, TableHead, TableRow } from '@mui/material';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { createAsset, getAssets, getCustomers } from '../api/queries';

export function Assets() {
  const qc = useQueryClient();
  const { data: customers = [] } = useQuery({ queryKey: ['customers'], queryFn: getCustomers });
  const { data: assets = [] } = useQuery({ queryKey: ['assets'], queryFn: getAssets });
  const [customerId, setCustomerId] = useState<number>(0);
  const [target, setTarget] = useState('');
  const [type, setType] = useState('url');
  const [exposure, setExposure] = useState('external');
  const mutation = useMutation({
    mutationFn: createAsset,
    onSuccess: () => { setTarget(''); qc.invalidateQueries({ queryKey: ['assets'] }); qc.invalidateQueries({ queryKey: ['dashboard-stats'] }); },
  });

  return (
    <Stack spacing={3}>
      <div>
        <Typography variant="h4">Assets</Typography>
        <Typography color="text.secondary">Register URLs, hosts, IPs and networks for future scans.</Typography>
      </div>
      <Card sx={{ border: '1px solid #1e293b' }}><CardContent>
        <Stack direction={{ xs: 'column', md: 'row' }} spacing={2}>
          <TextField select label="Customer" value={customerId} onChange={(e) => setCustomerId(Number(e.target.value))} sx={{ minWidth: 220 }}>
            <MenuItem value={0}>Select customer</MenuItem>
            {customers.map(c => <MenuItem key={c.id} value={c.id}>{c.name}</MenuItem>)}
          </TextField>
          <TextField label="Target" value={target} onChange={(e) => setTarget(e.target.value)} fullWidth />
          <TextField select label="Type" value={type} onChange={(e) => setType(e.target.value)} sx={{ minWidth: 140 }}>
            <MenuItem value="url">URL</MenuItem><MenuItem value="hostname">Hostname</MenuItem><MenuItem value="ip">IP</MenuItem><MenuItem value="subnet">Subnet</MenuItem>
          </TextField>
          <TextField select label="Exposure" value={exposure} onChange={(e) => setExposure(e.target.value)} sx={{ minWidth: 150 }}>
            <MenuItem value="external">External</MenuItem><MenuItem value="internal">Internal</MenuItem>
          </TextField>
          <Button variant="contained" onClick={() => mutation.mutate({ customer_id: customerId, target, type, exposure })} disabled={!customerId || !target}>Create</Button>
        </Stack>
      </CardContent></Card>
      <Card sx={{ border: '1px solid #1e293b' }}><CardContent>
        <Table>
          <TableHead><TableRow><TableCell>ID</TableCell><TableCell>Customer ID</TableCell><TableCell>Target</TableCell><TableCell>Type</TableCell><TableCell>Exposure</TableCell></TableRow></TableHead>
          <TableBody>{assets.map(a => <TableRow key={a.id}><TableCell>{a.id}</TableCell><TableCell>{a.customer_id}</TableCell><TableCell>{a.target}</TableCell><TableCell>{a.type}</TableCell><TableCell>{a.exposure}</TableCell></TableRow>)}</TableBody>
        </Table>
      </CardContent></Card>
    </Stack>
  );
}
