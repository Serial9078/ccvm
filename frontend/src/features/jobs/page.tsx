import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  LinearProgress,
  MenuItem,
  TextField,
  Typography,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useState } from "react";
import { useAssets } from "../assets/hooks";
import { useCreateJob, useJobs } from "./hooks";

export function Jobs() {
  const { data: jobs = [], isLoading, error } = useJobs();
  const { data: assets = [] } = useAssets();
  const createJob = useCreateJob();

  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({
    asset_id: "",
    plugin: "dummy",
  });

  const columns: GridColDef[] = [
    { field: "id", headerName: "ID", width: 80 },
    { field: "plugin", headerName: "Plugin", flex: 1 },
    { field: "status", headerName: "Status", flex: 1 },
    {
      field: "progress",
      headerName: "Progress",
      flex: 1.5,
      renderCell: (params) => (
        <Box sx={{ width: "100%", pt: 1.5 }}>
          <LinearProgress variant="determinate" value={params.value ?? 0} />
        </Box>
      ),
    },
    { field: "message", headerName: "Message", flex: 2 },
    {
      field: "asset_id",
      headerName: "Asset",
      flex: 1.5,
      valueGetter: (_value, row) => {
        const asset = assets.find((a) => a.id === row.asset_id);
        return asset?.name || asset?.target || row.asset_id;
      },
    },
  ];

  const saveJob = async () => {
    await createJob.mutateAsync({
      asset_id: Number(form.asset_id),
      plugin: form.plugin,
    });

    setForm({ asset_id: "", plugin: "dummy" });
    setOpen(false);
  };

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 3 }}>
        <Typography variant="h4">Jobs</Typography>
        <Button variant="contained" onClick={() => setOpen(true)}>
          New Dummy Job
        </Button>
      </Box>

      <Box sx={{ height: 560, width: "100%" }}>
        <DataGrid
          rows={jobs}
          columns={columns}
          loading={isLoading}
          getRowId={(row) => row.uuid}
          pageSizeOptions={[10, 25, 50]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 10, page: 0 },
            },
          }}
        />
      </Box>

      <Dialog open={open} onClose={() => setOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>New Dummy Job</DialogTitle>
        <DialogContent>
          <Box sx={{ display: "flex", flexDirection: "column", gap: 2, mt: 1 }}>
            <TextField
              select
              label="Asset"
              value={form.asset_id}
              onChange={(e) => setForm({ ...form, asset_id: e.target.value })}
              required
            >
              {assets.map((asset) => (
                <MenuItem key={asset.id} value={asset.id}>
                  {asset.name || asset.target}
                </MenuItem>
              ))}
            </TextField>

            <TextField
              select
              label="Plugin"
              value={form.plugin}
              onChange={(e) => setForm({ ...form, plugin: e.target.value })}
            >
              <MenuItem value="dummy">Dummy</MenuItem>
              <MenuItem value="nuclei">Nuclei</MenuItem>
            </TextField>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={saveJob}
            disabled={!form.asset_id || createJob.isPending}
          >
            Start
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
