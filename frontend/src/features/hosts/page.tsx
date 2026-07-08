import { Box, Chip, Typography } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useHosts } from "./hooks";

export function Hosts() {
  const { data = [], isLoading, error } = useHosts();

  const columns: GridColDef[] = [
    { field: "hostname", headerName: "Hostname", flex: 2 },
    { field: "ip_address", headerName: "IP Address", flex: 1 },
    {
      field: "alive",
      headerName: "Alive",
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params.value ? "ALIVE" : "UNKNOWN"}
          color={params.value ? "success" : "default"}
          size="small"
        />
      ),
    },
    { field: "source", headerName: "Source", width: 160 },
    { field: "subdomain_id", headerName: "Subdomain ID", width: 150 },
  ];

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Hosts
      </Typography>

      <Box sx={{ height: 620, width: "100%" }}>
        <DataGrid
          rows={data}
          columns={columns}
          loading={isLoading}
          getRowId={(row) => row.id}
          pageSizeOptions={[10, 25, 50]}
        />
      </Box>
    </Box>
  );
}
