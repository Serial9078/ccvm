import { Box, Typography } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { usePorts } from "./hooks";

export function Ports() {
  const { data = [], isLoading, error } = usePorts();

  const columns: GridColDef[] = [
    { field: "host_id", headerName: "Host ID", width: 120 },
    { field: "port", headerName: "Port", width: 120 },
    { field: "protocol", headerName: "Protocol", width: 140 },
    { field: "service", headerName: "Service", flex: 1 },
    { field: "banner", headerName: "Banner", flex: 2 },
    { field: "source", headerName: "Source", width: 160 },
  ];

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Ports
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
