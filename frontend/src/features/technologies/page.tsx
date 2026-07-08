import { Box, Typography } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useTechnologies } from "./hooks";

export function Technologies() {
  const { data = [], isLoading, error } = useTechnologies();

  const columns: GridColDef[] = [
    { field: "host_id", headerName: "Host ID", width: 120 },
    { field: "name", headerName: "Technology", flex: 1 },
    { field: "version", headerName: "Version", width: 160 },
    { field: "category", headerName: "Category", width: 180 },
    { field: "source", headerName: "Source", width: 160 },
  ];

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Technologies
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
