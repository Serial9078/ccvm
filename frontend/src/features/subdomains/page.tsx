import { Box, Typography } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useSubdomains } from "./hooks";

export function Subdomains() {
  const { data = [], isLoading, error } = useSubdomains();

  const columns: GridColDef[] = [
    { field: "name", headerName: "Subdomain", flex: 2 },
    { field: "source", headerName: "Source", width: 160 },
    { field: "customer_id", headerName: "Customer ID", width: 140 },
    { field: "domain_id", headerName: "Domain ID", width: 140 },
  ];

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Subdomains
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
