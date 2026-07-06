import { Box, Chip, Typography } from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";
import { useFindings } from "./hooks";

function severityColor(severity: string) {
  switch (severity) {
    case "critical":
      return "error";
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "success";
    default:
      return "default";
  }
}

export function Findings() {
  const { data = [], isLoading, error } = useFindings();

  const columns: GridColDef[] = [
    {
      field: "severity",
      headerName: "Severity",
      width: 130,
      renderCell: (params) => (
        <Chip
          label={String(params.value).toUpperCase()}
          color={severityColor(String(params.value))}
          size="small"
        />
      ),
    },
    { field: "name", headerName: "Finding", flex: 2 },
    { field: "host", headerName: "Host", flex: 1 },
    { field: "scanner", headerName: "Scanner", width: 120 },
    { field: "template_id", headerName: "Template", flex: 1.5 },
    { field: "cve", headerName: "CVE", width: 160 },
    { field: "status", headerName: "Status", width: 120 },
  ];

  if (error) return <Typography color="error">Fehler beim Laden.</Typography>;

  return (
    <Box>
      <Typography variant="h4" sx={{ mb: 3 }}>
        Findings
      </Typography>

      <Box sx={{ height: 620, width: "100%" }}>
        <DataGrid
          rows={data}
          columns={columns}
          loading={isLoading}
          getRowId={(row) => row.id}
          pageSizeOptions={[10, 25, 50, 100]}
          initialState={{
            pagination: {
              paginationModel: { pageSize: 25, page: 0 },
            },
          }}
        />
      </Box>
    </Box>
  );
}
