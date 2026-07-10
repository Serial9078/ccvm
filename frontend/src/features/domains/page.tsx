import { useState } from "react";

import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import RefreshIcon from "@mui/icons-material/Refresh";
import {
  Alert,
  Box,
  Button,
  Chip,
  Snackbar,
  Typography,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type {
  GridColDef,
  GridRenderCellParams,
} from "@mui/x-data-grid";

import type { Domain } from "./api";
import {
  useDomains,
  useStartDiscovery,
} from "./hooks";

export function Domains() {
  const {
    data = [],
    isLoading,
    error,
    refetch,
    isFetching,
  } = useDomains();

  const discoveryMutation = useStartDiscovery();

  const [runningDomainId, setRunningDomainId] = useState<number | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleDiscover = async (domain: Domain) => {
    setRunningDomainId(domain.id);
    setSuccessMessage(null);
    setErrorMessage(null);

    try {
      const result = await discoveryMutation.mutateAsync(domain.id);

      const stages = result.jobs
        .map((job) => job.plugin)
        .join(" → ");

      setSuccessMessage(
        `Discovery für ${domain.name} gestartet: ${stages}`,
      );
    } catch (mutationError) {
      console.error(mutationError);

      setErrorMessage(
        `Discovery für ${domain.name} konnte nicht gestartet werden.`,
      );
    } finally {
      setRunningDomainId(null);
    }
  };

  const columns: GridColDef[] = [
    {
      field: "name",
      headerName: "Domain",
      flex: 1.5,
      minWidth: 240,
      renderCell: (params: GridRenderCellParams) => (
        <Typography sx={{ fontWeight: 700 }}>
          {String(params.value ?? "")}
        </Typography>
      ),
    },
    {
      field: "description",
      headerName: "Description",
      flex: 2,
      minWidth: 280,
      valueGetter: (_value, row) => row.description || "-",
    },
    {
      field: "customer_id",
      headerName: "Customer ID",
      width: 140,
    },
    {
      field: "status",
      headerName: "Status",
      width: 140,
      sortable: false,
      filterable: false,
      renderCell: () => (
        <Chip
          label="MANAGED"
          size="small"
          color="success"
          variant="outlined"
          sx={{ fontWeight: 700 }}
        />
      ),
    },
    {
      field: "actions",
      headerName: "Actions",
      width: 210,
      sortable: false,
      filterable: false,
      disableColumnMenu: true,
      renderCell: (params: GridRenderCellParams) => {
        const domain = params.row as Domain;
        const running = runningDomainId === domain.id;

        return (
          <Button
            variant="contained"
            size="small"
            startIcon={<PlayArrowIcon />}
            disabled={running || discoveryMutation.isPending}
            onClick={(event) => {
              event.stopPropagation();
              void handleDiscover(domain);
            }}
          >
            {running ? "Starting..." : "Discover"}
          </Button>
        );
      },
    },
  ];

  if (error) {
    return (
      <Alert severity="error">
        Domains konnten nicht geladen werden.
      </Alert>
    );
  }

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 2,
          mb: 3,
        }}
      >
        <Box>
          <Typography
            variant="h4"
            sx={{ fontWeight: 800 }}
          >
            Domains
          </Typography>

          <Typography color="text.secondary">
            Root domains and attack-surface discovery
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          disabled={isFetching}
          onClick={() => void refetch()}
        >
          {isFetching ? "Refreshing..." : "Refresh"}
        </Button>
      </Box>

      <Alert
        severity="info"
        sx={{ mb: 3 }}
      >
        Discover startet automatisch Subfinder, DNSX, HTTPX und Naabu.
      </Alert>

      <Box
        sx={{
          height: 620,
          width: "100%",
        }}
      >
        <DataGrid
          rows={data}
          columns={columns}
          loading={isLoading}
          getRowId={(row) => row.id}
          pageSizeOptions={[10, 25, 50]}
          initialState={{
            pagination: {
              paginationModel: {
                page: 0,
                pageSize: 25,
              },
            },
          }}
          disableRowSelectionOnClick
        />
      </Box>

      <Snackbar
        open={Boolean(successMessage)}
        autoHideDuration={7000}
        onClose={() => setSuccessMessage(null)}
        anchorOrigin={{
          vertical: "bottom",
          horizontal: "right",
        }}
      >
        <Alert
          severity="success"
          variant="filled"
          onClose={() => setSuccessMessage(null)}
        >
          {successMessage}
        </Alert>
      </Snackbar>

      <Snackbar
        open={Boolean(errorMessage)}
        autoHideDuration={7000}
        onClose={() => setErrorMessage(null)}
        anchorOrigin={{
          vertical: "bottom",
          horizontal: "right",
        }}
      >
        <Alert
          severity="error"
          variant="filled"
          onClose={() => setErrorMessage(null)}
        >
          {errorMessage}
        </Alert>
      </Snackbar>
    </Box>
  );
}
