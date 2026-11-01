import DownloadIcon from "@mui/icons-material/Download";
import FilterAltOffIcon from "@mui/icons-material/FilterAltOff";
import RefreshIcon from "@mui/icons-material/Refresh";

import {
  Box,
  Button,
  Chip,
  FormControl,
  FormControlLabel,
  InputLabel,
  MenuItem,
  Select,
  Switch,
  TextField,
} from "@mui/material";

import type {
  StatusFilter,
  UrlFilters,
} from "../utils";

import {
  initialUrlFilters,
} from "../utils";


interface UrlToolbarProps {
  filters: UrlFilters;
  filteredCount: number;
  totalCount: number;
  isFetching: boolean;

  onChange: (
    filters: UrlFilters,
  ) => void;

  onRefresh: () => void;
  onExport: () => void;
}


function parseStatusFilter(
  value: unknown,
): StatusFilter {
  const normalized = String(value);

  if (normalized === "success") {
    return "success";
  }

  if (normalized === "redirect") {
    return "redirect";
  }

  if (normalized === "client-error") {
    return "client-error";
  }

  if (normalized === "server-error") {
    return "server-error";
  }

  if (normalized === "unknown") {
    return "unknown";
  }

  return "all";
}


export function UrlToolbar({
  filters,
  filteredCount,
  totalCount,
  isFetching,
  onChange,
  onRefresh,
  onExport,
}: UrlToolbarProps) {
  const setSearch = (
    value: string,
  ) => {
    onChange({
      ...filters,
      search: value,
    });
  };

  const setStatus = (
    value: unknown,
  ) => {
    onChange({
      ...filters,
      status: parseStatusFilter(
        value,
      ),
    });
  };

  const setFindingsOnly = (
    value: boolean,
  ) => {
    onChange({
      ...filters,
      findingsOnly: value,
    });
  };

  const setMissingHeadersOnly = (
    value: boolean,
  ) => {
    onChange({
      ...filters,
      missingHeadersOnly: value,
    });
  };

  const setScreenshotsOnly = (
    value: boolean,
  ) => {
    onChange({
      ...filters,
      screenshotsOnly: value,
    });
  };

  const setLoginPagesOnly = (
    value: boolean,
  ) => {
    onChange({
      ...filters,
      loginPagesOnly: value,
    });
  };

  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        gap: 2,
        mb: 3,
      }}
    >
      <Box
        sx={{
          display: "flex",
          gap: 2,
          flexWrap: "wrap",
          alignItems: "center",
        }}
      >
        <TextField
          label="Search URLs, CVEs, findings, titles or servers"
          value={filters.search}
          onChange={(event) => {
            setSearch(
              event.target.value,
            );
          }}
          sx={{
            flex: 1,
            minWidth: 320,
          }}
        />

        <FormControl
          sx={{
            minWidth: 180,
          }}
        >
          <InputLabel id="url-status-filter-label">
            HTTP status
          </InputLabel>

          <Select
            labelId="url-status-filter-label"
            label="HTTP status"
            value={filters.status}
            onChange={(event) => {
              setStatus(
                event.target.value,
              );
            }}
          >
            <MenuItem value="all">
              All
            </MenuItem>

            <MenuItem value="success">
              2xx Success
            </MenuItem>

            <MenuItem value="redirect">
              3xx Redirect
            </MenuItem>

            <MenuItem value="client-error">
              4xx Client Error
            </MenuItem>

            <MenuItem value="server-error">
              5xx Server Error
            </MenuItem>

            <MenuItem value="unknown">
              Unknown
            </MenuItem>
          </Select>
        </FormControl>

        <Chip
          label={`${filteredCount} / ${totalCount} URLs`}
          color="primary"
          sx={{
            height: 56,
            px: 1,
            fontWeight: 800,
          }}
        />

        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
          disabled={isFetching}
          onClick={onRefresh}
          sx={{
            height: 56,
          }}
        >
          {isFetching
            ? "Refreshing"
            : "Refresh"}
        </Button>

        <Button
          variant="contained"
          startIcon={<DownloadIcon />}
          disabled={
            filteredCount === 0
          }
          onClick={onExport}
          sx={{
            height: 56,
          }}
        >
          CSV
        </Button>
      </Box>

      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 2,
        }}
      >
        <FormControlLabel
          control={
            <Switch
              checked={
                filters.findingsOnly
              }
              onChange={(event) => {
                setFindingsOnly(
                  event.target.checked,
                );
              }}
            />
          }
          label="Open findings"
        />

        <FormControlLabel
          control={
            <Switch
              checked={
                filters
                  .missingHeadersOnly
              }
              onChange={(event) => {
                setMissingHeadersOnly(
                  event.target.checked,
                );
              }}
            />
          }
          label="Missing headers"
        />

        <FormControlLabel
          control={
            <Switch
              checked={
                filters.screenshotsOnly
              }
              onChange={(event) => {
                setScreenshotsOnly(
                  event.target.checked,
                );
              }}
            />
          }
          label="Screenshots"
        />

        <FormControlLabel
          control={
            <Switch
              checked={
                filters.loginPagesOnly
              }
              onChange={(event) => {
                setLoginPagesOnly(
                  event.target.checked,
                );
              }}
            />
          }
          label="Login pages"
        />

        <Button
          size="small"
          startIcon={
            <FilterAltOffIcon />
          }
          onClick={() => {
            onChange(
              initialUrlFilters,
            );
          }}
        >
          Reset filters
        </Button>
      </Box>
    </Box>
  );
}
