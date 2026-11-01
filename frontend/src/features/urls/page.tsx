import {
  useMemo,
  useState,
} from "react";

import {
  Alert,
  Box,
  Typography,
} from "@mui/material";

import type {
  UrlInventoryRow,
} from "./api";

import {
  ScreenshotDialog,
} from "./components/ScreenshotDialog";

import {
  UrlDrawer,
} from "./components/UrlDrawer";

import {
  UrlGrid,
} from "./components/UrlGrid";

import {
  UrlToolbar,
} from "./components/UrlToolbar";

import {
  exportUrlRowsCsv,
  filterUrlRows,
  initialUrlFilters,
  toGridRow,
} from "./utils";

import type {
  UrlFilters,
  UrlGridRow,
} from "./utils";

import {
  useUrls,
} from "./hooks";

export function Urls() {
  const {
    data = [],
    isLoading,
    isFetching,
    error,
    refetch,
  } = useUrls();

  const [
    filters,
    setFilters,
  ] = useState<UrlFilters>(
    initialUrlFilters,
  );

  const [
    selectedRow,
    setSelectedRow,
  ] = useState<UrlInventoryRow | null>(
    null,
  );

  const [
    screenshotRow,
    setScreenshotRow,
  ] = useState<UrlInventoryRow | null>(
    null,
  );

  const rows = useMemo<
    UrlGridRow[]
  >(
    () =>
      data
        .map(toGridRow)
        .sort(
          (
            left,
            right,
          ) =>
            right.criticalCount
              - left.criticalCount
            || right.highCount
              - left.highCount
            || right.mediumCount
              - left.mediumCount
            || right.openFindingCount
              - left.openFindingCount
            || (
              left.displayScore
              ?? -1
            )
              - (
                right.displayScore
                ?? -1
              ),
        ),
    [data],
  );

  const filteredRows = useMemo(
    () =>
      filterUrlRows(
        rows,
        filters,
      ),
    [
      rows,
      filters,
    ],
  );

  if (error) {
    return (
      <Alert severity="error">
        URL Intelligence could not be loaded.
      </Alert>
    );
  }

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent:
            "space-between",
          gap: 2,
          mb: 3,
        }}
      >
        <Box>
          <Typography
            variant="h4"
            sx={{
              fontWeight: 800,
            }}
          >
            URL Intelligence
          </Typography>

          <Typography color="text.secondary">
            Screenshots, HTTP metadata,
            findings and security headers
          </Typography>
        </Box>
      </Box>

      <UrlToolbar
        filters={filters}
        filteredCount={
          filteredRows.length
        }
        totalCount={rows.length}
        isFetching={isFetching}
        onChange={setFilters}
        onRefresh={() => {
          void refetch();
        }}
        onExport={() => {
          exportUrlRowsCsv(
            filteredRows,
          );
        }}
      />

      <UrlGrid
        rows={filteredRows}
        loading={isLoading}
        onSelect={(row) => {
          setSelectedRow(row);
        }}
        onOpenScreenshot={(row) => {
          setScreenshotRow(row);
        }}
      />

      <UrlDrawer
        row={selectedRow}
        onClose={() => {
          setSelectedRow(null);
        }}
        onOpenScreenshot={(row) => {
          setScreenshotRow(row);
        }}
      />

      <ScreenshotDialog
        row={screenshotRow}
        onClose={() => {
          setScreenshotRow(null);
        }}
      />
    </Box>
  );
}
