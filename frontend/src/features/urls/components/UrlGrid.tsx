import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import ImageIcon from "@mui/icons-material/Image";
import LoginIcon from "@mui/icons-material/Login";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import SecurityIcon from "@mui/icons-material/Security";

import {
  Box,
  Chip,
  IconButton,
  LinearProgress,
  Link,
  Tooltip,
  Typography,
} from "@mui/material";

import {
  DataGrid,
} from "@mui/x-data-grid";

import type {
  GridColDef,
  GridRenderCellParams,
} from "@mui/x-data-grid";

import type {
  UrlGridRow,
} from "../utils";

import {
  scoreColor,
  screenshotUrl,
  statusColor,
} from "../utils";

interface UrlGridProps {
  rows: UrlGridRow[];
  loading: boolean;

  onSelect: (
    row: UrlGridRow,
  ) => void;

  onOpenScreenshot: (
    row: UrlGridRow,
  ) => void;
}

function SeverityChip({
  label,
  count,
  color,
}: {
  label: string;
  count: number;
  color:
    | "error"
    | "warning"
    | "info";
}) {
  if (count === 0) {
    return null;
  }

  return (
    <Chip
      label={`${label} ${count}`}
      size="small"
      color={color}
      variant="outlined"
      sx={{
        height: 24,
        fontSize: 11,
        fontWeight: 800,
      }}
    />
  );
}

export function UrlGrid({
  rows,
  loading,
  onSelect,
  onOpenScreenshot,
}: UrlGridProps) {
  const copyUrl = async (
    value: string,
  ) => {
    await navigator.clipboard.writeText(
      value,
    );
  };

  const columns:
  GridColDef<UrlGridRow>[] = [
    {
      field: "preview",
      headerName: "",
      width: 110,
      sortable: false,
      filterable: false,

      renderCell: (
        params:
        GridRenderCellParams<
          UrlGridRow
        >,
      ) => {
        const imageUrl = screenshotUrl(
          params.row.screenshot
            ?.screenshot_path,
        );

        if (!imageUrl) {
          return (
            <Box
              sx={{
                width: 82,
                height: 48,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                borderRadius: 1,
                bgcolor:
                  "action.hover",
              }}
            >
              <ImageIcon
                color="disabled"
              />
            </Box>
          );
        }

        return (
          <Box
            component="img"
            src={imageUrl}
            alt={params.row.url}
            onClick={(event) => {
              event.stopPropagation();
              onOpenScreenshot(
                params.row,
              );
            }}
            sx={{
              width: 82,
              height: 48,
              objectFit: "cover",
              objectPosition: "top",
              borderRadius: 1,
              cursor: "pointer",
              border: "1px solid",
              borderColor: "divider",
            }}
          />
        );
      },
    },

    {
      field: "displayStatus",
      headerName: "Status",
      width: 105,

      renderCell: (
        params:
        GridRenderCellParams<
          UrlGridRow
        >,
      ) => (
        <Chip
          label={
            params.row.displayStatus
              !== null
              ? String(
                  params.row
                    .displayStatus,
                )
              : "UNKNOWN"
          }
          size="small"
          color={statusColor(
            params.row.displayStatus,
          )}
        />
      ),
    },

    {
      field: "displayScore",
      headerName: "Security",
      width: 150,

      renderCell: (
        params:
        GridRenderCellParams<
          UrlGridRow
        >,
      ) => {
        const score =
          params.row.displayScore;

        return (
          <Box
            sx={{
              width: "100%",
              pr: 1,
            }}
          >
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent:
                  "space-between",
                mb: 0.5,
              }}
            >
              <Typography
                variant="caption"
                sx={{
                  fontWeight: 800,
                }}
              >
                {score !== null
                  ? `${score}/100`
                  : "Not checked"}
              </Typography>

              <Chip
                label={
                  score !== null
                    ? String(score)
                    : "-"
                }
                size="small"
                color={scoreColor(score)}
                sx={{
                  height: 20,
                  fontSize: 11,
                }}
              />
            </Box>

            <LinearProgress
              variant="determinate"
              value={score ?? 0}
              color={scoreColor(score)}
              sx={{
                height: 6,
                borderRadius: 3,
              }}
            />
          </Box>
        );
      },
    },

    {
      field: "severity",
      headerName: "Risk",
      width: 260,
      sortable: false,

      renderCell: (
        params:
        GridRenderCellParams<
          UrlGridRow
        >,
      ) => (
        <Box
          sx={{
            display: "flex",
            flexWrap: "wrap",
            gap: 0.5,
            alignItems: "center",
          }}
        >
          {params.row
            .openFindingCount === 0 ? (
              <Chip
                label="No open findings"
                size="small"
                color="success"
                variant="outlined"
              />
            ) : (
              <>
                <SeverityChip
                  label="C"
                  count={
                    params.row
                      .criticalCount
                  }
                  color="error"
                />

                <SeverityChip
                  label="H"
                  count={
                    params.row
                      .highCount
                  }
                  color="error"
                />

                <SeverityChip
                  label="M"
                  count={
                    params.row
                      .mediumCount
                  }
                  color="warning"
                />

                <SeverityChip
                  label="L"
                  count={
                    params.row
                      .lowCount
                  }
                  color="info"
                />
              </>
            )}

          {params.row
            .hasMissingHeaders && (
              <Tooltip title="Missing security headers">
                <SecurityIcon
                  color="error"
                  fontSize="small"
                />
              </Tooltip>
            )}

          {params.row.isLoginPage && (
            <Tooltip title="Possible login or admin page">
              <LoginIcon
                color="warning"
                fontSize="small"
              />
            </Tooltip>
          )}
        </Box>
      ),
    },

    {
      field: "url",
      headerName: "Discovered URL",
      flex: 3,
      minWidth: 420,

      renderCell: (
        params:
        GridRenderCellParams<
          UrlGridRow
        >,
      ) => {
        const value =
          params.row.url;

        return (
          <Box
            sx={{
              width: "100%",
              display: "flex",
              alignItems: "center",
              gap: 1,
            }}
          >
            <Link
              href={value}
              target="_blank"
              rel="noreferrer"
              sx={{
                flex: 1,
                overflow: "hidden",
                textOverflow:
                  "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {value}
            </Link>

            <Tooltip title="Copy URL">
              <IconButton
                size="small"
                onClick={(event) => {
                  event.stopPropagation();

                  void copyUrl(
                    value,
                  );
                }}
              >
                <ContentCopyIcon
                  fontSize="small"
                />
              </IconButton>
            </Tooltip>

            <Tooltip title="Open URL">
              <IconButton
                size="small"
                component="a"
                href={value}
                target="_blank"
                rel="noreferrer"
                onClick={(event) => {
                  event.stopPropagation();
                }}
              >
                <OpenInNewIcon
                  fontSize="small"
                />
              </IconButton>
            </Tooltip>
          </Box>
        );
      },
    },

    {
      field: "displayTitle",
      headerName: "Title",
      flex: 1.5,
      minWidth: 220,
    },

    {
      field: "displayServer",
      headerName: "Server",
      flex: 1,
      minWidth: 180,
    },
  ];

  return (
    <Box
      sx={{
        height: 760,
        width: "100%",
      }}
    >
      <DataGrid
        rows={rows}
        columns={columns}
        loading={loading}
        getRowId={(row) => row.id}
        rowHeight={64}
        pageSizeOptions={[
          25,
          50,
          100,
        ]}
        initialState={{
          pagination: {
            paginationModel: {
              page: 0,
              pageSize: 25,
            },
          },

          sorting: {
            sortModel: [
              {
                field:
                  "openFindingCount",
                sort: "desc",
              },
            ],
          },
        }}
        disableRowSelectionOnClick
        onRowClick={(params) => {
          onSelect(params.row);
        }}
      />
    </Box>
  );
}
