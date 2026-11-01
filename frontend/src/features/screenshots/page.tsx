import { useMemo, useState } from "react";

import BrokenImageIcon from "@mui/icons-material/BrokenImage";
import ImageSearchIcon from "@mui/icons-material/ImageSearch";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import RefreshIcon from "@mui/icons-material/Refresh";

import {
  Alert,
  Box,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  FormControl,
  InputLabel,
  LinearProgress,
  MenuItem,
  Select,
  TextField,
  Typography,
} from "@mui/material";

import type {
  ScreenshotInventoryRow,
} from "./api";

import {
  useScreenshotInventory,
} from "./hooks";


function statusColor(
  statusCode?: number | null,
):
  | "success"
  | "warning"
  | "error"
  | "default" {
  if (!statusCode) {
    return "default";
  }

  if (
    statusCode >= 200
    && statusCode < 300
  ) {
    return "success";
  }

  if (
    statusCode >= 300
    && statusCode < 400
  ) {
    return "warning";
  }

  if (statusCode >= 400) {
    return "error";
  }

  return "default";
}


function ScreenshotImage({
  row,
  height,
  fit = "cover",
}: {
  row: ScreenshotInventoryRow;
  height?: number | string;
  fit?: "cover" | "contain";
}) {
  const [
    failed,
    setFailed,
  ] = useState(false);

  if (failed) {
    return (
      <Box
        sx={{
          width: "100%",
          height: height || 210,
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          justifyContent: "center",
          gap: 1,
          bgcolor: "background.default",
          color: "text.secondary",
        }}
      >
        <BrokenImageIcon />

        <Typography variant="caption">
          Screenshot konnte nicht geladen werden
        </Typography>

        <Typography
          variant="caption"
          sx={{
            maxWidth: "90%",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {row.filename}
        </Typography>
      </Box>
    );
  }

  return (
    <Box
      component="img"
      src={row.screenshot_url}
      alt={row.title || row.url}
      loading="lazy"
      onError={() => {
        setFailed(true);
      }}
      sx={{
        width: "100%",
        height: height || "auto",
        display: "block",
        objectFit: fit,
        objectPosition: "top",
      }}
    />
  );
}


function ScreenshotDialog({
  row,
  onClose,
}: {
  row: ScreenshotInventoryRow | null;
  onClose: () => void;
}) {
  return (
    <Dialog
      open={Boolean(row)}
      onClose={onClose}
      maxWidth="xl"
      fullWidth
    >
      {!row ? null : (
        <>
          <DialogTitle>
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                justifyContent:
                  "space-between",
                gap: 2,
              }}
            >
              <Box sx={{ minWidth: 0 }}>
                <Typography
                  variant="h6"
                  sx={{
                    fontWeight: 800,
                  }}
                >
                  {row.title
                    || row.hostname}
                </Typography>

                <Typography
                  variant="body2"
                  color="text.secondary"
                  sx={{
                    wordBreak:
                      "break-all",
                  }}
                >
                  {row.final_url
                    || row.url}
                </Typography>
              </Box>

              <Button
                component="a"
                href={
                  row.final_url
                  || row.url
                }
                target="_blank"
                rel="noreferrer"
                endIcon={
                  <OpenInNewIcon />
                }
              >
                Open URL
              </Button>
            </Box>
          </DialogTitle>

          <DialogContent>
            <ScreenshotImage
              row={row}
              fit="contain"
            />
          </DialogContent>
        </>
      )}
    </Dialog>
  );
}


function ScreenshotCard({
  row,
  onOpen,
}: {
  row: ScreenshotInventoryRow;
  onOpen: (
    row: ScreenshotInventoryRow,
  ) => void;
}) {
  return (
    <Card
      sx={{
        overflow: "hidden",
        height: "100%",
      }}
    >
      <CardActionArea
        onClick={() => {
          onOpen(row);
        }}
        sx={{
          height: "100%",
          display: "flex",
          flexDirection: "column",
          alignItems: "stretch",
        }}
      >
        <Box
          sx={{
            position: "relative",
            height: 210,
            bgcolor:
              "background.default",
            overflow: "hidden",
          }}
        >
          <ScreenshotImage
            row={row}
            height={210}
          />

          <Chip
            label={
              row.status_code
              ?? "UNKNOWN"
            }
            size="small"
            color={statusColor(
              row.status_code,
            )}
            sx={{
              position: "absolute",
              top: 12,
              right: 12,
              fontWeight: 800,
            }}
          />
        </Box>

        <CardContent
          sx={{
            width: "100%",
            flex: 1,
          }}
        >
          <Typography
            variant="subtitle1"
            sx={{
              fontWeight: 800,
              mb: 0.5,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {row.title
              || row.hostname}
          </Typography>

          <Typography
            variant="body2"
            color="primary.main"
            sx={{
              mb: 1.5,
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {row.hostname}
          </Typography>

          <Typography
            variant="caption"
            color="text.secondary"
            sx={{
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient:
                "vertical",
              overflow: "hidden",
              wordBreak: "break-all",
            }}
          >
            {row.final_url
              || row.url}
          </Typography>

          <Box
            sx={{
              display: "flex",
              justifyContent:
                "space-between",
              gap: 2,
              mt: 2,
            }}
          >
            <Typography
              variant="caption"
              color="text.secondary"
            >
              {row.viewport_width}
              ×
              {row.viewport_height}
            </Typography>

            <Typography
              variant="caption"
              color="text.secondary"
            >
              {row.duration_ms
                ? `${row.duration_ms} ms`
                : "-"}
            </Typography>
          </Box>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}


export function Screenshots() {
  const {
    data = [],
    isLoading,
    isFetching,
    error,
    refetch,
  } = useScreenshotInventory();

  const [
    search,
    setSearch,
  ] = useState("");

  const [
    selectedHost,
    setSelectedHost,
  ] = useState("all");

  const [
    selectedRow,
    setSelectedRow,
  ] = useState<
    ScreenshotInventoryRow | null
  >(null);

  const hosts = useMemo(
    () => Array.from(
      new Set(
        data.map(
          (row) => row.hostname,
        ),
      ),
    ).sort(),
    [data],
  );

  const filteredRows = useMemo(() => {
    const normalizedSearch = search
      .trim()
      .toLowerCase();

    return data.filter((row) => {
      if (
        selectedHost !== "all"
        && row.hostname !== selectedHost
      ) {
        return false;
      }

      if (!normalizedSearch) {
        return true;
      }

      return [
        row.hostname,
        row.title,
        row.url,
        row.final_url,
      ].some((value) => (
        String(value || "")
          .toLowerCase()
          .includes(
            normalizedSearch,
          )
      ));
    });
  }, [
    data,
    search,
    selectedHost,
  ]);

  if (error) {
    return (
      <Alert severity="error">
        Screenshots konnten nicht geladen werden.
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
          gap: 3,
          mb: 3,
        }}
      >
        <Box>
          <Typography
            variant="h4"
            sx={{ fontWeight: 800 }}
          >
            Web Application Gallery
          </Typography>

          <Typography
            color="text.secondary"
          >
            Visuelle Übersicht der erkannten Webanwendungen
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={
            <RefreshIcon />
          }
          disabled={isFetching}
          onClick={() => {
            void refetch();
          }}
        >
          {isFetching
            ? "Refreshing..."
            : "Refresh"}
        </Button>
      </Box>

      <Alert
        severity="info"
        icon={<ImageSearchIcon />}
        sx={{ mb: 3 }}
      >
        Es werden ausschließlich erreichbare HTML-Seiten dargestellt.
        Technische Ressourcen wie JavaScript, JSON und CSS werden nicht
        fotografiert.
      </Alert>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns:
            "minmax(300px, 1fr) 260px auto",
          gap: 2,
          mb: 3,
        }}
      >
        <TextField
          label="Search host, title or URL"
          value={search}
          onChange={(event) => {
            setSearch(
              event.target.value,
            );
          }}
        />

        <FormControl>
          <InputLabel id="host-filter-label">
            Host
          </InputLabel>

          <Select
            labelId="host-filter-label"
            label="Host"
            value={selectedHost}
            onChange={(event) => {
              setSelectedHost(
                String(
                  event.target.value,
                ),
              );
            }}
          >
            <MenuItem value="all">
              All hosts
            </MenuItem>

            {hosts.map((host) => (
              <MenuItem
                key={host}
                value={host}
              >
                {host}
              </MenuItem>
            ))}
          </Select>
        </FormControl>

        <Chip
          label={
            `${filteredRows.length} screenshots`
          }
          color="primary"
          sx={{
            height: 56,
            px: 1,
            fontWeight: 800,
          }}
        />
      </Box>

      {isLoading && (
        <LinearProgress sx={{ mb: 3 }} />
      )}

      {!isLoading
      && filteredRows.length === 0 && (
        <Alert severity="warning">
          Keine passenden Screenshots vorhanden.
        </Alert>
      )}

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns:
            "repeat(auto-fill, minmax(320px, 1fr))",
          gap: 3,
        }}
      >
        {filteredRows.map((row) => (
          <ScreenshotCard
            key={row.id}
            row={row}
            onOpen={setSelectedRow}
          />
        ))}
      </Box>

      <ScreenshotDialog
        row={selectedRow}
        onClose={() => {
          setSelectedRow(null);
        }}
      />
    </Box>
  );
}
