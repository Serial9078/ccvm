import { useState } from "react";

import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import ErrorIcon from "@mui/icons-material/Error";
import ExpandLessIcon from "@mui/icons-material/ExpandLess";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import HourglassEmptyIcon from "@mui/icons-material/HourglassEmpty";
import PauseCircleIcon from "@mui/icons-material/PauseCircle";
import PlayCircleIcon from "@mui/icons-material/PlayCircle";
import RefreshIcon from "@mui/icons-material/Refresh";
import SkipNextIcon from "@mui/icons-material/SkipNext";

import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Collapse,
  Divider,
  LinearProgress,
  Typography,
} from "@mui/material";

import type {
  Pipeline,
  PipelineJob,
} from "./api";

import { usePipelines } from "./hooks";


function statusColor(
  status: string,
):
  | "success"
  | "error"
  | "warning"
  | "info"
  | "default" {
  switch (status.toLowerCase()) {
    case "finished":
      return "success";

    case "failed":
      return "error";

    case "running":
      return "info";

    case "queued":
      return "warning";

    case "skipped":
    case "partial":
      return "default";

    default:
      return "default";
  }
}


function statusIcon(
  status: string,
) {
  switch (status.toLowerCase()) {
    case "finished":
      return (
        <CheckCircleIcon
          color="success"
          fontSize="small"
        />
      );

    case "failed":
      return (
        <ErrorIcon
          color="error"
          fontSize="small"
        />
      );

    case "running":
      return (
        <CircularProgress
          size={18}
          thickness={5}
        />
      );

    case "queued":
      return (
        <HourglassEmptyIcon
          color="warning"
          fontSize="small"
        />
      );

    case "skipped":
      return (
        <SkipNextIcon
          color="disabled"
          fontSize="small"
        />
      );

    default:
      return (
        <PauseCircleIcon
          color="disabled"
          fontSize="small"
        />
      );
  }
}


function PipelineStage({
  job,
  isLast,
}: {
  job: PipelineJob;
  isLast: boolean;
}) {
  return (
    <Box
      sx={{
        position: "relative",
        display: "grid",
        gridTemplateColumns:
          "40px minmax(160px, 220px) 130px 1fr",
        gap: 2,
        alignItems: "center",
        py: 2,
      }}
    >
      <Box
        sx={{
          position: "relative",
          display: "flex",
          justifyContent: "center",
          alignItems: "center",
          zIndex: 1,
        }}
      >
        {statusIcon(job.status)}

        {!isLast && (
          <Box
            sx={{
              position: "absolute",
              top: 24,
              width: 2,
              height: 42,
              bgcolor: "divider",
              zIndex: -1,
            }}
          />
        )}
      </Box>

      <Box>
        <Typography
          sx={{
            fontWeight: 800,
            textTransform: "uppercase",
          }}
        >
          {job.plugin}
        </Typography>

        <Typography
          variant="caption"
          color="text.secondary"
        >
          Job #{job.id}
          {job.parent_job_id
            ? ` · Parent #${job.parent_job_id}`
            : " · Root Stage"}
        </Typography>
      </Box>

      <Chip
        label={job.status.toUpperCase()}
        color={statusColor(job.status)}
        size="small"
        variant={
          job.status === "running"
            ? "filled"
            : "outlined"
        }
        sx={{
          fontWeight: 800,
          justifySelf: "start",
        }}
      />

      <Box>
        <Box
          sx={{
            display: "flex",
            justifyContent: "space-between",
            gap: 2,
            mb: 0.75,
          }}
        >
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {job.message || "-"}
          </Typography>

          <Typography
            variant="body2"
            sx={{
              fontWeight: 700,
              minWidth: 42,
              textAlign: "right",
            }}
          >
            {job.progress}%
          </Typography>
        </Box>

        <LinearProgress
          variant="determinate"
          value={Math.min(
            100,
            Math.max(0, job.progress),
          )}
          color={
            job.status === "failed"
              ? "error"
              : job.status === "finished"
                ? "success"
                : "primary"
          }
          sx={{
            height: 8,
            borderRadius: 999,
          }}
        />
      </Box>
    </Box>
  );
}


function PipelineCard({
  pipeline,
}: {
  pipeline: Pipeline;
}) {
  const [expanded, setExpanded] = useState(
    pipeline.status === "running"
    || pipeline.status === "failed",
  );

  return (
    <Card
      sx={{
        mb: 2,
        border:
          pipeline.status === "running"
            ? "1px solid"
            : undefined,
        borderColor:
          pipeline.status === "running"
            ? "primary.main"
            : undefined,
      }}
    >
      <CardContent>
        <Box
          sx={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 3,
          }}
        >
          <Box sx={{ minWidth: 0 }}>
            <Box
              sx={{
                display: "flex",
                alignItems: "center",
                gap: 1.5,
                mb: 1,
                flexWrap: "wrap",
              }}
            >
              <Typography
                variant="h6"
                sx={{ fontWeight: 800 }}
              >
                {pipeline.domain_name
                  || pipeline.asset_name
                  || pipeline.asset_target
                  || `Domain #${pipeline.domain_id ?? "-"}`}
              </Typography>

              <Chip
                label={pipeline.status.toUpperCase()}
                size="small"
                color={statusColor(
                  pipeline.status,
                )}
                sx={{ fontWeight: 800 }}
              />
            </Box>

            <Typography
              variant="body2"
              color="text.secondary"
              sx={{
                wordBreak: "break-all",
              }}
            >
              Pipeline: {pipeline.pipeline_id}
            </Typography>
          </Box>

          <Button
            variant="text"
            endIcon={
              expanded
                ? <ExpandLessIcon />
                : <ExpandMoreIcon />
            }
            onClick={() => {
              setExpanded(
                (current) => !current,
              );
            }}
          >
            {expanded
              ? "Collapse"
              : "Details"}
          </Button>
        </Box>

        <Box
          sx={{
            display: "grid",
            gridTemplateColumns:
              "repeat(6, minmax(0, 1fr))",
            gap: 1.5,
            mt: 3,
            mb: 2,
          }}
        >
          <Chip
            label={`Total ${pipeline.total_jobs}`}
            variant="outlined"
          />

          <Chip
            label={`Finished ${pipeline.finished_jobs}`}
            color="success"
            variant="outlined"
          />

          <Chip
            label={`Running ${pipeline.running_jobs}`}
            color="info"
            variant="outlined"
          />

          <Chip
            label={`Queued ${pipeline.queued_jobs}`}
            color="warning"
            variant="outlined"
          />

          <Chip
            label={`Failed ${pipeline.failed_jobs}`}
            color="error"
            variant="outlined"
          />

          <Chip
            label={`Skipped ${pipeline.skipped_jobs}`}
            variant="outlined"
          />
        </Box>

        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            gap: 2,
          }}
        >
          <LinearProgress
            variant="determinate"
            value={pipeline.progress}
            color={
              pipeline.status === "failed"
                ? "error"
                : pipeline.status === "finished"
                  ? "success"
                  : "primary"
            }
            sx={{
              flex: 1,
              height: 10,
              borderRadius: 999,
            }}
          />

          <Typography
            sx={{
              fontWeight: 800,
              minWidth: 48,
              textAlign: "right",
            }}
          >
            {pipeline.progress}%
          </Typography>
        </Box>

        <Collapse
          in={expanded}
          timeout="auto"
          unmountOnExit
        >
          <Divider sx={{ my: 3 }} />

          <Box>
            {pipeline.jobs.map(
              (job, index) => (
                <PipelineStage
                  key={job.id}
                  job={job}
                  isLast={
                    index
                    === pipeline.jobs.length - 1
                  }
                />
              ),
            )}
          </Box>
        </Collapse>
      </CardContent>
    </Card>
  );
}


export function Pipelines() {
  const {
    data = [],
    isLoading,
    isFetching,
    error,
    refetch,
  } = usePipelines();

  if (error) {
    return (
      <Alert severity="error">
        Pipelines konnten nicht geladen werden.
      </Alert>
    );
  }

  return (
    <Box>
      <Box
        sx={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 3,
          mb: 3,
        }}
      >
        <Box>
          <Typography
            variant="h4"
            sx={{ fontWeight: 800 }}
          >
            Discovery Pipelines
          </Typography>

          <Typography color="text.secondary">
            Live-Status aller abhängigen Discovery-Stufen
          </Typography>
        </Box>

        <Button
          variant="outlined"
          startIcon={<RefreshIcon />}
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
        icon={<PlayCircleIcon />}
        sx={{ mb: 3 }}
      >
        Die Ansicht aktualisiert sich automatisch alle drei Sekunden.
        Eine Stufe startet erst, wenn ihr Parent-Job erfolgreich beendet wurde.
      </Alert>

      {isLoading && (
        <LinearProgress sx={{ mb: 3 }} />
      )}

      {!isLoading && data.length === 0 && (
        <Alert severity="warning">
          Noch keine Pipeline-Läufe vorhanden.
        </Alert>
      )}

      {data.map((pipeline) => (
        <PipelineCard
          key={pipeline.pipeline_id}
          pipeline={pipeline}
        />
      ))}
    </Box>
  );
}
