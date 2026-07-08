import { Chip } from "@mui/material";

interface Props {
  status: string;
}

export default function StatusChip({ status }: Props) {
  const value = status.toLowerCase();

  const colors: Record<string, string> = {
    open: "#ef4444",
    fixed: "#22c55e",
    accepted: "#8b5cf6",
    progress: "#f59e0b",
    "in progress": "#f59e0b",
  };

  return (
    <Chip
      label={status.toUpperCase()}
      size="small"
      sx={{
        bgcolor: colors[value] ?? "#64748b",
        color: "#fff",
        fontWeight: 700,
      }}
    />
  );
}
