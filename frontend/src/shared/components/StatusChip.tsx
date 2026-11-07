import { Chip } from "@mui/material";

interface Props {
  status: string;
}

export default function StatusChip({ status }: Props) {
  const value = status.toLowerCase();

  const colors: Record<string, string> = {
    open: "#991b1b",
    fixed: "#166534",
    accepted: "#404040",
    progress: "#92400e",
    "in progress": "#92400e",
  };

  return (
    <Chip
      label={status.toUpperCase()}
      size="small"
      sx={{
        bgcolor: colors[value] ?? "#404040",
        color: "#fff",
        fontWeight: 700,
      }}
    />
  );
}
