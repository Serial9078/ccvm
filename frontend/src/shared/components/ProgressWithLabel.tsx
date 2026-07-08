import { Box, LinearProgress, Typography } from "@mui/material";

interface Props {
  value: number;
}

export default function ProgressWithLabel({ value }: Props) {
  const normalized = Math.max(0, Math.min(100, value));

  return (
    <Box sx={{ display: "flex", alignItems: "center", gap: 2, width: "100%" }}>
      <Box sx={{ flex: 1 }}>
        <LinearProgress
          variant="determinate"
          value={normalized}
          sx={{
            height: 8,
            borderRadius: 8,
          }}
        />
      </Box>

      <Typography variant="body2" sx={{ minWidth: 42, fontWeight: 700 }}>
        {normalized} %
      </Typography>
    </Box>
  );
}
