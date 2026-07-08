import { useEffect, useState } from "react";
import { Box, Chip, Typography } from "@mui/material";

interface Props {
  title: string;
}

export default function DashboardHeader({ title }: Props) {
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const interval = window.setInterval(() => {
      setNow(new Date());
    }, 5000);

    return () => window.clearInterval(interval);
  }, []);

  return (
    <Box
      sx={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        mb: 3,
      }}
    >
      <Box>
        <Typography variant="h4" sx={{ fontWeight: 800 }}>
          {title}
        </Typography>
        <Typography color="text.secondary">
          Last refresh: {now.toLocaleTimeString("de-DE")}
        </Typography>
      </Box>

      <Chip label="● LIVE · 5s refresh" color="success" sx={{ fontWeight: 800 }} />
    </Box>
  );
}
