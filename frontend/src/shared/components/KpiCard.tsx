import {
  Card,
  CardContent,
  Typography,
  Box,
} from "@mui/material";

interface Props {
  title: string;
  value: number | string;
  color: string;
  subtitle?: string;
}

export default function KpiCard({
  title,
  value,
  color,
  subtitle,
}: Props) {
  return (
    <Card
      sx={{
        height: "100%",
        borderLeft: `6px solid ${color}`,
        transition: "all .25s ease",
        "&:hover": {
          transform: "translateY(-3px)",
          boxShadow: `0 0 18px ${color}55`,
        },
      }}
    >
      <CardContent>

        <Typography
          variant="overline"
          sx={{
            color: "text.secondary",
            fontWeight: 700,
            letterSpacing: 1,
          }}
        >
          {title}
        </Typography>

        <Box
          sx={{
            display: "flex",
            alignItems: "center",
            mt: 1,
          }}
        >
          <Typography
            sx={{
              fontSize: 56,
              fontWeight: 800,
              color,
              lineHeight: 1,
            }}
          >
            {value}
          </Typography>
        </Box>

        {subtitle && (
          <Typography
            variant="body2"
            color="text.secondary"
            sx={{ mt: 1 }}
          >
            {subtitle}
          </Typography>
        )}

      </CardContent>
    </Card>
  );
}
