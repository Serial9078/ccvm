import { Box, Card, CardContent, Chip, LinearProgress, Typography } from "@mui/material";

interface Props {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function SecurityScore({ critical, high, medium, low }: Props) {
  let score = 100;

  score -= critical * 25;
  score -= high * 10;
  score -= medium * 5;
  score -= low;

  score = Math.max(score, 0);

  const riskLabel = score >= 90 ? "LOW RISK" : score >= 70 ? "MEDIUM RISK" : "HIGH RISK";
  const riskColor = score >= 90 ? "success" : score >= 70 ? "warning" : "error";
  const posture =
    score >= 90 ? "Excellent Security Posture" : score >= 70 ? "Needs Attention" : "Critical Exposure";

  return (
    <Card sx={{ mb: 4 }}>
      <CardContent>
        <Box sx={{ display: "flex", justifyContent: "space-between", alignItems: "center", mb: 2 }}>
          <Box>
            <Typography variant="h5" sx={{ fontWeight: 700 }}>
              Security Score
            </Typography>
            <Typography color="text.secondary">{posture}</Typography>
          </Box>

          <Chip label={riskLabel} color={riskColor} variant="filled" />
        </Box>

        <Typography variant="h2" sx={{ fontWeight: 800, mb: 2 }}>
          {score} %
        </Typography>

        <LinearProgress
          variant="determinate"
          value={score}
          sx={{
            height: 18,
            borderRadius: 10,
          }}
        />
      </CardContent>
    </Card>
  );
}
