import { Card, CardContent, Typography } from "@mui/material";
import { PieChart } from "@mui/x-charts/PieChart";
import { severityColor } from "../severity";

interface ChartPoint {
  label: string;
  value: number;
}

interface Props {
  title: string;
  data: ChartPoint[];
}

function colorForLabel(label: string) {
  const key = label.toLowerCase();

  if (["critical", "high", "medium", "low", "info"].includes(key)) {
    return severityColor(key);
  }

  return "#6366f1";
}

export default function DonutChartCard({ title, data }: Props) {
  const chartData = data
    .filter((item) => item.value > 0)
    .map((item, index) => ({
      id: index,
      value: item.value,
      label: item.label,
      color: colorForLabel(item.label),
    }));

  return (
    <Card sx={{ height: "100%" }}>
      <CardContent>
        <Typography variant="h6" sx={{ mb: 2, fontWeight: 700 }}>
          {title}
        </Typography>

        {chartData.length === 0 ? (
          <Typography color="text.secondary">No data available</Typography>
        ) : (
          <PieChart
            series={[
              {
                data: chartData,
                innerRadius: 65,
                paddingAngle: 3,
                cornerRadius: 5,
              },
            ]}
            height={280}
          />
        )}
      </CardContent>
    </Card>
  );
}
