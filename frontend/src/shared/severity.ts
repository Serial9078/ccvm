export const severityColors = {
  critical: "#d32f2f",
  high: "#f57c00",
  medium: "#fbc02d",
  low: "#43a047",
  info: "#0288d1",
};

export function severityColor(severity: string) {
  return severityColors[
    (severity?.toLowerCase() as keyof typeof severityColors) ?? "info"
  ] ?? severityColors.info;
}
