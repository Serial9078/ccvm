import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Drawer,
  Link,
  Typography,
} from "@mui/material";

import type { Finding } from "../api";
import StatusChip from "../../../shared/components/StatusChip";
import CopyField from "../../../shared/components/CopyField";
import { severityColor } from "../../../shared/severity";

interface Props {
  open: boolean;
  finding: Finding | null;
  onClose: () => void;
}


export default function FindingDrawer({ open, finding, onClose }: Props) {
  const references = finding?.reference
    ? finding.reference.split("\n").filter(Boolean)
    : [];

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={onClose}
      slotProps={{
        paper: {
          sx: {
            width: 560,
            p: 3,
            bgcolor: "background.paper",
          },
        },
      }}
    >
      {!finding && <Typography>No Finding selected.</Typography>}

      {finding && (
        <>
          <Typography variant="h5" sx={{ fontWeight: 800, mb: 2 }}>
            {finding.name}
          </Typography>

          <Box sx={{ display: "flex", gap: 1, mb: 3, flexWrap: "wrap" }}>
            <Chip
              label={finding.severity.toUpperCase()}
              size="small"
              sx={{
                bgcolor: severityColor(finding.severity),
                color: "#fff",
                fontWeight: 800,
              }}
            />
            <StatusChip status={finding.status} />

            {finding.cvss_score && (
              <Chip label={`CVSS ${finding.cvss_score}`} size="small" color="warning" />
            )}

            {finding.cve && (
              <Chip label={finding.cve} size="small" color="error" />
            )}
          </Box>

          <Card sx={{ mb: 3 }}>
            <CardContent>
              <CopyField label="Host" value={finding.host} />
              <CopyField label="Scanner" value={finding.scanner} />
              <CopyField label="Template" value={finding.template_id} />
              <CopyField label="Matched At" value={finding.matched_at} />
            </CardContent>
          </Card>

          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1, fontWeight: 700 }}>
                Description
              </Typography>
              <Typography color="text.secondary">
                {finding.description || "-"}
              </Typography>
            </CardContent>
          </Card>

          <Card sx={{ mb: 3 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1, fontWeight: 700 }}>
                Recommendation
              </Typography>
              <Typography color="text.secondary">
                {finding.remediation || "-"}
              </Typography>
            </CardContent>
          </Card>

          <Divider sx={{ my: 3 }} />

          <Typography variant="h6" sx={{ mb: 1, fontWeight: 700 }}>
            References
          </Typography>

          {references.length === 0 && (
            <Typography color="text.secondary">-</Typography>
          )}

          {references.map((ref) => (
            <Box key={ref} sx={{ mb: 1 }}>
              <Link href={ref} target="_blank" rel="noreferrer" underline="hover">
                {ref}
              </Link>
            </Box>
          ))}
        </>
      )}
    </Drawer>
  );
}
