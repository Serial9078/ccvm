import {
  Box,
  IconButton,
  Tooltip,
  Typography,
} from "@mui/material";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";

interface Props {
  label: string;
  value?: string | null;
}

export default function CopyField({ label, value }: Props) {
  const copy = async () => {
    if (!value) return;
    await navigator.clipboard.writeText(value);
  };

  return (
    <Box sx={{ mb: 2 }}>
      <Typography variant="overline" color="text.secondary">
        {label}
      </Typography>

      <Box
        sx={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 1,
        }}
      >
        <Typography sx={{ wordBreak: "break-word" }}>
          {value || "-"}
        </Typography>

        {value && (
          <Tooltip title="Copy">
            <IconButton size="small" onClick={copy}>
              <ContentCopyIcon fontSize="inherit" />
            </IconButton>
          </Tooltip>
        )}
      </Box>
    </Box>
  );
}
