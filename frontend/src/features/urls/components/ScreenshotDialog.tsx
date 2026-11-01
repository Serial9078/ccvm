import CloseIcon from "@mui/icons-material/Close";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";

import {
  Box,
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Link,
  Typography,
} from "@mui/material";

import type {
  UrlInventoryRow,
} from "../api";

import {
  screenshotUrl,
} from "../utils";


interface ScreenshotDialogProps {
  row: UrlInventoryRow | null;
  onClose: () => void;
}


export function ScreenshotDialog({
  row,
  onClose,
}: ScreenshotDialogProps) {
  const imageUrl = screenshotUrl(
    row?.screenshot
      ?.screenshot_path,
  );

  return (
    <Dialog
      open={Boolean(
        row && imageUrl,
      )}
      onClose={onClose}
      maxWidth="xl"
      fullWidth
    >
      <DialogTitle
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 2,
        }}
      >
        <Box sx={{ flex: 1 }}>
          <Typography
            variant="h6"
            sx={{
              fontWeight: 800,
            }}
          >
            {row?.screenshot?.title
              || row?.detail?.title
              || "Screenshot"}
          </Typography>

          {row?.url && (
            <Link
              href={row.url}
              target="_blank"
              rel="noreferrer"
              sx={{
                display:
                  "inline-flex",
                alignItems:
                  "center",
                gap: 0.5,
                fontSize: 13,
                wordBreak:
                  "break-all",
              }}
            >
              {row.url}

              <OpenInNewIcon
                fontSize="inherit"
              />
            </Link>
          )}
        </Box>

        <IconButton
          onClick={onClose}
          aria-label="Close screenshot"
        >
          <CloseIcon />
        </IconButton>
      </DialogTitle>

      <DialogContent>
        {!imageUrl ? (
          <Typography
            color="text.secondary"
          >
            No screenshot available.
          </Typography>
        ) : (
          <Box
            component="img"
            src={imageUrl}
            alt={
              row?.screenshot?.title
              || row?.url
              || "Screenshot"
            }
            sx={{
              width: "100%",
              display: "block",
              borderRadius: 2,
              border:
                "1px solid",
              borderColor:
                "divider",
            }}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}
