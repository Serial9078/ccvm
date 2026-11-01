import CloseIcon from "@mui/icons-material/Close";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";

import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Drawer,
  IconButton,
  LinearProgress,
  Link,
  Typography,
} from "@mui/material";

import type {
  UrlFinding,
  UrlInventoryRow,
} from "../api";

import {
  isOpenFinding,
  scoreColor,
  screenshotUrl,
  severityColor,
  statusColor,
} from "../utils";

interface UrlDrawerProps {
  row: UrlInventoryRow | null;
  onClose: () => void;

  onOpenScreenshot: (
    row: UrlInventoryRow,
  ) => void;
}

function HeaderValue({
  label,
  present,
  value,
}: {
  label: string;
  present: boolean;
  value?: string | null;
}) {
  return (
    <Box
      sx={{
        mb: 2,
      }}
    >
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          gap: 1,
          mb: 0.5,
        }}
      >
        <Typography
          sx={{
            fontWeight: 700,
          }}
        >
          {label}
        </Typography>

        <Chip
          label={
            present
              ? "PRESENT"
              : "MISSING"
          }
          size="small"
          color={
            present
              ? "success"
              : "error"
          }
          variant="outlined"
        />
      </Box>

      <Typography
        variant="body2"
        color="text.secondary"
        sx={{
          whiteSpace: "pre-wrap",
          wordBreak: "break-word",
        }}
      >
        {value || "-"}
      </Typography>
    </Box>
  );
}

function FindingItem({
  finding,
}: {
  finding: UrlFinding;
}) {
  return (
    <Accordion
      disableGutters
      sx={{
        mb: 1,
        border: "1px solid",
        borderColor: "divider",
        "&::before": {
          display: "none",
        },
      }}
    >
      <AccordionSummary
        expandIcon={<ExpandMoreIcon />}
      >
        <Box
          sx={{
            width: "100%",
            display: "flex",
            gap: 1,
            alignItems: "center",
            pr: 2,
          }}
        >
          <Chip
            label={
              finding.severity
                .toUpperCase()
            }
            size="small"
            color={severityColor(
              finding.severity,
            )}
            sx={{
              minWidth: 78,
              fontWeight: 800,
            }}
          />

          <Typography
            sx={{
              flex: 1,
              minWidth: 0,
              fontWeight: 700,
              overflow: "hidden",
              textOverflow:
                "ellipsis",
              whiteSpace: "nowrap",
            }}
          >
            {finding.name}
          </Typography>

          <Chip
            label={finding.scanner}
            size="small"
            variant="outlined"
          />
        </Box>
      </AccordionSummary>

      <AccordionDetails>
        <Typography variant="overline">
          Template
        </Typography>

        <Typography
          sx={{
            mb: 2,
            wordBreak: "break-all",
          }}
        >
          {finding.template_id || "-"}
        </Typography>

        <Typography variant="overline">
          Matched at
        </Typography>

        <Typography
          sx={{
            mb: 2,
            wordBreak: "break-all",
          }}
        >
          {finding.matched_at || "-"}
        </Typography>

        <Box
          sx={{
            display: "flex",
            flexWrap: "wrap",
            gap: 1,
            mb: 2,
          }}
        >
          {finding.cve && (
            <Chip
              label={finding.cve}
              color="error"
              variant="outlined"
            />
          )}

          {finding.cvss_score
            !== null
          && finding.cvss_score
            !== undefined && (
              <Chip
                label={
                  `CVSS ${
                    finding.cvss_score
                  }`
                }
                color="warning"
                variant="outlined"
              />
            )}

          <Chip
            label={
              finding.status
                .toUpperCase()
            }
            variant="outlined"
          />
        </Box>

        <Typography variant="overline">
          Description
        </Typography>

        <Typography
          sx={{
            mb: 2,
            whiteSpace: "pre-wrap",
          }}
        >
          {finding.description || "-"}
        </Typography>

        <Typography variant="overline">
          Remediation
        </Typography>

        <Typography
          sx={{
            mb: 2,
            whiteSpace: "pre-wrap",
          }}
        >
          {finding.remediation || "-"}
        </Typography>

        {finding.reference && (
          <>
            <Typography variant="overline">
              References
            </Typography>

            <Typography
              sx={{
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {finding.reference}
            </Typography>
          </>
        )}
      </AccordionDetails>
    </Accordion>
  );
}

export function UrlDrawer({
  row,
  onClose,
  onOpenScreenshot,
}: UrlDrawerProps) {
  if (!row) {
    return (
      <Drawer
        anchor="right"
        open={false}
        onClose={onClose}
      />
    );
  }

  const imageUrl = screenshotUrl(
    row.screenshot?.screenshot_path,
  );

  const status =
    row.detail?.status_code
    ?? row.status_code
    ?? row.security?.status_code
    ?? null;

  const score =
    row.security?.security_score
    ?? null;

  const openFindings =
    row.findings.filter(
      isOpenFinding,
    );

  return (
    <Drawer
      anchor="right"
      open
      onClose={onClose}
      slotProps={{
        paper: {
          sx: {
            width: {
              xs: "100%",
              md: 760,
            },
            p: 3,
          },
        },
      }}
    >
      <Box
        sx={{
          display: "flex",
          alignItems: "flex-start",
          gap: 2,
          mb: 3,
        }}
      >
        <Box sx={{ flex: 1 }}>
          <Typography
            variant="h5"
            sx={{
              fontWeight: 800,
              mb: 0.5,
            }}
          >
            URL Intelligence
          </Typography>

          <Link
            href={row.url}
            target="_blank"
            rel="noreferrer"
            sx={{
              display: "inline-flex",
              alignItems: "center",
              gap: 0.5,
              wordBreak: "break-all",
            }}
          >
            {row.url}
            <OpenInNewIcon
              fontSize="inherit"
            />
          </Link>
        </Box>

        <IconButton
          onClick={onClose}
        >
          <CloseIcon />
        </IconButton>
      </Box>

      <Box
        sx={{
          display: "flex",
          flexWrap: "wrap",
          gap: 1,
          mb: 3,
        }}
      >
        <Chip
          label={row.method}
          variant="outlined"
        />

        <Chip
          label={
            status !== null
              ? String(status)
              : "UNKNOWN"
          }
          color={statusColor(status)}
        />

        <Chip
          label={
            `${openFindings.length} open findings`
          }
          color={
            openFindings.length > 0
              ? "error"
              : "success"
          }
          variant="outlined"
        />
      </Box>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography
            variant="h6"
            sx={{
              fontWeight: 800,
              mb: 1,
            }}
          >
            Security Score
          </Typography>

          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 2,
            }}
          >
            <Box sx={{ flex: 1 }}>
              <LinearProgress
                variant="determinate"
                value={score ?? 0}
                color={scoreColor(score)}
                sx={{
                  height: 12,
                  borderRadius: 6,
                }}
              />
            </Box>

            <Chip
              label={
                score !== null
                  ? `${score}/100`
                  : "Not checked"
              }
              color={scoreColor(score)}
              sx={{
                fontWeight: 800,
              }}
            />
          </Box>
        </CardContent>
      </Card>

      {imageUrl && (
        <Card sx={{ mb: 3 }}>
          <CardContent>
            <Typography
              variant="h6"
              sx={{
                fontWeight: 800,
                mb: 2,
              }}
            >
              Screenshot
            </Typography>

            <Box
              component="img"
              src={imageUrl}
              alt={
                row.screenshot?.title
                || row.url
              }
              onClick={() => {
                onOpenScreenshot(row);
              }}
              sx={{
                width: "100%",
                maxHeight: 360,
                objectFit: "cover",
                objectPosition: "top",
                display: "block",
                borderRadius: 2,
                cursor: "pointer",
                border: "1px solid",
                borderColor: "divider",
              }}
            />

            <Button
              size="small"
              sx={{ mt: 2 }}
              onClick={() => {
                onOpenScreenshot(row);
              }}
            >
              Open fullscreen
            </Button>
          </CardContent>
        </Card>
      )}

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography
            variant="h6"
            sx={{
              fontWeight: 800,
              mb: 2,
            }}
          >
            Findings
          </Typography>

          {openFindings.length === 0 ? (
            <Alert severity="success">
              No open findings for this URL.
            </Alert>
          ) : (
            openFindings.map(
              (finding) => (
                <FindingItem
                  key={finding.id}
                  finding={finding}
                />
              ),
            )
          )}
        </CardContent>
      </Card>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography
            variant="h6"
            sx={{
              fontWeight: 800,
              mb: 2,
            }}
          >
            HTTP Intelligence
          </Typography>

          <Typography variant="overline">
            Title
          </Typography>

          <Typography sx={{ mb: 2 }}>
            {row.detail?.title
              || row.screenshot?.title
              || "-"}
          </Typography>

          <Typography variant="overline">
            Final URL
          </Typography>

          <Typography
            sx={{
              mb: 2,
              wordBreak: "break-all",
            }}
          >
            {row.detail?.final_url
              || row.screenshot?.final_url
              || "-"}
          </Typography>

          <Typography variant="overline">
            IP address
          </Typography>

          <Typography sx={{ mb: 2 }}>
            {row.detail?.ip_address || "-"}
          </Typography>

          <Typography variant="overline">
            Content type
          </Typography>

          <Typography sx={{ mb: 2 }}>
            {row.detail?.content_type
              || row.content_type
              || "-"}
          </Typography>

          <Typography variant="overline">
            Content length
          </Typography>

          <Typography sx={{ mb: 2 }}>
            {row.detail?.content_length
              ?.toLocaleString()
              || "-"}
          </Typography>

          <Typography variant="overline">
            Webserver
          </Typography>

          <Typography sx={{ mb: 2 }}>
            {row.detail?.webserver
              || row.security?.server
              || "-"}
          </Typography>

          <Typography variant="overline">
            Powered by
          </Typography>

          <Typography sx={{ mb: 2 }}>
            {row.security?.powered_by
              || "-"}
          </Typography>

          <Typography variant="overline">
            Response time
          </Typography>

          <Typography>
            {row.detail
              ?.response_time_seconds
              !== null
            && row.detail
              ?.response_time_seconds
              !== undefined
              ? `${
                  row.detail
                    .response_time_seconds
                    .toFixed(3)
                } s`
              : "-"}
          </Typography>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Typography
            variant="h6"
            sx={{
              fontWeight: 800,
              mb: 2,
            }}
          >
            Security Headers
          </Typography>

          <HeaderValue
            label="Strict-Transport-Security"
            present={
              Boolean(
                row.security
                  ?.hsts_present,
              )
            }
            value={
              row.security
                ?.strict_transport_security
            }
          />

          <HeaderValue
            label="Content-Security-Policy"
            present={
              Boolean(
                row.security
                  ?.csp_present,
              )
            }
            value={
              row.security
                ?.content_security_policy
            }
          />

          <HeaderValue
            label="X-Frame-Options"
            present={
              Boolean(
                row.security
                  ?.xfo_present,
              )
            }
            value={
              row.security
                ?.x_frame_options
            }
          />

          <HeaderValue
            label="X-Content-Type-Options"
            present={
              Boolean(
                row.security
                  ?.xcto_present,
              )
            }
            value={
              row.security
                ?.x_content_type_options
            }
          />

          <HeaderValue
            label="Referrer-Policy"
            present={
              Boolean(
                row.security
                  ?.referrer_policy_present,
              )
            }
            value={
              row.security
                ?.referrer_policy
            }
          />

          <HeaderValue
            label="Permissions-Policy"
            present={
              Boolean(
                row.security
                  ?.permissions_policy_present,
              )
            }
            value={
              row.security
                ?.permissions_policy
            }
          />

          <Typography variant="overline">
            Missing headers
          </Typography>

          <Typography
            color={
              row.security
                ?.missing_headers
                ? "error"
                : "success.main"
            }
            sx={{
              whiteSpace: "pre-wrap",
            }}
          >
            {row.security
              ?.missing_headers
              || "No missing headers detected"}
          </Typography>
        </CardContent>
      </Card>
    </Drawer>
  );
}
