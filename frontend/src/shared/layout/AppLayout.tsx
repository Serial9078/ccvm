import DashboardIcon from "@mui/icons-material/Dashboard";
import BusinessIcon from "@mui/icons-material/Business";
import DomainIcon from "@mui/icons-material/Domain";
import PublicIcon from "@mui/icons-material/Public";
import DnsIcon from "@mui/icons-material/Dns";
import LanIcon from "@mui/icons-material/Lan";
import MemoryIcon from "@mui/icons-material/Memory";
import DevicesIcon from "@mui/icons-material/Devices";
import RadarIcon from "@mui/icons-material/Radar";
import BugReportIcon from "@mui/icons-material/BugReport";
import AssessmentIcon from "@mui/icons-material/Assessment";
import SettingsIcon from "@mui/icons-material/Settings";
import { Box, Chip, List, ListItemButton, ListItemIcon, ListItemText, Typography } from "@mui/material";
import { NavLink, Outlet } from "react-router-dom";

const navItems = [
  { label: "Dashboard", path: "/dashboard", icon: <DashboardIcon /> },
  { label: "Customers", path: "/customers", icon: <BusinessIcon /> },
  { label: "Domains", path: "/domains", icon: <DomainIcon /> },
  { label: "Subdomains", path: "/subdomains", icon: <PublicIcon /> },
  { label: "Hosts", path: "/hosts", icon: <DnsIcon /> },
  { label: "Ports", path: "/ports", icon: <LanIcon /> },
  { label: "Technologies", path: "/technologies", icon: <MemoryIcon /> },
  { label: "Assets", path: "/assets", icon: <DevicesIcon /> },
  { label: "Scans", path: "/scans", icon: <RadarIcon /> },
  { label: "Findings", path: "/findings", icon: <BugReportIcon /> },
  { label: "Reports", path: "/reports", icon: <AssessmentIcon /> },
  { label: "Settings", path: "/settings", icon: <SettingsIcon /> },
];

export function AppLayout() {
  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
      <Box
        sx={{
          height: 72,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          px: 3,
          bgcolor: "background.paper",
          borderBottom: "1px solid #1e293b",
        }}
      >
        <Typography variant="h6">CloudCollab Vulnerability Manager</Typography>
        <Chip label="v3.1 Discovery" color="primary" size="small" />
      </Box>

      <Box sx={{ display: "flex" }}>
        <Box
          sx={{
            width: 260,
            minHeight: "calc(100vh - 72px)",
            borderRight: "1px solid #1e293b",
            p: 2,
          }}
        >
          <Typography variant="overline" sx={{ color: "text.secondary", mb: 2, display: "block" }}>
            Navigation
          </Typography>

          <List>
            {navItems.map((item) => (
              <ListItemButton
                key={item.path}
                component={NavLink}
                to={item.path}
                sx={{
                  borderRadius: 3,
                  mb: 1,
                  "&.active": {
                    bgcolor: "rgba(56, 189, 248, 0.16)",
                    color: "primary.main",
                  },
                }}
              >
                <ListItemIcon sx={{ color: "inherit", minWidth: 40 }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItemButton>
            ))}
          </List>
        </Box>

        <Box sx={{ flex: 1, p: 4, overflow: "auto" }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
