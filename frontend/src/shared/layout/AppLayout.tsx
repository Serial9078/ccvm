import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import AssessmentIcon from "@mui/icons-material/Assessment";
import BugReportIcon from "@mui/icons-material/BugReport";
import BusinessIcon from "@mui/icons-material/Business";
import DashboardIcon from "@mui/icons-material/Dashboard";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import DevicesIcon from "@mui/icons-material/Devices";
import DnsIcon from "@mui/icons-material/Dns";
import DomainIcon from "@mui/icons-material/Domain";
import ImageSearchIcon from "@mui/icons-material/ImageSearch";
import LanIcon from "@mui/icons-material/Lan";
import LinkIcon from "@mui/icons-material/Link";
import MemoryIcon from "@mui/icons-material/Memory";
import MenuIcon from "@mui/icons-material/Menu";
import PublicIcon from "@mui/icons-material/Public";
import RadarIcon from "@mui/icons-material/Radar";
import SettingsIcon from "@mui/icons-material/Settings";
import StorageIcon from "@mui/icons-material/Storage";
import TerminalIcon from "@mui/icons-material/Terminal";
import VpnKeyIcon from "@mui/icons-material/VpnKey";
import {
  Box,
  Chip,
  Drawer,
  IconButton,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
  useMediaQuery,
  useTheme,
} from "@mui/material";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { customerNavigationSearch, navigationGroups } from "./navigation";

const icons = {
  domain: <DomainIcon fontSize="small" />,
  link: <LinkIcon fontSize="small" />,
  network: <LanIcon fontSize="small" />,
  server: <DnsIcon fontSize="small" />,
  client: <DesktopWindowsIcon fontSize="small" />,
  terminal: <TerminalIcon fontSize="small" />,
  virtualization: <StorageIcon fontSize="small" />,
  radar: <RadarIcon fontSize="small" />,
  finding: <BugReportIcon fontSize="small" />,
  pipeline: <AccountTreeIcon fontSize="small" />,
  report: <AssessmentIcon fontSize="small" />,
  inventory: <VpnKeyIcon fontSize="small" />,
  public: <PublicIcon fontSize="small" />,
  technology: <MemoryIcon fontSize="small" />,
  image: <ImageSearchIcon fontSize="small" />,
  devices: <DevicesIcon fontSize="small" />,
  settings: <SettingsIcon fontSize="small" />,
};

export function AppLayout() {
  const [navigationOpen, setNavigationOpen] = useState(false);
  const theme = useTheme();
  const desktop = useMediaQuery(theme.breakpoints.up("md"));
  useEffect(() => {
    if (desktop) setNavigationOpen(false);
  }, [desktop]);
  const location = useLocation();
  const customerSearch = customerNavigationSearch(location.search);
  const item = (label: string, path: string, icon: ReactNode) => (
    <ListItemButton
      key={path}
      component={NavLink}
      to={{ pathname: path, search: customerSearch }}
      end
      onClick={() => setNavigationOpen(false)}
      sx={{
        borderRadius: 2,
        minHeight: 40,
        py: 0.5,
        mb: 0.25,
        "&.active": { bgcolor: "rgba(56, 189, 248, 0.16)", color: "primary.main" },
      }}
    >
      <ListItemIcon sx={{ color: "inherit", minWidth: 34 }}>{icon}</ListItemIcon>
      <ListItemText primary={label} slotProps={{ primary: { variant: "body2" } }} />
    </ListItemButton>
  );
  const navigation = (
    <Box component="nav" aria-label="Hauptnavigation" sx={{ p: 1.5 }}>
      <List disablePadding>
        {item("Dashboard", "/dashboard", <DashboardIcon fontSize="small" />)}
        {item("Kunden", "/customers", <BusinessIcon fontSize="small" />)}
      </List>
      {navigationGroups.map((group) => (
        <Box key={group.label} sx={{ mt: 2 }}>
          <Typography
            component="h2"
            variant="overline"
            sx={{ color: "text.secondary", display: "block", px: 1.5, mb: 0.5, lineHeight: 1.6 }}
          >
            {group.label}
          </Typography>
          <List disablePadding aria-label={group.label}>
            {group.items.map((entry) => item(entry.label, entry.path, icons[entry.icon]))}
          </List>
        </Box>
      ))}
    </Box>
  );
  return (
    <Box sx={{ minHeight: "100vh", bgcolor: "background.default" }}>
      <Box
        component="header"
        sx={{
          minHeight: 64,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 2,
          px: { xs: 1.5, md: 3 },
          bgcolor: "background.paper",
          borderBottom: "1px solid",
          borderColor: "divider",
        }}
      >
        <Box sx={{ display: "flex", alignItems: "center", minWidth: 0, gap: 1 }}>
          <IconButton
            aria-label="Navigation öffnen"
            onClick={() => setNavigationOpen(true)}
            sx={{ display: { md: "none" } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" sx={{ fontSize: { xs: "0.95rem", sm: "1.15rem" } }}>
            CloudCollab Vulnerability Manager
          </Typography>
        </Box>
        <Chip
          label="Web & Infrastruktur"
          color="primary"
          size="small"
          variant="outlined"
          sx={{ display: { xs: "none", sm: "inline-flex" } }}
        />
      </Box>
      <Box sx={{ display: "flex", alignItems: "flex-start" }}>
        <Box
          component="aside"
          sx={{
            width: 240,
            flexShrink: 0,
            position: "sticky",
            top: 0,
            maxHeight: "100vh",
            overflowY: "auto",
            borderRight: "1px solid",
            borderColor: "divider",
            display: { xs: "none", md: "block" },
          }}
        >
          {navigation}
        </Box>
        <Drawer
          open={navigationOpen && !desktop}
          onClose={() => setNavigationOpen(false)}
          sx={{ display: { xs: "block", md: "none" } }}
          slotProps={{ paper: { sx: { width: 260 } } }}
        >
          {navigation}
        </Drawer>
        <Box component="main" sx={{ flex: 1, minWidth: 0, p: { xs: 2, md: 3 } }}>
          <Outlet />
        </Box>
      </Box>
    </Box>
  );
}
