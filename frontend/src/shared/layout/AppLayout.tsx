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
import { cloudcollabBrand as brand } from "../theme/theme";

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
        borderRadius: 1.5,
        borderLeft: "3px solid transparent",
        color: "#d4d4d4",
        minHeight: 40,
        py: 0.5,
        mb: 0.25,
        "&:hover": { bgcolor: brand.raised, color: brand.white },
        "&.active": {
          bgcolor: brand.white,
          color: brand.black,
          borderLeftColor: brand.matrix,
          "&:hover": { bgcolor: "#e5e5e5", color: brand.black },
        },
        "&.Mui-focusVisible": { outline: `2px solid ${brand.matrix}`, outlineOffset: 2 },
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
          minHeight: 80,
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 2,
          px: { xs: 1.5, md: 3 },
          bgcolor: brand.black,
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
          <Box
            component={NavLink}
            to={{ pathname: "/dashboard", search: customerSearch }}
            aria-label="CloudCollab CCVM – Dashboard"
            sx={{
              display: "flex", alignItems: "center", gap: { xs: 1, sm: 1.5 }, minWidth: 0,
              color: brand.white, textDecoration: "none", borderRadius: 1,
              "&:focus-visible": { outline: `2px solid ${brand.matrix}`, outlineOffset: 3 },
            }}
          >
            <Box
              component="img"
              src="/assets/cloudcollab-logo.jpg"
              alt="CloudCollab"
              width={64}
              height={64}
              sx={{ width: { xs: 52, sm: 64 }, height: { xs: 52, sm: 64 }, objectFit: "contain" }}
            />
            <Box sx={{ pl: { xs: 1, sm: 1.5 }, borderLeft: "1px solid #444", minWidth: 0 }}>
              <Typography sx={{ fontWeight: 800, fontSize: { xs: 17, sm: 19 }, letterSpacing: ".08em", lineHeight: 1.1 }}>
                CCVM
              </Typography>
              <Typography variant="caption" sx={{ display: "block", color: brand.muted, mt: 0.35 }}>
                Vulnerability Manager
              </Typography>
            </Box>
          </Box>
        </Box>
        <Chip
          label="Web & Infrastruktur"
          color="primary"
          size="small"
          variant="outlined"
          sx={{
            display: { xs: "none", sm: "inline-flex" },
            bgcolor: brand.surface, borderColor: "#444", color: brand.white,
          }}
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
            bgcolor: brand.canvas,
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
