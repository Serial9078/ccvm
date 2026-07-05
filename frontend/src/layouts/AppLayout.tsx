import DashboardIcon from '@mui/icons-material/Dashboard';
import BusinessIcon from '@mui/icons-material/Business';
import DnsIcon from '@mui/icons-material/Dns';
import RadarIcon from '@mui/icons-material/Radar';
import BugReportIcon from '@mui/icons-material/BugReport';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SettingsIcon from '@mui/icons-material/Settings';
import { Box, Drawer, List, ListItemButton, ListItemIcon, ListItemText, Toolbar, Typography, AppBar, Chip } from '@mui/material';
import { Link, Outlet, useLocation } from 'react-router-dom';

const drawerWidth = 260;

const nav = [
  { label: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { label: 'Customers', icon: <BusinessIcon />, path: '/customers' },
  { label: 'Assets', icon: <DnsIcon />, path: '/assets' },
  { label: 'Scans', icon: <RadarIcon />, path: '/scans' },
  { label: 'Findings', icon: <BugReportIcon />, path: '/findings' },
  { label: 'Reports', icon: <AssessmentIcon />, path: '/reports' },
  { label: 'Settings', icon: <SettingsIcon />, path: '/settings' },
];

export function AppLayout() {
  const location = useLocation();

  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AppBar position="fixed" sx={{ zIndex: (theme) => theme.zIndex.drawer + 1, bgcolor: '#020617', borderBottom: '1px solid #1e293b' }} elevation={0}>
        <Toolbar>
          <Typography variant="h6" sx={{ fontWeight: 900, flexGrow: 1 }}>
            CloudCollab Vulnerability Manager
          </Typography>
          <Chip label="v0.4.0 Phoenix" color="primary" variant="outlined" />
        </Toolbar>
      </AppBar>
      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          flexShrink: 0,
          [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box', bgcolor: '#020617', borderRight: '1px solid #1e293b' },
        }}
      >
        <Toolbar />
        <Box sx={{ p: 2 }}>
          <Typography variant="overline" color="text.secondary">Navigation</Typography>
          <List>
            {nav.map((item) => (
              <ListItemButton
                key={item.path}
                component={Link}
                to={item.path}
                selected={location.pathname === item.path}
                sx={{ borderRadius: 2, mb: 0.5 }}
              >
                <ListItemIcon sx={{ color: 'inherit' }}>{item.icon}</ListItemIcon>
                <ListItemText primary={item.label} />
              </ListItemButton>
            ))}
          </List>
        </Box>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 4, bgcolor: '#020617' }}>
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  );
}
