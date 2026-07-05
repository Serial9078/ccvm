import { Box, Drawer, List, ListItemButton, ListItemIcon, ListItemText, Toolbar, AppBar, Typography } from '@mui/material';
import DashboardIcon from '@mui/icons-material/Dashboard';
import BusinessIcon from '@mui/icons-material/Business';
import DnsIcon from '@mui/icons-material/Dns';
import RadarIcon from '@mui/icons-material/Radar';
import AssessmentIcon from '@mui/icons-material/Assessment';
import SettingsIcon from '@mui/icons-material/Settings';
import { Link, Outlet } from 'react-router-dom';

const drawerWidth = 260;
const items = [
  ['Dashboard', '/', <DashboardIcon />],
  ['Customers', '/customers', <BusinessIcon />],
  ['Assets', '/assets', <DnsIcon />],
  ['Scans', '/scans', <RadarIcon />],
  ['Reports', '/reports', <AssessmentIcon />],
  ['Settings', '/settings', <SettingsIcon />],
] as const;

export default function AppLayout() {
  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar position="fixed" sx={{ zIndex: theme => theme.zIndex.drawer + 1 }}>
        <Toolbar>
          <Typography variant="h6" noWrap>CloudCollab Vulnerability Manager</Typography>
        </Toolbar>
      </AppBar>
      <Drawer variant="permanent" sx={{ width: drawerWidth, flexShrink: 0, [`& .MuiDrawer-paper`]: { width: drawerWidth, boxSizing: 'border-box' } }}>
        <Toolbar />
        <List>
          {items.map(([text, path, icon]) => (
            <ListItemButton component={Link} to={path} key={text}>
              <ListItemIcon>{icon}</ListItemIcon>
              <ListItemText primary={text} />
            </ListItemButton>
          ))}
        </List>
      </Drawer>
      <Box component="main" sx={{ flexGrow: 1, p: 3 }}>
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  );
}
