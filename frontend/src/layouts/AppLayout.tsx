import {
  Box,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Toolbar,
  AppBar,
  Typography,
  Chip,
} from '@mui/material'
import DashboardIcon from '@mui/icons-material/Dashboard'
import BusinessIcon from '@mui/icons-material/Business'
import DevicesIcon from '@mui/icons-material/Devices'
import RadarIcon from '@mui/icons-material/Radar'
import BugReportIcon from '@mui/icons-material/BugReport'
import AssessmentIcon from '@mui/icons-material/Assessment'
import SettingsIcon from '@mui/icons-material/Settings'
import { NavLink, Outlet } from 'react-router-dom'

const drawerWidth = 260

const navItems = [
  { label: 'Dashboard', path: '/dashboard', icon: <DashboardIcon /> },
  { label: 'Customers', path: '/customers', icon: <BusinessIcon /> },
  { label: 'Assets', path: '/assets', icon: <DevicesIcon /> },
  { label: 'Scans', path: '/scans', icon: <RadarIcon /> },
  { label: 'Findings', path: '/findings', icon: <BugReportIcon /> },
  { label: 'Reports', path: '/reports', icon: <AssessmentIcon /> },
  { label: 'Settings', path: '/settings', icon: <SettingsIcon /> },
]

export function AppLayout() {
  return (
    <Box sx={{ display: 'flex', minHeight: '100vh' }}>
      <AppBar
        position="fixed"
        sx={{
          zIndex: 1300,
          bgcolor: '#020617',
          borderBottom: '1px solid #1e293b',
          boxShadow: 'none',
        }}
      >
        <Toolbar>
          <Typography variant="h6" sx={{ flexGrow: 1 }}>
            CloudCollab Vulnerability Manager
          </Typography>
          <Chip label="v0.4 Phoenix" color="primary" size="small" />
        </Toolbar>
      </AppBar>

      <Drawer
        variant="permanent"
        sx={{
          width: drawerWidth,
          '& .MuiDrawer-paper': {
            width: drawerWidth,
            bgcolor: '#020617',
            borderRight: '1px solid #1e293b',
          },
        }}
      >
        <Toolbar />
        <Box sx={{ p: 2 }}>
          <Typography variant="overline" color="text.secondary">
            Navigation
          </Typography>
        </Box>
        <List>
          {navItems.map((item) => (
            <ListItemButton
              key={item.path}
              component={NavLink}
              to={item.path}
              sx={{
                mx: 1,
                mb: 0.5,
                borderRadius: 2,
                '&.active': {
                  bgcolor: 'rgba(56,189,248,0.14)',
                  color: '#38bdf8',
                },
              }}
            >
              <ListItemIcon sx={{ color: 'inherit' }}>{item.icon}</ListItemIcon>
              <ListItemText primary={item.label} />
            </ListItemButton>
          ))}
        </List>
      </Drawer>

      <Box component="main" sx={{ flexGrow: 1, p: 4, mt: 8 }}>
        <Outlet />
      </Box>
    </Box>
  )
}
