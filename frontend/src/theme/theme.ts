import { createTheme } from '@mui/material/styles';

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#38bdf8' },
    secondary: { main: '#a78bfa' },
    background: { default: '#020617', paper: '#0f172a' },
    success: { main: '#22c55e' },
    warning: { main: '#f59e0b' },
    error: { main: '#ef4444' },
  },
  shape: { borderRadius: 14 },
  typography: {
    fontFamily: ['Inter', 'Arial', 'sans-serif'].join(','),
    h4: { fontWeight: 800 },
    h5: { fontWeight: 700 },
  },
});
