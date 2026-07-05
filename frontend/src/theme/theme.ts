import { createTheme } from '@mui/material/styles'

export const ccvmTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#38bdf8' },
    secondary: { main: '#8b5cf6' },
    background: {
      default: '#020617',
      paper: '#0f172a',
    },
    success: { main: '#22c55e' },
    warning: { main: '#f97316' },
    error: { main: '#ef4444' },
  },
  typography: {
    fontFamily: 'Inter, Arial, sans-serif',
    h4: { fontWeight: 700 },
    h6: { fontWeight: 700 },
  },
  shape: {
    borderRadius: 14,
  },
})
