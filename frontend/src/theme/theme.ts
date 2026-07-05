import { createTheme } from '@mui/material/styles';

export const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: { main: '#38bdf8' },
    background: { default: '#0f172a', paper: '#111827' }
  },
  typography: {
    fontFamily: 'Inter, Arial, sans-serif'
  }
});
