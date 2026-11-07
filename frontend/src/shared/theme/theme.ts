import { alpha, createTheme } from "@mui/material/styles";
import type {} from "@mui/x-data-grid/themeAugmentation";

// Monochrome website tokens: cloudcollab-website@f32ab00459827cf1b449253a172fdc0e78595793,
// src/index.css and src/Layout.jsx. Matrix green is CloudCollab's operational CI accent.
export const cloudcollabBrand = {
  black: "#000000", canvas: "#080808", surface: "#0f0f0f", raised: "#171717",
  border: "#292929", white: "#fafafa", muted: "#b0b0b0", matrix: "#00ff41",
} as const;
const brand = cloudcollabBrand;
const focusRing = `2px solid ${brand.matrix}`;

export const ccvmTheme = createTheme({
  palette: {
    mode: "dark",
    primary: { main: brand.white, contrastText: "#080808" },
    secondary: { main: "#d4d4d4", contrastText: "#080808" },
    background: { default: brand.canvas, paper: brand.surface },
    text: { primary: brand.white, secondary: brand.muted, disabled: "#737373" },
    divider: brand.border,
    success: { main: "#4ade80", contrastText: "#041909" },
    warning: { main: "#fbbf24", contrastText: "#211601" },
    error: { main: "#f87171", contrastText: "#250809" },
    info: { main: "#d4d4d4", contrastText: "#080808" },
    action: { active: brand.white, hover: alpha(brand.white, 0.05), selected: alpha(brand.white, 0.1),
      focus: alpha(brand.matrix, 0.12), disabled: "#737373", disabledBackground: "#202020" },
  },
  typography: {
    fontFamily: 'Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: 14,
    h1: { fontWeight: 800, letterSpacing: "-0.045em" },
    h2: { fontWeight: 800, letterSpacing: "-0.04em" },
    h3: { fontWeight: 800, letterSpacing: "-0.035em" },
    h4: { fontWeight: 800, letterSpacing: "-0.035em" },
    h5: { fontWeight: 750, letterSpacing: "-0.025em" },
    h6: { fontWeight: 750, letterSpacing: "-0.02em" },
    body1: { lineHeight: 1.55 }, body2: { lineHeight: 1.55 },
    button: { fontWeight: 700, textTransform: "none", letterSpacing: "0.01em" },
    overline: { fontWeight: 700, letterSpacing: "0.12em" },
  },
  shape: { borderRadius: 12 },
  components: {
    MuiCssBaseline: { styleOverrides: {
      html: { backgroundColor: brand.canvas, colorScheme: "dark" },
      body: { minWidth: 320, textRendering: "optimizeLegibility" },
      "::selection": { backgroundColor: brand.white, color: brand.black },
      ":focus-visible": { outline: focusRing, outlineOffset: 3 },
      "*": { scrollbarWidth: "thin", scrollbarColor: "#555 #0f0f0f" },
    } },
    MuiPaper: { defaultProps: { elevation: 0 }, styleOverrides: {
      root: { backgroundImage: "none", border: `1px solid ${brand.border}` },
    } },
    MuiCard: { styleOverrides: { root: { backgroundColor: brand.surface } } },
    MuiButton: { defaultProps: { disableElevation: true }, styleOverrides: {
      root: { borderRadius: 9, minHeight: 38, paddingInline: 15,
        "&.Mui-focusVisible": { outline: focusRing, outlineOffset: 3 } },
      contained: { "&.MuiButton-colorPrimary:not(.Mui-disabled)": {
        backgroundColor: brand.white, color: brand.black,
        "&:hover": { backgroundColor: "#dedede" },
      } },
      outlined: { "&.MuiButton-colorPrimary:not(.Mui-disabled)": {
        borderColor: "#5c5c5c",
        "&:hover": { borderColor: brand.white, backgroundColor: alpha(brand.white, 0.06) },
      } },
      text: { "&.MuiButton-colorPrimary:hover": { backgroundColor: alpha(brand.white, 0.06) } },
    } },
    MuiIconButton: { styleOverrides: { root: {
      "&.Mui-focusVisible": { outline: focusRing, outlineOffset: 2 },
    } } },
    MuiOutlinedInput: { styleOverrides: { root: {
      backgroundColor: brand.canvas,
      "& .MuiOutlinedInput-notchedOutline": { borderColor: "#444" },
      "&:hover .MuiOutlinedInput-notchedOutline": { borderColor: "#888" },
      "&.Mui-focused .MuiOutlinedInput-notchedOutline": { borderColor: brand.matrix },
    } } },
    MuiInputLabel: { styleOverrides: { root: { "&.Mui-focused": { color: brand.white } } } },
    MuiMenuItem: { styleOverrides: { root: {
      "&.Mui-selected": { backgroundColor: alpha(brand.white, 0.1) },
      "&.Mui-selected:hover": { backgroundColor: alpha(brand.white, 0.15) },
    } } },
    MuiChip: { styleOverrides: {
      root: { borderRadius: 7, fontWeight: 650 },
    } },
    MuiTableCell: { styleOverrides: {
      root: { borderColor: brand.border },
      head: { backgroundColor: brand.raised, color: brand.white, fontWeight: 700 },
    } },
    MuiTableRow: { styleOverrides: {
      hover: { "&:hover": { backgroundColor: alpha(brand.white, 0.035) } },
    } },
    MuiAccordion: { defaultProps: { disableGutters: true, elevation: 0 }, styleOverrides: {
      root: { borderRadius: 10, "&:before": { display: "none" },
        "&:first-of-type, &:last-of-type": { borderRadius: 10 } },
    } },
    MuiAccordionSummary: { styleOverrides: {
      root: { minHeight: 50, "&:hover": { backgroundColor: brand.raised } },
    } },
    MuiDialog: { styleOverrides: { paper: { border: "1px solid #444", backgroundColor: brand.surface } } },
    MuiDialogTitle: { styleOverrides: { root: { fontWeight: 750, borderBottom: `1px solid ${brand.border}` } } },
    MuiDrawer: { styleOverrides: { paper: { backgroundColor: brand.canvas } } },
    MuiLink: { defaultProps: { underline: "always" }, styleOverrides: { root: { textUnderlineOffset: 3 } } },
    MuiLinearProgress: { styleOverrides: { root: { backgroundColor: "#333", borderRadius: 4 } } },
    MuiDataGrid: { styleOverrides: { root: {
      borderColor: brand.border, backgroundColor: brand.surface,
      "--DataGrid-containerBackground": brand.raised, "--DataGrid-rowBorderColor": brand.border,
      "& .MuiDataGrid-columnHeader": { color: brand.white, fontWeight: 700 },
      "& .MuiDataGrid-cell": { borderColor: brand.border },
      "& .MuiDataGrid-row:hover": { backgroundColor: alpha(brand.white, 0.035) },
      "& .MuiDataGrid-cell:focus, & .MuiDataGrid-columnHeader:focus": { outline: focusRing, outlineOffset: -2 },
    } } },
  },
});
