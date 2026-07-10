import { useState } from "react";
import {
  Box,
  Chip,
  LinearProgress,
  Typography,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import type { GridColDef } from "@mui/x-data-grid";

import DashboardHeader from "../../shared/components/DashboardHeader";
import DonutChartCard from "../../shared/components/DonutChartCard";
import KpiCard from "../../shared/components/KpiCard";
import ProgressWithLabel from "../../shared/components/ProgressWithLabel";
import SecurityScore from "../../shared/components/SecurityScore";
import StatusChip from "../../shared/components/StatusChip";
import { severityColor } from "../../shared/severity";
import { getFinding } from "../findings/api";
import type { Finding } from "../findings/api";
import FindingDrawer from "../findings/components/FindingDrawer";
import { useDashboardSummary } from "./hooks";

export function Dashboard() {
  const { data, isLoading, error } = useDashboardSummary();
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const openFinding = async (id: number) => {
    const finding = await getFinding(id);
    setSelectedFinding(finding);
    setDrawerOpen(true);
  };

  if (isLoading) {
    return (
      <Box>
        <DashboardHeader title="Executive Dashboard" />
        <LinearProgress />
      </Box>
    );
  }

  if (error || !data) {
    return <Typography color="error">Fehler beim Laden des Dashboards.</Typography>;
  }

  const riskCards = [
    {
      title: "Critical",
      value: data.critical,
      color: severityColor("critical"),
      subtitle: "Immediate action",
    },
    {
      title: "High",
      value: data.high,
      color: severityColor("high"),
      subtitle: "Needs attention",
    },
    {
      title: "Medium",
      value: data.medium,
      color: severityColor("medium"),
      subtitle: "Review",
    },
    {
      title: "Low",
      value: data.low,
      color: severityColor("low"),
      subtitle: "Minor risk",
    },
    {
      title: "Info",
      value: data.info,
      color: severityColor("info"),
      subtitle: "Informational",
    },
    {
      title: "Open",
      value: data.open,
      color: "#e5e7eb",
      subtitle: "Awaiting remediation",
    },
    {
      title: "Fixed",
      value: data.fixed,
      color: "#22c55e",
      subtitle: "Resolved",
    },
    {
      title: "Running Jobs",
      value: data.running_jobs,
      color: "#38bdf8",
      subtitle: "Currently scanning",
    },
  ];

  const inventoryCards = [
    { title: "Customers", value: data.customers, color: "#38bdf8", subtitle: "Managed tenants" },
    { title: "Domains", value: data.domains, color: "#8b5cf6", subtitle: "Root domains" },
    { title: "Subdomains", value: data.subdomains, color: "#06b6d4", subtitle: "Discovered names" },
    { title: "Hosts", value: data.hosts, color: "#22c55e", subtitle: "Resolved systems" },
    { title: "Ports", value: data.ports, color: "#f59e0b", subtitle: "Open services" },
    { title: "Technologies", value: data.technologies, color: "#ec4899", subtitle: "Detected stacks" },
    { title: "Assets", value: data.assets, color: "#14b8a6", subtitle: "Managed assets" },
    { title: "Findings", value: data.findings, color: "#f97316", subtitle: "Security findings" },
    { title: "Jobs", value: data.jobs, color: "#e5e7eb", subtitle: "Pipeline executions" },
  ];

  const findingColumns: GridColDef[] = [
    {
      field: "severity",
      headerName: "Severity",
      width: 120,
      renderCell: (params) => (
        <Chip
          label={String(params.value).toUpperCase()}
          size="small"
          sx={{
            bgcolor: severityColor(String(params.value)),
            color: "#fff",
            fontWeight: 700,
          }}
        />
      ),
    },
    { field: "name", headerName: "Finding", flex: 2 },
    { field: "host", headerName: "Host", flex: 1 },
    { field: "scanner", headerName: "Scanner", width: 120 },
    { field: "status", headerName: "Status", width: 120 },
  ];

  const jobColumns: GridColDef[] = [
    { field: "id", headerName: "ID", width: 80 },
    { field: "plugin", headerName: "Plugin", width: 140 },
    {
      field: "status",
      headerName: "Status",
      width: 140,
      renderCell: (params) => (
        <StatusChip status={String(params.value)} />
      ),
    },
    {
      field: "progress",
      headerName: "Progress",
      flex: 1,
      renderCell: (params) => (
        <ProgressWithLabel value={Number(params.value ?? 0)} />
      ),
    },
    { field: "message", headerName: "Message", flex: 2 },
    { field: "worker", headerName: "Worker", width: 180 },
  ];

  return (
    <Box>
      <DashboardHeader title="Executive Dashboard" />

      <SecurityScore
        critical={data.critical}
        high={data.high}
        medium={data.medium}
        low={data.low}
      />

      <Typography variant="h6" sx={{ mb: 2 }}>
        Risk Overview
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
          gap: 2,
          mb: 4,
        }}
      >
        {riskCards.map((card) => (
          <KpiCard
            key={card.title}
            title={card.title}
            value={card.value}
            color={card.color}
            subtitle={card.subtitle}
          />
        ))}
      </Box>

      <Typography variant="h6" sx={{ mb: 2 }}>
        Attack Surface Inventory
      </Typography>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
          gap: 2,
          mb: 4,
        }}
      >
        {inventoryCards.map((card) => (
          <KpiCard
            key={card.title}
            title={card.title}
            value={card.value}
            color={card.color}
            subtitle={card.subtitle}
          />
        ))}
      </Box>

      <Box
        sx={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 3,
          mb: 4,
        }}
      >
        <DonutChartCard
          title="Severity Distribution"
          data={data.severity_chart}
        />
        <DonutChartCard
          title="Scanner Distribution"
          data={data.scanner_chart}
        />
      </Box>

      <Typography variant="h6" sx={{ mb: 2 }}>
        Latest Findings
      </Typography>

      <Box sx={{ height: 360, width: "100%", mb: 4 }}>
        <DataGrid
          rows={data.latest_findings}
          columns={findingColumns}
          getRowId={(row) => row.id}
          hideFooter
          onRowClick={(params) => openFinding(Number(params.id))}
        />
      </Box>

      <Typography variant="h6" sx={{ mb: 2 }}>
        Active Jobs
      </Typography>

      <Box sx={{ height: 300, width: "100%" }}>
        <DataGrid
          rows={data.active_jobs}
          columns={jobColumns}
          getRowId={(row) => row.id}
          hideFooter
        />
      </Box>

      <FindingDrawer
        open={drawerOpen}
        finding={selectedFinding}
        onClose={() => setDrawerOpen(false)}
      />
    </Box>
  );
}
