import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./shared/layout/AppLayout";
import { Dashboard } from "./features/dashboard/page";
import { Customers } from "./features/customers/page";
import { Domains } from "./features/domains/page";
import { Subdomains } from "./features/subdomains/page";
import { Hosts } from "./features/hosts/page";
import { Ports } from "./features/ports/page";
import { Technologies } from "./features/technologies/page";
import { Assets } from "./features/assets/page";
import { Jobs } from "./features/jobs/page";
import { Findings } from "./features/findings/page";
import { PlaceholderPage } from "./pages/PlaceholderPage";

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Navigate to="/dashboard" />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/customers" element={<Customers />} />
        <Route path="/domains" element={<Domains />} />
        <Route path="/subdomains" element={<Subdomains />} />
        <Route path="/hosts" element={<Hosts />} />
        <Route path="/ports" element={<Ports />} />
        <Route path="/technologies" element={<Technologies />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/scans" element={<Jobs />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/reports" element={<PlaceholderPage title="Reports" />} />
        <Route path="/settings" element={<PlaceholderPage title="Settings" />} />
      </Route>
    </Routes>
  );
}
