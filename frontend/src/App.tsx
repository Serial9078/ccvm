import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./shared/layout/AppLayout";
import { Dashboard } from "./features/dashboard/page";
import { Customers } from "./features/customers/page";
import { Assets } from "./features/assets/page";
import { PlaceholderPage } from "./pages/PlaceholderPage";

export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Navigate to="/dashboard" />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/customers" element={<Customers />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/scans" element={<PlaceholderPage title="Scans" />} />
        <Route path="/findings" element={<PlaceholderPage title="Findings" />} />
        <Route path="/reports" element={<PlaceholderPage title="Reports" />} />
        <Route path="/settings" element={<PlaceholderPage title="Settings" />} />
      </Route>
    </Routes>
  );
}
