import {
  Navigate,
  Route,
  Routes,
} from "react-router-dom";

import { Assets } from "./features/assets/page";
import { Customers } from "./features/customers/page";
import { Dashboard } from "./features/dashboard/page";
import { Domains } from "./features/domains/page";
import { Findings } from "./features/findings/page";
import { Hosts } from "./features/hosts/page";
import { Jobs } from "./features/jobs/page";
import { Networks } from "./features/networks/page";
import { Pipelines } from "./features/pipelines/page";
import { Ports } from "./features/ports/page";
import { Screenshots } from "./features/screenshots/page";
import { Subdomains } from "./features/subdomains/page";
import { Technologies } from "./features/technologies/page";
import { Urls } from "./features/urls/page";
import { PlaceholderPage } from "./pages/PlaceholderPage";
import { AppLayout } from "./shared/layout/AppLayout";


export default function App() {
  return (
    <Routes>
      <Route element={<AppLayout />}>
        <Route
          path="/"
          element={
            <Navigate
              to="/dashboard"
              replace
            />
          }
        />

        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/customers"
          element={<Customers />}
        />

        <Route
          path="/domains"
          element={<Domains />}
        />

        <Route path="/networks" element={<Networks />} />

        <Route
          path="/pipelines"
          element={<Pipelines />}
        />

        <Route
          path="/subdomains"
          element={<Subdomains />}
        />

        <Route
          path="/hosts"
          element={<Hosts />}
        />

        <Route
          path="/ports"
          element={<Ports />}
        />

        <Route
          path="/technologies"
          element={<Technologies />}
        />

        <Route
          path="/urls"
          element={<Urls />}
        />

        <Route
          path="/screenshots"
          element={<Screenshots />}
        />

        <Route
          path="/assets"
          element={<Assets />}
        />

        <Route
          path="/scans"
          element={<Jobs />}
        />

        <Route
          path="/findings"
          element={<Findings />}
        />

        <Route
          path="/reports"
          element={
            <PlaceholderPage
              title="Reports"
            />
          }
        />

        <Route
          path="/settings"
          element={
            <PlaceholderPage
              title="Settings"
            />
          }
        />
      </Route>
    </Routes>
  );
}
