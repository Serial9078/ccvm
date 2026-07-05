import { BrowserRouter, Route, Routes } from 'react-router-dom';
import AppLayout from './layout/AppLayout';
import Dashboard from './pages/Dashboard';
import Customers from './pages/Customers';
import Assets from './pages/Assets';
import Placeholder from './pages/Placeholder';

export default function App() {
  return <BrowserRouter>
    <Routes>
      <Route element={<AppLayout />}>
        <Route path="/" element={<Dashboard />} />
        <Route path="/customers" element={<Customers />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/scans" element={<Placeholder title="Scans" />} />
        <Route path="/reports" element={<Placeholder title="Reports" />} />
        <Route path="/settings" element={<Placeholder title="Settings" />} />
      </Route>
    </Routes>
  </BrowserRouter>;
}
