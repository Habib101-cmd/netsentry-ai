import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth";
import Layout from "./pages/Layout";
import Login from "./pages/Login";
import ChangePassword from "./pages/ChangePassword";
import Dashboard from "./pages/Dashboard";
import Scans from "./pages/Scans";
import Hosts from "./pages/Hosts";
import HostDetail from "./pages/HostDetail";
import Findings from "./pages/Findings";
import Admin from "./pages/Admin";
import Reports from "./pages/Reports";
import History from "./pages/History"
import NetworkMap from "./pages/NetworkMap";
import Timeline from "./pages/Timeline";
import Anomalies from "./pages/Anomalies";

function Protected({ children }) {
  const { user, loading } = useAuth();
  if (loading) return <p className="p-5 text-center">Chargement…</p>;
  if (!user) return <Navigate to="/login" replace />;
  if (user.must_change_password) return <Navigate to="/change-password" replace />;
  return children;
}

function AdminOnly({ children }) {
  const { user } = useAuth();
  return user.role === "admin" ? children : <Navigate to="/" replace />;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/change-password" element={<ChangePassword />} />
          <Route element={<Protected><Layout /></Protected>}>
            <Route index element={<Dashboard />} />
            <Route path="scans" element={<Scans />} />
            <Route path="hosts" element={<Hosts />} />
            <Route path="hosts/:id" element={<HostDetail />} />
            <Route path="findings" element={<Findings />} />
            <Route path="history" element={<History />} />
            <Route path="reports" element={<Reports />} />
            <Route path="map" element={<NetworkMap />} />
            <Route path="timeline" element={<Timeline />} />
            <Route path="anomalies" element={<Anomalies />} />
            <Route path="admin" element={<AdminOnly><Admin /></AdminOnly>} />
          </Route>
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}