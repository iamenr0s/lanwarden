import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { api } from "./api/client";
import Layout from "./components/Layout";
import { Loading } from "./components/ui";
import { AuthContext, useAuth } from "./hooks/auth";
import EnrolMfa from "./pages/EnrolMfa";
import AdGuard from "./pages/AdGuard";
import Dashboard from "./pages/Dashboard";
import DeviceDetail from "./pages/DeviceDetail";
import Devices from "./pages/Devices";
import Events from "./pages/Events";
import Login from "./pages/Login";
import Notifications from "./pages/Notifications";
import Settings from "./pages/Settings";
import type { AuthState } from "./types";

export default function App() {
  const [auth, setAuth] = useState<AuthState | null>(null);

  const refresh = useCallback(async () => {
    try {
      setAuth(await api<AuthState>("/auth/state"));
    } catch {
      setAuth({ setup_required: false, setup_token_required: false, insecure_transport: false, authenticated: false, username: null, mfa_enabled: false, mfa_enrolment_required: false, mfa_required: false, mfa_token: null });
    }
  }, []);

  useEffect(() => {
    void refresh();
    const onExpired = () => void refresh();
    window.addEventListener("ga:unauthorized", onExpired);
    return () => window.removeEventListener("ga:unauthorized", onExpired);
  }, [refresh]);

  if (!auth) return <div className="p-8"><Loading /></div>;
  if (!auth.authenticated)
    return <Login setupRequired={auth.setup_required} tokenRequired={auth.setup_token_required} insecure={auth.insecure_transport} onDone={refresh} />;

  return (
    <AuthContext.Provider value={{ auth, refresh }}>
      <AppRoutes />
    </AuthContext.Provider>
  );
}

export function AppRoutes() {
  const { auth } = useAuth();
  if (auth.mfa_enrolment_required) return <EnrolMfa />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="devices" element={<Devices />} />
        <Route path="devices/:id" element={<DeviceDetail />} />
        <Route path="events" element={<Events />} />
        <Route path="adguard" element={<AdGuard />} />
        <Route path="notifications" element={<Notifications />} />
        <Route path="settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}
