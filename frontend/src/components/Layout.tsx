import { useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { api } from "../api/client";
import Logo from "./Logo";
import InsecureNotice from "./InsecureNotice";
import { useAuth } from "../hooks/auth";
import { Theme, useTheme } from "../hooks/useTheme";

// A global Network page is not planned yet; per-device network history lives on the device page.
const NAV = [
  { to: "/", label: "Dashboard", end: true },
  { to: "/devices", label: "Devices" },
  { to: "/events", label: "Events" },
  { to: "/adguard", label: "AdGuard" },
  { to: "/notifications", label: "Notifications" },
  { to: "/settings", label: "Settings" },
];

export default function Layout() {
  const { auth, refresh } = useAuth();
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useTheme();
  const [hidden, setHidden] = useState(() => {
    try {
      return sessionStorage.getItem("ga-insecure-dismissed") === "1";
    } catch {
      return false;
    }
  });
  const dismiss = () => {
    setHidden(true);
    try {
      sessionStorage.setItem("ga-insecure-dismissed", "1");
    } catch {
      /* storage unavailable */
    }
  };

  const logout = async () => {
    await api("/auth/logout", { method: "POST" });
    await refresh();
  };

  const linkCls = ({ isActive }: { isActive: boolean }) =>
    `block rounded-md px-3 py-2 text-sm font-medium ${
      isActive
        ? "bg-emerald-600/15 text-emerald-700 dark:text-emerald-400"
        : "text-slate-600 hover:bg-slate-200/60 dark:text-slate-300 dark:hover:bg-slate-800"
    }`;

  return (
    <div className="min-h-screen md:flex">
      <header className="flex items-center justify-between border-b border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-900 md:hidden">
        <span className="flex items-center gap-2 font-semibold"><Logo size={24} />LanWarden</span>
        <button
          aria-label="Toggle navigation"
          aria-expanded={open}
          onClick={() => setOpen(!open)}
          className="rounded-md border border-slate-300 px-3 py-1 text-sm dark:border-slate-700"
        >
          Menu
        </button>
      </header>

      <aside
        className={`${open ? "block" : "hidden"} w-full shrink-0 border-r border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900 md:block md:w-56`}
      >
        <div className="mb-6 hidden items-center gap-2 md:flex">
          <Logo size={32} />
          <span className="text-lg font-semibold">LanWarden</span>
        </div>
        <nav className="space-y-1" aria-label="Main">
          {NAV.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end} className={linkCls} onClick={() => setOpen(false)}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-6 space-y-3 border-t border-slate-200 pt-4 text-sm dark:border-slate-800">
          <label className="block">
            <span className="mb-1 block text-slate-500">Theme</span>
            <select
              value={theme}
              onChange={(e) => setTheme(e.target.value as Theme)}
              className="w-full rounded-md border border-slate-300 bg-white px-2 py-1.5 dark:border-slate-700 dark:bg-slate-950"
            >
              <option value="dark">Dark</option>
              <option value="light">Light</option>
              <option value="system">System</option>
            </select>
          </label>
          <p className="text-slate-500">Signed in as {auth.username}</p>
          <button onClick={logout} className="text-emerald-600 hover:underline dark:text-emerald-400">
            Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 p-4 md:p-8">
        {auth.insecure_transport && !hidden && <div className="mb-4"><InsecureNotice onDismiss={dismiss} /></div>}
        <Outlet />
      </main>
    </div>
  );
}
