import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { qs } from "../api/client";
import AdGuardCard from "../components/AdGuardCard";
import { BarList, COLORS, Donut, LineChart } from "../components/charts";
import ScanCard from "../components/ScanCard";
import { StatusBadge } from "../components/StatusBadge";
import { Card, ErrorBox, Loading } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { eventLabel, timeAgo } from "../lib/format";
import type { DashboardData, Device, DeviceEvent, Page, Status } from "../types";

const REFRESH_MS = 30_000;
const RANGES = [
  { id: "24h", label: "24 hours" },
  { id: "7d", label: "7 days" },
  { id: "30d", label: "30 days" },
] as const;

function Summary({ label, value, tone, to }: { label: string; value: number; tone: string; to: string }) {
  return (
    <Link
      to={to}
      className="rounded-lg border border-slate-200 bg-white p-4 hover:border-emerald-500/60 dark:border-slate-800 dark:bg-slate-900"
    >
      <div className="text-sm text-slate-500 dark:text-slate-400">{label}</div>
      <div className={`mt-1 text-3xl font-semibold ${tone}`}>{value}</div>
    </Link>
  );
}

function Empty({ children }: { children: string }) {
  return <p className="text-sm text-slate-500">{children}</p>;
}

function DeviceRow({ d, when }: { d: Device; when: string | null }) {
  return (
    <li className="flex items-center justify-between gap-3 py-2 text-sm">
      <Link to={`/devices/${d.id}`} className="min-w-0 truncate font-medium hover:underline">
        {d.display_name}
      </Link>
      <span className="flex shrink-0 items-center gap-2">
        <span className="text-slate-500">{timeAgo(when)}</span>
        <StatusBadge device={d} />
      </span>
    </li>
  );
}

export default function Dashboard() {
  const [range, setRange] = useState<(typeof RANGES)[number]["id"]>("24h");
  const status = useApi<Status>("/status");
  const board = useApi<DashboardData>(`/dashboard?range=${range}`);
  const recent = useApi<Page<Device>>(`/devices${qs({ sort: "first_seen", order: "desc", limit: 6 })}`);
  const events = useApi<Page<DeviceEvent>>(`/events${qs({ limit: 8 })}`);

  const refreshAll = () => {
    status.reload();
    board.reload();
    recent.reload();
    events.reload();
  };

  // A monitoring screen should stay current: refresh while the tab is visible.
  useEffect(() => {
    const t = setInterval(() => {
      if (document.visibilityState === "visible") refreshAll();
    }, REFRESH_MS);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (status.error) return <ErrorBox message={status.error} />;
  if (!status.data) return <Loading />;
  const d = status.data.devices;
  const neverSeen = Math.max(0, d.total - d.online - d.offline);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold">Dashboard</h1>

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-6">
        <Summary label="Total devices" value={d.total} tone="" to="/devices" />
        <Summary label="Online" value={d.online} tone="text-online" to="/devices?online=true" />
        <Summary label="Offline" value={d.offline} tone="text-slate-500" to="/devices?online=false" />
        <Summary label="New / Unknown" value={d.unknown} tone="text-warn" to="/devices?known=false" />
        <Summary label="Anomalies (7 days)" value={status.data.anomalies_7d} tone={status.data.anomalies_7d ? "text-warn" : ""} to="/events?event_type=DEVICE_ANOMALY" />
        <Summary label="Always-connected down" value={d.always_connected_down} tone={d.always_connected_down ? "text-down" : ""} to="/devices?always_connected=true&online=false" />
      </div>

      {d.total === 0 && (
        <Card>
          <p className="text-sm">
            <span className="font-medium">No devices yet.</span>{" "}
            <span className="text-slate-500">
              Press <em>Scan now</em> below. If nothing is found, choose the network to scan in{" "}
              <Link to="/settings" className="text-emerald-600 hover:underline dark:text-emerald-400">Settings</Link>.
            </span>
          </p>
        </Card>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Online vs offline">
          <Donut
            centerLabel="devices"
            segments={[
              { label: "Online", value: d.online, color: COLORS.online },
              { label: "Offline", value: d.offline, color: COLORS.offline },
              { label: "Not seen yet", value: neverSeen, color: "#94a3b8" },
            ]}
          />
        </Card>
        <Card title="Device types">
          {board.data ? <BarList items={board.data.type_distribution.map((t) => ({ label: t.type, value: t.count }))} /> : <Loading />}
        </Card>
      </div>

      <Card title="Devices over time">
        <div role="group" aria-label="Time range" className="mb-3 flex flex-wrap items-center gap-2">
          {RANGES.map((r) => (
            <button
              key={r.id}
              aria-pressed={range === r.id}
              onClick={() => setRange(r.id)}
              className={`rounded-full border px-3 py-1 text-sm ${
                range === r.id
                  ? "border-emerald-500 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                  : "border-slate-300 text-slate-600 hover:bg-slate-100 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800"
              }`}
            >
              {r.label}
            </button>
          ))}
          <span className="ml-auto flex items-center gap-4 text-xs text-slate-500">
            <span className="flex items-center gap-1.5"><span className="inline-block h-0.5 w-4" style={{ background: COLORS.online }} />online</span>
            <span className="flex items-center gap-1.5"><span className="inline-block w-4 border-t border-dashed" style={{ borderColor: COLORS.offline }} />known</span>
          </span>
        </div>
        {board.error && <ErrorBox message={board.error} />}
        {board.data ? <div className="text-slate-900 dark:text-slate-100"><LineChart points={board.data.series} range={range} /></div> : <Loading />}
        <p className="mt-2 text-xs text-slate-500">History starts when LanWarden began recording.</p>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <ScanCard onFinished={refreshAll} />
        <AdGuardCard />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Recently discovered">
          {recent.data?.items.length ? (
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {recent.data.items.map((x) => <DeviceRow key={x.id} d={x} when={x.first_seen} />)}
            </ul>
          ) : <Empty>Nothing yet.</Empty>}
        </Card>

        <Card title="Recently disconnected">
          {board.data?.recently_disconnected.length ? (
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {board.data.recently_disconnected.map((x) => <DeviceRow key={x.id} d={x} when={x.last_disconnection} />)}
            </ul>
          ) : <Empty>No device has gone offline.</Empty>}
        </Card>

        <Card title="Recent events">
          {events.data?.items.length ? (
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {events.data.items.map((e) => (
                <li key={e.id} className="flex items-center justify-between gap-3 py-2 text-sm">
                  <span className="min-w-0 truncate">
                    <span className="font-medium">{eventLabel(e.event_type)}</span>
                    {e.device_name && <span className="text-slate-500"> · {e.device_name}</span>}
                  </span>
                  <span className="shrink-0 text-slate-500">{timeAgo(e.timestamp)}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>No events recorded.</Empty>}
        </Card>
      </div>
    </div>
  );
}
