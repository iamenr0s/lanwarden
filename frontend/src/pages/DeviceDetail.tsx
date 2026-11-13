import { FormEvent, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api/client";
import { StatusBadge } from "../components/StatusBadge";
import { btnCls, Card, ErrorBox, Field, inputCls, Loading, Toggle } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { duration, eventLabel, fullTime, timeAgo } from "../lib/format";
import PresenceTimeline from "../components/PresenceTimeline";
import type { Device, DeviceAdGuard, DeviceEvent, DeviceSession, DeviceUpdate, NetworkHistory, Page, Presence } from "../types";

const TABS = ["Overview", "Presence", "Sessions", "Events", "Network", "AdGuard", "Settings"] as const;
const RANGES = [
  { id: "today", label: "Today" },
  { id: "24h", label: "24 hours" },
  { id: "7d", label: "7 days" },
  { id: "30d", label: "30 days" },
] as const;
type Tab = (typeof TABS)[number];

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex justify-between gap-4 py-2 text-sm">
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-right">{value ?? "—"}</dd>
    </div>
  );
}

export default function DeviceDetail() {
  const { id } = useParams();
  const [tab, setTab] = useState<Tab>("Overview");
  const device = useApi<Device>(`/devices/${id}`);

  if (device.error) return <ErrorBox message={device.error} />;
  if (!device.data) return <Loading />;
  const d = device.data;

  return (
    <div className="space-y-6">
      <Link to="/devices" className="text-sm text-emerald-600 hover:underline dark:text-emerald-400">← Devices</Link>
      <header className="flex flex-wrap items-center gap-3">
        <h1 className="text-2xl font-semibold">{d.display_name}</h1>
        <StatusBadge device={d} />
        {!d.is_known && (
          <button
            className={btnCls}
            onClick={async () => device.setData(await api<Device>(`/devices/${d.id}`, { method: "PATCH", body: { is_known: true } }))}
          >
            Mark as known
          </button>
        )}
      </header>
      <p className="font-mono text-sm text-slate-500">
        {[d.hostname, d.current_ip, d.mac_address, d.effective_vendor].filter(Boolean).join(" · ") || "No details observed yet"}
      </p>

      <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800">
        {TABS.map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-4 py-2 text-sm font-medium ${
              tab === t ? "border-emerald-500 text-emerald-600 dark:text-emerald-400" : "border-transparent text-slate-500 hover:text-slate-900 dark:hover:text-slate-100"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "Overview" && (
        <Card>
          <dl className="divide-y divide-slate-200 dark:divide-slate-800">
            <Row label="First seen" value={fullTime(d.first_seen)} />
            <Row label="Last seen" value={`${fullTime(d.last_seen)} (${timeAgo(d.last_seen)})`} />
            <Row label="Last connection" value={fullTime(d.last_connection)} />
            <Row label="Last disconnection" value={fullTime(d.last_disconnection)} />
            <Row label="Current IP" value={d.current_ip} />
            <Row label="Hostname" value={d.hostname} />
            <Row label="Vendor" value={d.effective_vendor} />
            <Row label="Model" value={d.model} />
            <Row label="Type" value={d.effective_type ? `${d.effective_type}${d.device_type ? "" : " (auto)"}` : null} />
            <Row label="Group" value={d.device_group} />
            <Row label="Notes" value={d.notes} />
          </dl>
        </Card>
      )}
      {tab === "Presence" && <PresenceTab id={d.id} />}
      {tab === "Network" && <NetworkTab id={d.id} />}
      {tab === "Sessions" && <Sessions id={d.id} />}
      {tab === "Events" && <Events id={d.id} />}
      {tab === "AdGuard" && <AdGuardTab id={d.id} />}
      {tab === "Settings" && <DeviceSettings device={d} onSaved={device.setData} />}
    </div>
  );
}

function PresenceTab({ id }: { id: number }) {
  const [range, setRange] = useState<(typeof RANGES)[number]["id"]>("24h");
  const tz = -new Date().getTimezoneOffset(); // minutes east of UTC; defines "today"
  const { data, error, loading } = useApi<Presence>(`/devices/${id}/presence?range=${range}&tz_offset_minutes=${tz}`);

  return (
    <div className="space-y-4">
      <div role="group" aria-label="Time range" className="flex flex-wrap gap-2">
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
      </div>
      {error && <ErrorBox message={error} />}
      {!data && loading && <Loading />}
      {data && (
        <Card>
          <PresenceTimeline data={data} />
          <dl className="mt-4 grid grid-cols-2 gap-4 text-sm sm:grid-cols-4">
            <Stat label="Online time" value={duration(data.online_seconds)} />
            <Stat label="Availability" value={data.online_percent === null ? "—" : `${data.online_percent}%`} />
            <Stat label="Connections" value={String(data.session_count)} />
            <Stat label="Tracked for" value={duration(data.tracked_seconds)} />
          </dl>
          {data.segments.length === 0 && <p className="mt-3 text-sm text-slate-500">Not seen online in this period.</p>}
        </Card>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-slate-500">{label}</dt>
      <dd className="text-lg font-semibold">{value}</dd>
    </div>
  );
}

function NetworkTab({ id }: { id: number }) {
  const { data, error, loading } = useApi<NetworkHistory>(`/devices/${id}/network`);
  if (error) return <ErrorBox message={error} />;
  if (loading || !data) return <Loading />;
  const empty = <p className="text-sm text-slate-500">Nothing recorded yet.</p>;

  return (
    <div className="space-y-4">
      <Card title="IP addresses">
        {data.addresses.length === 0 ? empty : (
          <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {data.addresses.map((a) => (
              <li key={a.ip} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <span>
                  <span className="font-mono">{a.ip}</span>
                  {a.current && <span className="ml-2 rounded-full bg-online/15 px-2 py-0.5 text-xs text-green-700 dark:text-green-400">current</span>}
                </span>
                <span className="text-slate-500">{fullTime(a.first_seen)} → {fullTime(a.last_seen)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Observed hostnames">
        {data.names.length === 0 ? empty : (
          <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {data.names.map((n) => (
              <li key={`${n.name}-${n.source}`} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <span><span className="font-medium">{n.name}</span> <span className="text-slate-500">via {n.source}</span></span>
                <span className="text-slate-500">last {timeAgo(n.last_seen)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title={`Discovery sources (last ${data.observation_retention_days} days)`}>
        {data.sources.length === 0 ? empty : (
          <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {data.sources.map((s) => (
              <li key={s.source} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <span><span className="font-medium">{s.source}</span> <span className="text-slate-500">· {s.observations} sightings</span></span>
                <span className="text-slate-500">first {timeAgo(s.first_observed)}, last {timeAgo(s.last_observed)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Sessions({ id }: { id: number }) {
  const { data, error, loading } = useApi<DeviceSession[]>(`/devices/${id}/sessions`);
  if (error) return <ErrorBox message={error} />;
  if (loading || !data) return <Loading />;
  if (!data.length) return <p className="text-sm text-slate-500">No sessions recorded yet.</p>;
  return (
    <Card>
      <table className="w-full text-left text-sm">
        <thead className="text-xs uppercase text-slate-500">
          <tr><th className="py-2">Connected</th><th>Disconnected</th><th>Duration</th></tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
          {data.map((s) => (
            <tr key={s.id}>
              <td className="py-2">{fullTime(s.connected_at)}</td>
              <td>{s.disconnected_at ? fullTime(s.disconnected_at) : <span className="text-online">still connected</span>}</td>
              <td>{duration(s.duration_seconds)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}

function Events({ id }: { id: number }) {
  const { data, error, loading } = useApi<Page<DeviceEvent>>(`/devices/${id}/events?limit=100`);
  if (error) return <ErrorBox message={error} />;
  if (loading || !data) return <Loading />;
  if (!data.items.length) return <p className="text-sm text-slate-500">No events recorded yet.</p>;
  return (
    <Card>
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {data.items.map((e) => (
          <li key={e.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
            <span>
              <span className="font-medium">{eventLabel(e.event_type)}</span>
              {(e.old_value || e.new_value) && (
                <span className="text-slate-500"> · {e.old_value ?? "—"} → {e.new_value ?? "—"}</span>
              )}
            </span>
            <span className="text-slate-500">{fullTime(e.timestamp)}{e.source ? ` · ${e.source}` : ""}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

function AdGuardTab({ id }: { id: number }) {
  const { data, error, loading } = useApi<DeviceAdGuard>(`/devices/${id}/adguard`);
  if (error) return <ErrorBox message={error} />;
  if (loading || !data) return <Loading />;
  if (!data.configured)
    return (
      <p className="text-sm text-slate-500">
        AdGuard Home is not configured. <Link to="/adguard" className="text-emerald-600 hover:underline dark:text-emerald-400">Set it up</Link> to see DNS activity for this device.
      </p>
    );
  if (!data.available) return <ErrorBox message={`AdGuard Home: ${data.error?.message ?? "unavailable"}`} />;

  return (
    <div className="space-y-4">
      <Card title="Client">
        <dl className="divide-y divide-slate-200 dark:divide-slate-800">
          <Row label="Known to AdGuard" value={data.recognized ? `Yes — “${data.client_name}”` : "No persistent client entry"} />
          {data.client_ids.length > 0 && <Row label="Identifiers" value={<span className="font-mono text-xs">{data.client_ids.join(", ")}</span>} />}
          <Row label="Queries (AdGuard stats window)" value={data.stats_queries ?? "not reported"} />
          <Row label="Last query" value={data.last_query ? `${fullTime(data.last_query)} (${timeAgo(data.last_query)})` : "none in the query log"} />
          <Row label="Recent sample" value={`${data.sample_size} queries, ${data.sample_blocked} blocked`} />
        </dl>
      </Card>
      {data.top_domains.length > 0 && (
        <Card title="Top domains (recent sample)">
          <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {data.top_domains.map((t) => (
              <li key={t.domain} className="flex justify-between gap-3 py-1.5">
                <span className="min-w-0 truncate font-mono text-xs">{t.domain}</span>
                <span className="text-slate-500">{t.count}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {data.recent.length > 0 && (
        <Card title="Recent queries">
          <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {data.recent.map((q, i) => (
              <li key={i} className="flex items-center justify-between gap-3 py-1.5">
                <span className="min-w-0 truncate">
                  <span className="font-mono text-xs">{q.domain}</span>
                  {q.type && <span className="ml-2 text-xs text-slate-500">{q.type}</span>}
                </span>
                <span className="flex shrink-0 items-center gap-2 text-slate-500">
                  {q.blocked && <span className="rounded-full bg-down/15 px-2 py-0.5 text-xs text-red-600 dark:text-red-400">blocked</span>}
                  {timeAgo(q.time)}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
      {data.sample_size === 0 && <p className="text-sm text-slate-500">No queries from this device in AdGuard’s query log.</p>}
    </div>
  );
}

function DeviceSettings({ device, onSaved }: { device: Device; onSaved: (d: Device) => void }) {
  const [form, setForm] = useState({
    friendly_name: device.friendly_name ?? "",
    vendor_override: device.vendor_override ?? "",
    device_type: device.device_type ?? "",
    device_group: device.device_group ?? "",
    notes: device.notes ?? "",
    is_known: device.is_known,
    is_trusted: device.is_trusted,
    is_favorite: device.is_favorite,
    always_connected: device.always_connected,
    alert_enabled: device.alert_enabled,
    is_ignored: device.is_ignored,
  });
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => setSaved(false), [form]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // empty strings are sent as-is; the server turns them into NULL (clears the override)
      const body: DeviceUpdate = { ...form };
      onSaved(await api<Device>(`/devices/${device.id}`, { method: "PATCH", body }));
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const text = (key: "friendly_name" | "vendor_override" | "device_type" | "device_group", label: string, hint?: string, max = 100) => (
    <Field label={label} hint={hint}>
      <input className={inputCls} maxLength={max} value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} />
    </Field>
  );
  const flag = (key: "is_known" | "is_trusted" | "is_favorite" | "always_connected" | "alert_enabled" | "is_ignored", label: string) => (
    <Toggle label={label} checked={form[key]} onChange={(v) => setForm({ ...form, [key]: v })} />
  );

  return (
    <form onSubmit={submit} className="max-w-2xl space-y-5">
      {error && <ErrorBox message={error} />}
      <Card title="Identity (manual values are never overwritten by scans)">
        <div className="grid gap-4 sm:grid-cols-2">
          {text("friendly_name", "Name", "Overrides the discovered hostname")}
          {text("vendor_override", "Vendor", "Overrides the detected vendor", 255)}
          {text("device_type", "Type", "e.g. router, nas, phone", 50)}
          {text("device_group", "Group", "e.g. Living room, IoT", 50)}
        </div>
      </Card>
      <Card title="Behaviour">
        <div className="grid gap-3 sm:grid-cols-2">
          {flag("is_known", "Known device")}
          {flag("is_trusted", "Trusted")}
          {flag("is_favorite", "Favorite")}
          {flag("always_connected", "Always connected (alert when down)")}
          {flag("alert_enabled", "Alerts enabled")}
          {flag("is_ignored", "Ignore (hide from lists and counts)")}
        </div>
      </Card>
      <Card title="Notes">
        <textarea className={inputCls} rows={4} maxLength={2000} value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} aria-label="Notes" />
      </Card>
      <div className="flex items-center gap-3">
        <button className={btnCls} disabled={busy}>Save</button>
        {saved && <span role="status" className="text-sm text-online">Saved</span>}
      </div>
    </form>
  );
}
