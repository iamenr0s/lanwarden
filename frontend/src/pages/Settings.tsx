import { FormEvent, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import MfaCard from "../components/MfaCard";
import { btnCls, btnGhostCls, Card, ErrorBox, Field, inputCls, Loading, Toggle } from "../components/ui";
import { useApi } from "../hooks/useApi";
import type { ScannerSettings, SettingsResponse } from "../types";

const list = (s: string) => s.split(/[\s,]+/).filter(Boolean);

function AccountCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setDone(false);
    if (next !== again) return setError("The new passwords do not match.");
    setBusy(true);
    try {
      await api("/auth/password", { method: "POST", body: { current_password: current, new_password: next } });
      setCurrent("");
      setNext("");
      setAgain("");
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not change the password");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card title="Account">
      <form onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-3">
          <Field label="Current password">
            <input className={inputCls} type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required />
          </Field>
          <Field label="New password" hint="At least 10 characters">
            <input className={inputCls} type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required minLength={10} />
          </Field>
          <Field label="Repeat new password">
            <input className={inputCls} type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required minLength={10} />
          </Field>
        </div>
        {error && <ErrorBox message={error} />}
        <div className="flex items-center gap-3">
          <button className={btnGhostCls} disabled={busy}>Change password</button>
          {done && <span role="status" className="text-sm text-online">Password changed. Other signed-in sessions were signed out.</span>}
        </div>
      </form>
    </Card>
  );
}

export default function Settings() {
  const { data, error, setData } = useApi<SettingsResponse>("/settings");
  const [form, setForm] = useState<ScannerSettings | null>(null);
  const [ifaces, setIfaces] = useState("");
  const [nets, setNets] = useState("");
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (data) {
      setForm(data.settings.scanner);
      setIfaces(data.settings.scanner.interfaces.join(", "));
      setNets(data.settings.scanner.networks.join(", "));
    }
  }, [data]);

  // The account cards do not depend on the scanner settings loading: changing your password or enrolling
  // MFA must keep working even if that request is slow or fails.
  const account = (
    <>
      <h1 className="text-2xl font-semibold">Settings</h1>
      <AccountCard />
      <MfaCard />
    </>
  );
  if (error) return <div className="max-w-3xl space-y-6">{account}<ErrorBox message={error} /></div>;
  if (!data || !form) return <div className="max-w-3xl space-y-6">{account}<Loading /></div>;

  const num = (key: keyof ScannerSettings, label: string, hint: string, min: number) => (
    <Field label={label} hint={hint}>
      <input
        className={inputCls}
        type="number"
        min={min}
        value={form[key] as number}
        onChange={(e) => setForm({ ...form, [key]: Number(e.target.value) })}
      />
    </Field>
  );

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaveError(null);
    setSaved(false);
    try {
      const res = await api<SettingsResponse>("/settings", {
        method: "PUT",
        body: { scanner: { ...form, interfaces: list(ifaces), networks: list(nets) } },
      });
      setData(res);
      setSaved(true);
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : "Save failed");
    }
  };

  return (
    <div className="max-w-3xl space-y-6">
      {account}

      <form onSubmit={save} className="space-y-6">
        {saveError && <ErrorBox message={saveError} />}

        <Card title="Networks">
          {data.detected_networks.length > 0 && (
            <div className="mb-4 text-sm">
              <p className="mb-2 text-slate-500">
                {data.detection_ambiguous
                  ? "Several networks were detected — choose which ones to scan explicitly."
                  : "Detected network:"}
              </p>
              <div className="flex flex-wrap gap-2">
                {data.detected_networks.map((n) => (
                  <button
                    type="button"
                    key={`${n.interface}-${n.cidr}`}
                    className={btnGhostCls}
                    onClick={() => {
                      setIfaces((cur) => [...new Set([...list(cur), n.interface])].join(", "));
                      setNets((cur) => [...new Set([...list(cur), n.cidr])].join(", "));
                    }}
                  >
                    + {n.interface} · {n.cidr}
                  </button>
                ))}
              </div>
            </div>
          )}
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Interfaces" hint="Comma separated, e.g. eth0">
              <input className={inputCls} value={ifaces} onChange={(e) => setIfaces(e.target.value)} />
            </Field>
            <Field label="CIDR networks" hint="Comma separated, e.g. 192.168.1.0/24 (smallest allowed prefix: /16)">
              <input className={inputCls} value={nets} onChange={(e) => setNets(e.target.value)} />
            </Field>
          </div>
        </Card>

        <Card title="Timing">
          <div className="grid gap-4 sm:grid-cols-2">
            {num("scan_interval_seconds", "Scan interval (s)", "30 – 86400", 30)}
            {num("offline_threshold_seconds", "Offline threshold (s)", "Silence before a device counts as offline; ≥ scan interval", 60)}
            {num("always_connected_offline_threshold_seconds", "Always-connected threshold (s)", "Offline time before an alert is raised", 60)}
            {num("new_device_window_hours", "New-device window (h)", "How long an unacknowledged device stays “New”", 1)}
            {num("observation_retention_days", "Sighting retention (days)", "Raw discovery sightings are pruned after this; devices, events and sessions are kept", 1)}
          </div>
        </Card>

        <Card title="Discovery sources">
          <div className="space-y-3">
            <Toggle label="arp-scan" checked={form.arp_scan_enabled} onChange={(v) => setForm({ ...form, arp_scan_enabled: v })} />
            <Toggle label="Neighbour table" checked={form.neighbor_discovery_enabled} onChange={(v) => setForm({ ...form, neighbor_discovery_enabled: v })} />
            <Toggle label="mDNS + SSDP (model names)" checked={form.service_discovery_enabled} onChange={(v) => setForm({ ...form, service_discovery_enabled: v })} />
            <Toggle label="AdGuard Home" checked={form.adguard_discovery_enabled} onChange={(v) => setForm({ ...form, adguard_discovery_enabled: v })} />
          </div>
          <p className="mt-3 text-xs text-slate-500">
            AdGuard discovery needs the connection set up on the <Link to="/adguard" className="text-emerald-600 hover:underline dark:text-emerald-400">AdGuard page</Link>.
          </p>
        </Card>

        <div className="flex items-center gap-3">
          <button className={btnCls}>Save</button>
          {saved && <span role="status" className="text-sm text-online">Saved</span>}
        </div>
      </form>
    </div>
  );
}
