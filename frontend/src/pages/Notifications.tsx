import { FormEvent, useState } from "react";
import { api } from "../api/client";
import { btnCls, btnGhostCls, Card, ErrorBox, Field, inputCls, Loading, Toggle } from "../components/ui";
import { useApi } from "../hooks/useApi";
import { timeAgo } from "../lib/format";
import type { Delivery, NotificationRule } from "../types";

// the alerts people usually want first, then the optional general events
const EVENTS: [string, string][] = [
  ["DEVICE_DISCOVERED", "Unknown device discovered"],
  ["ALWAYS_CONNECTED_DEVICE_DOWN", "Always-connected device offline"],
  ["ALWAYS_CONNECTED_DEVICE_RECOVERED", "Always-connected device recovered"],
  ["DEVICE_CONNECTED", "Device connected"],
  ["DEVICE_DISCONNECTED", "Device disconnected"],
  ["DEVICE_IP_CHANGED", "Device IP changed"],
  ["DEVICE_NAME_CHANGED", "Device name changed"],
  ["DEVICE_ANOMALY", "Network anomaly (possible spoofing or IP conflict)"],
];
const LABELS = Object.fromEntries(EVENTS);

interface Form {
  id: number | null;
  name: string;
  provider: "email" | "webhook";
  events: string[];
  enabled: boolean;
  // email
  host: string;
  port: number;
  security: "starttls" | "ssl" | "none";
  username: string;
  password: string;
  from_addr: string;
  to_addrs: string;
  // webhook
  url: string;
  secret: string;
  verify_tls: boolean;
}

const blank = (): Form => ({
  id: null, name: "", provider: "email", events: ["DEVICE_DISCOVERED", "ALWAYS_CONNECTED_DEVICE_DOWN", "ALWAYS_CONNECTED_DEVICE_RECOVERED", "DEVICE_ANOMALY"],
  enabled: true, host: "", port: 587, security: "starttls", username: "", password: "", from_addr: "", to_addrs: "",
  url: "", secret: "", verify_tls: true,
});

function fromRule(r: NotificationRule): Form {
  const c = r.config;
  return {
    ...blank(), id: r.id, name: r.name, provider: r.provider, events: r.event_types, enabled: r.enabled,
    host: (c.host as string) ?? "", port: (c.port as number) ?? 587, security: (c.security as Form["security"]) ?? "starttls",
    username: (c.username as string) ?? "", from_addr: (c.from_addr as string) ?? "",
    to_addrs: ((c.to_addrs as string[]) ?? []).join(", "), url: "", verify_tls: (c.verify_tls as boolean) ?? true,
  };
}

// An empty secret field is omitted so the server keeps the stored one.
function toBody(f: Form) {
  const config =
    f.provider === "email"
      ? {
          host: f.host, port: f.port, security: f.security, username: f.username, from_addr: f.from_addr,
          to_addrs: f.to_addrs.split(/[\s,;]+/).filter(Boolean), verify_tls: f.verify_tls,
          ...(f.password ? { password: f.password } : {}),
        }
      : { verify_tls: f.verify_tls, ...(f.url ? { url: f.url } : {}), ...(f.secret ? { secret: f.secret } : {}) };
  return { name: f.name, provider: f.provider, event_types: f.events, enabled: f.enabled, config };
}

export default function Notifications() {
  const rules = useApi<NotificationRule[]>("/notifications/rules");
  const deliveries = useApi<Delivery[]>("/notifications/deliveries");
  const [form, setForm] = useState<Form | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState<number | null>(null);
  const [testResult, setTestResult] = useState<{ id: number; ok: boolean; error: string | null } | null>(null);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => (f ? { ...f, [k]: v } : f));

  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!form) return;
    setBusy(true);
    setError(null);
    try {
      await api(form.id === null ? "/notifications/rules" : `/notifications/rules/${form.id}`, {
        method: form.id === null ? "POST" : "PUT",
        body: toBody(form),
      });
      setForm(null);
      rules.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setBusy(false);
    }
  };

  const remove = async (r: NotificationRule) => {
    if (!window.confirm(`Delete rule “${r.name}”?`)) return;
    await api(`/notifications/rules/${r.id}`, { method: "DELETE" });
    rules.reload();
  };

  const test = async (r: NotificationRule) => {
    setTesting(r.id);
    setTestResult(null);
    try {
      const res = await api<{ ok: boolean; error: string | null }>(`/notifications/rules/${r.id}/test`, { method: "POST" });
      setTestResult({ id: r.id, ...res });
      deliveries.reload();
    } finally {
      setTesting(null);
    }
  };

  const editing = form?.id != null ? rules.data?.find((r) => r.id === form.id) : undefined;
  const secretSet = (key: string) => Boolean(editing?.config[`${key}_set`]);

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold">Notifications</h1>
        {!form && (
          <button className={btnCls} onClick={() => { setForm(blank()); setError(null); }}>
            New rule
          </button>
        )}
      </div>

      {form && (
        <form onSubmit={save} className="space-y-5">
          <Card title={form.id === null ? "New rule" : "Edit rule"}>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Name">
                <input className={inputCls} value={form.name} onChange={(e) => set("name", e.target.value)} required maxLength={100} />
              </Field>
              <Field label="Type">
                <select className={inputCls} value={form.provider} disabled={form.id !== null} onChange={(e) => set("provider", e.target.value as Form["provider"])}>
                  <option value="email">Email (SMTP)</option>
                  <option value="webhook">Webhook</option>
                </select>
              </Field>
            </div>
            <fieldset className="mt-4">
              <legend className="mb-2 text-sm font-medium">Notify me about</legend>
              <div className="grid gap-2 sm:grid-cols-2">
                {EVENTS.map(([type, label]) => (
                  <Toggle
                    key={type}
                    label={label}
                    checked={form.events.includes(type)}
                    onChange={(on) => set("events", on ? [...form.events, type] : form.events.filter((x) => x !== type))}
                  />
                ))}
              </div>
            </fieldset>
            <div className="mt-4"><Toggle label="Rule enabled" checked={form.enabled} onChange={(v) => set("enabled", v)} /></div>
          </Card>

          <Card title={form.provider === "email" ? "SMTP server" : "Webhook"}>
            {form.provider === "email" ? (
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Host"><input className={inputCls} value={form.host} onChange={(e) => set("host", e.target.value)} required placeholder="smtp.example.com" /></Field>
                <Field label="Port"><input className={inputCls} type="number" min={1} max={65535} value={form.port} onChange={(e) => set("port", Number(e.target.value))} /></Field>
                <Field label="Security">
                  <select className={inputCls} value={form.security} onChange={(e) => set("security", e.target.value as Form["security"])}>
                    <option value="starttls">STARTTLS (587)</option>
                    <option value="ssl">SSL/TLS (465)</option>
                    <option value="none">None (not recommended)</option>
                  </select>
                </Field>
                <Field label="Username"><input className={inputCls} value={form.username} onChange={(e) => set("username", e.target.value)} autoComplete="off" /></Field>
                <Field label="Password" hint={secretSet("password") ? "A password is stored. Leave empty to keep it." : undefined}>
                  <input className={inputCls} type="password" value={form.password} onChange={(e) => set("password", e.target.value)} autoComplete="new-password" />
                </Field>
                <Field label="From address"><input className={inputCls} type="email" value={form.from_addr} onChange={(e) => set("from_addr", e.target.value)} required /></Field>
                <div className="sm:col-span-2">
                  <Field label="To" hint="One or more addresses, comma separated">
                    <input className={inputCls} value={form.to_addrs} onChange={(e) => set("to_addrs", e.target.value)} required />
                  </Field>
                </div>
              </div>
            ) : (
              <div className="grid gap-4">
                <Field
                  label="URL"
                  hint={secretSet("url") ? `Stored encrypted (${String(editing?.config.url_hint ?? "")}). Leave empty to keep it.` : "Receives a JSON POST: {source, title, text, events[]}. Stored encrypted: webhook URLs usually carry a token."}
                >
                  <input className={inputCls} type="password" value={form.url} onChange={(e) => set("url", e.target.value)} required={!secretSet("url")} autoComplete="off" placeholder={secretSet("url") ? "unchanged" : "https://example.com/hook"} />
                </Field>
                <Field
                  label="Signing secret (optional)"
                  hint={secretSet("secret") ? "A secret is stored. Leave empty to keep it." : "Adds an X-LanWarden-Signature: sha256=… HMAC header"}
                >
                  <input className={inputCls} type="password" value={form.secret} onChange={(e) => set("secret", e.target.value)} autoComplete="new-password" />
                </Field>
              </div>
            )}
            <div className="mt-4"><Toggle label="Verify TLS certificate" checked={form.verify_tls} onChange={(v) => set("verify_tls", v)} /></div>
            <p className="mt-3 text-xs text-slate-500">Secrets are encrypted on the server and never sent back to the browser.</p>
          </Card>

          {error && <ErrorBox message={error} />}
          <div className="flex gap-3">
            <button className={btnCls} disabled={busy || form.events.length === 0}>Save</button>
            <button type="button" className={btnGhostCls} onClick={() => setForm(null)}>Cancel</button>
          </div>
        </form>
      )}

      <Card title="Rules">
        {rules.error && <ErrorBox message={rules.error} />}
        {!rules.data ? <Loading /> : rules.data.length === 0 ? (
          <p className="text-sm text-slate-500">No rules yet. Create one to get alerted about new devices and always-connected devices going down.</p>
        ) : (
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {rules.data.map((r) => (
              <li key={r.id} className="space-y-2 py-3 text-sm">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span>
                    <span className="font-medium">{r.name}</span>
                    <span className="ml-2 rounded-full bg-slate-500/15 px-2 py-0.5 text-xs">{r.provider}</span>
                    {!r.enabled && <span className="ml-2 text-xs text-slate-500">disabled</span>}
                  </span>
                  <span className="flex gap-2">
                    <button className={btnGhostCls} onClick={() => test(r)} disabled={testing === r.id}>{testing === r.id ? "Sending…" : "Send test"}</button>
                    <button className={btnGhostCls} onClick={() => { setForm(fromRule(r)); setError(null); window.scrollTo({ top: 0 }); }}>Edit</button>
                    <button className={btnGhostCls} onClick={() => remove(r)}>Delete</button>
                  </span>
                </div>
                <p className="text-slate-500">{r.event_types.map((t) => LABELS[t] ?? t).join(" · ")}</p>
                {testResult?.id === r.id && (testResult.ok
                  ? <p role="status" className="text-online">Test notification sent.</p>
                  : <ErrorBox message={`Test failed: ${testResult.error}`} />)}
              </li>
            ))}
          </ul>
        )}
      </Card>

      <Card title="Recent deliveries">
        {!deliveries.data ? <Loading /> : deliveries.data.length === 0 ? (
          <p className="text-sm text-slate-500">Nothing sent since the server started.</p>
        ) : (
          <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
            {deliveries.data.map((d) => (
              <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 py-2">
                <span>
                  <span className={`mr-2 inline-block h-2.5 w-2.5 rounded-full ${d.ok ? "bg-online" : "bg-down"}`} aria-label={d.ok ? "Sent" : "Failed"} role="img" />
                  {d.rule_name} <span className="text-slate-500">· {d.events === 0 ? "test" : `${d.events} event${d.events === 1 ? "" : "s"}`}</span>
                  {d.error && <span className="ml-2 text-red-600 dark:text-red-400">{d.error}</span>}
                </span>
                <span className="text-slate-500">{timeAgo(d.time)}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
